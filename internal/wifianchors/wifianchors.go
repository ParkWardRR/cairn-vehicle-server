// Package wifianchors serves the dongle the access-point positions the store has
// learned, so it can locate itself from a Wi-Fi scan at power-up and hand the
// GNSS receiver an initial-position hint (format/v3 §6.4).
//
// Why: a cold receiver in the M240i drew nothing for the first eight minutes of
// the drive of 2026-10-25, and the hint it gets today is the last saved fix at
// ±10 km. The store already knows where the access points around the owner's
// places are (v_wifi_ap_learned, store/v1.7), learned from trusted fixes beside
// the device's own learning scans; this package turns that view into a compact,
// sorted table the firmware binary-searches.
//
// The body is deterministic for a given set of rows: generated_at is the newest
// sighting behind the set, not the wall clock, so the ETag can be a plain content
// hash and a device whose copy is current gets a 304 instead of 64 KiB.
package wifianchors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// The binary layout, format/v3 §6.4. Little-endian like the rest of format/v3.
const (
	Magic      = "CWA1"
	Version    = 1
	HeaderSize = 16
	RecordSize = 16

	// MaxRecords caps the table at 64 KiB of records: one PSRAM allocation on
	// the dongle and a few seconds on its slowest link. A car's learned set is
	// far smaller today (hundreds); the cap is there for the day it is not.
	MaxRecords = 4096

	// The accuracy each anchor claims: its learned spread plus 25 m (the same
	// pad v_wifi_scan_unfixed adds), never under 25 m, never over 500 m. A
	// spread is an RMS of fix positions around the centre, not the distance at
	// which the access point is still heard, so the pad stands for the radio
	// range the spread cannot see.
	accPadM = 25
	MinAccM = 25
	MaxAccM = 500
)

// Anchor is one learned access point.
type Anchor struct {
	BSSID        [6]byte
	Lat, Lon     float64
	Observations int64
	SpreadM      float64
	MaxRSSIdBm   int
	LastSeen     time.Time
}

// AccuracyM is the accuracy an anchor is served with.
func AccuracyM(spreadM float64) uint16 {
	if math.IsNaN(spreadM) || spreadM < 0 {
		spreadM = 0
	}
	a := math.Ceil(spreadM + accPadM)
	if a < MinAccM {
		a = MinAccM
	}
	if a > MaxAccM {
		a = MaxAccM
	}
	return uint16(a)
}

// better says whether a should be kept over b: more sightings first, then the
// strongest reading (taken closest to the access point), then the tighter spread.
func better(a, b Anchor) bool {
	if a.Observations != b.Observations {
		return a.Observations > b.Observations
	}
	if a.MaxRSSIdBm != b.MaxRSSIdBm {
		return a.MaxRSSIdBm > b.MaxRSSIdBm
	}
	if a.SpreadM != b.SpreadM {
		return a.SpreadM < b.SpreadM
	}
	return bytes.Compare(a.BSSID[:], b.BSSID[:]) < 0
}

// Select merges the rows of several vehicles (one access point may have been
// learned by both cars in the garage; the better-observed row wins), keeps at
// most max of the best-observed, and returns them sorted by BSSID, the order the
// device searches in.
func Select(rows []Anchor, max int) []Anchor {
	byBSSID := make(map[[6]byte]Anchor, len(rows))
	for _, r := range rows {
		if old, ok := byBSSID[r.BSSID]; !ok || better(r, old) {
			byBSSID[r.BSSID] = r
		}
	}
	out := make([]Anchor, 0, len(byBSSID))
	for _, a := range byBSSID {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return better(out[i], out[j]) })
	if max >= 0 && len(out) > max {
		out = out[:max]
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].BSSID[:], out[j].BSSID[:]) < 0 })
	return out
}

// Encode renders the table. anchors must already be selected (sorted, unique).
//
//	header  16 B: "CWA1", version u16, record_size u16, count u32, generated_at u32
//	record  16 B: bssid[6], lat_e7 i32, lon_e7 i32, acc_m u16
func Encode(anchors []Anchor) []byte {
	var newest time.Time
	for _, a := range anchors {
		if a.LastSeen.After(newest) {
			newest = a.LastSeen
		}
	}
	gen := uint32(0)
	if !newest.IsZero() && newest.Unix() > 0 && newest.Unix() <= math.MaxUint32 {
		gen = uint32(newest.Unix())
	}

	out := make([]byte, HeaderSize+RecordSize*len(anchors))
	copy(out, Magic)
	binary.LittleEndian.PutUint16(out[4:], Version)
	binary.LittleEndian.PutUint16(out[6:], RecordSize)
	binary.LittleEndian.PutUint32(out[8:], uint32(len(anchors)))
	binary.LittleEndian.PutUint32(out[12:], gen)
	for i, a := range anchors {
		r := out[HeaderSize+i*RecordSize:]
		copy(r, a.BSSID[:])
		binary.LittleEndian.PutUint32(r[6:], uint32(e7(a.Lat)))
		binary.LittleEndian.PutUint32(r[10:], uint32(e7(a.Lon)))
		binary.LittleEndian.PutUint16(r[14:], AccuracyM(a.SpreadM))
	}
	return out
}

func e7(deg float64) int32 { return int32(math.Round(deg * 1e7)) }

// ETag is the quoted SHA-256 of the body.
func ETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// ParseBSSID reads the store's "aa:bb:cc:dd:ee:ff".
func ParseBSSID(s string) ([6]byte, error) {
	var b [6]byte
	raw, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(raw) != 6 || len(s) != 17 {
		return b, fmt.Errorf("not a BSSID: %q", s)
	}
	copy(b[:], raw)
	return b, nil
}

// ─── the store ──────────────────────────────────────────────────────────────

// ErrStoreUnavailable means the analytical store could not be read; the device
// should keep its copy and ask again later.
var ErrStoreUnavailable = errors.New("the analytical store is unavailable")

// Assignments is the part of the vehicle registry the service reads.
type Assignments interface {
	Assignments(deviceID string) []*vehicles.Assignment
}

// Service builds a device's table from cairn-tsdb.
type Service struct {
	// StoreURL is the loopback cairn-tsdb base URL (cairn-server -app-snapshot-url).
	StoreURL string
	Vehicles Assignments
	Client   *http.Client
	Max      int // 0 means MaxRecords
}

// learnedSQL reads every learned access point of the given vehicles. The view
// already refuses an access point seen fewer than twice or over more than 300 m.
const learnedSQL = `SELECT vehicle_id, bssid, lat, lon, observations, spread_m, max_rssi_dbm, last_seen
FROM v_wifi_ap_learned WHERE vehicle_id IN (%s)`

// VehiclesFor lists the vehicles a device holds open assignments to: its garage.
// A car the device has been moved away from no longer contributes.
func (s *Service) VehiclesFor(deviceHex string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range s.Vehicles.Assignments(deviceHex) {
		v := strings.ToLower(a.VehicleID)
		if !a.Open() || seen[v] || !isHex32(v) {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// For returns the encoded table for a device. A device with no open assignment,
// or whose cars have learned nothing yet, gets an empty table, not an error.
func (s *Service) For(ctx context.Context, deviceHex string) ([]byte, int, error) {
	vs := s.VehiclesFor(deviceHex)
	if len(vs) == 0 {
		return Encode(nil), 0, nil
	}
	rows, err := s.fetch(ctx, vs)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	max := s.Max
	if max <= 0 {
		max = MaxRecords
	}
	sel := Select(rows, max)
	return Encode(sel), len(sel), nil
}

func (s *Service) fetch(ctx context.Context, vehicleIDs []string) ([]Anchor, error) {
	quoted := make([]string, len(vehicleIDs))
	for i, v := range vehicleIDs {
		quoted[i] = "'" + v + "'" // isHex32 already: nothing to escape
	}
	body := fmt.Sprintf(learnedSQL, strings.Join(quoted, ", "))

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(s.StoreURL, "/")+"/query", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("store answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var res struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("store answer: %w", err)
	}
	return rowsToAnchors(res.Columns, res.Rows)
}

func rowsToAnchors(cols []string, rows [][]any) ([]Anchor, error) {
	idx := map[string]int{}
	for i, c := range cols {
		idx[c] = i
	}
	for _, c := range []string{"bssid", "lat", "lon", "observations", "spread_m", "max_rssi_dbm", "last_seen"} {
		if _, ok := idx[c]; !ok {
			return nil, fmt.Errorf("the store has no column %s (is it older than store/v1.7?)", c)
		}
	}
	num := func(v any) (float64, bool) {
		f, ok := v.(float64)
		return f, ok && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	out := make([]Anchor, 0, len(rows))
	for _, row := range rows {
		if len(row) != len(cols) {
			return nil, errors.New("a row does not match the columns")
		}
		bs, _ := row[idx["bssid"]].(string)
		bssid, err := ParseBSSID(bs)
		if err != nil {
			continue // the store only holds well-formed BSSIDs; skip rather than fail the set
		}
		lat, ok1 := num(row[idx["lat"]])
		lon, ok2 := num(row[idx["lon"]])
		if !ok1 || !ok2 || lat < -90 || lat > 90 || lon < -180 || lon > 180 || (lat == 0 && lon == 0) {
			continue
		}
		a := Anchor{BSSID: bssid, Lat: lat, Lon: lon}
		if n, ok := num(row[idx["observations"]]); ok {
			a.Observations = int64(n)
		}
		if sp, ok := num(row[idx["spread_m"]]); ok {
			a.SpreadM = sp
		}
		if r, ok := num(row[idx["max_rssi_dbm"]]); ok {
			a.MaxRSSIdBm = int(r)
		} else {
			a.MaxRSSIdBm = -128
		}
		if ts, ok := row[idx["last_seen"]].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				a.LastSeen = t
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func isHex32(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
