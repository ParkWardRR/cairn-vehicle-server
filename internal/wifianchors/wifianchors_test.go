package wifianchors

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

func bssid(b ...byte) [6]byte {
	var o [6]byte
	copy(o[:], b)
	return o
}

func TestAccuracyClamp(t *testing.T) {
	for _, c := range []struct {
		spread float64
		want   uint16
	}{{0, 25}, {-3, 25}, {math.NaN(), 25}, {0.4, 26}, {12, 37}, {300, 325}, {475, 500}, {476, 500}, {1e9, 500}} {
		if got := AccuracyM(c.spread); got != c.want {
			t.Errorf("AccuracyM(%v) = %d, want %d", c.spread, got, c.want)
		}
	}
}

func TestEncodeLayout(t *testing.T) {
	seen := time.Date(2026, 10, 25, 18, 4, 5, 0, time.UTC)
	a := []Anchor{
		{BSSID: bssid(0x10, 0x20, 0x30, 0x40, 0x50, 0x60), Lat: 37.7749295, Lon: -122.4194155, SpreadM: 12.2, LastSeen: seen.Add(-time.Hour)},
		{BSSID: bssid(0xf0, 0, 0, 0, 0, 1), Lat: -33.8688197, Lon: 151.2092955, SpreadM: 900, LastSeen: seen},
	}
	b := Encode(a)
	if len(b) != HeaderSize+2*RecordSize {
		t.Fatalf("length %d", len(b))
	}
	if string(b[:4]) != "CWA1" || binary.LittleEndian.Uint16(b[4:]) != 1 || binary.LittleEndian.Uint16(b[6:]) != 16 {
		t.Fatalf("header % x", b[:16])
	}
	if binary.LittleEndian.Uint32(b[8:]) != 2 {
		t.Fatal("count")
	}
	if got := binary.LittleEndian.Uint32(b[12:]); got != uint32(seen.Unix()) {
		t.Fatalf("generated_at %d, want the newest sighting %d", got, seen.Unix())
	}
	// Byte for byte, the first record.
	want := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60}
	lat, lon := int32(377749295), int32(-1224194155)
	want = binary.LittleEndian.AppendUint32(want, uint32(lat))
	want = binary.LittleEndian.AppendUint32(want, uint32(lon))
	want = binary.LittleEndian.AppendUint16(want, 38)
	if !bytes.Equal(b[16:32], want) {
		t.Fatalf("record 0\n got % x\nwant % x", b[16:32], want)
	}
	if acc := binary.LittleEndian.Uint16(b[46:]); acc != 500 {
		t.Fatalf("record 1 acc %d", acc)
	}

	// Empty: a header that says zero, and generated_at zero.
	e := Encode(nil)
	if len(e) != 16 || binary.LittleEndian.Uint32(e[8:]) != 0 || binary.LittleEndian.Uint32(e[12:]) != 0 {
		t.Fatalf("empty % x", e)
	}
	// Deterministic, so the ETag is stable.
	if ETag(Encode(a)) != ETag(b) || !strings.HasPrefix(ETag(b), `"`) || len(ETag(b)) != 66 {
		t.Fatal("ETag")
	}
}

func TestSelectMergesCapsAndSorts(t *testing.T) {
	rows := []Anchor{
		{BSSID: bssid(9), Observations: 2, MaxRSSIdBm: -80, Lat: 1, Lon: 1},
		{BSSID: bssid(1), Observations: 5, MaxRSSIdBm: -70, Lat: 2, Lon: 2},
		// The same access point learned by the other car: more sightings win.
		{BSSID: bssid(1), Observations: 9, MaxRSSIdBm: -75, Lat: 3, Lon: 3},
		{BSSID: bssid(5), Observations: 5, MaxRSSIdBm: -50, Lat: 4, Lon: 4},
		{BSSID: bssid(7), Observations: 5, MaxRSSIdBm: -50, SpreadM: 10, Lat: 5, Lon: 5},
		{BSSID: bssid(3), Observations: 5, MaxRSSIdBm: -50, SpreadM: 5, Lat: 6, Lon: 6},
	}
	all := Select(rows, 100)
	if len(all) != 5 {
		t.Fatalf("%d after merging", len(all))
	}
	for i := 1; i < len(all); i++ {
		if bytes.Compare(all[i-1].BSSID[:], all[i].BSSID[:]) >= 0 {
			t.Fatal("not sorted by BSSID")
		}
	}
	if all[0].BSSID != bssid(1) || all[0].Lat != 3 {
		t.Fatalf("merge kept %+v", all[0])
	}

	// Cap 3: the 9-sighting one, then the -50 dBm ones by spread (3 before 7 before 5? 5 has
	// spread 0, so 5, 3, 7), and the 2-sighting one is dropped first.
	top := Select(rows, 3)
	var got []byte
	for _, a := range top {
		got = append(got, a.BSSID[0])
	}
	if !bytes.Equal(got, []byte{1, 3, 5}) {
		t.Fatalf("cap kept %v", got)
	}
}

func TestParseBSSID(t *testing.T) {
	if b, err := ParseBSSID("aa:bb:cc:dd:ee:0f"); err != nil || b != bssid(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f) {
		t.Fatal(b, err)
	}
	for _, bad := range []string{"", "aabbccddeeff", "aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"} {
		if _, err := ParseBSSID(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

type fakeAssignments []*vehicles.Assignment

func (f fakeAssignments) Assignments(string) []*vehicles.Assignment { return f }

const (
	carA = "0190aaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	carB = "0190bbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	carC = "0190cccccccccccccccccccccccccccc"
)

// fakeStore answers /query like cairn-tsdb, from rows keyed by vehicle.
func fakeStore(t *testing.T, rows map[string][][]any, queries *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/query" {
			http.NotFound(w, r)
			return
		}
		q, _ := io.ReadAll(r.Body)
		*queries = append(*queries, string(q))
		out := [][]any{}
		for v, rs := range rows {
			if strings.Contains(string(q), "'"+v+"'") {
				out = append(out, rs...)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"columns": []string{"vehicle_id", "bssid", "lat", "lon", "observations", "spread_m", "max_rssi_dbm", "last_seen"},
			"rows":    out,
		})
	}))
}

func TestServiceReadsOnlyOpenAssignments(t *testing.T) {
	var queries []string
	store := fakeStore(t, map[string][][]any{
		carA: {{carA, "aa:00:00:00:00:02", 37.1, -122.1, 4, 10.0, -55, "2026-10-25T18:00:00Z"}},
		carB: {{carB, "aa:00:00:00:00:01", 37.2, -122.2, 3, 20.0, -60, "2026-10-26T08:00:00Z"},
			{carB, "not-a-bssid", 37.2, -122.2, 3, 20.0, -60, "2026-10-26T08:00:00Z"},
			{carB, "aa:00:00:00:00:09", 0.0, 0.0, 3, 20.0, -60, "2026-10-26T08:00:00Z"}},
		carC: {{carC, "aa:00:00:00:00:03", 1.0, 1.0, 9, 1.0, -40, "2026-10-26T09:00:00Z"}},
	}, &queries)
	defer store.Close()

	s := &Service{StoreURL: store.URL + "/", Vehicles: fakeAssignments{
		{VehicleID: carA}, {VehicleID: strings.ToUpper(carB)}, {VehicleID: carA},
		{VehicleID: carC, EndsAt: time.Now()}, // moved away: no longer the device's car
	}}
	body, n, err := s.For(context.Background(), "01")
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || binary.LittleEndian.Uint32(body[8:]) != 2 {
		t.Fatalf("count %d", n)
	}
	if len(queries) != 1 || strings.Contains(queries[0], carC) || !strings.Contains(queries[0], carA) || !strings.Contains(queries[0], carB) {
		t.Fatalf("query %q", queries)
	}
	// Sorted: ...:01 (car B) before ...:02 (car A); the malformed and null-island rows skipped.
	if body[16+5] != 1 || body[32+5] != 2 {
		t.Fatalf("order % x", body)
	}
	if binary.LittleEndian.Uint16(body[16+14:]) != 45 {
		t.Fatal("acc for spread 20")
	}
	if got := binary.LittleEndian.Uint32(body[12:]); got != uint32(time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC).Unix()) {
		t.Fatalf("generated_at %d", got)
	}
}

func TestServiceCap(t *testing.T) {
	var queries []string
	var rows [][]any
	for i := 0; i < 50; i++ {
		rows = append(rows, []any{carA, fmt.Sprintf("aa:00:00:00:00:%02x", i), 37.0, -122.0, float64(2 + i), 5.0, -70, "2026-10-25T18:00:00Z"})
	}
	store := fakeStore(t, map[string][][]any{carA: rows}, &queries)
	defer store.Close()
	s := &Service{StoreURL: store.URL, Vehicles: fakeAssignments{{VehicleID: carA}}, Max: 10}
	body, n, err := s.For(context.Background(), "01")
	if err != nil || n != 10 || len(body) != 16+10*16 {
		t.Fatalf("n=%d len=%d err=%v", n, len(body), err)
	}
	// The ten most-observed are 40..49.
	if body[16+5] != 40 || body[16+9*16+5] != 49 {
		t.Fatalf("kept % x", body[16:])
	}
}

func TestServiceNoAssignmentNoQuery(t *testing.T) {
	s := &Service{StoreURL: "http://127.0.0.1:9", Vehicles: fakeAssignments{}}
	body, n, err := s.For(context.Background(), "01")
	if err != nil || n != 0 || len(body) != 16 {
		t.Fatalf("%d %v", n, err)
	}
}

func TestServiceStoreDown(t *testing.T) {
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer broken.Close()
	for _, url := range []string{broken.URL, "http://127.0.0.1:9"} {
		s := &Service{StoreURL: url, Vehicles: fakeAssignments{{VehicleID: carA}}}
		if _, _, err := s.For(context.Background(), "01"); !errors.Is(err, ErrStoreUnavailable) {
			t.Errorf("%s: %v", url, err)
		}
	}
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"columns":["bssid"],"rows":[]}`))
	}))
	defer old.Close()
	s := &Service{StoreURL: old.URL, Vehicles: fakeAssignments{{VehicleID: carA}}}
	if _, _, err := s.For(context.Background(), "01"); !errors.Is(err, ErrStoreUnavailable) {
		t.Errorf("a store without the view's columns: %v", err)
	}
}
