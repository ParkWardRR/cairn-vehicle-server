package gnssassist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/jsonstore"
)

// Limits and cadence. The usage policy (Thingstream, read 2026-10-25) is 300
// Predictive Orbits requests a month per device on an Evaluation profile and 2 a
// day on a Commercial one; registration is "only needed once, but can also be
// repeated". The plan below stays inside the stricter of the two.
const (
	// One download a day. AssistNow regenerates its predictions hourly, but a
	// seven-day set fetched daily is never more than a day old, and that is the
	// granularity the receiver uses them at.
	RefreshEvery = 24 * time.Hour

	// A failed download is retried after an hour, at most twice in any 24 h
	// (the Commercial profile's daily allowance), and a 403 waits for the next
	// UTC midnight, when u-blox resets its counters.
	retryAfter     = time.Hour
	maxFetchPerDay = 2

	// Registration attempts for one receiver, per 24 h.
	maxRegPerDay = 3

	// The largest body a device is sent. The firmware reserves this much PSRAM
	// for the download and refuses anything larger; seven days of four
	// constellations is ~77 KB.
	MaxDeviceBytes = 128 << 10

	// Stored data older than this is not served: the almanac, the longest-lived
	// part, is good for "up to 28 days" (GPS, Galileo, BeiDou).
	maxServeAge = 28 * 24 * time.Hour

	// The bound on one round trip to u-blox.
	requestTimeout = 60 * time.Second
)

// ErrBadIdentity is a device report that is not two valid UBX replies.
var ErrBadIdentity = errors.New("not a valid receiver identity")

// ErrNotAvailable is "nothing to serve this device yet": no receiver reported,
// not registered, or no data downloaded. The device simply asks again later.
var ErrNotAvailable = errors.New("no GNSS assistance data for this device")

// receiverState is everything about one receiver except its chipcode.
type receiverState struct {
	SecUniqID string    `json:"sec_uniqid"`
	MonVer    string    `json:"mon_ver"`
	Receiver  string    `json:"receiver"`
	FirstSeen time.Time `json:"first_seen"`

	Registered       bool        `json:"registered"`
	RegisteredAt     time.Time   `json:"registered_at,omitempty"`
	RegAttempts      []time.Time `json:"reg_attempts,omitempty"`
	NextRegAttempt   time.Time   `json:"next_reg_attempt,omitempty"`
	FetchAttempts    []time.Time `json:"fetch_attempts,omitempty"`
	NextFetchAttempt time.Time   `json:"next_fetch_attempt,omitempty"`

	FetchedAt time.Time `json:"fetched_at,omitempty"`
	Data      string    `json:"data,omitempty"`
	Bytes     int       `json:"bytes,omitempty"`
	ANO       int       `json:"ano,omitempty"`
	Almanac   int       `json:"almanac,omitempty"`
	FirstDay  string    `json:"first_day,omitempty"`
	LastDay   string    `json:"last_day,omitempty"`

	LastError  string    `json:"last_error,omitempty"`
	LastStatus int       `json:"last_status,omitempty"`
	LastFailAt time.Time `json:"last_fail_at,omitempty"`
}

type index struct {
	// Receivers by unique id (lowercase hex).
	Receivers map[string]*receiverState `json:"receivers"`
	// Devices maps a device id (32 hex) to the receiver it last reported.
	Devices map[string]string `json:"devices"`
}

func emptyIndex() index {
	return index{Receivers: map[string]*receiverState{}, Devices: map[string]string{}}
}

// Config configures a Service.
type Config struct {
	Dir  string // <data>/gnss-assist
	ZTP  ZTP
	HTTP *http.Client
	Log  *slog.Logger
	Now  func() time.Time
}

// Service holds the registrations, the cached data and the schedule.
type Service struct {
	dir  string
	ztp  ZTP
	hc   *http.Client
	log  *slog.Logger
	now  func() time.Time
	idx  *jsonstore.Store[index]
	kick chan struct{}

	work sync.Mutex // one registration or download at a time

	cacheMu sync.Mutex
	cache   map[string]cachedOrbits // by unique id
}

type cachedOrbits struct {
	modAt  time.Time
	size   int64
	frames []Frame
}

// New opens (or creates) the state under cfg.Dir.
func New(cfg Config) (*Service, error) {
	if cfg.Dir == "" {
		return nil, errors.New("gnssassist: no directory")
	}
	if err := os.MkdirAll(filepath.Join(cfg.Dir, "receivers"), 0o700); err != nil {
		return nil, fmt.Errorf("gnssassist: %w", err)
	}
	idx, err := jsonstore.Open(filepath.Join(cfg.Dir, "state.json"), emptyIndex)
	if err != nil {
		return nil, fmt.Errorf("gnssassist: open state: %w", err)
	}
	s := &Service{
		dir:   cfg.Dir,
		ztp:   cfg.ZTP,
		hc:    cfg.HTTP,
		log:   cfg.Log,
		now:   cfg.Now,
		idx:   idx,
		kick:  make(chan struct{}, 1),
		cache: map[string]cachedOrbits{},
	}
	if s.hc == nil {
		s.hc = &http.Client{Timeout: requestTimeout}
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

func (s *Service) receiverDir(uid string) string { return filepath.Join(s.dir, "receivers", uid) }
func (s *Service) orbitsPath(uid string) string {
	return filepath.Join(s.receiverDir(uid), "orbits.ubx")
}
func (s *Service) credPath(uid string) string {
	return filepath.Join(s.receiverDir(uid), "credentials.json")
}

// ReportResult tells the device what became of its report.
type ReportResult struct {
	UniqueID   string
	Registered bool
	Changed    bool
}

// ReportReceiver records which receiver a device has. Registration and the
// first download happen in the background (Run), so the device's session is not
// held open on a call to u-blox.
func (s *Service) ReportReceiver(deviceHex, secHex, monHex string) (ReportResult, error) {
	id, err := ParseIdentity(secHex, monHex)
	if err != nil {
		return ReportResult{}, fmt.Errorf("%w: %v", ErrBadIdentity, err)
	}
	deviceHex = strings.ToLower(deviceHex)
	res, err := s.recordIdentity(deviceHex, id)
	if err != nil {
		return ReportResult{}, err
	}
	if res.Changed {
		s.log.Info("GNSS receiver reported",
			"device", deviceHex, "unique_id", id.UniqueID, "receiver", id.Describe(),
			"registered", res.Registered)
	}
	if !res.Registered {
		s.Kick()
	}
	return res, nil
}

func (s *Service) recordIdentity(deviceHex string, id Identity) (ReportResult, error) {
	res := ReportResult{UniqueID: id.UniqueID}
	secHex := hex.EncodeToString(id.SecUniqID)
	monHex := hex.EncodeToString(id.MonVer)
	err := s.idx.Update(func(ix *index) error {
		if ix.Receivers == nil {
			ix.Receivers = map[string]*receiverState{}
		}
		if ix.Devices == nil {
			ix.Devices = map[string]string{}
		}
		r := ix.Receivers[id.UniqueID]
		if r == nil {
			r = &receiverState{FirstSeen: s.now().UTC()}
			ix.Receivers[id.UniqueID] = r
			res.Changed = true
		}
		if r.SecUniqID != secHex || r.MonVer != monHex {
			// A firmware update on the receiver changes MON-VER; ZTP wants the
			// current one, so a change re-registers.
			if r.SecUniqID != "" {
				r.Registered = false
			}
			r.SecUniqID, r.MonVer, r.Receiver = secHex, monHex, id.Describe()
			res.Changed = true
		}
		if deviceHex != "" && ix.Devices[deviceHex] != id.UniqueID {
			ix.Devices[deviceHex] = id.UniqueID
			res.Changed = true
		}
		res.Registered = r.Registered
		return nil
	})
	return res, err
}

// Kick asks Run to look at the schedule now.
func (s *Service) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run drives registration and downloads until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.kick:
		}
	}
}

// Tick does whatever registration or download is due. Exported for tests and
// for the administrative mode.
func (s *Service) Tick(ctx context.Context) {
	s.work.Lock()
	defer s.work.Unlock()

	var uids []string
	s.idx.View(func(ix *index) {
		for uid := range ix.Receivers {
			uids = append(uids, uid)
		}
	})
	sort.Strings(uids)
	for _, uid := range uids {
		if ctx.Err() != nil {
			return
		}
		s.tickReceiver(ctx, uid)
	}
}

func recent(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0:0]
	for _, t := range ts {
		if now.Sub(t) < 24*time.Hour {
			out = append(out, t)
		}
	}
	return out
}

func (s *Service) tickReceiver(ctx context.Context, uid string) {
	now := s.now().UTC()
	var r receiverState
	s.idx.View(func(ix *index) {
		if p := ix.Receivers[uid]; p != nil {
			r = *p
		}
	})

	if !r.Registered || !fileExists(s.credPath(uid)) {
		if now.Before(r.NextRegAttempt) || len(recent(r.RegAttempts, now)) >= maxRegPerDay {
			return
		}
		if err := s.registerReceiver(ctx, uid, r, now); err != nil {
			return
		}
		r.Registered = true
	}

	due := r.FetchedAt.IsZero() || now.Sub(r.FetchedAt) >= RefreshEvery || !fileExists(s.orbitsPath(uid))
	if !due || now.Before(r.NextFetchAttempt) || len(recent(r.FetchAttempts, now)) >= maxFetchPerDay {
		return
	}
	_ = s.refresh(ctx, uid, now)
}

func (s *Service) registerReceiver(ctx context.Context, uid string, r receiverState, now time.Time) error {
	id, err := ParseIdentity(r.SecUniqID, r.MonVer)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cred, regErr := register(cctx, s.hc, s.ztp, id)

	_ = s.idx.Update(func(ix *index) error {
		p := ix.Receivers[uid]
		if p == nil {
			return nil
		}
		p.RegAttempts = append(recent(p.RegAttempts, now), now)
		if regErr != nil {
			p.Registered = false
			p.NextRegAttempt = now.Add(retryAfter)
			p.LastError, p.LastStatus, p.LastFailAt = regErr.Error(), statusOf(regErr), now
			return nil
		}
		p.Registered, p.RegisteredAt, p.NextRegAttempt = true, now, time.Time{}
		p.LastError, p.LastStatus = "", 0
		return nil
	})
	if regErr != nil {
		s.log.Warn("AssistNow registration failed", "unique_id", uid, "status", statusOf(regErr), "error", regErr)
		return regErr
	}
	if err := writeDurable(s.credPath(uid), mustJSON(credentialsFile{
		UniqueID:     uid,
		Chipcode:     cred.Chipcode.reveal(),
		ServiceURL:   cred.ServiceURL,
		AllowedData:  cred.AllowedData,
		RegisteredAt: now,
		Receiver:     id.Describe(),
	}), 0o600); err != nil {
		s.log.Error("storing AssistNow credentials failed", "unique_id", uid, "error", err)
		_ = s.idx.Update(func(ix *index) error {
			if p := ix.Receivers[uid]; p != nil {
				p.Registered = false
			}
			return nil
		})
		return err
	}
	s.log.Info("AssistNow registered", "unique_id", uid, "receiver", id.Describe(),
		"allowed_data", strings.Join(cred.AllowedData, ","))
	return nil
}

func (s *Service) loadCredentials(uid string) (Credentials, error) {
	raw, err := os.ReadFile(s.credPath(uid))
	if err != nil {
		return Credentials{}, err
	}
	var f credentialsFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Chipcode == "" {
		return Credentials{}, errors.New("stored AssistNow credentials are unreadable")
	}
	return Credentials{Chipcode: secret(f.Chipcode), ServiceURL: f.ServiceURL, AllowedData: f.AllowedData}, nil
}

// refresh downloads, validates and stores one receiver's data.
func (s *Service) refresh(ctx context.Context, uid string, now time.Time) error {
	cred, err := s.loadCredentials(uid)
	if err != nil {
		s.log.Warn("AssistNow credentials missing; registering again", "unique_id", uid, "error", err)
		_ = s.idx.Update(func(ix *index) error {
			if p := ix.Receivers[uid]; p != nil {
				p.Registered = false
			}
			return nil
		})
		return err
	}

	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	raw, data, fetchErr := fetchOrbits(cctx, s.hc, cred)

	var sum Summary
	if fetchErr == nil {
		frames, perr := SplitFrames(raw)
		if perr != nil {
			// A 200 that is not UBX is an error string in a success status.
			fetchErr = fmt.Errorf("AssistNow Predictive Orbits: %v (%q)", perr, excerpt(raw, cred.Chipcode.reveal()))
		} else {
			kept, dropped := cleanForCache(frames)
			sum = summarise(kept)
			sum.DroppedINI = dropped
			if sum.ANO == 0 {
				fetchErr = errors.New("AssistNow Predictive Orbits: the response holds no UBX-MGA-ANO")
			} else {
				var buf []byte
				for _, f := range kept {
					buf = append(buf, f.Raw...)
				}
				if err := writeDurable(s.orbitsPath(uid), buf, 0o600); err != nil {
					fetchErr = fmt.Errorf("store orbits: %w", err)
				}
			}
		}
	}

	status := statusOf(fetchErr)
	_ = s.idx.Update(func(ix *index) error {
		p := ix.Receivers[uid]
		if p == nil {
			return nil
		}
		p.FetchAttempts = append(recent(p.FetchAttempts, now), now)
		if fetchErr != nil {
			p.LastError, p.LastStatus, p.LastFailAt = fetchErr.Error(), status, now
			switch status {
			case http.StatusForbidden:
				p.NextFetchAttempt = nextUTCMidnight(now)
			case http.StatusUnauthorized:
				// The chipcode is no longer accepted: register again (bounded).
				p.Registered = false
				p.NextFetchAttempt = now
			default:
				p.NextFetchAttempt = now.Add(retryAfter)
			}
			return nil
		}
		p.FetchedAt, p.Data, p.NextFetchAttempt = now, data, time.Time{}
		p.Bytes, p.ANO, p.Almanac = sum.Bytes, sum.ANO, sum.Almanac
		p.FirstDay, p.LastDay = sum.FirstDay.Format(time.DateOnly), sum.LastDay.Format(time.DateOnly)
		p.LastError, p.LastStatus = "", 0
		return nil
	})
	if fetchErr != nil {
		s.log.Warn("AssistNow download failed", "unique_id", uid, "status", status, "error", fetchErr)
		return fetchErr
	}
	s.log.Info("AssistNow Predictive Orbits stored", "unique_id", uid, "data", data,
		"bytes", sum.Bytes, "ano", sum.ANO, "almanac", sum.Almanac,
		"first_day", sum.FirstDay.Format(time.DateOnly), "last_day", sum.LastDay.Format(time.DateOnly),
		"dropped_ini", sum.DroppedINI)
	return nil
}

// Data is what device deviceHex is served now, and its entity tag.
func (s *Service) Data(deviceHex string) ([]byte, string, error) {
	var uid string
	var r receiverState
	s.idx.View(func(ix *index) {
		uid = ix.Devices[strings.ToLower(deviceHex)]
		if p := ix.Receivers[uid]; p != nil {
			r = *p
		}
	})
	if uid == "" || r.FetchedAt.IsZero() {
		return nil, "", ErrNotAvailable
	}
	now := s.now().UTC()
	if now.Sub(r.FetchedAt) > maxServeAge {
		return nil, "", ErrNotAvailable
	}
	frames, err := s.loadOrbits(uid)
	if err != nil {
		return nil, "", ErrNotAvailable
	}
	body := forDevice(frames, now, MaxDeviceBytes)
	if len(body) == 0 {
		return nil, "", ErrNotAvailable
	}
	return body, ETag(body), nil
}

// ETag is the strong entity tag of a body: its SHA-256 in lowercase hex, quoted.
// Defined by content rather than by version so the device can recompute it from
// the copy on its card and send it back in If-None-Match without storing it.
func ETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

func (s *Service) loadOrbits(uid string) ([]Frame, error) {
	path := s.orbitsPath(uid)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	c, ok := s.cache[uid]
	s.cacheMu.Unlock()
	if ok && c.modAt.Equal(info.ModTime()) && c.size == info.Size() {
		return c.frames, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	frames, err := SplitFrames(raw)
	if err != nil {
		return nil, err
	}
	s.cacheMu.Lock()
	s.cache[uid] = cachedOrbits{modAt: info.ModTime(), size: info.Size(), frames: frames}
	s.cacheMu.Unlock()
	return frames, nil
}

// RegisterNow registers a receiver from hex the operator supplies and downloads
// its data straight away: the administrative path, for an identity captured on
// the bench. It ignores the daily attempt bounds, since a person is watching.
func (s *Service) RegisterNow(ctx context.Context, secHex, monHex string) (string, error) {
	id, err := ParseIdentity(secHex, monHex)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadIdentity, err)
	}
	if _, err := s.recordIdentity("", id); err != nil {
		return "", err
	}
	s.work.Lock()
	defer s.work.Unlock()
	now := s.now().UTC()
	var r receiverState
	s.idx.View(func(ix *index) { r = *ix.Receivers[id.UniqueID] })
	if err := s.registerReceiver(ctx, id.UniqueID, r, now); err != nil {
		return id.UniqueID, err
	}
	return id.UniqueID, s.refresh(ctx, id.UniqueID, now)
}

// Status is a printable summary of every receiver, without secrets.
func (s *Service) Status() []string {
	var lines []string
	s.idx.View(func(ix *index) {
		devs := map[string][]string{}
		for d, u := range ix.Devices {
			devs[u] = append(devs[u], d)
		}
		var uids []string
		for u := range ix.Receivers {
			uids = append(uids, u)
		}
		sort.Strings(uids)
		for _, u := range uids {
			r := ix.Receivers[u]
			line := fmt.Sprintf("receiver %s (%s) devices=%s registered=%v", u, r.Receiver, strings.Join(devs[u], ","), r.Registered)
			if !r.FetchedAt.IsZero() {
				line += fmt.Sprintf(" fetched=%s data=%s bytes=%d ano=%d almanac=%d days=%s..%s",
					r.FetchedAt.Format(time.RFC3339), r.Data, r.Bytes, r.ANO, r.Almanac, r.FirstDay, r.LastDay)
			}
			if r.LastError != "" {
				line += fmt.Sprintf(" last_error=%q at %s", r.LastError, r.LastFailAt.Format(time.RFC3339))
			}
			lines = append(lines, line)
		}
	})
	if len(lines) == 0 {
		lines = []string{"no GNSS receiver reported yet"}
	}
	return lines
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// writeDurable writes atomically and durably: temp file, fsync, rename, fsync
// the directory. The same sequence internal/receipts uses.
func writeDurable(final string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(final)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
