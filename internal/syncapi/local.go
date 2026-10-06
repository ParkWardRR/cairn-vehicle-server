package syncapi

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/engine"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/insight"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// LocalConfig configures the local listener's handler.
type LocalConfig struct {
	Vehicles *vehicles.Registry

	// Engines supplies the engine profile each vehicle is served with. Nil serves none.
	Engines *engine.Catalog

	// StoreURL is the loopback cairn-tsdb base URL the health summary reads its statistics
	// from. Empty disables the health route (503).
	StoreURL string

	// WriteToken is the shared secret the web layer presents to change anything. Empty
	// disables every write route (403): reading display data is what the loopback bind
	// alone can protect, writing is not.
	WriteToken string

	Client *http.Client
	Log    *slog.Logger
}

// LocalHandler is the read-only vehicle list for processes on the same host. It is
// NewLocalHandler with nothing but the registry.
func LocalHandler(reg *vehicles.Registry) http.Handler {
	return NewLocalHandler(LocalConfig{Vehicles: reg})
}

// NewLocalHandler is the API for processes on the same host: today, the web UI's server
// side asking what to call each vehicle, what its engine's limits are, how it is doing,
// and recording the tunes its owner makes.
//
// It is deliberately NOT part of the app API. It exists on its own loopback-only
// listener, and the loopback bind is the access control for what it READS. That is only
// safe if nothing can forward traffic to it, and the one thing that routinely forwards
// traffic to loopback ports on this host is tailscale serve. So every route refuses any
// request that carries a Tailscale identity header or the Funnel marker: if someone
// points Serve (or a reverse proxy that adds those) at this port by mistake, it answers
// 403 instead of handing the vehicle list to the tailnet.
//
// What it WRITES is guarded by more than the bind. A loopback port is reachable by every
// process on the host and, through DNS rebinding, by a web page in a browser on it, so a
// route that changes state also demands the shared WriteToken. The web layer holds the
// token and is responsible for who may use it: it asks for a passkey used in the last five
// minutes before it calls a write route, and records who asked. This handler records the
// actor it was told, never decides it.
//
// What it returns is display data only: id, name, engine code and profile, tune records,
// archived. Never the VIN, sealed or otherwise, and never an assignment or a device id.
func NewLocalHandler(cfg LocalConfig) http.Handler {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 20 * time.Second}
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	l := &local{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/local/vehicles", l.guard(false, l.listVehicles))
	mux.HandleFunc("GET /v1/local/vehicles/{id}/health", l.guard(false, l.health))
	mux.HandleFunc("POST /v1/local/vehicles/{id}/tunes", l.guard(true, l.addTune))
	mux.HandleFunc("PUT /v1/local/vehicles/{id}/tunes/{tune}", l.guard(true, l.updateTune))
	mux.HandleFunc("DELETE /v1/local/vehicles/{id}/tunes/{tune}", l.guard(true, l.deleteTune))
	return mux
}

type local struct {
	cfg LocalConfig
}

// maxLocalBody bounds a write body: a tune is a date and a note of at most 500 characters.
const maxLocalBody = 8 << 10

var vehicleIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (l *local) guard(write bool, h func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderFunnel) != "" || r.Header.Get(HeaderTailscaleLogin) != "" ||
			r.Header.Get(HeaderTailscaleName) != "" {
			http.Error(w, "this endpoint is for local processes only", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if write {
			if l.cfg.WriteToken == "" {
				localError(w, http.StatusForbidden, "writes_disabled", "this server was started without a local write token")
				return
			}
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(l.cfg.WriteToken)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="cairn-local"`)
				localError(w, http.StatusUnauthorized, "unauthenticated", "a valid local write token is required")
				return
			}
			// A browser form can post text/plain across origins without a preflight;
			// insisting on JSON removes that route even if the token were guessed.
			if ct := r.Header.Get("Content-Type"); r.Method != http.MethodDelete &&
				!strings.HasPrefix(strings.ToLower(ct), "application/json") {
				localError(w, http.StatusUnsupportedMediaType, "bad_content_type", "send application/json")
				return
			}
		}
		h(w, r)
	}
}

func localError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

func localJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// tuneJSON is a tune as the API shows it. created_by names the actor the web layer
// reported, which is a label for people, not an identity this server verified.
type tuneJSON struct {
	ID        string `json:"id"`
	VehicleID string `json:"vehicle_id"`
	At        string `json:"at"`
	Note      string `json:"note"`
	CreatedBy string `json:"created_by,omitempty"`
}

func tunesJSON(in []vehicles.Tune) []tuneJSON {
	out := make([]tuneJSON, 0, len(in))
	for _, t := range in {
		out = append(out, tuneJSON{t.ID, t.VehicleID, t.At, t.Note, t.CreatedBy})
	}
	return out
}

func (l *local) listVehicles(w http.ResponseWriter, _ *http.Request) {
	type vehicle struct {
		ID            string       `json:"id"`
		DisplayName   string       `json:"display_name"`
		EngineCode    string       `json:"engine_code,omitempty"`
		EngineProfile *engine.View `json:"engine_profile"`
		Tunes         []tuneJSON   `json:"tunes"`
		Archived      bool         `json:"archived"`
	}
	out := []vehicle{}
	for _, v := range l.cfg.Vehicles.Vehicles() {
		out = append(out, vehicle{
			ID: v.ID, DisplayName: v.DisplayName, EngineCode: v.EngineCode,
			EngineProfile: l.cfg.Engines.For(v.EngineCode).View(),
			Tunes:         tunesJSON(v.Tunes), Archived: v.Archived(),
		})
	}
	localJSON(w, http.StatusOK, map[string]any{"vehicles": out})
}

// vehicleFrom resolves {id}. A malformed id and an unknown one answer the same way.
func (l *local) vehicleFrom(w http.ResponseWriter, r *http.Request) (*vehicles.Vehicle, bool) {
	id := strings.ToLower(r.PathValue("id"))
	if vehicleIDPattern.MatchString(id) {
		if v, err := l.cfg.Vehicles.Vehicle(id); err == nil {
			return v, true
		}
	}
	localError(w, http.StatusNotFound, "unknown_vehicle", "no such vehicle")
	return nil, false
}

type tuneRequest struct {
	At    string `json:"at"`
	Note  string `json:"note"`
	Actor string `json:"actor"`
}

func readTune(w http.ResponseWriter, r *http.Request) (tuneRequest, bool) {
	var req tuneRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLocalBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		localError(w, http.StatusBadRequest, "bad_request", "the body must be JSON with at and note")
		return req, false
	}
	req.Actor = strings.TrimSpace(req.Actor)
	if len([]rune(req.Actor)) > 64 {
		req.Actor = string([]rune(req.Actor)[:64])
	}
	return req, true
}

func (l *local) tuneFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vehicles.ErrBadTune):
		localError(w, http.StatusBadRequest, "bad_tune", err.Error())
	case errors.Is(err, vehicles.ErrUnknownTune), errors.Is(err, vehicles.ErrUnknownVehicle):
		localError(w, http.StatusNotFound, "not_found", "no such tune record")
	case errors.Is(err, vehicles.ErrVehicleArchived):
		localError(w, http.StatusConflict, "archived", "this vehicle is archived and takes no changes")
	default:
		l.cfg.Log.Error("tune write failed", "error", err)
		localError(w, http.StatusInternalServerError, "internal", "the change could not be saved")
	}
}

func (l *local) addTune(w http.ResponseWriter, r *http.Request) {
	v, ok := l.vehicleFrom(w, r)
	if !ok {
		return
	}
	req, ok := readTune(w, r)
	if !ok {
		return
	}
	t, err := l.cfg.Vehicles.AddTune(v.ID, req.At, req.Note, req.Actor)
	if err != nil {
		l.tuneFailure(w, err)
		return
	}
	l.refreshStore()
	localJSON(w, http.StatusCreated, tuneJSON{t.ID, t.VehicleID, t.At, t.Note, t.CreatedBy})
}

func (l *local) updateTune(w http.ResponseWriter, r *http.Request) {
	v, ok := l.vehicleFrom(w, r)
	if !ok {
		return
	}
	req, ok := readTune(w, r)
	if !ok {
		return
	}
	t, err := l.cfg.Vehicles.UpdateTune(v.ID, r.PathValue("tune"), req.At, req.Note)
	if err != nil {
		l.tuneFailure(w, err)
		return
	}
	l.refreshStore()
	localJSON(w, http.StatusOK, tuneJSON{t.ID, t.VehicleID, t.At, t.Note, t.CreatedBy})
}

func (l *local) deleteTune(w http.ResponseWriter, r *http.Request) {
	v, ok := l.vehicleFrom(w, r)
	if !ok {
		return
	}
	if err := l.cfg.Vehicles.DeleteTune(v.ID, r.PathValue("tune")); err != nil {
		l.tuneFailure(w, err)
		return
	}
	l.refreshStore()
	w.WriteHeader(http.StatusNoContent)
}

// refreshStore asks the store to rebuild so a changed tune shows in the comparison now
// rather than at its next scheduled look. Best effort and off the request: the tune is
// saved either way, and the store's own watch picks the change up if this fails.
func (l *local) refreshStore() {
	if l.cfg.StoreURL == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(l.cfg.StoreURL, "/")+"/reload", nil)
		if err != nil {
			return
		}
		resp, err := l.cfg.Client.Do(req)
		if err != nil {
			l.cfg.Log.Warn("store refresh after a tune change failed; the store will pick it up on its own", "error", err)
			return
		}
		resp.Body.Close()
	}()
}

// healthSQL reads the statistics for one car. The id has been matched against the
// 32-hex pattern and the registry before it is placed here.
const healthSQL = `SELECT metric, recent_median, recent_n, baseline_median, baseline_n, last_observed_at, tuned_at
FROM v_health_stats WHERE vehicle_id = '%s'`

func (l *local) health(w http.ResponseWriter, r *http.Request) {
	v, ok := l.vehicleFrom(w, r)
	if !ok {
		return
	}
	if l.cfg.StoreURL == "" {
		localError(w, http.StatusServiceUnavailable, "no_store", "this server is not connected to the analytical store")
		return
	}
	stats, err := l.fetchStats(r.Context(), v.ID)
	if err != nil {
		l.cfg.Log.Error("health statistics unavailable", "error", err)
		localError(w, http.StatusBadGateway, "store_unavailable", "the analytical store could not be read")
		return
	}

	profile := l.cfg.Engines.For(v.EngineCode)
	resp := map[string]any{
		"vehicle_id": v.ID,
		"health":     insight.Health(profile, stats),
		// The profile the sentences were judged against, so the page can say "no limits
		// known for this engine" instead of implying the car is fine.
		"engine_profile": profile.View(),
	}
	if len(stats) > 0 && !stats[0].LastObserved.IsZero() {
		resp["as_of"] = stats[0].LastObserved.UTC().Format(time.RFC3339)
	}
	localJSON(w, http.StatusOK, resp)
}

func (l *local) fetchStats(ctx context.Context, vehicleID string) ([]insight.Stat, error) {
	body := fmt.Sprintf(healthSQL, vehicleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(l.cfg.StoreURL, "/")+"/query", bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	resp, err := l.cfg.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
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
	return statsFromRows(res.Columns, res.Rows)
}

func statsFromRows(cols []string, rows [][]any) ([]insight.Stat, error) {
	idx := map[string]int{}
	for i, c := range cols {
		idx[c] = i
	}
	for _, c := range []string{"metric", "recent_median", "recent_n", "baseline_median", "baseline_n", "last_observed_at", "tuned_at"} {
		if _, ok := idx[c]; !ok {
			return nil, fmt.Errorf("the store has no column %s (is it older than store/v1.1?)", c)
		}
	}
	num := func(v any) *float64 {
		f, ok := v.(float64)
		if !ok {
			return nil
		}
		return &f
	}
	ts := func(v any) *time.Time {
		s, ok := v.(string)
		if !ok {
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return nil
		}
		return &t
	}
	out := make([]insight.Stat, 0, len(rows))
	for _, row := range rows {
		if len(row) != len(cols) {
			return nil, errors.New("a row does not match the columns")
		}
		metric, _ := row[idx["metric"]].(string)
		st := insight.Stat{
			Metric:         metric,
			RecentMedian:   num(row[idx["recent_median"]]),
			BaselineMedian: num(row[idx["baseline_median"]]),
			TunedAt:        ts(row[idx["tuned_at"]]),
		}
		if n := num(row[idx["recent_n"]]); n != nil {
			st.RecentN = int64(*n)
		}
		if n := num(row[idx["baseline_n"]]); n != nil {
			st.BaselineN = int64(*n)
		}
		if t := ts(row[idx["last_observed_at"]]); t != nil {
			st.LastObserved = *t
		}
		out = append(out, st)
	}
	return out, nil
}
