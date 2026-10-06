package syncapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/engine"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

const writeToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func localServer(t *testing.T, e *env, mod func(*LocalConfig)) *httptest.Server {
	t.Helper()
	cat, err := engine.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cfg := LocalConfig{Vehicles: e.vehicles, Engines: cat, WriteToken: writeToken}
	if mod != nil {
		mod(&cfg)
	}
	srv := httptest.NewServer(NewLocalHandler(cfg))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url, token, contentType, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestLocalVehiclesCarryTheEngineProfileAndTunes(t *testing.T) {
	e := newEnv(t)
	e.vehicles.AddTune(e.n20.ID, "2026-08-01", "Stage 2", "alfa")
	srv := localServer(t, e, nil)

	resp, body := do(t, "GET", srv.URL+"/v1/local/vehicles", "", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("%d: %s", resp.StatusCode, body)
	}
	var out struct {
		Vehicles []struct {
			ID            string
			EngineCode    string          `json:"engine_code"`
			EngineProfile *engine.View    `json:"engine_profile"`
			Tunes         []tuneJSON      `json:"tunes"`
			Raw           json.RawMessage `json:"-"`
		}
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	byID := map[string]int{}
	for i, v := range out.Vehicles {
		byID[v.ID] = i
	}
	n20, b58 := out.Vehicles[byID[e.n20.ID]], out.Vehicles[byID[e.b58.ID]]
	if n20.EngineProfile == nil || n20.EngineProfile.ID != "bmw-n20" || len(n20.EngineProfile.Signals) == 0 {
		t.Fatalf("n20 profile: %+v", n20.EngineProfile)
	}
	if len(n20.Tunes) != 1 || n20.Tunes[0].At != "2026-08-01" || n20.Tunes[0].Note != "Stage 2" || n20.Tunes[0].CreatedBy != "alfa" {
		t.Fatalf("n20 tunes: %+v", n20.Tunes)
	}
	if b58.EngineProfile == nil || b58.EngineProfile.Status != "stub" {
		t.Fatalf("b58 profile: %+v", b58.EngineProfile)
	}
	if b58.Tunes == nil || len(b58.Tunes) != 0 {
		t.Fatalf("a car with no tunes lists an empty array: %#v", b58.Tunes)
	}
	// Provenance stays in the profile file; the API carries only what a page needs.
	for _, leak := range []string{`"sources"`, `"codes"`, `"schema"`} {
		if strings.Contains(body, leak) {
			t.Fatalf("the API exposed %s: %s", leak, body)
		}
	}
}

func TestLocalVehicleWithAnUnknownEngineHasNullProfile(t *testing.T) {
	e := newEnv(t)
	e.vehicles.CreateVehicle(vehiclesSpec("Mystery", "S55"))
	e.vehicles.CreateVehicle(vehiclesSpec("No engine", ""))
	srv := localServer(t, e, nil)
	_, body := do(t, "GET", srv.URL+"/v1/local/vehicles", "", "", "")
	if strings.Count(body, `"engine_profile":null`) != 2 {
		t.Fatalf("an engine with no profile is null, so the page can say so: %s", body)
	}
}

func TestTuneWritesNeedTheTokenAndJSON(t *testing.T) {
	e := newEnv(t)
	srv := localServer(t, e, nil)
	url := srv.URL + "/v1/local/vehicles/" + e.n20.ID + "/tunes"
	body := `{"at":"2026-08-01","note":"Stage 2","actor":"alfa"}`

	for name, tc := range map[string]struct {
		token, ct string
		want      int
	}{
		"no token":    {"", "application/json", 401},
		"wrong token": {strings.Repeat("a", 64), "application/json", 401},
		"form post":   {writeToken, "text/plain", 415},
	} {
		if resp, b := do(t, "POST", url, tc.token, tc.ct, body); resp.StatusCode != tc.want {
			t.Errorf("%s: %d %s", name, resp.StatusCode, b)
		}
	}
	if tunes, _ := e.vehicles.Tunes(e.n20.ID); len(tunes) != 0 {
		t.Fatalf("a refused request wrote %+v", tunes)
	}

	resp, b := do(t, "POST", url, writeToken, "application/json; charset=utf-8", body)
	if resp.StatusCode != 201 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	var made tuneJSON
	json.Unmarshal([]byte(b), &made)
	if made.ID == "" || made.VehicleID != e.n20.ID || made.CreatedBy != "alfa" {
		t.Fatalf("%+v", made)
	}
	if tunes, _ := e.vehicles.Tunes(e.n20.ID); len(tunes) != 1 || tunes[0].ID != made.ID {
		t.Fatalf("not stored: %+v", tunes)
	}
}

func TestTuneWritesAreOffWithoutAConfiguredToken(t *testing.T) {
	e := newEnv(t)
	srv := localServer(t, e, func(c *LocalConfig) { c.WriteToken = "" })
	resp, _ := do(t, "POST", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/tunes", writeToken, "application/json",
		`{"at":"2026-08-01"}`)
	if resp.StatusCode != 403 {
		t.Fatalf("a server with no token must not accept any: %d", resp.StatusCode)
	}
	// Reading still works.
	if resp, _ := do(t, "GET", srv.URL+"/v1/local/vehicles", "", "", ""); resp.StatusCode != 200 {
		t.Fatalf("read: %d", resp.StatusCode)
	}
}

func TestTuneUpdateDeleteAndTheirFailures(t *testing.T) {
	e := newEnv(t)
	srv := localServer(t, e, nil)
	base := srv.URL + "/v1/local/vehicles/" + e.n20.ID + "/tunes"
	other := srv.URL + "/v1/local/vehicles/" + e.b58.ID + "/tunes"

	_, b := do(t, "POST", base, writeToken, "application/json", `{"at":"2026-08-01","note":"first"}`)
	var made tuneJSON
	json.Unmarshal([]byte(b), &made)

	resp, b := do(t, "PUT", base+"/"+made.ID, writeToken, "application/json", `{"at":"2026-08-03","note":"moved"}`)
	if resp.StatusCode != 200 || !strings.Contains(b, "2026-08-03") {
		t.Fatalf("update: %d %s", resp.StatusCode, b)
	}
	// Another car's id in the path does not reach this car's tune.
	if resp, _ := do(t, "PUT", other+"/"+made.ID, writeToken, "application/json", `{"at":"2026-08-04"}`); resp.StatusCode != 404 {
		t.Fatalf("cross-vehicle update: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "POST", base, writeToken, "application/json", `{"at":"someday"}`); resp.StatusCode != 400 {
		t.Fatalf("bad date: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "POST", base, writeToken, "application/json", `{"at":"2026-08-01","nope":1}`); resp.StatusCode != 400 {
		t.Fatalf("an unknown field is refused: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "POST", srv.URL+"/v1/local/vehicles/zz/tunes", writeToken, "application/json", `{"at":"2026-08-01"}`); resp.StatusCode != 404 {
		t.Fatalf("malformed vehicle id: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "DELETE", base+"/"+made.ID, writeToken, "", ""); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "DELETE", base+"/"+made.ID, writeToken, "", ""); resp.StatusCode != 404 {
		t.Fatalf("second delete: %d", resp.StatusCode)
	}
	if resp, _ := do(t, "DELETE", base+"/"+made.ID, "", "", ""); resp.StatusCode != 401 {
		t.Fatalf("delete without a token: %d", resp.StatusCode)
	}

	e.vehicles.Archive(e.n20.ID)
	if resp, _ := do(t, "POST", base, writeToken, "application/json", `{"at":"2026-08-01"}`); resp.StatusCode != 409 {
		t.Fatalf("archived vehicle: %d", resp.StatusCode)
	}
}

func TestTuneWriteRefreshesTheStore(t *testing.T) {
	e := newEnv(t)
	var reloads atomic.Int32
	done := make(chan struct{}, 4)
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/reload" {
			reloads.Add(1)
			done <- struct{}{}
		}
	}))
	defer store.Close()
	srv := localServer(t, e, func(c *LocalConfig) { c.StoreURL = store.URL })

	do(t, "POST", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/tunes", writeToken, "application/json", `{"at":"2026-08-01"}`)
	<-done
	if reloads.Load() != 1 {
		t.Fatalf("reloads = %d", reloads.Load())
	}
	// A refused write must not rebuild anything.
	do(t, "POST", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/tunes", writeToken, "application/json", `{"at":"nope"}`)
	do(t, "POST", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/tunes", "", "application/json", `{"at":"2026-08-02"}`)
	if reloads.Load() != 1 {
		t.Fatalf("a refused write triggered a rebuild: %d", reloads.Load())
	}
}

// storeStub answers the health query like cairn-tsdb does.
func storeStub(t *testing.T, vehicle string, rows [][]any) *httptest.Server {
	t.Helper()
	cols := []string{"metric", "recent_median", "recent_n", "baseline_median", "baseline_n", "last_observed_at", "tuned_at"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := string(b)
		if r.URL.Path != "/query" || !strings.Contains(q, "FROM v_health_stats WHERE vehicle_id = '"+vehicle+"'") {
			http.Error(w, "unexpected query: "+q, 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"columns": cols, "rows": rows})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthSummaryUsesTheVehiclesProfile(t *testing.T) {
	e := newEnv(t)
	last := "2026-10-01T09:00:00Z"
	rows := [][]any{
		{"boost_psi", 21.5, 6.0, nil, 0.0, last, nil},
		{"ltft_pct", 2.0, 6.0, nil, 0.0, last, nil},
	}
	store := storeStub(t, e.n20.ID, rows)
	srv := localServer(t, e, func(c *LocalConfig) { c.StoreURL = store.URL })

	resp, body := do(t, "GET", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/health", "", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var out struct {
		VehicleID string `json:"vehicle_id"`
		AsOf      string `json:"as_of"`
		Health    []struct{ Metric, Status, Sentence string }
		Profile   *engine.View `json:"engine_profile"`
	}
	json.Unmarshal([]byte(body), &out)
	if out.VehicleID != e.n20.ID || out.AsOf != last || out.Profile == nil || out.Profile.ID != "bmw-n20" {
		t.Fatalf("%+v", out)
	}
	if len(out.Health) != 2 || out.Health[0].Metric != "boost_psi" || out.Health[0].Status != "watch" ||
		out.Health[1].Metric != "ltft_pct" || out.Health[1].Status != "ok" {
		t.Fatalf("%+v", out.Health)
	}
	if !strings.Contains(out.Health[0].Sentence, "21.5 psi") {
		t.Fatalf("%q", out.Health[0].Sentence)
	}
}

func TestHealthForAStubEngineSaysNothingAboutAbsoluteValues(t *testing.T) {
	e := newEnv(t)
	rows := [][]any{{"boost_psi", 25.0, 9.0, nil, 0.0, "2026-10-01T09:00:00Z", nil}}
	store := storeStub(t, e.b58.ID, rows)
	srv := localServer(t, e, func(c *LocalConfig) { c.StoreURL = store.URL })
	_, body := do(t, "GET", srv.URL+"/v1/local/vehicles/"+e.b58.ID+"/health", "", "", "")
	if !strings.Contains(body, `"health":[]`) || !strings.Contains(body, `"status":"stub"`) {
		t.Fatalf("an empty list plus the stub profile lets the page say 'no limits known': %s", body)
	}
}

func TestHealthFailureModes(t *testing.T) {
	e := newEnv(t)
	// No store configured.
	srv := localServer(t, e, nil)
	if resp, _ := do(t, "GET", srv.URL+"/v1/local/vehicles/"+e.n20.ID+"/health", "", "", ""); resp.StatusCode != 503 {
		t.Fatalf("no store: %d", resp.StatusCode)
	}
	// Store down.
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	srv2 := localServer(t, e, func(c *LocalConfig) { c.StoreURL = dead.URL })
	if resp, body := do(t, "GET", srv2.URL+"/v1/local/vehicles/"+e.n20.ID+"/health", "", "", ""); resp.StatusCode != 502 ||
		strings.Contains(body, "127.0.0.1") {
		t.Fatalf("store down: %d %s (the error must not echo the store's address)", resp.StatusCode, body)
	}
	// An older store without the view.
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Catalog Error: Table with name v_health_stats does not exist", 400)
	}))
	defer old.Close()
	srv3 := localServer(t, e, func(c *LocalConfig) { c.StoreURL = old.URL })
	if resp, _ := do(t, "GET", srv3.URL+"/v1/local/vehicles/"+e.n20.ID+"/health", "", "", ""); resp.StatusCode != 502 {
		t.Fatalf("old store: %d", resp.StatusCode)
	}
	// Unknown vehicle.
	if resp, _ := do(t, "GET", srv.URL+"/v1/local/vehicles/00000000000000000000000000000000/health", "", "", ""); resp.StatusCode != 404 {
		t.Fatalf("unknown vehicle: %d", resp.StatusCode)
	}
}

func TestHealthQueryCannotBeInjectedThroughTheVehicleID(t *testing.T) {
	e := newEnv(t)
	hit := false
	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer store.Close()
	srv := localServer(t, e, func(c *LocalConfig) { c.StoreURL = store.URL })
	for _, id := range []string{"x'%20OR%201=1--", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", e.n20.ID + "00"} {
		if resp, _ := do(t, "GET", srv.URL+"/v1/local/vehicles/"+id+"/health", "", "", ""); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", id, resp.StatusCode)
		}
	}
	if hit {
		t.Fatal("a malformed id reached the store")
	}
}

func TestEveryLocalRouteRefusesAProxiedRequest(t *testing.T) {
	e := newEnv(t)
	srv := localServer(t, e, nil)
	for _, route := range []struct{ method, path string }{
		{"GET", "/v1/local/vehicles"},
		{"GET", "/v1/local/vehicles/" + e.n20.ID + "/health"},
		{"POST", "/v1/local/vehicles/" + e.n20.ID + "/tunes"},
		{"DELETE", "/v1/local/vehicles/" + e.n20.ID + "/tunes/x"},
	} {
		req, _ := http.NewRequest(route.method, srv.URL+route.path, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+writeToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Tailscale-User-Login", "someone@example.com")
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 403 {
			t.Errorf("%s %s with a tailnet identity: %d", route.method, route.path, resp.StatusCode)
		}
	}
}

func vehiclesSpec(name, engineCode string) vehicles.NewVehicleSpec {
	return vehicles.NewVehicleSpec{DisplayName: name, EngineCode: engineCode}
}
