package syncapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const tsdbCols = `["vehicle_id","boot_id","device_id","started_ms","ended_ms","duration_ms","distance_m","max_gnss_speed_cmps","max_obd_speed_cmps","max_rpm","obd_samples","gnss_samples","boost_samples","gap_count","gap_duration_ms","bundle_count","decoder_version"]`

func fakeTSDB(t *testing.T, rows *atomic.Value) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/query" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"columns":` + tsdbCols + `,"rows":` + rows.Load().(string) + `}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPublisherPublishesIdempotentlyAndPerVehicle(t *testing.T) {
	e := newEnv(t)

	// The registry's own vehicle ids, so scope filtering is exercised for real.
	var rows atomic.Value
	rows.Store(`[
	  ["` + e.n20.ID + `","bootA","dev1",1790000000000,1790000600000,600000,5230,2410,2500,6100,300,590,300,1,4000,1,3],
	  ["` + e.b58.ID + `","bootB","dev1",1790001000000,1790001300000,300000,2100,3100,3200,5200,150,290,150,0,0,1,3]
	]`)
	up := fakeTSDB(t, &rows)
	pub := &TripPublisher{URL: up.URL, Store: e.store}

	changed, err := pub.Once(context.Background())
	if err != nil || changed != 2 {
		t.Fatalf("first pass = %d, %v; want 2 published", changed, err)
	}
	// Re-reading the same trips is a no-op: no new records, no churn for clients.
	head := e.store.Head()
	changed, err = pub.Once(context.Background())
	if err != nil || changed != 0 || e.store.Head() != head {
		t.Fatalf("second pass = %d, %v, head %d -> %d; want a no-op", changed, err, head, e.store.Head())
	}

	// A client scoped to the N20 sees the N20's trip and never the B58's.
	scoped := e.enrol("user", e.n20.ID)
	var trips []change
	for _, c := range pull(t, scoped, "").Changes {
		if c.EntityType == EntityTypeTripSummary {
			trips = append(trips, c)
		}
	}
	if len(trips) != 1 {
		t.Fatalf("an N20-scoped client received %d trips, want exactly 1", len(trips))
	}
	c := trips[0]
	if c.VehicleID != e.n20.ID || c.EntityID != e.n20.ID+":bootA" {
		t.Fatalf("got vehicle %q entity %q, want the N20's bootA trip", c.VehicleID, c.EntityID)
	}
	var d map[string]any
	if err := json.Unmarshal(c.Data, &d); err != nil {
		t.Fatal(err)
	}
	// Integers only, per the protocol: no float may appear in a payload.
	for k, v := range d {
		if f, ok := v.(float64); ok && f != float64(int64(f)) {
			t.Fatalf("field %s = %v is not an integer", k, v)
		}
	}
	if d["distance_m"].(float64) != 5230 || d["started_ms"].(float64) != 1790000000000 {
		t.Fatalf("payload = %s", c.Data)
	}

	// A full-scope client sees both, and a B58-scoped one only the B58's.
	all := e.enrol("user", "*")
	n := 0
	for _, c := range pull(t, all, "").Changes {
		if c.EntityType == EntityTypeTripSummary {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("a full-scope client received %d trips, want 2", n)
	}

	// A reprocessed trip (more samples) publishes a new version of the same entity.
	rows.Store(`[["` + e.n20.ID + `","bootA","dev1",1790000000000,1790000600000,600000,5230,2410,2500,6100,310,590,300,1,4000,1,4]]`)
	changed, err = pub.Once(context.Background())
	if err != nil || changed != 1 {
		t.Fatalf("after reprocessing = %d, %v; want exactly the changed trip", changed, err)
	}
}

func TestPublisherRefusesAnUnexpectedSchema(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"columns":["vehicle_id"],"rows":[["x"]]}`))
	}))
	defer up.Close()
	e := newEnv(t)
	_, err := (&TripPublisher{URL: up.URL, Store: e.store}).Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "lacks column") {
		t.Fatalf("err = %v; a changed upstream schema must fail loudly, not publish blanks", err)
	}
}

func TestPublisherSurvivesAnUnavailableStore(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "building", http.StatusServiceUnavailable)
	}))
	defer up.Close()
	e := newEnv(t)
	if _, err := (&TripPublisher{URL: up.URL, Store: e.store}).Once(context.Background()); err == nil {
		t.Fatal("a 503 from the analytical store was treated as success")
	}
}
