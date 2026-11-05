package syncapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
)

// A cairn-tsdb that answers one canned result and remembers the SQL it was
// handed, so the scope checks can be shown to happen *before* the store is
// touched — which is the difference between a refusal and a leak.
func fakeTrackTSDB(t *testing.T, rows [][]any) (*httptest.Server, func() string) {
	t.Helper()
	var lastSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<20)
		n, _ := r.Body.Read(body)
		lastSQL = string(body[:n])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"columns": []string{"at_ms", "lat", "lon"},
			"rows":    rows,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, func() string { return lastSQL }
}

func decodeTrack(t *testing.T, r *http.Response) trackBody {
	t.Helper()
	var body trackBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("decode track: %v", err)
	}
	return body
}

func TestTrackIsAuthenticatedScopedAndShaped(t *testing.T) {
	base := int64(1790000000000)
	// Ten seconds of driving, then a five-minute hole, then ten more. One trip,
	// two runs, one gap: a dropout is a gap in knowledge, not a straight road.
	rows := [][]any{}
	for i := range 10 {
		rows = append(rows, []any{base + int64(i)*1000, 37.7749 + float64(i)*0.0001, -122.4194})
	}
	for i := range 10 {
		rows = append(rows, []any{base + 300000 + int64(i)*1000, 37.78 + float64(i)*0.0001, -122.42})
	}
	upstream, lastSQL := fakeTrackTSDB(t, rows)

	e := newEnv(t, func(c *Config) { c.SnapshotURL = upstream.URL })
	full := e.enrol(clients.RoleUser, clients.ScopeAll)
	narrow := e.enrol(clients.RoleUser, e.n20.ID)

	id := fmt.Sprintf("%s:%d", e.n20.ID, base)
	target := fmt.Sprintf("/v1/trips/%s/track?ended_ms=%d", id, base+600000)

	// Unsigned is refused before the store is touched.
	if resp, _ := http.Get(e.ts.URL + target); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned track: %d", resp.StatusCode)
	}
	if lastSQL() != "" {
		t.Fatal("an unauthenticated request reached the analytical store")
	}

	// Somebody else's car is a 403, and the store never hears about it. The same
	// answer whether or not the trip exists: a 404 would be a way to ask which
	// cars there are.
	other := fmt.Sprintf("/v1/trips/%s:%d/track?ended_ms=%d", e.b58.ID, base, base+600000)
	if r := narrow.do("GET", other, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("out of scope: %d, want 403", r.StatusCode)
	}
	if lastSQL() != "" {
		t.Fatal("an out-of-scope request reached the analytical store")
	}

	r := narrow.do("GET", target, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("own car: %d", r.StatusCode)
	}
	body := decodeTrack(t, r)

	if body.TripID != id || body.VehicleID != e.n20.ID {
		t.Fatalf("identity: %+v", body)
	}
	if body.Encoding != "polyline5" {
		t.Fatalf("encoding %q", body.Encoding)
	}
	if body.PointCount != 20 {
		t.Fatalf("point count %d, want 20", body.PointCount)
	}
	if len(body.Runs) != 2 {
		t.Fatalf("runs %d, want 2 (a dropout is not a straight road)", len(body.Runs))
	}
	if len(body.Gaps) != 1 || body.Gaps[0].DurationMS != 291000 {
		t.Fatalf("gaps %+v", body.Gaps)
	}
	if body.Runs[0].Count != 10 || body.Runs[1].Count != 10 {
		t.Fatalf("run counts %d and %d", body.Runs[0].Count, body.Runs[1].Count)
	}
	for _, run := range body.Runs {
		if run.Polyline == "" {
			t.Fatal("a run with no polyline in it")
		}
	}

	// The query asks the trusted view, excludes the phone's own fixes, and is
	// bounded by the span it was given.
	sql := lastSQL()
	if !strings.Contains(sql, "v_position_trusted") {
		t.Fatalf("not the trusted view:\n%s", sql)
	}
	if !strings.Contains(sql, "(source_flags & 32) = 0") {
		t.Fatalf("phone fixes are not excluded:\n%s", sql)
	}
	if !strings.Contains(sql, e.n20.ID) || !strings.Contains(sql, "1790000600000") {
		t.Fatalf("span or vehicle missing:\n%s", sql)
	}

	// A full-scope client gets any car.
	if r := full.do("GET", other, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("full scope, other car: %d", r.StatusCode)
	}
}

func TestTrackRefusesMalformedRequests(t *testing.T) {
	upstream, lastSQL := fakeTrackTSDB(t, nil)
	e := newEnv(t, func(c *Config) { c.SnapshotURL = upstream.URL })
	app := e.enrol(clients.RoleUser, clients.ScopeAll)
	base := int64(1790000000000)

	cases := []struct {
		name   string
		target string
	}{
		{"not a trip id", "/v1/trips/nonsense/track?ended_ms=1"},
		{"vehicle is not hex", "/v1/trips/zzzz:1790000000000/track?ended_ms=1790000600000"},
		{"no started_ms", fmt.Sprintf("/v1/trips/%s:/track?ended_ms=1", e.n20.ID)},
		{"no span", fmt.Sprintf("/v1/trips/%s:%d/track", e.n20.ID, base)},
		{"span runs backwards", fmt.Sprintf("/v1/trips/%s:%d/track?ended_ms=%d", e.n20.ID, base, base-1)},
		{"span longer than two days", fmt.Sprintf("/v1/trips/%s:%d/track?ended_ms=%d", e.n20.ID, base, base+3*24*3600*1000)},
		{"an injection attempt in the id", "/v1/trips/%27%20OR%201%3D1%20--:1/track?ended_ms=2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r := app.do("GET", c.target, nil); r.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s: %d, want 400", c.name, r.StatusCode)
			}
			if lastSQL() != "" {
				t.Fatalf("%s: reached the analytical store", c.name)
			}
		})
	}
}

func TestTrackWithNoPositionsIsAnEmptyTrackNotAnError(t *testing.T) {
	// A trip whose fixes were all untrusted, or which happened in a tunnel, is
	// a trip with no shape. That is an answer, not a failure: the phone shows
	// the numbers and no map rather than an error it cannot act on.
	upstream, _ := fakeTrackTSDB(t, [][]any{})
	e := newEnv(t, func(c *Config) { c.SnapshotURL = upstream.URL })
	app := e.enrol(clients.RoleUser, clients.ScopeAll)
	base := int64(1790000000000)

	r := app.do("GET", fmt.Sprintf("/v1/trips/%s:%d/track?ended_ms=%d", e.n20.ID, base, base+1000), nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("empty track: %d", r.StatusCode)
	}
	body := decodeTrack(t, r)
	if body.PointCount != 0 || len(body.Runs) != 0 || len(body.Gaps) != 0 {
		t.Fatalf("expected an empty track, got %+v", body)
	}
}

func TestTrackThinsRatherThanTruncates(t *testing.T) {
	// Losing the end of a route reads as a trip that stopped somewhere it did
	// not. Thinning keeps the shape and loses only the sample rate, and says so.
	base := int64(1790000000000)
	rows := make([][]any, 0, trackMaxPoints*2)
	for i := range trackMaxPoints * 2 {
		rows = append(rows, []any{base + int64(i)*100, 37.0 + float64(i)*1e-5, -122.0})
	}
	upstream, _ := fakeTrackTSDB(t, rows)
	e := newEnv(t, func(c *Config) { c.SnapshotURL = upstream.URL })
	app := e.enrol(clients.RoleUser, clients.ScopeAll)

	r := app.do("GET", fmt.Sprintf("/v1/trips/%s:%d/track?ended_ms=%d", e.n20.ID, base, base+int64(len(rows))*100), nil)
	body := decodeTrack(t, r)
	if !body.Thinned {
		t.Fatal("a thinned track must say so")
	}
	if body.PointCount > trackMaxPoints+1 {
		t.Fatalf("point count %d is over the cap", body.PointCount)
	}
	last := body.Runs[len(body.Runs)-1]
	if want := base + int64(len(rows)-1)*100; last.EndedMS != want {
		t.Fatalf("the end of the route was lost: %d, want %d", last.EndedMS, want)
	}
}

func TestPolylineEncodesTheWayEveryMapLibraryDecodes(t *testing.T) {
	// The worked example from Google's own description of the format, which is
	// what makes this an independent check rather than a round trip with
	// itself: (38.5,-120.2) (40.7,-120.95) (43.252,-126.453).
	got := encodePolyline([]trackPoint{
		{lat: 38.5, lon: -120.2},
		{lat: 40.7, lon: -120.95},
		{lat: 43.252, lon: -126.453},
	})
	if want := `_p~iF~ps|U_ulLnnqC_mqNvxq` + "`@"; got != want {
		t.Fatalf("polyline\n got %q\nwant %q", got, want)
	}
}

func TestParseTripID(t *testing.T) {
	vehicle := strings.Repeat("ab", 16)
	if v, ms, ok := parseTripID(vehicle + ":1790000000000"); !ok || v != vehicle || ms != 1790000000000 {
		t.Fatalf("good id: %q %d %v", v, ms, ok)
	}
	for _, bad := range []string{
		"", "nocolon", vehicle, vehicle + ":", vehicle + ":abc", vehicle + ":0", vehicle + ":-1",
		"short:1790000000000", vehicle + ":1:2", strings.ToUpper(vehicle) + ":1790000000000",
	} {
		if _, _, ok := parseTripID(bad); ok && bad != strings.ToUpper(vehicle)+":1790000000000" {
			t.Fatalf("accepted %q", bad)
		}
	}
	// An uppercase vehicle id is lowercased, not refused: a client that echoes
	// an id back with different case is not attacking anything.
	if v, _, ok := parseTripID(strings.ToUpper(vehicle) + ":1790000000000"); !ok || v != vehicle {
		t.Fatalf("uppercase id: %q %v", v, ok)
	}
}
