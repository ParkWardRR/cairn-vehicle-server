package syncapi

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
)

var vehicleIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// handleSnapshot serves the analytical snapshot (Parquet tables) to an
// authenticated app, by proxying the loopback cairn-tsdb.
//
// cairn-tsdb binds loopback and has no authentication of its own, so this is
// the only way the phone ever reaches it, and only after the same signature
// check as everything else.
//
// Scope is enforced here, not trusted to the caller. Every table in the snapshot
// carries vehicle_id and cairn-tsdb can narrow the archive to one car, so:
//
//   - a client scoped to specific vehicles MUST name one with ?vehicle=<id>, and
//     it must be one of theirs — otherwise a table dump of every car would walk
//     straight past the scope that governs the rest of the API;
//   - a client scoped to every vehicle may omit it and gets the whole archive.
//
// The vehicle id is validated as 32 lowercase hex before it goes anywhere, and
// it is the only parameter other than format that is forwarded.
func (s *Server) handleSnapshot(q *request) (int, string) {
	if s.cfg.SnapshotURL == "" {
		s.writeError(q.w, http.StatusNotFound, "not_found", "snapshots are not enabled on this server")
		return http.StatusNotFound, "snapshot disabled"
	}

	vehicle := strings.ToLower(q.r.URL.Query().Get("vehicle"))
	fullScope := len(q.client.Vehicles) == 1 && q.client.Vehicles[0] == clients.ScopeAll
	switch {
	case vehicle != "" && !vehicleIDRE.MatchString(vehicle):
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "vehicle must be 32 hex characters")
		return http.StatusBadRequest, "bad vehicle id"
	case vehicle == "" && !fullScope:
		s.writeError(q.w, http.StatusForbidden, "vehicle_required",
			"this client is scoped to specific vehicles; name one with ?vehicle=<id>")
		return http.StatusForbidden, "scoped client omitted the vehicle"
	case vehicle != "" && !q.client.InScope(vehicle):
		// Same answer whether or not the vehicle exists, so the endpoint cannot
		// be used to probe for other cars.
		s.writeError(q.w, http.StatusForbidden, "scope", "that vehicle is outside this client's scope")
		return http.StatusForbidden, "vehicle out of scope"
	}

	target, err := url.Parse(strings.TrimRight(s.cfg.SnapshotURL, "/") + "/snapshot")
	if err != nil {
		s.writeError(q.w, http.StatusInternalServerError, "internal", "snapshot misconfigured")
		return http.StatusInternalServerError, "bad snapshot url"
	}
	// Only the format selector is forwarded; the proxy is not a general window
	// onto the analytical store.
	fwd := url.Values{}
	if f := q.r.URL.Query().Get("format"); f != "" {
		fwd.Set("format", f)
	}
	if vehicle != "" {
		fwd.Set("vehicle", vehicle)
	}
	target.RawQuery = fwd.Encode()

	req, _ := http.NewRequestWithContext(q.r.Context(), http.MethodGet, target.String(), nil)
	if inm := q.r.Header.Get("If-None-Match"); inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	resp, err := (&http.Client{Timeout: 2 * time.Minute}).Do(req)
	if err != nil {
		s.writeError(q.w, http.StatusBadGateway, "upstream_unavailable", "the analytical store is not reachable")
		return http.StatusBadGateway, "tsdb unreachable"
	}
	defer resp.Body.Close()

	for _, h := range []string{"Content-Type", "ETag", "Content-Length", "X-Cairn-Snapshot-Manifest"} {
		if v := resp.Header.Get(h); v != "" {
			q.w.Header().Set(h, v)
		}
	}
	q.w.Header().Set("Cache-Control", "no-store")
	q.w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(q.w, resp.Body)
	return resp.StatusCode, ""
}
