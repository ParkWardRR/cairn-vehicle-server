package syncapi

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/clients"
)

// handleSnapshot serves the analytical snapshot (Parquet tables) to an
// authenticated app, by proxying the loopback cairn-tsdb.
//
// cairn-tsdb binds loopback and has no authentication of its own, so this is
// the only way the phone ever reaches it, and only after the same signature
// check as everything else. The snapshot is not yet filtered per vehicle — the
// derived layer does not carry vehicle_id until ROADMAP Phase 19 finishes — so
// it is limited to clients whose scope is every vehicle. A client scoped to one
// car must not receive another's trips by way of a table dump, and refusing is
// the honest answer until the tables can be filtered.
func (s *Server) handleSnapshot(q *request) (int, string) {
	if s.cfg.SnapshotURL == "" {
		s.writeError(q.w, http.StatusNotFound, "not_found", "snapshots are not enabled on this server")
		return http.StatusNotFound, "snapshot disabled"
	}
	if !q.client.InScope(clients.ScopeAll) || len(q.client.Vehicles) != 1 || q.client.Vehicles[0] != clients.ScopeAll {
		s.writeError(q.w, http.StatusForbidden, "scope_too_narrow",
			"snapshots are not yet filtered per vehicle; they need an all-vehicles client")
		return http.StatusForbidden, "snapshot needs full scope"
	}

	target, err := url.Parse(strings.TrimRight(s.cfg.SnapshotURL, "/") + "/snapshot")
	if err != nil {
		s.writeError(q.w, http.StatusInternalServerError, "internal", "snapshot misconfigured")
		return http.StatusInternalServerError, "bad snapshot url"
	}
	// Only the format selector is forwarded; the proxy is not a general window
	// onto the analytical store.
	if f := q.r.URL.Query().Get("format"); f != "" {
		target.RawQuery = url.Values{"format": {f}}.Encode()
	}

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
