package syncapi

import (
	"encoding/json"
	"net/http"

	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

// LocalHandler is the read-only API for processes on the same host — today, the
// web UI's server side asking what to call each vehicle.
//
// It is deliberately NOT part of the app API and deliberately has no
// authentication of its own: it exists on its own loopback-only listener, and
// the loopback bind IS the access control. That is only safe if nothing can
// forward traffic to it, and the one thing that routinely forwards traffic to
// loopback ports on this host is tailscale serve. So the handler refuses any
// request that carries a Tailscale identity header or the Funnel marker: if
// someone points Serve (or a reverse proxy that adds those) at this port by
// mistake, it answers 403 instead of handing the vehicle list to the tailnet.
//
// What it returns is display data only: id, name, engine code, archived. Never
// the VIN, sealed or otherwise, and never an assignment or a device id.
func LocalHandler(reg *vehicles.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/local/vehicles", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderFunnel) != "" || r.Header.Get(HeaderTailscaleLogin) != "" ||
			r.Header.Get(HeaderTailscaleName) != "" {
			http.Error(w, "this endpoint is for local processes only", http.StatusForbidden)
			return
		}

		type vehicle struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			EngineCode  string `json:"engine_code,omitempty"`
			Archived    bool   `json:"archived"`
		}
		out := []vehicle{}
		for _, v := range reg.Vehicles() {
			out = append(out, vehicle{v.ID, v.DisplayName, v.EngineCode, v.Archived()})
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{"vehicles": out})
	})
	return mux
}
