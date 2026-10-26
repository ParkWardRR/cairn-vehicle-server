package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/wifianchors"
)

func asDevice(r *http.Request, cn string) *http.Request {
	if cn != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	}
	return r
}

// anchorsEnv is a device listener with one enrolled device, one revoked one,
// a real vehicle registry and a fake cairn-tsdb.
func anchorsEnv(t *testing.T, storeRows *[][]any, storeUp *bool) (http.Handler, string, string, *vehicles.Registry) {
	t.Helper()
	dir := t.TempDir()
	reg, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	var id, gone [16]byte
	id[0], gone[0] = 0x01, 0x02
	for _, d := range []struct {
		id   [16]byte
		name string
	}{{id, "dongle"}, {gone, "stolen"}} {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, err := reg.Enroll(d.id, d.name, pub, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.Revoke(gone, "test"); err != nil {
		t.Fatal(err)
	}
	vreg, err := vehicles.Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "vehicles.key"))
	if err != nil {
		t.Fatal(err)
	}

	store := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !*storeUp {
			http.Error(w, "loading", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"columns": []string{"vehicle_id", "bssid", "lat", "lon", "observations", "spread_m", "max_rssi_dbm", "last_seen"},
			"rows":    *storeRows,
		})
	}))
	t.Cleanup(store.Close)

	s := New(Config{Registry: reg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limiter: NewLimiter(120, 2), RequireClientCert: true,
		WiFiAnchors: &wifianchors.Service{StoreURL: store.URL, Vehicles: vreg}})
	return s.Routes(), hex.EncodeToString(id[:]), hex.EncodeToString(gone[:]), vreg
}

func TestWiFiAnchorsRoute(t *testing.T) {
	rows := [][]any{}
	up := true
	h, dev, revoked, vreg := anchorsEnv(t, &rows, &up)

	get := func(cn, inm string) *httptest.ResponseRecorder {
		r := asDevice(httptest.NewRequest("GET", "/api/v2/wifi-anchors", nil), cn)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	// Authentication: a certificate naming an enrolled, unrevoked device.
	for name, cn := range map[string]string{
		"no certificate": "", "not a device id": "dongle", "unknown device": strings.Repeat("ab", 16), "revoked": revoked,
	} {
		if w := get(cn, ""); w.Code != http.StatusForbidden {
			t.Errorf("%s: %d", name, w.Code)
		}
	}

	// No assignment yet: an empty table, 200, not an error.
	w := get(dev, "")
	if w.Code != http.StatusOK || w.Body.Len() != 16 || string(w.Body.Bytes()[:4]) != "CWA1" ||
		w.Header().Get("X-Cairn-Anchor-Count") != "0" || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("empty: %d % x %v", w.Code, w.Body.Bytes(), w.Header())
	}

	// Assigned, with two learned access points.
	v, err := vreg.CreateVehicle(vehicles.NewVehicleSpec{DisplayName: "M240i"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vreg.Assign(dev, v.ID, "test"); err != nil {
		t.Fatal(err)
	}
	rows = [][]any{
		{v.ID, "bb:00:00:00:00:02", 37.5, -122.5, 6, 30.0, -50, "2026-10-26T08:00:00Z"},
		{v.ID, "aa:00:00:00:00:01", 37.4, -122.4, 2, 2.0, -70, "2026-10-25T08:00:00Z"},
	}
	w = get(dev, "")
	if w.Code != http.StatusOK || w.Body.Len() != 16+32 || w.Header().Get("X-Cairn-Anchor-Count") != "2" {
		t.Fatalf("full: %d len %d", w.Code, w.Body.Len())
	}
	b := w.Body.Bytes()
	if b[16] != 0xaa || b[32] != 0xbb || binary.LittleEndian.Uint16(b[46:]) != 55 {
		t.Fatalf("order/acc % x", b)
	}
	etag := w.Header().Get("ETag")
	if etag != wifianchors.ETag(b) {
		t.Fatalf("ETag %q is not the body's hash", etag)
	}

	// If-None-Match: the same set is a 304 with no body; W/ and lists accepted.
	for _, inm := range []string{etag, "W/" + etag, `"x", ` + etag, "*"} {
		if w := get(dev, inm); w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != etag {
			t.Errorf("If-None-Match %s: %d", inm, w.Code)
		}
	}
	if w := get(dev, `"stale"`); w.Code != http.StatusOK {
		t.Errorf("stale tag: %d", w.Code)
	}

	// The set changes: a new tag, and the old one no longer matches.
	rows = rows[:1]
	if w := get(dev, etag); w.Code != http.StatusOK || w.Header().Get("ETag") == etag || w.Body.Len() != 32 {
		t.Fatalf("changed set: %d", w.Code)
	}

	// The store is down: 503, so the device keeps its copy.
	up = false
	if w := get(dev, ""); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("store down: %d", w.Code)
	}
}

// Without a store the route is not registered at all.
func TestWiFiAnchorsRouteAbsentWithoutStore(t *testing.T) {
	reg, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{Registry: reg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, asDevice(httptest.NewRequest("GET", "/api/v2/wifi-anchors", nil), strings.Repeat("01", 16)))
	if w.Code != http.StatusNotFound {
		t.Fatalf("%d", w.Code)
	}
}

var _ WiFiAnchors = (*wifianchors.Service)(nil)
