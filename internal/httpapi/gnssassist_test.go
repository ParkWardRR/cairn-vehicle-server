package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/ParkWardRR/cairn-vehicle-server/internal/gnssassist"
)

type fakeGNSS struct {
	reports []string
	body    []byte
}

func (f *fakeGNSS) ReportReceiver(dev, sec, mon string) (gnssassist.ReportResult, error) {
	f.reports = append(f.reports, dev)
	if _, err := gnssassist.ParseIdentity(sec, mon); err != nil {
		return gnssassist.ReportResult{}, gnssassist.ErrBadIdentity
	}
	return gnssassist.ReportResult{UniqueID: "a1b2c3d4e5f6", Registered: f.body != nil}, nil
}

func (f *fakeGNSS) Data(dev string) ([]byte, string, error) {
	if f.body == nil {
		return nil, "", gnssassist.ErrNotAvailable
	}
	return f.body, gnssassist.ETag(f.body), nil
}

func gnssServer(t *testing.T, g GNSSAssist) (*Server, string, string) {
	t.Helper()
	reg, err := devices.Open(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var id, gone [16]byte
	id[0], gone[0] = 0x01, 0x02
	if _, err := reg.Enroll(id, "dongle", pub, 0); err != nil {
		t.Fatal(err)
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := reg.Enroll(gone, "stolen", pub2, 0); err != nil {
		t.Fatal(err)
	}
	if err := reg.Revoke(gone, "test"); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Registry: reg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Limiter: NewLimiter(120, 2), RequireClientCert: true, GNSSAssist: g})
	return s, hex.EncodeToString(id[:]), hex.EncodeToString(gone[:])
}

func asDevice(r *http.Request, cn string) *http.Request {
	if cn != "" {
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
	}
	return r
}

func ubx(class, id byte, payload []byte) string {
	return hex.EncodeToString(gnssassist.Encode(class, id, payload))
}

func TestGNSSAssistRoutes(t *testing.T) {
	g := &fakeGNSS{}
	s, dev, revoked := gnssServer(t, g)
	h := s.Routes()

	report := func(cn, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, asDevice(httptest.NewRequest("POST", "/api/v2/gnss-assist/receiver", strings.NewReader(body)), cn))
		return w
	}
	get := func(cn, inm string) *httptest.ResponseRecorder {
		r := asDevice(httptest.NewRequest("GET", "/api/v2/gnss-assist", nil), cn)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	sec := ubx(0x27, 0x03, []byte{2, 0, 0, 0, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6})
	mon := ubx(0x0A, 0x04, make([]byte, 40))
	good := `{"sec_uniqid":"` + sec + `","mon_ver":"` + mon + `"}`

	// Authentication: a certificate naming an enrolled, unrevoked device.
	for name, cn := range map[string]string{
		"no certificate": "", "not a device id": "dongle", "unknown device": strings.Repeat("ab", 16), "revoked": revoked,
	} {
		if w := report(cn, good); w.Code != http.StatusForbidden {
			t.Errorf("report, %s: %d", name, w.Code)
		}
		if w := get(cn, ""); w.Code != http.StatusForbidden {
			t.Errorf("get, %s: %d", name, w.Code)
		}
	}
	if len(g.reports) != 0 {
		t.Fatal("an unauthenticated report reached the service")
	}

	// A report before registration: 202, and nothing to download yet.
	if w := report(dev, good); w.Code != http.StatusAccepted {
		t.Fatalf("report: %d %s", w.Code, w.Body)
	}
	if len(g.reports) != 1 || g.reports[0] != dev {
		t.Fatalf("reports %v", g.reports)
	}
	if w := report(dev, `{"sec_uniqid":"B562270300002AA5","mon_ver":"`+mon+`"}`); w.Code != http.StatusBadRequest {
		t.Errorf("the poll as a reply: %d", w.Code)
	}
	if w := report(dev, "not json"); w.Code != http.StatusBadRequest {
		t.Errorf("not json: %d", w.Code)
	}
	if w := report(dev, `{"sec_uniqid":"`+strings.Repeat("0", 5000)+`"}`); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: %d", w.Code)
	}
	if w := get(dev, ""); w.Code != http.StatusNotFound {
		t.Errorf("before data: %d", w.Code)
	}

	// With data: 200 with a content ETag, then 304 for that tag.
	g.body = []byte{0xB5, 0x62, 0x13, 0x20, 0, 0, 0x33, 0xA9}
	w := get(dev, "")
	if w.Code != http.StatusOK || w.Body.String() != string(g.body) {
		t.Fatalf("get: %d", w.Code)
	}
	etag := w.Header().Get("ETag")
	if etag != gnssassist.ETag(g.body) || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Errorf("headers %v", w.Header())
	}
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		if w := get(dev, inm); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
			t.Errorf("If-None-Match %s: %d", inm, w.Code)
		}
	}
	if w := get(dev, `"`+strings.Repeat("0", 64)+`"`); w.Code != http.StatusOK {
		t.Errorf("stale tag: %d", w.Code)
	}
	if w := report(dev, good); w.Code != http.StatusOK {
		t.Errorf("report once registered: %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(report(dev, good).Body.Bytes(), &resp)
	if resp["registered"] != true || resp["unique_id"] != "a1b2c3d4e5f6" {
		t.Errorf("report body %v", resp)
	}
}

// Without an AssistNow credential the routes do not exist at all.
func TestGNSSAssistRoutesAbsentWhenOff(t *testing.T) {
	s, dev, _ := gnssServer(t, nil)
	w := httptest.NewRecorder()
	s.Routes().ServeHTTP(w, asDevice(httptest.NewRequest("GET", "/api/v2/gnss-assist", nil), dev))
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET with the feature off: %d", w.Code)
	}
	w = httptest.NewRecorder()
	s.Routes().ServeHTTP(w, asDevice(httptest.NewRequest("POST", "/api/v2/gnss-assist/receiver", strings.NewReader("{}")), dev))
	if w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST with the feature off: %d", w.Code)
	}
}
