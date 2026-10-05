package syncapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLocalHandlerListsDisplayDataOnly(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(LocalHandler(e.vehicles))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/local/vehicles")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	for _, want := range []string{e.n20.ID, "N20", e.b58.ID, "B58"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response lacks %q: %s", want, body)
		}
	}
	// The N20 was created with a VIN. Nothing derived from it may appear.
	for _, leak := range []string{"WBA3A5C50EF123456", "3456", "vin", "ciphertext", "device_id", "assignment"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the local API leaked %q: %s", leak, body)
		}
	}
}

// If tailscale serve (or any proxy adding these headers) is pointed at the local
// port by mistake, the tailnet must get a refusal, not the vehicle list.
func TestLocalHandlerRefusesAnythingThatWasProxied(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(LocalHandler(e.vehicles))
	defer srv.Close()

	for _, h := range []string{"Tailscale-User-Login", "Tailscale-User-Name", "Tailscale-Funnel-Request"} {
		req, _ := http.NewRequest("GET", srv.URL+"/v1/local/vehicles", nil)
		req.Header.Set(h, "x")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("with %s: %d, want 403", h, resp.StatusCode)
		}
	}

	// Only GET, only that path.
	if resp, _ := http.Post(srv.URL+"/v1/local/vehicles", "text/plain", nil); resp.StatusCode == 200 {
		t.Fatal("a POST was accepted")
	}
	if resp, _ := http.Get(srv.URL + "/v1/sync/pull"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an app route answered on the local listener: %d", resp.StatusCode)
	}
}
