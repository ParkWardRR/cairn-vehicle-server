package syncapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/audit"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
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

func postInvite(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", url+"/v1/local/clients/invite", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLocalInviteMintsAUserInvitationThatEnrolsAPhone(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Clients: e.clients, WriteToken: "tok"}))
	defer srv.Close()

	resp := postInvite(t, srv.URL, "tok", `{"name":"Sam's iPhone","ttl_seconds":600,"actor":"passkey"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("invite: %d %s", resp.StatusCode, readBody(resp))
	}
	var out struct {
		Code      string    `json:"code"`
		Role      string    `json:"role"`
		Vehicles  []string  `json:"vehicles"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	mustDecode(t, resp, &out)
	if out.Role != "user" || len(out.Vehicles) != 1 || out.Vehicles[0] != clients.ScopeAll {
		t.Fatalf("invitation is %s for %v, want a user for every vehicle", out.Role, out.Vehicles)
	}
	if d := out.ExpiresAt.Sub(e.clock()); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatalf("expires in %s, want about the 10 minutes asked for", d)
	}

	// The shown code enrols a phone, which is a user and so cannot administer anything.
	phone := e.enrolWithCode(out.Code, "Sam's iPhone")
	if r := phone.do("GET", "/v1/clients", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("the invited phone can list clients: %d", r.StatusCode)
	}
}

func TestLocalInviteIsGuardedAndBounded(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Clients: e.clients, WriteToken: "tok"}))
	defer srv.Close()

	if r := postInvite(t, srv.URL, "", `{}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d, want 401", r.StatusCode)
	}
	if r := postInvite(t, srv.URL, "wrong", `{}`); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: %d, want 401", r.StatusCode)
	}
	for name, body := range map[string]string{
		"an admin role":     `{"role":"admin"}`,
		"a day":             `{"ttl_seconds":86400}`,
		"a negative ttl":    `{"ttl_seconds":-1}`,
		"a malformed scope": `{"vehicles":["not a vehicle id"]}`,
	} {
		if r := postInvite(t, srv.URL, "tok", body); r.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, r.StatusCode)
		}
	}

	noWrites := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Clients: e.clients}))
	defer noWrites.Close()
	if r := postInvite(t, noWrites.URL, "tok", `{}`); r.StatusCode != http.StatusForbidden {
		t.Errorf("no write token configured: %d, want 403", r.StatusCode)
	}
	noReg := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, WriteToken: "tok"}))
	defer noReg.Close()
	if r := postInvite(t, noReg.URL, "tok", `{}`); r.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("no registry: %d, want 503", r.StatusCode)
	}
}

func localGet(t *testing.T, base, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func localPost(t *testing.T, base, path, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLocalClientsAreListedWithoutKeyMaterialAndOnlyWithTheToken(t *testing.T) {
	e := newEnv(t)
	phone := e.enrol(clients.RoleUser, clients.ScopeAll)
	srv := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Clients: e.clients, WriteToken: "tok"}))
	defer srv.Close()

	for _, token := range []string{"", "wrong"} {
		if r := localGet(t, srv.URL, "/v1/local/clients", token); r.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: %d, want 401", token, r.StatusCode)
		}
	}
	r := localGet(t, srv.URL, "/v1/local/clients", "tok")
	body := readBody(r)
	if r.StatusCode != 200 || !strings.Contains(body, phone.id) || !strings.Contains(body, `"status":"active"`) {
		t.Fatalf("list: %d %s", r.StatusCode, body)
	}
	if strings.Contains(body, "public_key") || strings.Contains(body, clients.PublicKeyHex(&phone.key.PublicKey)) {
		t.Fatalf("the list leaked key material: %s", body)
	}

	// Proxied traffic is refused here too, even with the token.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/local/clients", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Tailscale-User-Login", "someone@example.com")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxied list: %d, want 403", resp.StatusCode)
	}
}

func TestRevokingAPhoneFromTheDashboardStopsItAtOnce(t *testing.T) {
	e := newEnv(t)
	phone := e.enrol(clients.RoleUser, clients.ScopeAll)
	other := e.enrol(clients.RoleUser, clients.ScopeAll)
	srv := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Clients: e.clients, WriteToken: "tok"}))
	defer srv.Close()

	if r := phone.do("GET", "/v1/sync/pull?limit=1", nil); r.StatusCode != 200 {
		t.Fatalf("before: %d", r.StatusCode)
	}
	if r := localPost(t, srv.URL, "/v1/local/clients/"+phone.id+"/revoke", "", `{}`); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without the token: %d, want 401", r.StatusCode)
	}
	r := localPost(t, srv.URL, "/v1/local/clients/"+phone.id+"/revoke", "tok", `{"reason":"lost   it","actor":"passkey"}`)
	if r.StatusCode != 200 {
		t.Fatalf("revoke: %d %s", r.StatusCode, readBody(r))
	}

	// The revoked phone is refused on its next request; a bystander is not.
	if r := phone.do("GET", "/v1/sync/pull?limit=1", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after: %d, want 401", r.StatusCode)
	}
	if r := other.do("GET", "/v1/sync/pull?limit=1", nil); r.StatusCode != 200 {
		t.Fatalf("a different phone was affected: %d", r.StatusCode)
	}

	body := readBody(localGet(t, srv.URL, "/v1/local/clients", "tok"))
	if !strings.Contains(body, `"status":"revoked"`) || !strings.Contains(body, "lost it (passkey)") {
		t.Fatalf("the list does not show who revoked it and why: %s", body)
	}
	// Revoking twice is not an error; a made-up or malformed id is.
	if r := localPost(t, srv.URL, "/v1/local/clients/"+phone.id+"/revoke", "tok", `{}`); r.StatusCode != 200 {
		t.Errorf("revoke again: %d", r.StatusCode)
	}
	if r := localPost(t, srv.URL, "/v1/local/clients/"+strings.Repeat("0", 32)+"/revoke", "tok", `{}`); r.StatusCode != 404 {
		t.Errorf("unknown phone: %d, want 404", r.StatusCode)
	}
	if r := localPost(t, srv.URL, "/v1/local/clients/not-an-id/revoke", "tok", `{}`); r.StatusCode != 400 {
		t.Errorf("malformed id: %d, want 400", r.StatusCode)
	}
}

func TestLocalActivityHidesHealthProbesAndStaysWithinTheLimit(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	for i, route := range []string{"GET /v1/health", "POST /v1/enroll/app", "GET /v1/health", "POST /v1/relay/bundles/{id}/commit", "GET /v1/snapshot"} {
		_ = e.audit.Append(audit.Entry{Time: now.Add(time.Duration(i) * time.Second), ActorType: audit.ActorApp, ClientID: "c1",
			Transport: "lan", Route: route, TargetID: "t1", Status: 200, BodySHA256: "deadbeef", TailscaleLogin: "me@example.com"})
	}
	srv := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, Audit: e.audit, WriteToken: "tok"}))
	defer srv.Close()

	if r := localGet(t, srv.URL, "/v1/local/activity", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", r.StatusCode)
	}
	body := readBody(localGet(t, srv.URL, "/v1/local/activity", "tok"))
	if strings.Contains(body, "/v1/health") {
		t.Fatalf("health probes are in the feed: %s", body)
	}
	if strings.Contains(body, "deadbeef") || strings.Contains(body, "me@example.com") {
		t.Fatalf("the feed leaked a body hash or a Tailscale login: %s", body)
	}
	// Newest first: the snapshot read came last.
	if strings.Index(body, "snapshot") > strings.Index(body, "enroll") {
		t.Fatalf("not newest first: %s", body)
	}
	if got := strings.Count(readBody(localGet(t, srv.URL, "/v1/local/activity?limit=2", "tok")), `"route"`); got != 2 {
		t.Fatalf("limit=2 returned %d entries", got)
	}

	noLog := httptest.NewServer(NewLocalHandler(LocalConfig{Vehicles: e.vehicles, WriteToken: "tok"}))
	defer noLog.Close()
	if r := localGet(t, noLog.URL, "/v1/local/activity", "tok"); r.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("no audit log: %d, want 503", r.StatusCode)
	}
}
