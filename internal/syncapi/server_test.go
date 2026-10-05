package syncapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/audit"
	"github.com/ParkWardRR/Cairn/server/internal/clients"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

// ─── harness ────────────────────────────────────────────────────────────────

type env struct {
	t        *testing.T
	dir      string
	srv      *Server
	ts       *httptest.Server
	clients  *clients.Registry
	vehicles *vehicles.Registry
	devices  *devices.Registry
	store    *Store
	audit    *audit.Log

	mu  sync.Mutex
	now time.Time

	n20, b58 *vehicles.Vehicle
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func newEnv(t *testing.T, mods ...func(*Config)) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, dir: dir, now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}

	var err error
	paths := DataPaths(dir)
	if e.vehicles, err = vehicles.Open(paths.Vehicles, paths.VehicleKey); err != nil {
		t.Fatal(err)
	}
	if e.clients, err = clients.Open(paths.Clients, clients.WithClock(e.clock)); err != nil {
		t.Fatal(err)
	}
	if e.devices, err = devices.Open(filepath.Join(dir, "devices.json")); err != nil {
		t.Fatal(err)
	}
	if e.store, err = OpenStore(paths.SyncDir, WithStoreClock(e.clock)); err != nil {
		t.Fatal(err)
	}
	if e.audit, err = audit.Open(paths.AuditDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.store.Close(); e.audit.Close() })

	e.n20, _ = e.vehicles.CreateVehicle(vehicles.NewVehicleSpec{DisplayName: "2014 BMW 428i — N20", Year: 2014, EngineCode: "N20", VIN: "WBA3A5C50EF123456"})
	e.b58, _ = e.vehicles.CreateVehicle(vehicles.NewVehicleSpec{DisplayName: "2017 BMW M240i — B58", Year: 2017, EngineCode: "B58"})

	cfg := Config{
		Clients: e.clients, Vehicles: e.vehicles, Devices: e.devices, Store: e.store, Audit: e.audit,
		Classifier: &Classifier{LAN: DefaultLAN(), Tailnet: DefaultTailnet()},
		InstanceID: "00112233445566778899aabbccddeeff",
		AckPath:    filepath.Join(paths.SyncDir, "acks.json"),
		Now:        e.clock,
	}
	for _, m := range mods {
		m(&cfg)
	}
	e.srv, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.ts = httptest.NewServer(e.srv.Routes())
	t.Cleanup(e.ts.Close)
	return e
}

type app struct {
	e   *env
	id  string
	key *ecdsa.PrivateKey
}

// enrol runs the full invitation flow and returns a signing client.
func (e *env) enrol(role clients.Role, scope ...string) *app {
	e.t.Helper()
	code, _, err := e.clients.CreateInvite(clients.InviteSpec{Role: role, Vehicles: scope, Name: "test phone", CreatedBy: "test"})
	if err != nil {
		e.t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		e.t.Fatal(err)
	}
	pubHex := clients.PublicKeyHex(&key.PublicKey)
	proof, err := ecdsa.SignASN1(rand.Reader, key, sum(clients.EnrollProofMessage(code, pubHex)))
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{
		"code": code, "name": "test phone", "public_key": pubHex, "proof": base64.StdEncoding.EncodeToString(proof),
	})
	resp := e.rawPost("/v1/enroll/app", body, "")
	if resp.StatusCode != http.StatusCreated {
		e.t.Fatalf("enrol: %d %s", resp.StatusCode, readBody(resp))
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	mustDecode(e.t, resp, &out)
	return &app{e: e, id: out.ClientID, key: key}
}

func sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func (e *env) rawPost(path string, body []byte, auth string) *http.Response {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+path, bytes.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func readBody(r *http.Response) string {
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

func mustDecode(t *testing.T, r *http.Response, v any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// sign produces an Authorization header for a request as sent.
func (a *app) sign(method, uri string, body []byte) string {
	nonce, _ := NewNonce()
	h, err := AuthorizationHeader(a.key, a.id, method, uri, body, a.e.clock(), nonce)
	if err != nil {
		a.e.t.Fatal(err)
	}
	return h
}

func (a *app) do(method, uri string, body []byte) *http.Response {
	a.e.t.Helper()
	return a.doWith(method, uri, body, a.sign(method, uri, body))
}

func (a *app) doWith(method, uri string, body []byte, auth string) *http.Response {
	a.e.t.Helper()
	req, _ := http.NewRequest(method, a.e.ts.URL+uri, bytes.NewReader(body))
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.e.t.Fatal(err)
	}
	return resp
}

func op(id, vehicle, kind, payload string, mods ...func(*Op)) Op {
	canon, err := Canonicalize([]byte(payload))
	if err != nil {
		panic(err)
	}
	o := Op{
		OperationID: id, VehicleID: vehicle, Kind: kind, CreatedAt: "2026-10-05T12:00:00Z",
		PayloadVersion: 1, Payload: json.RawMessage(payload), ContentHash: ContentHash(canon),
	}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func push(t *testing.T, a *app, ops ...Op) []OpResult {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"operations": ops})
	resp := a.do("POST", "/v1/sync/push", body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("push: %d %s", resp.StatusCode, readBody(resp))
	}
	var out struct {
		Results []OpResult `json:"results"`
	}
	mustDecode(t, resp, &out)
	return out.Results
}

type pullResp struct {
	Epoch   string   `json:"epoch"`
	Changes []change `json:"changes"`
	Cursor  string   `json:"cursor"`
	HasMore bool     `json:"has_more"`
}

func pull(t *testing.T, a *app, cursor string) pullResp {
	t.Helper()
	uri := "/v1/sync/pull"
	if cursor != "" {
		uri += "?cursor=" + cursor
	}
	resp := a.do("GET", uri, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pull: %d %s", resp.StatusCode, readBody(resp))
	}
	var out pullResp
	mustDecode(t, resp, &out)
	return out
}

const (
	uid1 = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b"
	uid2 = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2c"
	uid3 = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2d"
)

// ─── tests ──────────────────────────────────────────────────────────────────

func TestHealthIsUnauthenticatedAndRevealsNothingAboutCars(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.ts.URL + "/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(resp)
	if resp.StatusCode != 200 || !strings.Contains(body, `"protocol_version":1`) {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
	for _, leak := range []string{"N20", "B58", "vehicle", "device", "WBA"} {
		if strings.Contains(body, leak) {
			t.Fatalf("health leaks %q: %s", leak, body)
		}
	}
}

func TestEnrolmentIsSingleUseAndRequiresProofOfPossession(t *testing.T) {
	e := newEnv(t)
	code, _, _ := e.clients.CreateInvite(clients.InviteSpec{Vehicles: []string{clients.ScopeAll}, CreatedBy: "test"})

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubHex := clients.PublicKeyHex(&key.PublicKey)

	mk := func(signer *ecdsa.PrivateKey) []byte {
		proof, _ := ecdsa.SignASN1(rand.Reader, signer, sum(clients.EnrollProofMessage(code, pubHex)))
		b, _ := json.Marshal(map[string]string{"code": code, "name": "x", "public_key": pubHex, "proof": base64.StdEncoding.EncodeToString(proof)})
		return b
	}

	// A proof made with a key the enroller does not hold is refused...
	if r := e.rawPost("/v1/enroll/app", mk(other), ""); r.StatusCode == http.StatusCreated {
		t.Fatal("enrolled a public key without proof of possession")
	}
	// ...and does not burn the invitation.
	if r := e.rawPost("/v1/enroll/app", mk(key), ""); r.StatusCode != http.StatusCreated {
		t.Fatalf("the genuine enrolment was refused after a bad attempt: %d", r.StatusCode)
	}
	// A code works once.
	if r := e.rawPost("/v1/enroll/app", mk(key), ""); r.StatusCode == http.StatusCreated {
		t.Fatal("an invitation was used twice")
	}
}

func TestSignedRequestAcceptedAndUnsignedRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	if r := a.do("GET", "/v1/sync/pull", nil); r.StatusCode != 200 {
		t.Fatalf("signed pull: %d", r.StatusCode)
	}
	resp, _ := http.Get(e.ts.URL + "/v1/sync/pull")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned pull: %d, want 401", resp.StatusCode)
	}
}

func TestReplayedRequestRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	auth := a.sign("GET", "/v1/sync/pull", nil)
	if r := a.doWith("GET", "/v1/sync/pull", nil, auth); r.StatusCode != 200 {
		t.Fatalf("first: %d", r.StatusCode)
	}
	if r := a.doWith("GET", "/v1/sync/pull", nil, auth); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: %d, want 401", r.StatusCode)
	}
}

func TestStaleAndFutureTimestampsRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	nonce, _ := NewNonce()
	old, _ := AuthorizationHeader(a.key, a.id, "GET", "/v1/sync/pull", nil, e.clock().Add(-5*time.Minute), nonce)
	if r := a.doWith("GET", "/v1/sync/pull", nil, old); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale: %d", r.StatusCode)
	}
	nonce, _ = NewNonce()
	future, _ := AuthorizationHeader(a.key, a.id, "GET", "/v1/sync/pull", nil, e.clock().Add(5*time.Minute), nonce)
	if r := a.doWith("GET", "/v1/sync/pull", nil, future); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("future: %d", r.StatusCode)
	}
}

func TestTamperedBodyAndRetargetedRequestRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	good, _ := json.Marshal(map[string]any{"cursor": ""})
	auth := a.sign("POST", "/v1/sync/ack", good)
	evil := []byte(`{"cursor":"x"}`)
	if r := a.doWith("POST", "/v1/sync/ack", evil, auth); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("swapped body: %d", r.StatusCode)
	}

	// A signature for one route cannot be replayed against another.
	auth = a.sign("GET", "/v1/sync/pull", nil)
	if r := a.doWith("GET", "/v1/clients", nil, auth); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("retargeted: %d", r.StatusCode)
	}
}

func TestSignatureFromAnotherKeyRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	imposter, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce, _ := NewNonce()
	h, _ := AuthorizationHeader(imposter, a.id, "GET", "/v1/sync/pull", nil, e.clock(), nonce)
	if r := a.doWith("GET", "/v1/sync/pull", nil, h); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("imposter: %d", r.StatusCode)
	}
}

func TestPushIsIdempotentAndDuplicateReturnsTheOriginal(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	o := op(uid1, e.n20.ID, KindMaintenanceEvent, `{"kind":"oil","odometer_km":45210}`)
	first := push(t, a, o)
	if first[0].Status != StatusAccepted || first[0].ServerSequence == 0 {
		t.Fatalf("first = %+v", first[0])
	}

	again := push(t, a, o)
	if again[0].Status != StatusDuplicate || again[0].ServerSequence != first[0].ServerSequence {
		t.Fatalf("retry = %+v, want a duplicate of sequence %d", again[0], first[0].ServerSequence)
	}

	// Exactly one record exists, however many times it was sent.
	p := pull(t, a, "")
	n := 0
	for _, c := range p.Changes {
		if c.Type == "operation" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d operation records after a retry, want 1", n)
	}
}

func TestHashMismatchRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	o := op(uid1, e.n20.ID, KindMaintenanceEvent, `{"kind":"oil"}`, func(o *Op) { o.ContentHash = strings.Repeat("0", 64) })
	if r := push(t, a, o); r[0].Status != StatusRejected || r[0].Reason != ReasonHashMismatch {
		t.Fatalf("result = %+v", r[0])
	}
}

func TestStaleBaseRevisionConflicts(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	set := op(uid1, e.n20.ID, KindTripAnnotation, `{"target":"trip-1","fields":{"title":"Commute"}}`)
	if r := push(t, a, set); r[0].Status != StatusAccepted || r[0].Revisions["title"] != 1 {
		t.Fatalf("set = %+v", r[0])
	}

	// A second client edit that still believes revision 0.
	stale := op(uid2, e.n20.ID, KindTripAnnotation, `{"target":"trip-1","fields":{"title":"Errand"}}`)
	r := push(t, a, stale)
	if r[0].Status != StatusConflict || len(r[0].Conflicts) != 1 || r[0].Conflicts[0].CurrentRevision != 1 {
		t.Fatalf("stale edit = %+v", r[0])
	}

	// Rebased on the revision it was told about, it applies.
	fixed := op(uid3, e.n20.ID, KindTripAnnotation, `{"target":"trip-1","fields":{"title":"Errand"}}`,
		func(o *Op) { o.BaseRevision = map[string]int64{"title": 1} })
	if r := push(t, a, fixed); r[0].Status != StatusAccepted || r[0].Revisions["title"] != 2 {
		t.Fatalf("rebased = %+v", r[0])
	}
}

func TestVehicleScopeEnforced(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, e.n20.ID) // only the N20

	if r := push(t, a, op(uid1, e.b58.ID, KindMaintenanceEvent, `{"kind":"oil"}`)); r[0].Reason != ReasonScope {
		t.Fatalf("push to an out-of-scope vehicle: %+v", r[0])
	}

	// A client that can see only the N20 never receives the B58's records.
	full := e.enrol(clients.RoleUser, clients.ScopeAll)
	push(t, full, op(uid2, e.b58.ID, KindMaintenanceEvent, `{"kind":"plugs"}`))
	for _, c := range pull(t, a, "").Changes {
		if c.VehicleID == e.b58.ID || (c.Operation != nil && c.Operation.VehicleID == e.b58.ID) {
			t.Fatalf("an N20-scoped client received a B58 record: %+v", c)
		}
	}
}

func TestPullIsRepeatableAndPagesWithACursor(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	push(t, a,
		op(uid1, e.n20.ID, KindMaintenanceEvent, `{"kind":"a"}`),
		op(uid2, e.n20.ID, KindMaintenanceEvent, `{"kind":"b"}`),
		op(uid3, e.n20.ID, KindMaintenanceEvent, `{"kind":"c"}`))

	one := a.do("GET", "/v1/sync/pull?limit=2", nil)
	var p1 pullResp
	mustDecode(t, one, &p1)
	if len(p1.Changes) != 2 || !p1.HasMore {
		t.Fatalf("page 1 = %d changes, has_more %v", len(p1.Changes), p1.HasMore)
	}

	// Pulling the same cursor twice returns the same page.
	r1 := pull(t, a, p1.Cursor)
	r2 := pull(t, a, p1.Cursor)
	j1, _ := json.Marshal(r1.Changes)
	j2, _ := json.Marshal(r2.Changes)
	if !bytes.Equal(j1, j2) {
		t.Fatal("the same cursor returned different pages")
	}
}

func TestPullDeliversVehiclesWithoutTheVIN(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	p := pull(t, a, "")

	var saw bool
	for _, c := range p.Changes {
		if c.EntityType == entityTypeVehicle && c.EntityID == e.n20.ID {
			saw = true
			if strings.Contains(string(c.Data), "WBA3A5C50EF123456") || strings.Contains(string(c.Data), "ciphertext") {
				t.Fatalf("the VIN leaked into a pull: %s", c.Data)
			}
			if !strings.Contains(string(c.Data), `"vin_last4":"3456"`) {
				t.Fatalf("vin_last4 missing: %s", c.Data)
			}
		}
	}
	if !saw {
		t.Fatal("the vehicle was not delivered")
	}
}

func TestCursorFromBeforeADataWipeIsReset(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	cursor := pull(t, a, "").Cursor

	// The server's sync data is wiped and recreated: a new epoch.
	e.store.Close()
	if err := os.RemoveAll(DataPaths(e.dir).SyncDir); err != nil {
		t.Fatal(err)
	}
	var err error
	e.store, err = OpenStore(DataPaths(e.dir).SyncDir, WithStoreClock(e.clock))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.Store = e.store

	resp := a.do("GET", "/v1/sync/pull?cursor="+cursor, nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("stale-epoch cursor: %d, want 410", resp.StatusCode)
	}
	if !strings.Contains(readBody(resp), "cursor_reset") {
		t.Fatal("the response does not say cursor_reset")
	}
}

func TestPublishedTripSummaryReachesInScopeClients(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	if _, _, err := e.store.Publish(Entity{Type: EntityTypeTripSummary, ID: "trip-9", VehicleID: e.n20.ID,
		Data: json.RawMessage(`{"distance_m":12000}`)}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range pull(t, a, "").Changes {
		if c.EntityType == EntityTypeTripSummary && c.EntityID == "trip-9" {
			found = true
		}
	}
	if !found {
		t.Fatal("trip summary not delivered")
	}
}

func TestAckOnlyMovesForward(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	c1 := pull(t, a, "").Cursor
	push(t, a, op(uid1, e.n20.ID, KindMaintenanceEvent, `{"kind":"a"}`))
	c2 := pull(t, a, c1).Cursor

	ack := func(c string) {
		body, _ := json.Marshal(map[string]string{"cursor": c})
		if r := a.do("POST", "/v1/sync/ack", body); r.StatusCode != 200 {
			t.Fatalf("ack: %d", r.StatusCode)
		}
	}
	ack(c2)
	ack(c1) // a delayed retry
	raw, _ := os.ReadFile(filepath.Join(DataPaths(e.dir).SyncDir, "acks.json"))
	seq2, _, _ := e.srv.decodeCursor(c2)
	if !strings.Contains(string(raw), `"sequence": `+itoa(seq2)) {
		t.Fatalf("a delayed ack moved the mark backwards:\n%s", raw)
	}
}

func itoa(n uint64) string { return strings.TrimSpace(strings.Repeat(" ", 0) + jsonNum(n)) }
func jsonNum(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestBearerTokenWorksForSyncOnlyAndDiesWithTheClient(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	resp := a.do("POST", "/v1/auth/token", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("token: %d", resp.StatusCode)
	}
	var tok struct{ Token string }
	mustDecode(t, resp, &tok)

	bearer := func(method, uri string) int {
		req, _ := http.NewRequest(method, e.ts.URL+uri, nil)
		req.Header.Set("Authorization", "Bearer "+tok.Token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if c := bearer("GET", "/v1/sync/pull"); c != 200 {
		t.Fatalf("bearer pull: %d", c)
	}
	// Not for minting more tokens, nor for administration.
	if c := bearer("POST", "/v1/auth/token"); c != http.StatusUnauthorized {
		t.Fatalf("bearer on the token route: %d", c)
	}
	if c := bearer("GET", "/v1/clients"); c != http.StatusUnauthorized {
		t.Fatalf("bearer on an admin route: %d", c)
	}

	// Revoking the client kills its outstanding token at once.
	if err := e.clients.Revoke(a.id, "lost"); err != nil {
		t.Fatal(err)
	}
	if c := bearer("GET", "/v1/sync/pull"); c != http.StatusUnauthorized {
		t.Fatalf("token after revocation: %d", c)
	}

	// Tokens expire.
	b := e.enrol(clients.RoleUser, clients.ScopeAll)
	resp = b.do("POST", "/v1/auth/token", nil)
	mustDecode(t, resp, &tok)
	e.advance(TokenTTL + time.Minute)
	if c := bearer("GET", "/v1/sync/pull"); c != http.StatusUnauthorized {
		t.Fatalf("expired token: %d", c)
	}
}

func TestRevocationIsImmediateIncludingFromAnotherProcess(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	if r := a.do("GET", "/v1/sync/pull", nil); r.StatusCode != 200 {
		t.Fatal("setup")
	}

	// The admin CLI is a separate process editing the same file.
	cli, err := clients.Open(DataPaths(e.dir).Clients, clients.WithClock(e.clock))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Revoke(a.id, "phone lost"); err != nil {
		t.Fatal(err)
	}

	if r := a.do("GET", "/v1/sync/pull", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("request after revocation: %d, want 401", r.StatusCode)
	}
}

func TestAdminCanRevokeADeviceAndAUserCannot(t *testing.T) {
	e := newEnv(t)
	admin := e.enrol(clients.RoleAdmin, clients.ScopeAll)
	user := e.enrol(clients.RoleUser, clients.ScopeAll)

	pub := make([]byte, 32)
	var id [16]byte
	id[0] = 0x87
	if _, err := e.devices.Enroll(id, "dongle", pub, 0); err != nil {
		t.Fatal(err)
	}
	path := "/v1/devices/" + hex.EncodeToString(id[:]) + "/revoke"

	if r := user.do("POST", path, []byte(`{"reason":"x"}`)); r.StatusCode != http.StatusForbidden {
		t.Fatalf("user revoking a device: %d, want 403", r.StatusCode)
	}
	if _, err := e.devices.Lookup(id); err != nil {
		t.Fatalf("a non-admin revoked the device: %v", err)
	}

	if r := admin.do("POST", path, []byte(`{"reason":"stolen"}`)); r.StatusCode != 200 {
		t.Fatalf("admin revoke: %d %s", r.StatusCode, readBody(r))
	}
	if _, err := e.devices.Lookup(id); err == nil {
		t.Fatal("the device is still usable after an admin revoked it")
	}
}

func TestFunnelMarkedRequestsAreRefused(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.ts.URL+"/v1/health", nil)
	req.Header.Set("Tailscale-Funnel-Request", "?1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("funnel request: %d, want 403", resp.StatusCode)
	}
}

// Identity headers are text a client typed unless a Serve proxy on loopback put
// them there.
func TestTailscaleHeadersAreOnlyTrustedFromLoopback(t *testing.T) {
	c := &Classifier{LAN: DefaultLAN(), Tailnet: DefaultTailnet(), TrustServe: true}

	mk := func(remote string) *http.Request {
		r := httptest.NewRequest("GET", "/v1/health", nil)
		r.RemoteAddr = remote
		r.Header.Set("Tailscale-User-Login", "owner@example.com")
		return r
	}

	if info := c.Classify(mk("127.0.0.1:5555")); info.Login != "owner@example.com" || info.Class != TransportTailnet {
		t.Fatalf("loopback with TrustServe: %+v", info)
	}
	if info := c.Classify(mk("192.168.1.50:5555")); info.Login != "" || info.Class != TransportLAN {
		t.Fatalf("a LAN peer's spoofed header was honoured: %+v", info)
	}
	if info := c.Classify(mk("203.0.113.9:5555")); info.Login != "" {
		t.Fatalf("an internet peer's spoofed header was honoured: %+v", info)
	}

	off := &Classifier{LAN: DefaultLAN(), Tailnet: DefaultTailnet()}
	if info := off.Classify(mk("127.0.0.1:5555")); info.Login != "" {
		t.Fatalf("headers honoured with TrustServe off: %+v", info)
	}
}

func TestTailnetIdentityRuleRefusesStrangers(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Classifier = &Classifier{LAN: DefaultLAN(), Tailnet: DefaultTailnet(),
			TrustServe: true, RequireIdentity: true, AllowLogins: []string{"owner@example.com"}}
	})
	get := func(login string) int {
		req, _ := http.NewRequest("GET", e.ts.URL+"/v1/health", nil)
		if login != "" {
			req.Header.Set("Tailscale-User-Login", login)
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if c := get("owner@example.com"); c != 200 {
		t.Fatalf("the allowed login: %d", c)
	}
	if c := get("stranger@example.com"); c != http.StatusForbidden {
		t.Fatalf("another tailnet user: %d, want 403", c)
	}
	if c := get(""); c != http.StatusForbidden {
		t.Fatalf("no identity behind Serve: %d, want 403", c)
	}
}

// What the audit trail must never hold.
func TestAuditAndLogsNeverContainSecrets(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)

	resp := a.do("POST", "/v1/auth/token", nil)
	var tok struct{ Token string }
	mustDecode(t, resp, &tok)

	body, _ := json.Marshal(map[string]any{"operations": []Op{
		op(uid1, e.n20.ID, KindMaintenanceEvent, `{"note":"SECRET-PAYLOAD-MARKER","lat":"36.5552","lon":"-121.9233"}`),
	}})
	auth := a.sign("POST", "/v1/sync/push", body)
	a.doWith("POST", "/v1/sync/push", body, auth)
	pull(t, a, "")

	var all strings.Builder
	err := filepath.Walk(DataPaths(e.dir).AuditDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			all.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	text := all.String()
	if text == "" {
		t.Fatal("the audit log is empty")
	}

	sig := auth[strings.Index(auth, `sig="`)+5:]
	sig = sig[:strings.Index(sig, `"`)]
	for _, secret := range []string{
		"SECRET-PAYLOAD-MARKER", "36.5552", "-121.9233", tok.Token, sig, "WBA3A5C50EF123456",
		clients.PublicKeyHex(&a.key.PublicKey),
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("the audit log contains %q", secret)
		}
	}
	// And it does record who did what, by what route.
	if !strings.Contains(text, "POST /v1/sync/push") || !strings.Contains(text, a.id) {
		t.Fatalf("the audit log is missing the actor or route:\n%s", text)
	}
}

func TestOversizedBodyRefused(t *testing.T) {
	e := newEnv(t)
	a := e.enrol(clients.RoleUser, clients.ScopeAll)
	big := bytes.Repeat([]byte("a"), maxBody+10)
	if r := a.do("POST", "/v1/sync/push", big); r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", r.StatusCode)
	}
}

func TestSnapshotIsAuthenticatedProxiedAndScoped(t *testing.T) {
	var gotPath, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.Header().Set("ETag", `"abc"`)
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write([]byte("SNAPSHOT-BYTES"))
	}))
	defer upstream.Close()

	e := newEnv(t, func(c *Config) { c.SnapshotURL = upstream.URL })
	full := e.enrol(clients.RoleUser, clients.ScopeAll)
	narrow := e.enrol(clients.RoleUser, e.n20.ID)

	// Unsigned: refused before the upstream is touched.
	if resp, _ := http.Get(e.ts.URL + "/v1/snapshot"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned snapshot: %d", resp.StatusCode)
	}
	if gotPath != "" {
		t.Fatal("an unauthenticated request reached the analytical store")
	}

	// A scoped client must name a vehicle...
	if r := narrow.do("GET", "/v1/snapshot", nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped client with no vehicle: %d, want 403", r.StatusCode)
	}
	if gotPath != "" {
		t.Fatal("a scoped client's un-scoped request reached the analytical store")
	}
	// ...and it must be one of theirs.
	if r := narrow.do("GET", "/v1/snapshot?vehicle="+e.b58.ID, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("scoped client asking for another car: %d, want 403", r.StatusCode)
	}
	if gotPath != "" {
		t.Fatal("an out-of-scope vehicle request reached the analytical store")
	}
	// Its own vehicle is served, filtered at the source.
	r := narrow.do("GET", "/v1/snapshot?vehicle="+e.n20.ID+"&format=tar&evil=1", nil)
	if r.StatusCode != 200 || readBody(r) != "SNAPSHOT-BYTES" {
		t.Fatalf("scoped client, own vehicle: %d", r.StatusCode)
	}
	if gotPath != "/snapshot" || gotQuery != "format=tar&vehicle="+e.n20.ID {
		t.Fatalf("upstream saw %s?%s; only format and vehicle may be forwarded", gotPath, gotQuery)
	}

	// A malformed vehicle id never reaches the upstream.
	gotPath = ""
	if r := full.do("GET", "/v1/snapshot?vehicle=%27%20OR%201%3D1%20--", nil); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed vehicle id: %d, want 400", r.StatusCode)
	}
	if gotPath != "" {
		t.Fatal("a malformed vehicle id was forwarded")
	}

	// A full-scope client may omit it (whole archive) or narrow it.
	if r := full.do("GET", "/v1/snapshot", nil); r.StatusCode != 200 || gotQuery != "" {
		t.Fatalf("full scope, no vehicle: %d, upstream query %q", r.StatusCode, gotQuery)
	}
	if r := full.do("GET", "/v1/snapshot?vehicle="+e.b58.ID, nil); r.StatusCode != 200 || gotQuery != "vehicle="+e.b58.ID {
		t.Fatalf("full scope, one vehicle: %d, upstream query %q", r.StatusCode, gotQuery)
	}
}
