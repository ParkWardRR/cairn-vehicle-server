package syncapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/audit"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/contracts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/intake"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/outbox"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// sync/v1 exchange vectors: contracts/sync/v1/vectors/exchanges.json.
//
// vectors.json pins the signing string and the header layout. This file pins whole
// request/response exchanges, so a client (the iOS app) can check both halves: that
// it builds the same request, and that it reads the same response. The exchanges are
// one timeline against one server, in order, because replay, expiry and scope depend
// on what came before. Every step carries its inputs (method, request target,
// headers, body, the server's clock, the nonce) and the exact status, headers and body
// the server answered with, negatives included.
//
// Nothing is random. The keys are fixed, the clock is a number each step states, the
// nonces are counted, and the server's own identifiers (bearer token, epoch, receipt
// id, invitation codes) come from a seeded source instead of the operating system's.
// ECDSA signatures are deterministic too (RFC 6979, below), so regenerating produces
// no diff and "the Authorization header" is a byte-exact expectation rather than a
// sample.
//
// The generator and the check share one server fixture and one driver:
//
//	CAIRN_CONTRACTS=<contracts dir> go test ./internal/syncapi -run SyncExchange -update-vectors
//
// writes the file (after a deliberate change; open a contracts pull request first),
// and without the flag the test replays the file's recorded requests against this
// server and requires the recorded responses back, and that regenerating gives the
// file byte for byte. A pinned contracts release that lacks the file skips, loudly.

const (
	exOrigin = 1790000000 // the server clock at the start, unix seconds
	exSeed   = 20261005   // seed of the stand-in for crypto/rand
	exFile   = "exchanges.json"
)

// ─── the vector file ────────────────────────────────────────────────────────

type exDoc struct {
	Version int       `json:"version"`
	Spec    string    `json:"spec"`
	Notes   []string  `json:"notes"`
	Fixture exFixture `json:"fixture"`
	Steps   []exStep  `json:"steps"`
}

type exFixture struct {
	InstanceID       string            `json:"instance_id"`
	ClockStartUnix   int64             `json:"clock_start_unix"`
	Clients          []exClient        `json:"clients"`
	Vehicles         []exVehicle       `json:"vehicles"`
	DeviceID         string            `json:"device_id"`
	DevicePublicKey  string            `json:"device_public_key_ed25519_hex"`
	ReceiptPublicKey string            `json:"receipt_signing_public_key_ed25519_hex"`
	Bundles          []exBundle        `json:"bundles"`
	InvitationCodes  map[string]string `json:"invitation_codes"`
	UnknownClientID  string            `json:"unknown_client_id"`
	UnknownVehicleID string            `json:"unknown_vehicle_id"`
	ForeignCursor    string            `json:"foreign_epoch_cursor"`
}

type exClient struct {
	Name             string   `json:"name"`
	ClientID         string   `json:"client_id"`
	Role             string   `json:"role"`
	Scope            []string `json:"scope"`
	PrivateScalarHex string   `json:"private_scalar_hex"`
	PublicKeyHex     string   `json:"public_key_x963_hex"`
}

type exVehicle struct {
	Name        string `json:"name"`
	ID          string `json:"vehicle_id"`
	DisplayName string `json:"display_name"`
	Archived    bool   `json:"archived"`
}

type exBundle struct {
	Name         string `json:"name"`
	BundleID     string `json:"bundle_id"`
	VehicleID    string `json:"vehicle_id"`
	ContentRoot  string `json:"content_root_hex"`
	ManifestHex  string `json:"manifest_cbor_hex"`
	SignatureHex string `json:"manifest_signature_hex"`
}

type exStep struct {
	Name     string     `json:"name"`
	Doc      string     `json:"doc"`
	Clock    int64      `json:"server_clock_unix"`
	Auth     string     `json:"auth"` // none | signed | bearer
	Request  exRequest  `json:"request"`
	Signing  *exSigning `json:"signing,omitempty"`
	Response exResponse `json:"response"`
}

type exRequest struct {
	Method   string            `json:"method"`
	Target   string            `json:"request_target"`
	Headers  map[string]string `json:"headers,omitempty"`
	BodyHex  string            `json:"body_hex"`
	BodyText string            `json:"body_text,omitempty"`
}

// exSigning explains an Authorization header made by signing. SigningString and
// SignatureB64 are what the signer produced; MatchesRequest says whether the request
// actually sent is the one that was signed, and SignatureValid whether the signature
// verifies, over SigningString, under the registered key of the client the header names.
type exSigning struct {
	Signer         string `json:"signer"`
	ClientID       string `json:"client_id"`
	TS             string `json:"ts"`
	Nonce          string `json:"nonce"`
	BodySHA256     string `json:"body_sha256"`
	SigningString  string `json:"signing_string"`
	SignatureB64   string `json:"signature_der_base64"`
	MatchesRequest bool   `json:"matches_request"`
	SignatureValid bool   `json:"signature_valid"`
	Mutation       string `json:"mutation,omitempty"`
}

type exResponse struct {
	Status    int               `json:"status"`
	ErrorCode string            `json:"error_code,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	BodyJSON  json.RawMessage   `json:"body_json,omitempty"`
	BodyHex   string            `json:"body_hex,omitempty"`
}

// The response headers a client is expected to be able to rely on. Others (Date,
// Content-Length) vary or belong to the HTTP stack.
var exResponseHeaders = []string{
	"Content-Type", "Cache-Control", "WWW-Authenticate", "X-Cairn-Receipt-Id", "X-Cairn-Already-Committed",
}

// ─── deterministic ECDSA (RFC 6979) ─────────────────────────────────────────

// signRFC6979 signs msg with ECDSA P-256 / SHA-256 and a nonce derived from the key
// and the message, so the same input always gives the same DER signature. Production
// signing stays randomised (CryptoKit's is); this exists so a vector is reproducible.
func signRFC6979(key *ecdsa.PrivateKey, msg []byte) []byte {
	curve := elliptic.P256()
	n := curve.Params().N
	digest := sha256.Sum256(msg)
	x := key.D.FillBytes(make([]byte, 32))
	h := new(big.Int).SetBytes(digest[:])
	h1 := new(big.Int).Mod(h, n).FillBytes(make([]byte, 32))

	mac := func(k []byte, parts ...[]byte) []byte {
		m := hmac.New(sha256.New, k)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	v := bytes.Repeat([]byte{0x01}, 32)
	k := make([]byte, 32)
	k = mac(k, v, []byte{0x00}, x, h1)
	v = mac(k, v)
	k = mac(k, v, []byte{0x01}, x, h1)
	v = mac(k, v)
	for {
		v = mac(k, v)
		nonce := new(big.Int).SetBytes(v)
		if nonce.Sign() > 0 && nonce.Cmp(n) < 0 {
			rx, _ := curve.ScalarBaseMult(v) //nolint:staticcheck // the only public scalar multiplication
			r := new(big.Int).Mod(rx, n)
			s := new(big.Int).Mul(r, key.D)
			s.Add(s, h)
			s.Mul(s, new(big.Int).ModInverse(nonce, n))
			s.Mod(s, n)
			if r.Sign() != 0 && s.Sign() != 0 {
				der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
				if err != nil {
					panic(err)
				}
				return der
			}
		}
		k = mac(k, v, []byte{0x00})
		v = mac(k, v)
	}
}

// RFC 6979 appendix A.2.5: P-256 with SHA-256, message "sample". If this drifts the
// signatures in the vectors are no longer the deterministic ones the RFC defines.
func TestRFC6979SignerMatchesTheRFCVector(t *testing.T) {
	d, _ := hex.DecodeString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
	key := &ecdsa.PrivateKey{D: new(big.Int).SetBytes(d)}
	key.Curve = elliptic.P256()
	key.PublicKey.X, key.PublicKey.Y = key.Curve.ScalarBaseMult(d)

	der := signRFC6979(key, []byte("sample"))
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		t.Fatal(err)
	}
	const wantR = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
	const wantS = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
	if got := hex.EncodeToString(sig.R.Bytes()); got != wantR {
		t.Errorf("r = %s, want %s", got, wantR)
	}
	if got := hex.EncodeToString(sig.S.Bytes()); got != wantS {
		t.Errorf("s = %s, want %s", got, wantS)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, sum([]byte("sample")), der) {
		t.Error("the deterministic signature does not verify")
	}
}

// ─── the server fixture ─────────────────────────────────────────────────────

type exEnv struct {
	t        *testing.T
	ts       *httptest.Server
	clock    atomic.Int64
	clients  []exClient
	keys     map[string]*ecdsa.PrivateKey
	invites  map[string]string
	vehicles []exVehicle
	bundles  map[string]*testbundle.Bundle
	device   [16]byte
	devKey   ed25519.PublicKey
	receipt  ed25519.PublicKey
	epoch    string
}

func (e *exEnv) setClock(unix int64) { e.clock.Store(unix) }
func (e *exEnv) now() time.Time      { return time.Unix(e.clock.Load(), 0).UTC() }

// exKey derives a client's signing key from its name: public, fixed, protects nothing.
func exKey(name string) *ecdsa.PrivateKey {
	h := sha256.Sum256([]byte("cairn sync/v1 exchange vectors -- PUBLIC TEST KEY: " + name))
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k := &ecdsa.PrivateKey{D: d}
	k.Curve = elliptic.P256()
	k.PublicKey.X, k.PublicKey.Y = k.Curve.ScalarBaseMult(d.FillBytes(make([]byte, 32)))
	return k
}

// exHexID is 16 bytes counting up from first, the way testbundle writes its ids.
func exHexID(first byte) string {
	var b [16]byte
	for j := range b {
		b[j] = first + byte(j)
	}
	return hex.EncodeToString(b[:])
}

// The enrolment order fixes who gets which client id.
var exClientSpecs = []struct {
	name, id, role string
	scope          func(v map[string]string) []string
}{
	{"admin", "0190c0de000070008000000000000a01", "admin", func(map[string]string) []string { return []string{"*"} }},
	{"alpha", "0190c0de000070008000000000000a02", "user", func(v map[string]string) []string { return []string{v["v1"]} }},
	{"bravo", "0190c0de000070008000000000000a03", "user", func(v map[string]string) []string { return []string{v["v2"]} }},
	{"charlie", "0190c0de000070008000000000000a04", "user", func(v map[string]string) []string { return []string{v["v1"]} }},
}

func newExchangeEnv(t *testing.T) *exEnv {
	t.Helper()
	cryptotest.SetGlobalRandom(t, exSeed)
	dir := t.TempDir()
	e := &exEnv{t: t, keys: map[string]*ecdsa.PrivateKey{}, invites: map[string]string{}, bundles: map[string]*testbundle.Bundle{}}
	e.setClock(exOrigin - 100)

	paths := DataPaths(dir)
	vr, err := vehicles.Open(paths.Vehicles, paths.VehicleKey, vehicles.WithClock(e.now))
	if err != nil {
		t.Fatal(err)
	}

	// Three vehicles: v1 is the dongle's car, v2 a second car, v3 archived. The clock
	// moves between creations because the registry lists vehicles by creation time.
	ids := map[string]string{"v1": hex.EncodeToString(vehicleIDBytes()), "v2": exHexID(0x40), "v3": exHexID(0x60)}
	for i, spec := range []struct {
		name, display, vin string
		archived           bool
	}{
		{"v1", "2014 BMW 428i — N20", "WBA3A5C50EF123456", false},
		{"v2", "2017 BMW M240i — B58", "", false},
		{"v3", "2009 BMW 335i — N54 (sold)", "", true},
	} {
		e.setClock(exOrigin - 100 + int64(i))
		if _, err := vr.CreateVehicle(vehicles.NewVehicleSpec{ID: ids[spec.name], DisplayName: spec.display, VIN: spec.vin}); err != nil {
			t.Fatal(err)
		}
		e.vehicles = append(e.vehicles, exVehicle{Name: spec.name, ID: ids[spec.name], DisplayName: spec.display, Archived: spec.archived})
	}

	devReg, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.device = testbundle.DeviceID()
	e.devKey, _ = testbundle.DeviceKey()
	if _, err := devReg.Enroll(e.device, "test-recorder", e.devKey, 0); err != nil {
		t.Fatal(err)
	}
	asg := testbundle.AssignmentID()
	e.setClock(exOrigin - 90)
	if _, err := vr.AssignWithID(hex.EncodeToString(asg[:]), hex.EncodeToString(e.device[:]), ids["v1"], "vectors"); err != nil {
		t.Fatal(err)
	}
	e.setClock(exOrigin - 80)
	if err := vr.Archive(ids["v3"]); err != nil {
		t.Fatal(err)
	}

	guard, err := counters.Open(filepath.Join(dir, "counters.json"))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keystore.Open(filepath.Join(dir, "keystore.json"), filepath.Join(dir, "keys", "keystore.master"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Put(hex.EncodeToString(e.device[:]), testbundle.DefaultKeyVersion, testbundle.RootKey()); err != nil {
		t.Fatal(err)
	}

	// The receipt-signing key: a fixed seed, so receipts are byte-reproducible.
	seed := sha256.Sum256([]byte("cairn sync/v1 exchange vectors -- PUBLIC TEST KEY: receipt signer"))
	seedPath := filepath.Join(dir, "keys", "receipt.seed")
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(seedPath, seed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := receipts.Open(receipts.Config{Dir: filepath.Join(dir, "receipts"), KeyPath: seedPath, Now: e.now})
	if err != nil {
		t.Fatal(err)
	}
	e.receipt = rec.PublicKey()

	casStore, err := cas.Open(filepath.Join(dir, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(filepath.Join(dir, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := intake.New(intake.Config{
		CAS: casStore, Receipts: rec, Registry: devReg, Outbox: ob, OfferDir: filepath.Join(dir, "offers"),
		Vehicles: vr, Counters: guard, Keys: ks,
	})
	if err != nil {
		t.Fatal(err)
	}

	next := 0
	clientReg, err := clients.Open(paths.Clients, clients.WithClock(e.now), clients.WithIDs(func() ([16]byte, error) {
		var id [16]byte
		raw, _ := hex.DecodeString(exClientSpecs[next].id)
		copy(id[:], raw)
		next++
		return id, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(paths.SyncDir, WithStoreClock(e.now))
	if err != nil {
		t.Fatal(err)
	}
	al, err := audit.Open(paths.AuditDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close(); al.Close() })

	// SnapshotURL points nowhere: the vectors cover the scope decisions, which are made
	// before anything is proxied, not the Parquet bytes behind them.
	srv, err := New(Config{
		Clients: clientReg, Vehicles: vr, Devices: devReg, Intake: svc, Store: st, Audit: al,
		Classifier: &Classifier{LAN: DefaultLAN(), Tailnet: DefaultTailnet()},
		InstanceID: "00112233445566778899aabbccddeeff", SnapshotURL: "http://127.0.0.1:9",
		AckPath: filepath.Join(paths.SyncDir, "acks.json"), Now: e.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.ts = httptest.NewServer(srv.Routes())
	t.Cleanup(e.ts.Close)
	e.epoch = st.Epoch()

	// One invitation per client, created now so the random source is consumed in the
	// same order whether generating or replaying.
	e.setClock(exOrigin)
	for _, c := range exClientSpecs {
		scope := c.scope(ids)
		role := clients.RoleUser
		if c.role == "admin" {
			role = clients.RoleAdmin
			scope = []string{clients.ScopeAll}
		}
		code, _, err := clientReg.CreateInvite(clients.InviteSpec{Role: role, Vehicles: scope, CreatedBy: "vectors"})
		if err != nil {
			t.Fatal(err)
		}
		e.invites[c.name] = code
		key := exKey(c.name)
		e.keys[c.name] = key
		e.clients = append(e.clients, exClient{
			Name: c.name, ClientID: c.id, Role: c.role, Scope: scope,
			PrivateScalarHex: hex.EncodeToString(key.D.FillBytes(make([]byte, 32))),
			PublicKeyHex:     clients.PublicKeyHex(&key.PublicKey),
		})
	}

	// Two bundles from the dongle: the first is relayed to a receipt; the second is
	// only ever refused.
	for i, name := range []string{"delivered", "refused"} {
		o := testbundle.Default()
		o.GNSSSamples, o.OBDSamples, o.JournalEntries = 2, 1, 1
		o.DeviceCounter = uint64(i + 1)
		b, err := testbundle.Build(o)
		if err != nil {
			t.Fatal(err)
		}
		e.bundles[name] = b
	}
	return e
}

func vehicleIDBytes() []byte { v := testbundle.VehicleID(); return v[:] }

func (e *exEnv) client(name string) exClient {
	for _, c := range e.clients {
		if c.Name == name {
			return c
		}
	}
	e.t.Fatalf("no fixture client %q", name)
	return exClient{}
}

func (e *exEnv) vehicle(name string) string {
	for _, v := range e.vehicles {
		if v.Name == name {
			return v.ID
		}
	}
	e.t.Fatalf("no fixture vehicle %q", name)
	return ""
}

// send performs one recorded request and records the answer.
func (e *exEnv) send(req exRequest) exResponse {
	e.t.Helper()
	body, err := hex.DecodeString(req.BodyHex)
	if err != nil {
		e.t.Fatal(err)
	}
	hr, err := http.NewRequest(req.Method, e.ts.URL+req.Target, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	out := exResponse{Status: resp.StatusCode, Headers: map[string]string{}}
	for _, h := range exResponseHeaders {
		if v := resp.Header.Get(h); v != "" {
			out.Headers[h] = v
		}
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var compact bytes.Buffer
		if err := json.Compact(&compact, raw); err != nil {
			e.t.Fatalf("response is not JSON: %v", err)
		}
		out.BodyJSON = compact.Bytes()
		var eb struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &eb)
		out.ErrorCode = eb.Error
	} else {
		out.BodyHex = hex.EncodeToString(raw)
	}
	return out
}

// ─── the generator ──────────────────────────────────────────────────────────

type exGen struct {
	e      *exEnv
	steps  []exStep
	nonces int
	byName map[string]*exStep
	tokens map[string]string
}

func (g *exGen) at(offset int64) { g.e.setClock(exOrigin + offset) }

func (g *exGen) nonce() string {
	g.nonces++
	h := sha256.Sum256([]byte(fmt.Sprintf("cairn sync/v1 exchange vectors nonce %d", g.nonces)))
	return hex.EncodeToString(h[:16])
}

type signPlan struct {
	ts       *int64
	nonce    string
	signer   string
	clientID string
	asMethod string
	asTarget string
	asBody   []byte
	flipSig  bool
	replayOf string
	mutation string
}

type signOpt func(*signPlan)

func withTS(unix int64) signOpt        { return func(p *signPlan) { p.ts = &unix } }
func withNonce(n string) signOpt       { return func(p *signPlan) { p.nonce = n } }
func signedBy(name string) signOpt     { return func(p *signPlan) { p.signer = name } }
func claimingClient(id string) signOpt { return func(p *signPlan) { p.clientID = id } }
func replayOf(step string) signOpt     { return func(p *signPlan) { p.replayOf = step } }
func mutated(what string) signOpt      { return func(p *signPlan) { p.mutation = what } }
func tamperedSignature() signOpt       { return func(p *signPlan) { p.flipSig = true } }
func signedForTarget(target string) signOpt {
	return func(p *signPlan) { p.asTarget = target }
}
func signedForBody(body []byte) signOpt { return func(p *signPlan) { p.asBody = body } }

func (g *exGen) record(name, doc, auth string, req exRequest, sg *exSigning) exStep {
	g.e.t.Helper()
	step := exStep{Name: name, Doc: doc, Clock: g.e.clock.Load(), Auth: auth, Request: req, Signing: sg, Response: g.e.send(req)}
	g.steps = append(g.steps, step)
	g.byName[name] = &g.steps[len(g.steps)-1]
	return step
}

func exRequestOf(method, target string, body []byte, hdr map[string]string) exRequest {
	r := exRequest{Method: method, Target: target, Headers: map[string]string{}, BodyHex: hex.EncodeToString(body)}
	for k, v := range hdr {
		r.Headers[k] = v
	}
	if len(body) > 0 && utf8Printable(body) {
		r.BodyText = string(body)
	}
	return r
}

func utf8Printable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 && c != '\n' || c == 0x7f || c >= 0x80 {
			return false
		}
	}
	return true
}

var jsonHdr = map[string]string{"Content-Type": "application/json"}

// plain sends a request with no Authorization header.
func (g *exGen) plain(name, doc, method, target string, body []byte, hdr map[string]string) exStep {
	g.e.t.Helper()
	return g.record(name, doc, "none", exRequestOf(method, target, body, hdr), nil)
}

// bearer sends a request authenticated by a bearer token.
func (g *exGen) bearer(name, doc, token, method, target string, body []byte, hdr map[string]string) exStep {
	g.e.t.Helper()
	h := map[string]string{"Authorization": "Bearer " + token}
	for k, v := range hdr {
		h[k] = v
	}
	return g.record(name, doc, "bearer", exRequestOf(method, target, body, h), nil)
}

// signed sends a request signed as `who`, with the options bending the signature.
func (g *exGen) signed(name, doc, who, method, target string, body []byte, hdr map[string]string, opts ...signOpt) exStep {
	g.e.t.Helper()
	p := signPlan{signer: who, nonce: ""}
	for _, o := range opts {
		o(&p)
	}
	h := map[string]string{}
	for k, v := range hdr {
		h[k] = v
	}
	req := exRequestOf(method, target, body, h)

	if p.replayOf != "" {
		prev := g.byName[p.replayOf]
		if prev == nil || prev.Signing == nil {
			g.e.t.Fatalf("%s: replay of unknown signed step %q", name, p.replayOf)
		}
		req.Headers["Authorization"] = prev.Request.Headers["Authorization"]
		sg := *prev.Signing
		sg.Mutation = p.mutation
		return g.record(name, doc, "signed", req, &sg)
	}

	signer := g.e.keys[p.signer]
	if signer == nil {
		g.e.t.Fatalf("%s: no key for %q", name, p.signer)
	}
	claimed := g.e.client(who).ClientID
	if p.clientID != "" {
		claimed = p.clientID
	}
	ts := g.e.clock.Load()
	if p.ts != nil {
		ts = *p.ts
	}
	nonce := p.nonce
	if nonce == "" {
		nonce = g.nonce()
	}
	sMethod, sTarget, sBody := method, target, body
	if p.asTarget != "" {
		sTarget = p.asTarget
	}
	if p.asBody != nil {
		sBody = p.asBody
	}
	tsText := fmt.Sprintf("%d", ts)
	bodyHash := BodyHashHex(sBody)
	msg := SigningString(sMethod, sTarget, tsText, nonce, bodyHash, claimed)
	sig := signRFC6979(signer, []byte(msg))
	if p.flipSig {
		sig[len(sig)-1] ^= 0x01
	}
	b64 := base64.StdEncoding.EncodeToString(sig)
	req.Headers["Authorization"] = fmt.Sprintf(`%s client="%s",ts="%s",nonce="%s",sig="%s"`, SigScheme, claimed, tsText, nonce, b64)

	valid := false
	for _, c := range g.e.clients {
		if c.ClientID == claimed {
			pub, err := clients.ParsePublicKey(c.PublicKeyHex)
			if err != nil {
				g.e.t.Fatal(err)
			}
			valid = clients.VerifyDER(pub, []byte(msg), sig)
		}
	}
	sg := &exSigning{
		Signer: p.signer, ClientID: claimed, TS: tsText, Nonce: nonce, BodySHA256: bodyHash,
		SigningString: msg, SignatureB64: b64, MatchesRequest: sMethod == method && sTarget == target && bytes.Equal(sBody, body),
		SignatureValid: valid, Mutation: p.mutation,
	}
	return g.record(name, doc, "signed", req, sg)
}

func (g *exGen) bodyOf(step exStep) map[string]any {
	g.e.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(step.Response.BodyJSON, &m); err != nil {
		g.e.t.Fatalf("%s: %v", step.Name, err)
	}
	return m
}

// opJSON builds a push body of one or more operations, with a correct content hash
// unless the caller breaks it afterwards.
func exOp(clientID, id, vehicle, kind, payload string, mods ...func(*Op)) Op {
	canon, err := Canonicalize([]byte(payload))
	if err != nil {
		panic(err)
	}
	o := Op{
		OperationID: id, ClientID: clientID, VehicleID: vehicle, Kind: kind, CreatedAt: "2026-09-21T13:33:20Z",
		PayloadVersion: 1, Payload: json.RawMessage(payload), ContentHash: ContentHash(canon),
	}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func exPushBody(ops ...Op) []byte {
	b, err := json.Marshal(map[string]any{"operations": ops})
	if err != nil {
		panic(err)
	}
	return b
}

func hexID(b [16]byte) string { return hex.EncodeToString(b[:]) }

func generateExchangeVectors(t *testing.T) *exDoc {
	t.Helper()
	e := newExchangeEnv(t)
	g := &exGen{e: e, byName: map[string]*exStep{}, tokens: map[string]string{}}

	admin, alpha, bravo, charlie := e.client("admin"), e.client("alpha"), e.client("bravo"), e.client("charlie")
	v1, v2, v3 := e.vehicle("v1"), e.vehicle("v2"), e.vehicle("v3")
	unknown := "99999999999999999999999999999999"

	enrolBody := func(who, name string) []byte {
		c := e.client(who)
		proof := signRFC6979(e.keys[who], clients.EnrollProofMessage(e.invites[who], c.PublicKeyHex))
		b, _ := json.Marshal(map[string]string{
			"code": e.invites[who], "name": name, "public_key": c.PublicKeyHex, "proof": base64.StdEncoding.EncodeToString(proof),
		})
		return b
	}

	// ── health and enrolment ────────────────────────────────────────────────
	g.at(0)
	g.plain("health", "Unauthenticated liveness. instance_id is what the app compares between its LAN and Tailnet URLs; server_time is for diagnosing clock skew.",
		"GET", "/v1/health", nil, nil)

	g.at(1)
	g.plain("enrol_admin", "A valid enrolment: 201 with the client id, role, scope and the server identity to pin.",
		"POST", "/v1/enroll/app", enrolBody("admin", "Admin iPhone"), jsonHdr)
	g.at(2)
	g.plain("enrol_alpha", "A client scoped to one vehicle (v1).", "POST", "/v1/enroll/app", enrolBody("alpha", "Alpha iPhone"), jsonHdr)

	g.at(3)
	badProof, _ := json.Marshal(map[string]string{
		"code": e.invites["bravo"], "name": "Bravo iPhone", "public_key": bravo.PublicKeyHex,
		"proof": base64.StdEncoding.EncodeToString(signRFC6979(e.keys["alpha"], clients.EnrollProofMessage(e.invites["bravo"], bravo.PublicKeyHex))),
	})
	g.plain("enrol_bad_proof", "NEGATIVE: the proof was made by a different key than the one being enrolled. 400, and the invitation is NOT consumed.",
		"POST", "/v1/enroll/app", badProof, jsonHdr)
	g.at(4)
	g.plain("enrol_bravo_after_bad_proof", "The same invitation still works after the bad proof above.", "POST", "/v1/enroll/app", enrolBody("bravo", "Bravo iPhone"), jsonHdr)
	g.at(5)
	g.plain("enrol_charlie", "A second client scoped to v1; used for the revocation steps.", "POST", "/v1/enroll/app", enrolBody("charlie", "Charlie iPhone"), jsonHdr)
	g.at(6)
	g.plain("enrol_code_already_used", "NEGATIVE: an invitation works once. 403 enrolment_refused (a used, expired or unknown code all look the same).",
		"POST", "/v1/enroll/app", enrolBody("admin", "Admin iPhone"), jsonHdr)

	// ── bearer tokens ───────────────────────────────────────────────────────
	g.at(10)
	tok := g.signed("token_mint_alpha", "Mint a 1-hour bearer token (signed, empty body). The token is opaque: its value here is whatever this server drew, a client must not parse it.",
		"alpha", "POST", "/v1/auth/token", nil, nil)
	g.tokens["alpha"], _ = g.bodyOf(tok)["token"].(string)
	tokC := g.signed("token_mint_charlie", "A token for the client that is revoked later.", "charlie", "POST", "/v1/auth/token", nil, nil)
	g.tokens["charlie"], _ = g.bodyOf(tokC)["token"].(string)
	g.at(11)
	g.bearer("token_on_signed_only_route", "NEGATIVE: a bearer token on /v1/auth/token, which accepts signatures only. 401 signature_required: the one 401 that is not the uniform `unauthenticated`, because the client knows it sent a token.",
		g.tokens["alpha"], "POST", "/v1/auth/token", nil, nil)

	// ── push ────────────────────────────────────────────────────────────────
	const (
		opA = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a01"
		opB = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a02"
		opC = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a03"
		opD = "0190a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a04"
	)
	oil := exOp(alpha.ClientID, opA, v1, "maintenance_event", `{"kind":"oil","odometer_km":45210}`)

	g.at(20)
	g.signed("push_accepted", "A signed push of one append-only operation: accepted with its server_sequence.",
		"alpha", "POST", "/v1/sync/push", exPushBody(oil), jsonHdr)
	g.at(21)
	g.signed("push_duplicate", "The same operation again (a retry, with a NEW nonce and signature): `duplicate` carrying the original server_sequence. This is success; creates nothing.",
		"alpha", "POST", "/v1/sync/push", exPushBody(oil), jsonHdr)
	g.at(22)
	g.bearer("push_with_bearer_token", "Push authenticated by the bearer token instead of a signature.",
		g.tokens["alpha"], "POST", "/v1/sync/push",
		exPushBody(exOp(alpha.ClientID, opB, v1, "observation", `{"note":"rattle at 3000 rpm"}`)), jsonHdr)
	g.at(23)
	g.signed("push_rejected_scope", "NEGATIVE, wrong scope: alpha is scoped to v1 and names v2. 200 overall, the operation is `rejected` with reason `scope`.",
		"alpha", "POST", "/v1/sync/push", exPushBody(exOp(alpha.ClientID, opC, v2, "observation", `{"note":"not mine"}`)), jsonHdr)
	g.signed("push_rejected_unknown_vehicle", "NEGATIVE, unknown vehicle: a client scoped to every vehicle names one that does not exist. `rejected`, reason `unknown_vehicle`.",
		"admin", "POST", "/v1/sync/push", exPushBody(exOp(admin.ClientID, opC, unknown, "observation", `{"note":"no such car"}`)), jsonHdr)
	g.signed("push_rejected_archived_vehicle", "NEGATIVE: the vehicle is archived. `rejected`, reason `archived_vehicle`.",
		"admin", "POST", "/v1/sync/push", exPushBody(exOp(admin.ClientID, opC, v3, "observation", `{"note":"sold car"}`)), jsonHdr)
	g.at(24)
	g.signed("push_rejected_hash_mismatch", "NEGATIVE: content_hash is not the SHA-256 of the canonical payload. `rejected`, reason `hash_mismatch`.",
		"alpha", "POST", "/v1/sync/push",
		exPushBody(exOp(alpha.ClientID, opC, v1, "observation", `{"note":"tampered"}`, func(o *Op) { o.ContentHash = strings.Repeat("0", 64) })), jsonHdr)
	g.signed("push_rejected_operation_id_conflict", "NEGATIVE: an operation_id reused with different content. `rejected`, reason `operation_id_conflict`.",
		"alpha", "POST", "/v1/sync/push", exPushBody(exOp(alpha.ClientID, opA, v1, "maintenance_event", `{"kind":"oil","odometer_km":99999}`)), jsonHdr)
	g.signed("push_rejected_client_mismatch", "NEGATIVE: the operation names a different client_id than the one authenticated. `rejected`, reason `client_mismatch`.",
		"alpha", "POST", "/v1/sync/push", exPushBody(exOp(bravo.ClientID, opC, v1, "observation", `{"note":"impersonation"}`)), jsonHdr)
	g.at(25)
	g.signed("push_mutable_accepted", "A mutable kind: per-field revisions come back (`title` is now at revision 1).",
		"alpha", "POST", "/v1/sync/push",
		exPushBody(exOp(alpha.ClientID, opC, v1, "trip_annotation", `{"target":"trip-1","fields":{"title":"Morning commute"}}`, func(o *Op) { o.BaseRevision = map[string]int64{} })), jsonHdr)
	g.signed("push_mutable_conflict", "NEGATIVE: base_revision says `title` was last seen at 0 but the server holds revision 1. `conflict` with the current value; nothing is applied.",
		"admin", "POST", "/v1/sync/push",
		exPushBody(exOp(admin.ClientID, opD, v1, "trip_annotation", `{"target":"trip-1","fields":{"title":"Evening commute"}}`, func(o *Op) { o.BaseRevision = map[string]int64{"title": 0} })), jsonHdr)
	g.at(26)
	g.signed("push_malformed_body", "NEGATIVE: not JSON. 400 bad_request.", "alpha", "POST", "/v1/sync/push", []byte(`{"operations":`), jsonHdr)
	g.signed("push_no_operations", "NEGATIVE: a push carries 1 to 200 operations. 400 bad_request.", "alpha", "POST", "/v1/sync/push", []byte(`{"operations":[]}`), jsonHdr)

	// ── pull, scoping and ack ───────────────────────────────────────────────
	g.at(30)
	p1 := g.signed("pull_first_page", "First page, no cursor, limit 3. Changes are in server_sequence order and scoped to the client's vehicle (v1 only). has_more is true.",
		"alpha", "GET", "/v1/sync/pull?limit=3", nil, nil)
	cur1, _ := g.bodyOf(p1)["cursor"].(string)
	g.at(31)
	g.signed("pull_second_page", "The page after the first cursor.", "alpha", "GET", "/v1/sync/pull?cursor="+cur1+"&limit=3", nil, nil)
	g.at(32)
	g.signed("pull_second_page_again", "A cursor is repeatable: the same request with a new nonce returns the byte-identical page.",
		"alpha", "GET", "/v1/sync/pull?cursor="+cur1+"&limit=3", nil, nil)
	g.at(33)
	pEnd := g.signed("pull_last_page", "Follow the cursor to the end with the default limit: has_more is false.",
		"alpha", "GET", "/v1/sync/pull?cursor="+cur1, nil, nil)
	curEnd, _ := g.bodyOf(pEnd)["cursor"].(string)
	g.at(34)
	g.signed("pull_scoped_to_other_vehicle", "VEHICLE SCOPING: bravo is scoped to v2 and sees only v2's records, none of alpha's operations.",
		"bravo", "GET", "/v1/sync/pull", nil, nil)
	g.signed("pull_all_vehicles", "A client scoped to every vehicle sees all of them (including the archived one, flagged `archived`).",
		"admin", "GET", "/v1/sync/pull", nil, nil)
	g.at(35)
	g.bearer("pull_with_bearer_token", "Pull authenticated by a bearer token.", g.tokens["alpha"], "GET", "/v1/sync/pull?cursor="+curEnd, nil, nil)
	g.at(36)
	g.signed("pull_bad_cursor", "NEGATIVE: a cursor the server did not issue. 400 bad_cursor.", "alpha", "GET", "/v1/sync/pull?cursor=bm90LWEtY3Vyc29y", nil, nil)
	foreign := base64.RawURLEncoding.EncodeToString([]byte("c1:" + strings.Repeat("0", 32) + ":1"))
	g.signed("pull_cursor_from_another_epoch", "NEGATIVE: a well-formed cursor from a different epoch (the server's data was reset). 410 cursor_reset: discard server-derived data and resync, do NOT treat as up to date.",
		"alpha", "GET", "/v1/sync/pull?cursor="+foreign, nil, nil)
	g.signed("pull_bad_limit", "NEGATIVE: limit must be a positive integer. 400 bad_request.", "alpha", "GET", "/v1/sync/pull?limit=0", nil, nil)

	g.at(40)
	g.signed("ack_accepted", "Acknowledge the cursor durably applied; the server reports the sequence it now holds.",
		"alpha", "POST", "/v1/sync/ack", []byte(`{"cursor":"`+curEnd+`"}`), jsonHdr)
	g.signed("ack_bad_cursor", "NEGATIVE: an ack of a cursor the server cannot place. 400 bad_cursor.", "alpha", "POST", "/v1/sync/ack", []byte(`{"cursor":"bm90LWEtY3Vyc29y"}`), jsonHdr)
	g.signed("ack_unknown_field", "NEGATIVE: unknown fields are refused. 400 bad_request.", "alpha", "POST", "/v1/sync/ack", []byte(`{"cursor":"`+curEnd+`","extra":1}`), jsonHdr)

	// ── snapshot scoping ────────────────────────────────────────────────────
	g.at(45)
	g.signed("snapshot_scoped_client_must_name_a_vehicle", "VEHICLE SCOPING: a client scoped to specific vehicles must name one. 403 vehicle_required.",
		"bravo", "GET", "/v1/snapshot", nil, nil)
	g.signed("snapshot_other_vehicle", "VEHICLE SCOPING, wrong scope: alpha asks for v2. 403 scope.",
		"alpha", "GET", "/v1/snapshot?vehicle="+v2, nil, nil)
	g.signed("snapshot_unknown_vehicle", "VEHICLE SCOPING, unknown vehicle: the same 403 scope as a real car outside the scope, so the endpoint cannot be used to probe for cars.",
		"alpha", "GET", "/v1/snapshot?vehicle="+unknown, nil, nil)
	g.signed("snapshot_malformed_vehicle", "NEGATIVE: vehicle is not 32 lowercase hex. 400 bad_request.", "alpha", "GET", "/v1/snapshot?vehicle=not-hex", nil, nil)

	// ── administration ──────────────────────────────────────────────────────
	g.at(50)
	g.signed("admin_route_as_user", "NEGATIVE: authenticated but not an admin. 403 admin_required.", "alpha", "GET", "/v1/clients", nil, nil)

	// ── bundle relay ────────────────────────────────────────────────────────
	del, ref := e.bundles["delivered"], e.bundles["refused"]
	offerHdr := func(b *testbundle.Bundle) map[string]string {
		return map[string]string{"Content-Type": "application/cbor", SignatureHeader: hex.EncodeToString(b.Signature)}
	}
	bid := func(b *testbundle.Bundle) string { return hex.EncodeToString(b.Manifest.BundleID[:]) }
	chunkURL := func(b *testbundle.Bundle, i int) string {
		return "/v1/relay/bundles/" + bid(b) + "/chunks/" + hex.EncodeToString(b.Manifest.ChunkDescriptors[i].SHA256[:])
	}
	octet := map[string]string{"Content-Type": "application/octet-stream"}

	g.at(60)
	g.signed("relay_offer_out_of_scope", "NEGATIVE, wrong scope: bravo (v2) offers a bundle whose manifest names v1. 403 scope, before any state is written.",
		"bravo", "POST", "/v1/relay/bundles/offer", ref.ManifestBytes, offerHdr(ref))
	g.signed("relay_chunk_after_refused_offer", "The refused offer left nothing behind: there is no offer to upload against. 404 unknown_bundle.",
		"alpha", "PUT", chunkURL(ref, 0), ref.Chunks[0], octet)
	g.signed("relay_offer_without_signature_header", "NEGATIVE: X-Cairn-Signature is required (128 hex). 400 bad_request.",
		"alpha", "POST", "/v1/relay/bundles/offer", del.ManifestBytes, map[string]string{"Content-Type": "application/cbor"})
	badSig := append([]byte(nil), ref.Signature...)
	badSig[0] ^= 0x01
	g.signed("relay_offer_bad_manifest_signature", "NEGATIVE: the manifest's device signature does not verify (one bit flipped). 401 bad_manifest_signature. Distinct from a bad REQUEST signature: this authenticates the data, not the caller.",
		"alpha", "POST", "/v1/relay/bundles/offer", ref.ManifestBytes,
		map[string]string{"Content-Type": "application/cbor", SignatureHeader: hex.EncodeToString(badSig)})

	g.at(61)
	g.signed("relay_offer", "OFFER: the manifest verbatim, its device signature in X-Cairn-Signature. The answer lists every missing chunk with its offset and length in the bundle byte stream and its SHA-256, so the phone needs no CBOR parser.",
		"alpha", "POST", "/v1/relay/bundles/offer", del.ManifestBytes, offerHdr(del))
	g.at(62)
	g.signed("relay_receipt_before_commit", "NEGATIVE: no receipt exists yet. 404 no_receipt.", "alpha", "GET", "/v1/relay/bundles/"+bid(del)+"/receipt", nil, nil)
	g.signed("relay_commit_with_chunks_missing", "NEGATIVE: commit before every chunk is uploaded. 409 chunks_missing.", "alpha", "POST", "/v1/relay/bundles/"+bid(del)+"/commit", nil, nil)
	g.signed("relay_chunk_wrong_bytes", "NEGATIVE: the bytes do not hash to the digest in the URL. 409 chunk_mismatch.",
		"alpha", "PUT", chunkURL(del, 0), append([]byte{0xff}, del.Chunks[0][1:]...), octet)
	g.at(63)
	for i := range del.Chunks {
		name := fmt.Sprintf("relay_chunk_%d", i)
		if i == len(del.Chunks)-1 {
			g.bearer(name+"_bearer", "CHUNK: the last chunk is uploaded with the bearer token, as a background URLSession would. 200 when the bytes hash to the URL digest and match the manifest's descriptor.",
				g.tokens["alpha"], "PUT", chunkURL(del, i), del.Chunks[i], octet)
			continue
		}
		g.signed(name, "CHUNK: PUT the exact range the offer named; 200 when the bytes hash to the URL digest and match the manifest's descriptor. Chunks are idempotent.",
			"alpha", "PUT", chunkURL(del, i), del.Chunks[i], octet)
	}
	g.at(64)
	g.signed("relay_chunk_out_of_scope", "NEGATIVE, wrong scope: bravo learned the bundle id and tries to upload to it. 403 scope: scope is checked on every step, not only the offer.",
		"bravo", "PUT", chunkURL(del, 0), del.Chunks[0], octet)
	g.signed("relay_commit_out_of_scope", "NEGATIVE, wrong scope: bravo cannot commit it either. 403 scope.", "bravo", "POST", "/v1/relay/bundles/"+bid(del)+"/commit", nil, nil)
	g.at(65)
	g.signed("relay_commit", "COMMIT (empty body): the signed receipt, CBOR, taken verbatim; its signature covers exactly those bytes. Verify with fixture.receipt_signing_public_key_ed25519_hex; it names this bundle's content root.",
		"alpha", "POST", "/v1/relay/bundles/"+bid(del)+"/commit", nil, nil)
	g.at(66)
	g.signed("relay_commit_again", "Committing again returns the same receipt bytes, flagged X-Cairn-Already-Committed.", "alpha", "POST", "/v1/relay/bundles/"+bid(del)+"/commit", nil, nil)
	g.signed("relay_receipt", "RECEIPT: fetched on its own, byte-identical to the commit's.", "alpha", "GET", "/v1/relay/bundles/"+bid(del)+"/receipt", nil, nil)
	g.signed("relay_receipt_out_of_scope", "NEGATIVE, wrong scope: bravo cannot read it. 403 scope.", "bravo", "GET", "/v1/relay/bundles/"+bid(del)+"/receipt", nil, nil)
	g.signed("relay_reoffer_after_commit", "Offering a delivered bundle again asks for nothing and says a receipt exists.",
		"alpha", "POST", "/v1/relay/bundles/offer", del.ManifestBytes, offerHdr(del))

	// ── authentication negatives ────────────────────────────────────────────
	// All against GET /v1/sync/pull?limit=1 so the only variable is the credential.
	const probe = "/v1/sync/pull?limit=1"
	g.at(100)
	g.signed("auth_baseline", "A correctly signed request. Every authentication negative below is this request with one thing wrong.", "alpha", "GET", probe, nil, nil)
	g.signed("auth_replay_same_header", "NEGATIVE, replay: the identical Authorization header again. A nonce is accepted once per client. 401 unauthenticated. Never retry with the same header.",
		"alpha", "GET", probe, nil, nil, replayOf("auth_baseline"), mutated("replay: the Authorization header of auth_baseline, byte for byte"))
	g.signed("auth_bad_signature", "NEGATIVE, bad signature: one bit of the DER signature flipped. 401 unauthenticated, the same body as every other authentication failure.",
		"alpha", "GET", probe, nil, nil, tamperedSignature(), mutated("last byte of the DER signature XOR 0x01"))
	g.signed("auth_signed_with_another_key", "NEGATIVE: signed correctly, but by bravo's key while claiming to be alpha. 401.",
		"alpha", "GET", probe, nil, nil, signedBy("bravo"), mutated("signed with bravo's key"))
	g.signed("auth_target_changed_after_signing", "NEGATIVE: the request target sent (limit=2) is not the one signed (limit=1). 401: the target is covered byte for byte.",
		"alpha", "GET", "/v1/sync/pull?limit=2", nil, nil, signedForTarget(probe), mutated("target signed as "+probe))
	g.signed("auth_body_changed_after_signing", "NEGATIVE: the body sent is not the one whose hash was signed. 401.",
		"alpha", "POST", "/v1/sync/ack", []byte(`{"cursor":"`+curEnd+`"}`), jsonHdr, signedForBody([]byte(`{"cursor":"AAAA"}`)), mutated(`body signed as {"cursor":"AAAA"}`))
	g.signed("auth_unknown_client", "NEGATIVE, unknown client: well-formed and signed, but the client id is not enrolled. 401, indistinguishable from a bad signature.",
		"alpha", "GET", probe, nil, nil, claimingClient("0190c0de0000700080000000000000ff"), mutated("client id not enrolled"))
	g.at(101)
	g.signed("auth_skew_120s_behind_is_accepted", "The window is +/-120 s: a timestamp exactly 120 s behind the server is accepted.",
		"alpha", "GET", probe, nil, nil, withTS(exOrigin+101-120))
	g.signed("auth_skew_120s_ahead_is_accepted", "A timestamp exactly 120 s ahead is accepted.", "alpha", "GET", probe, nil, nil, withTS(exOrigin+101+120))
	g.signed("auth_skew_121s_behind", "NEGATIVE, clock skew: 121 s behind. 401. (GET /v1/health returns server_time for diagnosing this.)",
		"alpha", "GET", probe, nil, nil, withTS(exOrigin+101-121), mutated("ts = server clock - 121"))
	g.signed("auth_skew_121s_ahead", "NEGATIVE, clock skew: 121 s ahead. 401.", "alpha", "GET", probe, nil, nil, withTS(exOrigin+101+121), mutated("ts = server clock + 121"))
	g.signed("auth_nonce_too_short", "NEGATIVE: nonce is 16 to 64 characters; this one has 8. 401.", "alpha", "GET", probe, nil, nil, withNonce("00112233"))
	g.plain("auth_missing_header", "NEGATIVE: no Authorization header. 401, with `WWW-Authenticate: Cairn-Sig`.", "GET", probe, nil, nil)
	g.plain("auth_unknown_scheme", "NEGATIVE: an Authorization scheme the server does not speak. 401.", "GET", probe, nil, map[string]string{"Authorization": "Basic YWxwaGE6eA=="})
	g.plain("auth_header_missing_signature", "NEGATIVE: a Cairn-Sig header with no sig parameter. 401.", "GET", probe, nil,
		map[string]string{"Authorization": fmt.Sprintf(`%s client="%s",ts="%d",nonce="%s"`, SigScheme, alpha.ClientID, exOrigin+101, g.nonce())})
	g.bearer("auth_unknown_bearer_token", "NEGATIVE: a bearer token the server never issued. 401.", "not-a-token", "GET", probe, nil, nil)

	// Revocation: effective on the target's next request, for signatures and tokens.
	g.at(110)
	g.signed("revoke_charlie_works_before", "Before revocation charlie's signed request is accepted.", "charlie", "GET", probe, nil, nil)
	g.bearer("revoke_charlie_token_works_before", "...and so is charlie's bearer token.", g.tokens["charlie"], "GET", probe, nil, nil)
	g.signed("revoke_charlie", "An admin revokes charlie; effective on charlie's next request.", "admin", "POST", "/v1/clients/"+charlie.ClientID+"/revoke", []byte(`{"reason":"lost phone"}`), jsonHdr)
	g.at(111)
	g.signed("revoked_client_signed_request", "NEGATIVE, revoked: a correctly signed request from a revoked client. 401, the same uniform body.", "charlie", "GET", probe, nil, nil)
	g.bearer("revoked_client_bearer_token", "NEGATIVE, revoked: the bearer token minted before the revocation stops working with the client (re-checked on every use). 401.",
		g.tokens["charlie"], "GET", probe, nil, nil)

	// Token expiry: the TTL is one hour from the mint (clock exOrigin+10).
	g.at(10 + 3600)
	g.bearer("token_valid_at_exactly_one_hour", "A token minted at server clock T is still accepted at T+3600 s.", g.tokens["alpha"], "GET", probe, nil, nil)
	g.at(10 + 3601)
	g.bearer("token_expired", "NEGATIVE, expired token: one second later it is not. 401. Mint a new one (signed) and retry.", g.tokens["alpha"], "GET", probe, nil, nil)
	g.signed("token_mint_after_expiry", "Minting again, signed, works: expiry costs one request, not the enrolment.", "alpha", "POST", "/v1/auth/token", nil, nil)

	doc := &exDoc{
		Version: 1,
		Spec:    "contracts/sync/v1/spec.md",
		Notes: []string{
			"STATUS: draft. sync/v1 stays draft until the iOS app has passed these vectors; the server producing and checking them is not independent validation.",
			"The steps are ONE timeline against ONE server, in order. Replay, expiry, revocation and cursors depend on what came before. Run them in order against your client's request builder and response parser; each step is self-contained (full request, full response), so a mock server can serve the recorded responses.",
			"server_clock_unix is the server's clock for that step. Build ts from the step's `signing.ts`, not from your own clock. A step whose signing.ts differs from server_clock_unix is a skew case.",
			"For a signed step, rebuild signing.signing_string from request (method, request_target, signing.ts, signing.nonce, SHA-256 of the body, signing.client_id) and require it equal. matches_request=false marks a step where the request sent differs from what was signed: your string for the request AS SENT will not equal signing_string, which is the point.",
			"signature_der_base64 is ASN.1 DER ECDSA-P256-SHA256, standard base64. These signatures are deterministic (RFC 6979) so the file is reproducible; CryptoKit's are randomised, so verify rather than compare. signature_valid says whether it verifies over signing_string under the registered key of the client the header names.",
			"The test keys are public and protect nothing. Client keys are in fixture.clients; the dongle's device key and the receipt-signing key are given as Ed25519 public keys.",
			"response.body_json is the compacted JSON the server sent; compare it as JSON, not as text. response.body_hex is used for non-JSON bodies (CBOR receipts). Opaque values (bearer token, cursor, epoch) are whatever this server drew: a client must treat them as opaque; they appear verbatim because later steps use them.",
			"Every authentication failure is 401 with error `unauthenticated` and the message `authentication failed`, whatever was wrong (the one exception is a bearer token on a signed-only route: `signature_required`). Do not branch on the cause.",
			"Not covered here: the 200 Parquet body of /v1/snapshot (it is the analytical store's output, not the sync protocol's) and the administration listings.",
		},
		Fixture: exFixture{
			InstanceID: "00112233445566778899aabbccddeeff", ClockStartUnix: exOrigin, Clients: e.clients, Vehicles: e.vehicles,
			DeviceID: hexID(e.device), DevicePublicKey: hex.EncodeToString(e.devKey), ReceiptPublicKey: hex.EncodeToString(e.receipt),
			InvitationCodes: e.invites, UnknownClientID: "0190c0de0000700080000000000000ff", UnknownVehicleID: unknown,
			ForeignCursor: foreign,
		},
		Steps: g.steps,
	}
	for _, name := range []string{"delivered", "refused"} {
		b := e.bundles[name]
		doc.Fixture.Bundles = append(doc.Fixture.Bundles, exBundle{
			Name: name, BundleID: bid(b), VehicleID: hex.EncodeToString(b.Manifest.VehicleID[:]),
			ContentRoot: hex.EncodeToString(b.Manifest.ContentRoot[:]), ManifestHex: hex.EncodeToString(b.ManifestBytes),
			SignatureHex: hex.EncodeToString(b.Signature),
		})
	}
	return doc
}

func marshalExchanges(t *testing.T, d *exDoc) []byte {
	t.Helper()
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// ─── the tests ──────────────────────────────────────────────────────────────

// Run by name, not by the broad pattern "Vectors": that also matches
// TestAppSyncVectorsAreStableAndVerify, whose -update-vectors rewrites
// vectors.json with fresh (randomised) signatures.
//
//	go test ./internal/syncapi -run SyncExchange -update-vectors
func TestSyncExchangeVectors(t *testing.T) {
	path := contracts.Path("sync", "v1", "vectors", exFile)
	if *updateVectors {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, marshalExchanges(t, generateExchangeVectors(t)), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skipf("SKIPPED, NOT CHECKED: the contracts at %s have no sync/v1 %s. The pinned release predates these vectors; "+
			"the owner must tag a contracts release that contains them and bump contracts.lock. Until then nothing "+
			"here checks the server against them (generate locally with -update-vectors against a contracts checkout).", contracts.Dir(), exFile)
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc exDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}

	t.Run("the file is internally consistent", func(t *testing.T) { checkExchangeFile(t, &doc) })
	t.Run("this server answers every recorded request as recorded", func(t *testing.T) { replayExchanges(t, &doc) })
	t.Run("regenerating reproduces the file", func(t *testing.T) {
		if got := marshalExchanges(t, generateExchangeVectors(t)); !bytes.Equal(got, raw) {
			t.Fatalf("regenerating %s gives a different file (%d bytes, file has %d). If the server's behaviour changed on purpose, "+
				"open a contracts pull request with the regenerated vectors first.", exFile, len(got), len(raw))
		}
	})
}

// checkExchangeFile verifies the vectors without the server: the claims a client
// author relies on (the signing string is derivable from the request, the signature
// does or does not verify) hold for every step.
func checkExchangeFile(t *testing.T, doc *exDoc) {
	pubs := map[string]*ecdsa.PublicKey{}
	for _, c := range doc.Fixture.Clients {
		pub, err := clients.ParsePublicKey(c.PublicKeyHex)
		if err != nil {
			t.Fatal(err)
		}
		pubs[c.ClientID] = pub
	}
	seen := map[string]bool{}
	for _, s := range doc.Steps {
		if seen[s.Name] {
			t.Errorf("duplicate step name %q", s.Name)
		}
		seen[s.Name] = true
		if s.Auth != "signed" {
			continue
		}
		sg := s.Signing
		if sg == nil {
			t.Errorf("%s: a signed step with no signing block", s.Name)
			continue
		}
		body, _ := hex.DecodeString(s.Request.BodyHex)
		str := SigningString(s.Request.Method, s.Request.Target, sg.TS, sg.Nonce, BodyHashHex(body), sg.ClientID)
		if (str == sg.SigningString) != sg.MatchesRequest {
			t.Errorf("%s: matches_request=%v but the string rebuilt from the request equal=%v", s.Name, sg.MatchesRequest, str == sg.SigningString)
		}
		sig, err := base64.StdEncoding.DecodeString(sg.SignatureB64)
		if err != nil {
			t.Errorf("%s: %v", s.Name, err)
			continue
		}
		valid := pubs[sg.ClientID] != nil && clients.VerifyDER(pubs[sg.ClientID], []byte(sg.SigningString), sig)
		if valid != sg.SignatureValid {
			t.Errorf("%s: signature_valid=%v but verification gives %v", s.Name, sg.SignatureValid, valid)
		}
		want := fmt.Sprintf(`%s client="%s",ts="%s",nonce="%s",sig="%s"`, SigScheme, sg.ClientID, sg.TS, sg.Nonce, sg.SignatureB64)
		if got := s.Request.Headers["Authorization"]; got != want {
			t.Errorf("%s: Authorization header layout drifted:\n got %s\nwant %s", s.Name, got, want)
		}
		if p := parseParams(s.Request.Headers["Authorization"][len(SigScheme)+1:]); p["client"] != sg.ClientID || p["ts"] != sg.TS || p["nonce"] != sg.Nonce {
			t.Errorf("%s: the server's header parser reads %v", s.Name, p)
		}
	}

	// The receipt in the vectors is a real signed one: a client verifies it with the
	// fixture's key and finds this bundle's content root in it.
	for _, s := range doc.Steps {
		if s.Name != "relay_commit" {
			continue
		}
		raw, _ := hex.DecodeString(s.Response.BodyHex)
		rc, err := format.ParseReceipt(raw)
		if err != nil {
			t.Fatalf("relay_commit: %v", err)
		}
		pub, _ := hex.DecodeString(doc.Fixture.ReceiptPublicKey)
		var root [32]byte
		for _, b := range doc.Fixture.Bundles {
			if b.Name == "delivered" {
				r, _ := hex.DecodeString(b.ContentRoot)
				copy(root[:], r)
			}
		}
		if err := rc.VerifyAcknowledges(ed25519.PublicKey(pub), root); err != nil {
			t.Errorf("relay_commit: the receipt does not verify as an acknowledgement of the delivered bundle: %v", err)
		}
	}
	for _, want := range []string{
		"auth_bad_signature", "auth_replay_same_header", "push_rejected_scope", "token_expired",
		"push_rejected_unknown_vehicle", "relay_offer", "relay_commit",
	} {
		if !seen[want] {
			t.Errorf("the required case %q is missing", want)
		}
	}
}

// replayExchanges is the conformance check proper: a fresh server, the recorded
// requests in order, each at its recorded clock.
func replayExchanges(t *testing.T, doc *exDoc) {
	e := newExchangeEnv(t)
	for i, s := range doc.Steps {
		e.setClock(s.Clock)
		got := e.send(s.Request)
		if got.Status != s.Response.Status || got.ErrorCode != s.Response.ErrorCode {
			t.Errorf("step %d %s: %d %q, recorded %d %q", i, s.Name, got.Status, got.ErrorCode, s.Response.Status, s.Response.ErrorCode)
			continue
		}
		for k, v := range s.Response.Headers {
			if got.Headers[k] != v {
				t.Errorf("step %d %s: header %s = %q, recorded %q", i, s.Name, k, got.Headers[k], v)
			}
		}
		var a, b bytes.Buffer
		if len(s.Response.BodyJSON) > 0 {
			_ = json.Compact(&a, s.Response.BodyJSON)
			_ = json.Compact(&b, got.BodyJSON)
			if a.String() != b.String() {
				t.Errorf("step %d %s: body\n got %s\nwant %s", i, s.Name, b.String(), a.String())
			}
		}
		if got.BodyHex != s.Response.BodyHex {
			t.Errorf("step %d %s: body bytes differ from the recorded ones", i, s.Name)
		}
	}
}
