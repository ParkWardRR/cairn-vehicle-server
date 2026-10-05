package syncapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/clients"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

// ─── harness ────────────────────────────────────────────────────────────────

type relayEnv struct {
	*env
	intake   *intake.Service
	receipts *receipts.Store
	cas      *cas.Store
	vehicle  string // the synthetic bundles' vehicle, hex
}

// newRelayEnv builds the app API with the relay enabled over a real intake
// service: real registries, a real CAS and a real receipt signer. The relay adds
// no trust decisions of its own, so a stub would prove nothing.
func newRelayEnv(t *testing.T) *relayEnv {
	t.Helper()
	root := t.TempDir()

	store, err := cas.Open(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipts.Open(receipts.Config{
		Dir: filepath.Join(root, "receipts"), KeyPath: filepath.Join(root, "keys", "receipt.seed"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := devices.Open(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	regs, err := testbundle.OpenRegistries(root)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := intake.New(intake.Config{
		CAS: store, Receipts: rec, Registry: dev, Outbox: ob, OfferDir: filepath.Join(root, "offers"),
		Vehicles: regs.Vehicles, Counters: regs.Counters, Keys: regs.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := testbundle.DeviceKey()
	if _, err := dev.Enroll(testbundle.DeviceID(), "test-recorder", pub, 0); err != nil {
		t.Fatal(err)
	}

	v := testbundle.VehicleID()
	e := newEnv(t, func(c *Config) { c.Intake = svc })
	return &relayEnv{env: e, intake: svc, receipts: rec, cas: store, vehicle: hex.EncodeToString(v[:])}
}

func (r *relayEnv) bundle(t *testing.T, counter uint64) *testbundle.Bundle {
	t.Helper()
	o := testbundle.Default()
	o.ChunkSize = 256
	o.DeviceCounter = counter
	b, err := testbundle.Build(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// do sends a request with an arbitrary header set, signed as the app.
func (a *app) doHdr(method, uri string, body []byte, hdr map[string]string) *http.Response {
	a.e.t.Helper()
	req, _ := http.NewRequest(method, a.e.ts.URL+uri, bytes.NewReader(body))
	req.Header.Set("Authorization", a.sign(method, uri, body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.e.t.Fatal(err)
	}
	return resp
}

type offerOut struct {
	BundleID         string `json:"bundle_id"`
	ReceiptAvailable bool   `json:"receipt_available"`
	TotalChunks      int    `json:"total_chunks"`
	Missing          []struct {
		Index  uint32 `json:"index"`
		Offset uint64 `json:"offset"`
		Length uint32 `json:"length"`
		SHA256 string `json:"sha256"`
	} `json:"missing_chunks"`
}

func (a *app) offer(t *testing.T, b *testbundle.Bundle) (int, offerOut, string) {
	t.Helper()
	resp := a.doHdr("POST", "/v1/relay/bundles/offer", b.ManifestBytes,
		map[string]string{SignatureHeader: hex.EncodeToString(b.Signature)})
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, offerOut{}, readBody(resp)
	}
	var out offerOut
	mustDecode(t, resp, &out)
	return http.StatusOK, out, ""
}

func (a *app) putChunk(b *testbundle.Bundle, idx int, data []byte) (int, string) {
	d := b.Manifest.ChunkDescriptors[idx]
	resp := a.do("PUT", "/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/chunks/"+hex.EncodeToString(d.SHA256[:]), data)
	return resp.StatusCode, readBody(resp)
}

func (a *app) commit(b *testbundle.Bundle) (int, []byte, http.Header) {
	resp := a.do("POST", "/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/commit", nil)
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes(), resp.Header
}

func errCode(body string) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal([]byte(body), &e)
	return e.Error
}

// ─── the happy path ─────────────────────────────────────────────────────────

func TestRelayCarriesABundleToAVerifiableReceipt(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	b := r.bundle(t, 1)

	status, out, body := phone.offer(t, b)
	if status != http.StatusOK {
		t.Fatalf("offer: %d %s", status, body)
	}
	if len(out.Missing) != len(b.Chunks) || out.ReceiptAvailable {
		t.Fatalf("a fresh bundle should miss every chunk: %+v", out)
	}

	// The offer's offsets and lengths are the whole point: the phone reads exactly
	// those ranges from the dongle and needs no CBOR parser. They must address the
	// bundle byte stream, and each range must hash to the digest the offer names.
	for _, m := range out.Missing {
		part := b.Stream[m.Offset : m.Offset+uint64(m.Length)]
		sum := sha256.Sum256(part)
		if hex.EncodeToString(sum[:]) != m.SHA256 {
			t.Fatalf("chunk %d: stream[%d:+%d] does not hash to the offered digest", m.Index, m.Offset, m.Length)
		}
		if st, body := phone.putChunk(b, int(m.Index), part); st != http.StatusOK {
			t.Fatalf("chunk %d: %d %s", m.Index, st, body)
		}
	}

	st, receiptBytes, hdr := phone.commit(b)
	if st != http.StatusOK {
		t.Fatalf("commit: %d %s", st, receiptBytes)
	}
	if hdr.Get("Content-Type") != "application/cbor" {
		t.Fatalf("receipt content type = %q", hdr.Get("Content-Type"))
	}

	// The receipt is what the dongle will verify against its pinned key, naming
	// this bundle's content root. Verify it exactly as the dongle would.
	parsed, err := format.ParseReceipt(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyAcknowledges(r.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Fatalf("the relayed receipt does not verify as an acknowledgement of this bundle: %v", err)
	}

	// Fetching it again is byte-identical: a phone that lost it before reaching
	// the dongle gets the same signed bytes, not a new receipt.
	resp := phone.do("GET", "/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/receipt", nil)
	again := readBody(resp)
	if resp.StatusCode != http.StatusOK || again != string(receiptBytes) {
		t.Fatalf("re-fetched receipt differs or failed: %d", resp.StatusCode)
	}

	// Re-offering a delivered bundle asks for nothing and says a receipt exists.
	status, out, _ = phone.offer(t, b)
	if status != http.StatusOK || len(out.Missing) != 0 || !out.ReceiptAvailable {
		t.Fatalf("re-offer after commit: %d %+v", status, out)
	}

	// The audit trail names who relayed what.
	entries, err := r.audit.Read()
	if err != nil {
		t.Fatal(err)
	}
	var sawCommit bool
	for _, e := range entries {
		if e.Route == "POST /v1/relay/bundles/{id}/commit" && e.ClientID == phone.id &&
			e.TargetID == hex.EncodeToString(b.Manifest.BundleID[:]) && e.Status == http.StatusOK {
			sawCommit = true
		}
	}
	if !sawCommit {
		t.Fatal("the audit log does not record which client relayed the commit")
	}
}

func TestRelayAcceptsABearerTokenForBackgroundUploads(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	b := r.bundle(t, 1)

	var tok struct {
		Token string `json:"token"`
	}
	mustDecode(t, phone.do("POST", "/v1/auth/token", nil), &tok)

	if st, _, body := phone.offer(t, b); st != http.StatusOK {
		t.Fatalf("offer: %d %s", st, body)
	}
	d := b.Manifest.ChunkDescriptors[0]
	req, _ := http.NewRequest("PUT", r.ts.URL+"/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/chunks/"+hex.EncodeToString(d.SHA256[:]), bytes.NewReader(b.Chunks[0]))
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a background upload with a bearer token was refused: %d %s", resp.StatusCode, readBody(resp))
	}
}

// ─── who may relay ──────────────────────────────────────────────────────────

func TestRelayRefusesAClientOutsideTheBundlesVehicleBeforeAnyStateIsWritten(t *testing.T) {
	r := newRelayEnv(t)
	other := r.enrol(clients.RoleUser, "ffffffffffffffffffffffffffffffff") // not the bundle's vehicle
	b := r.bundle(t, 1)

	st, _, body := other.offer(t, b)
	if st != http.StatusForbidden || errCode(body) != "scope" {
		t.Fatalf("offer from an out-of-scope client: %d %s", st, body)
	}

	// Nothing was recorded: there is no offer for anyone to upload chunks against.
	owner := r.enrol(clients.RoleUser, r.vehicle)
	if st, body := owner.putChunk(b, 0, b.Chunks[0]); st != http.StatusNotFound || errCode(body) != "unknown_bundle" {
		t.Fatalf("an out-of-scope offer left state behind: %d %s", st, body)
	}
}

func TestRelayScopeIsCheckedOnEveryStepNotOnlyTheOffer(t *testing.T) {
	r := newRelayEnv(t)
	owner := r.enrol(clients.RoleUser, r.vehicle)
	intruder := r.enrol(clients.RoleUser, "ffffffffffffffffffffffffffffffff")
	b := r.bundle(t, 1)

	if st, _, body := owner.offer(t, b); st != http.StatusOK {
		t.Fatalf("offer: %d %s", st, body)
	}
	for i := range b.Chunks {
		if st, body := owner.putChunk(b, i, b.Chunks[i]); st != http.StatusOK {
			t.Fatalf("chunk %d: %d %s", i, st, body)
		}
	}

	// Another client that learned the bundle id cannot finish or read it.
	if st, body := intruder.putChunk(b, 0, b.Chunks[0]); st != http.StatusForbidden || errCode(body) != "scope" {
		t.Fatalf("chunk upload by an out-of-scope client: %d %s", st, body)
	}
	if st, _, _ := intruder.commit(b); st != http.StatusForbidden {
		t.Fatalf("commit by an out-of-scope client: %d", st)
	}
	resp := intruder.do("GET", "/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/receipt", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("receipt fetch by an out-of-scope client: %d", resp.StatusCode)
	}

	// And it really was not committed on its behalf: the owner's commit is the first.
	if st, _, hdr := owner.commit(b); st != http.StatusOK || hdr.Get("X-Cairn-Already-Committed") != "" {
		t.Fatalf("the owner's commit was not the first: %d already=%q", st, hdr.Get("X-Cairn-Already-Committed"))
	}
}

func TestRelayRefusesUnauthenticatedAndRevokedCallers(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	b := r.bundle(t, 1)

	// No Authorization at all.
	req, _ := http.NewRequest("POST", r.ts.URL+"/v1/relay/bundles/offer", bytes.NewReader(b.ManifestBytes))
	req.Header.Set(SignatureHeader, hex.EncodeToString(b.Signature))
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated offer was accepted: %d", resp.StatusCode)
	}

	if err := r.clients.Revoke(phone.id, "test"); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := phone.offer(t, b); st != http.StatusUnauthorized {
		t.Fatalf("a revoked client could still relay: %d", st)
	}
}

// ─── what a hostile relay can and cannot do ─────────────────────────────────

func TestRelayCannotGetAReceiptForDataTheServerDoesNotHold(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	b := r.bundle(t, 1)
	if st, _, body := phone.offer(t, b); st != http.StatusOK {
		t.Fatalf("offer: %d %s", st, body)
	}

	// Commit with nothing uploaded.
	if st, _, _ := phone.commit(b); st != http.StatusConflict {
		t.Fatalf("commit with no chunks = %d, want 409", st)
	}

	// A flipped byte is refused and is not stored.
	bad := append([]byte(nil), b.Chunks[0]...)
	bad[3] ^= 0xff
	if st, body := phone.putChunk(b, 0, bad); st != http.StatusConflict || errCode(body) != "chunk_mismatch" {
		t.Fatalf("corrupt chunk: %d %s", st, body)
	}
	// A short chunk is refused for its length, as a client error, not a 500.
	if st, body := phone.putChunk(b, 0, b.Chunks[0][:len(b.Chunks[0])-1]); st != http.StatusConflict || errCode(body) != "chunk_mismatch" {
		t.Fatalf("short chunk: %d %s", st, body)
	}
	// A chunk body over the default app limit is judged on its merits (wrong
	// length), not rejected as an oversized request: the relay raises the limit
	// for chunks only.
	huge := bytes.Repeat([]byte{7}, 1_500_000)
	if st, body := phone.putChunk(b, 0, huge); st != http.StatusConflict || errCode(body) != "chunk_mismatch" {
		t.Fatalf("a 1.5 MB chunk body: %d %s", st, body)
	}

	// Chunk 0 never arrived intact, so there is still no receipt.
	if st, _, _ := phone.commit(b); st != http.StatusConflict {
		t.Fatalf("commit after only bad chunks = %d, want 409", st)
	}
	if _, _, err := r.receipts.Lookup(b.Manifest.ContentRoot); err == nil {
		t.Fatal("a receipt exists for a bundle whose data was never delivered")
	}

	// A chunk that is not part of this bundle at all is refused.
	stray := []byte("not part of the manifest")
	d := sha256.Sum256(stray)
	resp := phone.do("PUT", "/v1/relay/bundles/"+hex.EncodeToString(b.Manifest.BundleID[:])+"/chunks/"+hex.EncodeToString(d[:]), stray)
	if resp.StatusCode != http.StatusBadRequest || errCode(readBody(resp)) != "chunk_not_in_manifest" {
		t.Fatalf("a stray chunk was not refused: %d", resp.StatusCode)
	}
}

func TestRelayRefusesAManifestNotSignedByTheEnrolledDevice(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	b := r.bundle(t, 1)

	// The phone is authentic; the manifest is not. Flip a bit in the signature.
	forged := append([]byte(nil), b.Signature...)
	forged[0] ^= 1
	resp := phone.doHdr("POST", "/v1/relay/bundles/offer", b.ManifestBytes,
		map[string]string{SignatureHeader: hex.EncodeToString(forged)})
	if resp.StatusCode != http.StatusUnauthorized || errCode(readBody(resp)) != "bad_manifest_signature" {
		t.Fatalf("a forged manifest signature was accepted: %d", resp.StatusCode)
	}
	// And no offer exists to upload chunks against.
	if st, body := phone.putChunk(b, 0, b.Chunks[0]); st != http.StatusNotFound {
		t.Fatalf("a refused offer left an offer record: %d %s", st, body)
	}

	// Malformed headers and bodies are client errors.
	resp = phone.doHdr("POST", "/v1/relay/bundles/offer", b.ManifestBytes, map[string]string{SignatureHeader: "zz"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a malformed signature header: %d", resp.StatusCode)
	}
	resp = phone.doHdr("POST", "/v1/relay/bundles/offer", []byte("not cbor"), map[string]string{SignatureHeader: hex.EncodeToString(b.Signature)})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("a garbage manifest: %d", resp.StatusCode)
	}
}

func TestRelayAppliesTheSameBindingRulesAsTheDeviceListener(t *testing.T) {
	r := newRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	// Same counter, different content: a clone or a rolled-back device. Intake
	// quarantines it; the relay must not offer a way around that.
	first := r.bundle(t, 5)
	st, _, body := phone.offer(t, first)
	if st != http.StatusOK {
		t.Fatalf("first offer: %d %s", st, body)
	}
	for i := range first.Chunks {
		phone.putChunk(first, i, first.Chunks[i])
	}
	if st, _, _ := phone.commit(first); st != http.StatusOK {
		t.Fatalf("first commit: %d", st)
	}

	o := testbundle.Default()
	o.ChunkSize = 256
	o.DeviceCounter = 5
	o.GNSSSamples = 30 // different content, same counter
	second, err := testbundle.Build(o)
	if err != nil {
		t.Fatal(err)
	}
	st, _, body = phone.offer(t, second)
	if st != http.StatusUnprocessableEntity || errCode(body) != "quarantined" {
		t.Fatalf("a counter reused with different content: %d %s", st, body)
	}

	// An assignment the server never issued is refused (403), not quarantined.
	o = testbundle.Default()
	o.ChunkSize = 256
	o.DeviceCounter = 6
	o.AssignmentID = [16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	stranger, err := testbundle.Build(o)
	if err != nil {
		t.Fatal(err)
	}
	st, _, body = phone.offer(t, stranger)
	if st != http.StatusForbidden || errCode(body) != "assignment_refused" {
		t.Fatalf("an unissued assignment: %d %s", st, body)
	}
}

func TestRelayIsAbsentWhenTheServerHasNoIntake(t *testing.T) {
	e := newEnv(t) // no Intake configured
	phone := e.enrol(clients.RoleUser, clients.ScopeAll)
	resp := phone.do("POST", "/v1/relay/bundles/offer", []byte("x"))
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("relay routes exist without an intake service: %d", resp.StatusCode)
	}
}
