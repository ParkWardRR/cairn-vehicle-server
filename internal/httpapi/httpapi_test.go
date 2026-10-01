package httpapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

type env struct {
	ts       *httptest.Server
	receipts *receipts.Store
	registry *devices.Registry
	outbox   *outbox.Queue
	cas      *cas.Store
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()

	store, err := cas.Open(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(root, "receipts"),
		KeyPath: filepath.Join(root, "keys", "receipt.seed"),
		Now:     func() time.Time { return time.UnixMilli(1_790_000_123_456).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := devices.Open(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := intake.New(intake.Config{
		CAS: store, Receipts: rec, Registry: reg, Outbox: ob,
		OfferDir: filepath.Join(root, "offers"),
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := testbundle.DeviceKey()
	if _, err := reg.Enroll(testbundle.DeviceID(), "test-recorder", pub, 0); err != nil {
		t.Fatal(err)
	}

	api := New(Config{
		Intake: svc, Receipts: rec, Registry: reg, Outbox: ob,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// These tests run over plain HTTP; the certificate binding is
		// exercised over real TLS in identity_test.go.
		RequireClientCert: false,
	})

	ts := httptest.NewServer(api.Routes())
	t.Cleanup(ts.Close)

	return &env{ts: ts, receipts: rec, registry: reg, outbox: ob, cas: store}
}

func (e *env) offer(t *testing.T, b *testbundle.Bundle) (*http.Response, offerResponse) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/api/v2/bundles/offer",
		bytes.NewReader(b.ManifestBytes))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(SignatureHeader, hex.EncodeToString(b.Signature))
	req.Header.Set("Content-Type", ContentTypeCBOR)

	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	var decoded offerResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode offer response: %v", err)
		}
	}
	return resp, decoded
}

func (e *env) putChunk(t *testing.T, bundleID [16]byte, digest [32]byte, data []byte) (*http.Response, chunkResponse) {
	t.Helper()

	url := e.ts.URL + "/api/v2/bundles/" + hex.EncodeToString(bundleID[:]) +
		"/chunks/" + hex.EncodeToString(digest[:])

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := e.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	var decoded chunkResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			t.Fatalf("decode chunk response: %v", err)
		}
	}
	return resp, decoded
}

func (e *env) commit(t *testing.T, bundleID [16]byte) (*http.Response, []byte) {
	t.Helper()

	url := e.ts.URL + "/api/v2/bundles/" + hex.EncodeToString(bundleID[:]) + "/commit"
	resp, err := e.ts.Client().Post(url, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

// ─── end to end ─────────────────────────────────────────────────────────────

// The whole protocol over real HTTP: offer, transfer, commit, verify. This is
// the test that proves the wire shapes actually work together.
func TestFullSyncOverHTTP(t *testing.T) {
	e := newEnv(t)

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}

	resp, offer := e.offer(t, b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("offer status = %d, want 200", resp.StatusCode)
	}
	if offer.ReceiptAvailable {
		t.Error("a fresh bundle reported an available receipt")
	}
	if len(offer.MissingChunks) != len(b.Chunks) {
		t.Errorf("%d missing chunks, want %d", len(offer.MissingChunks), len(b.Chunks))
	}
	if offer.BytesExpected != int64(len(b.Stream)) {
		t.Errorf("BytesExpected = %d, want %d", offer.BytesExpected, len(b.Stream))
	}

	// Transfer every chunk the server asked for.
	for _, idx := range offer.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		resp, chunk := e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[idx])
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d status = %d, want 200", idx, resp.StatusCode)
		}
		if !chunk.Accepted {
			t.Errorf("chunk %d not accepted", idx)
		}
	}

	resp, body := e.commit(t, b.Manifest.BundleID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit status = %d, want 200: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != ContentTypeCBOR {
		t.Errorf("commit Content-Type = %q, want %q", ct, ContentTypeCBOR)
	}

	// The receipt must be verifiable from exactly the returned bytes — no
	// envelope, no re-encoding step.
	receipt, err := format.ParseReceipt(body)
	if err != nil {
		t.Fatalf("parse returned receipt: %v", err)
	}
	if err := receipt.VerifyAcknowledges(e.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Errorf("returned receipt does not acknowledge the upload: %v", err)
	}

	// Decode work must be queued, not done inline.
	pending, err := e.outbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Errorf("%d outbox entries, want 1", len(pending))
	}
}

// A device that loses Wi-Fi mid-transfer and comes back must resume, not
// restart. The missing set is derived from storage, so this works with no
// server-side progress tracking.
func TestResumeAfterInterruptedTransfer(t *testing.T) {
	e := newEnv(t)

	opts := testbundle.Default()
	opts.ChunkSize = 128
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}

	_, offer := e.offer(t, b)
	if len(b.Chunks) < 4 {
		t.Fatalf("need at least 4 chunks, got %d", len(b.Chunks))
	}

	// Send two chunks, then "lose the connection".
	for i := 0; i < 2; i++ {
		d := b.Manifest.ChunkDescriptors[i]
		if resp, _ := e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[i]); resp.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d status = %d", i, resp.StatusCode)
		}
	}

	// Re-offer on reconnect: only the outstanding chunks come back.
	_, resumed := e.offer(t, b)
	if len(resumed.MissingChunks) != len(offer.MissingChunks)-2 {
		t.Errorf("%d missing after resume, want %d",
			len(resumed.MissingChunks), len(offer.MissingChunks)-2)
	}
	if resumed.BytesOutstanding >= offer.BytesOutstanding {
		t.Error("BytesOutstanding did not shrink after partial transfer")
	}

	for _, idx := range resumed.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		if resp, _ := e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[idx]); resp.StatusCode != http.StatusOK {
			t.Fatalf("chunk %d status = %d", idx, resp.StatusCode)
		}
	}

	resp, body := e.commit(t, b.Manifest.BundleID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("commit after resume: status %d: %s", resp.StatusCode, body)
	}
}

// A device that never saw the commit response retries. It must receive the same
// receipt, not a second one.
func TestCommitRetryReturnsSameReceipt(t *testing.T) {
	e := newEnv(t)

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}

	_, offer := e.offer(t, b)
	for _, idx := range offer.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[idx])
	}

	_, first := e.commit(t, b.Manifest.BundleID)
	resp, second := e.commit(t, b.Manifest.BundleID)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retried commit status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Equal(first, second) {
		t.Error("a retried commit returned different receipt bytes")
	}
	if resp.Header.Get("X-Cairn-Already-Committed") != "1" {
		t.Error("the retry was not flagged as already committed")
	}

	count, err := e.outbox.Len()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d outbox entries after a retried commit, want 1", count)
	}
}

// ─── error mapping ──────────────────────────────────────────────────────────

// The 4xx/5xx split is what lets a device distinguish "stop retrying" from
// "try again later". Getting it wrong makes a device either give up on
// recoverable trouble or hammer the server over a permanent rejection.
func TestErrorStatusCodes(t *testing.T) {
	t.Run("unenrolled device is 403", func(t *testing.T) {
		e := newEnv(t)
		opts := testbundle.Default()
		opts.Mutate = func(m *format.Manifest) { m.DeviceID[0] ^= 0xFF }
		b, err := testbundle.Build(opts)
		if err != nil {
			t.Fatal(err)
		}

		resp, _ := e.offer(t, b)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("revoked device is 403", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}
		if err := e.registry.Revoke(testbundle.DeviceID(), "stolen"); err != nil {
			t.Fatal(err)
		}

		resp, _ := e.offer(t, b)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("bad signature is 401", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}
		b.Signature[0] ^= 0x01

		resp, _ := e.offer(t, b)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("inconsistent manifest is 422", func(t *testing.T) {
		e := newEnv(t)
		opts := testbundle.Default()
		opts.Mutate = func(m *format.Manifest) { m.ChunkDescriptors[0].ByteLength++ }
		b, err := testbundle.Build(opts)
		if err != nil {
			t.Fatal(err)
		}

		resp, _ := e.offer(t, b)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", resp.StatusCode)
		}
	})

	t.Run("committing early is 409", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}
		e.offer(t, b)

		// 409 rather than 4xx-terminal: the device has not failed, it simply
		// has more to send.
		resp, _ := e.commit(t, b.Manifest.BundleID)
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("status = %d, want 409", resp.StatusCode)
		}
	})

	t.Run("chunk for an unoffered bundle is 404", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}

		d := b.Manifest.ChunkDescriptors[0]
		resp, _ := e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[0])
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("corrupted chunk is 400", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}
		e.offer(t, b)

		corrupted := append([]byte(nil), b.Chunks[0]...)
		corrupted[5] ^= 0xFF

		d := b.Manifest.ChunkDescriptors[0]
		resp, _ := e.putChunk(t, b.Manifest.BundleID, d.SHA256, corrupted)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("missing signature header is 400", func(t *testing.T) {
		e := newEnv(t)
		b, err := testbundle.Build(testbundle.Default())
		if err != nil {
			t.Fatal(err)
		}

		resp, err := e.ts.Client().Post(e.ts.URL+"/api/v2/bundles/offer",
			ContentTypeCBOR, bytes.NewReader(b.ManifestBytes))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("malformed bundle id is 400", func(t *testing.T) {
		e := newEnv(t)
		resp, err := e.ts.Client().Post(e.ts.URL+"/api/v2/bundles/nothex/commit", "", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", resp.StatusCode)
		}
	})
}

// A 5xx must not leak server internals, while a 4xx should tell the device
// enough to act on.
func TestErrorDetailDisclosure(t *testing.T) {
	e := newEnv(t)
	opts := testbundle.Default()
	opts.Mutate = func(m *format.Manifest) { m.ChunkDescriptors[0].ByteLength++ }
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := e.offer(t, b)
	var payload errorResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error == "" {
		t.Error("no error message for a 4xx")
	}
	if payload.Detail == "" {
		t.Error("a 4xx should carry detail the device can act on")
	}
}

// ─── provisioning and health ────────────────────────────────────────────────

// A device pins this key and refuses to prune on anything it cannot verify, so
// the endpoint has to agree with what actually signs receipts.
func TestReceiptKeyEndpoint(t *testing.T) {
	e := newEnv(t)

	resp, err := e.ts.Client().Get(e.ts.URL + "/api/v2/server/receipt-key")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var payload struct {
		PublicKey string `json:"public_key"`
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.PublicKey != e.receipts.PublicKeyHex() {
		t.Error("the served key does not match the signing key")
	}
	keyID := e.receipts.KeyID()
	if payload.KeyID != hex.EncodeToString(keyID[:]) {
		t.Error("the served key ID does not match")
	}
	if payload.Algorithm != format.SignatureAlgorithmEd25519 {
		t.Errorf("algorithm = %q", payload.Algorithm)
	}
}

func TestHealthReportsBacklog(t *testing.T) {
	e := newEnv(t)

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	_, offer := e.offer(t, b)
	for _, idx := range offer.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		e.putChunk(t, b.Manifest.BundleID, d.SHA256, b.Chunks[idx])
	}
	e.commit(t, b.Manifest.BundleID)

	resp, err := e.ts.Client().Get(e.ts.URL + "/api/v2/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var payload struct {
		Status        string `json:"status"`
		DecodeBacklog int    `json:"decode_backlog"`
		FormatVersion int    `json:"format_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}

	if payload.Status != "ok" {
		t.Errorf("status = %q", payload.Status)
	}
	if payload.DecodeBacklog != 1 {
		t.Errorf("decode_backlog = %d, want 1", payload.DecodeBacklog)
	}
	if payload.FormatVersion != int(format.FormatVersion) {
		t.Errorf("format_version = %d, want %d", payload.FormatVersion, format.FormatVersion)
	}
}

// ─── rate limiting ──────────────────────────────────────────────────────────

// The limiter exists to contain a device stuck in a retry loop, which is a
// plausible firmware bug in a parked car, without shaping legitimate backlog
// syncs.
func TestLimiterAllowsBurstThenThrottles(t *testing.T) {
	l := NewLimiter(3, 0)

	for i := 0; i < 3; i++ {
		if !l.Allow("device-a") {
			t.Fatalf("request %d within the burst was denied", i)
		}
	}
	if l.Allow("device-a") {
		t.Error("the burst allowance was not enforced")
	}

	// One device's exhaustion must not affect another.
	if !l.Allow("device-b") {
		t.Error("a second device was throttled by the first device's usage")
	}
}

func TestLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(2, 1) // 1 token per second
	l.now = func() time.Time { return now }

	if !l.Allow("d") || !l.Allow("d") {
		t.Fatal("burst denied")
	}
	if l.Allow("d") {
		t.Fatal("bucket should be empty")
	}

	now = now.Add(2 * time.Second)
	if !l.Allow("d") {
		t.Error("bucket did not refill")
	}
}

func TestLimiterSweepsIdleBuckets(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(5, 1)
	l.now = func() time.Time { return now }

	l.Allow("stale")
	now = now.Add(time.Hour)
	l.Allow("fresh")

	if removed := l.Sweep(30 * time.Minute); removed != 1 {
		t.Errorf("swept %d buckets, want 1", removed)
	}
	if l.Tracked() != 1 {
		t.Errorf("%d buckets tracked after sweep, want 1", l.Tracked())
	}
}
