package intake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

// ─── harness ────────────────────────────────────────────────────────────────

type harness struct {
	svc      *Service
	cas      *cas.Store
	receipts *receipts.Store
	registry *devices.Registry
	outbox   *outbox.Queue

	root       string
	devicePriv ed25519.PrivateKey
	deviceID   [16]byte
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return newHarnessAt(t, t.TempDir())
}

// newHarnessAt builds a service over a specific root, so a test can simulate a
// restart by constructing a second harness over the same directories.
func newHarnessAt(t *testing.T, root string) *harness {
	t.Helper()

	store, err := cas.Open(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatalf("cas.Open: %v", err)
	}

	rec, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(root, "receipts"),
		KeyPath: filepath.Join(root, "keys", "receipt.seed"),
		Now:     func() time.Time { return time.UnixMilli(1_790_000_123_456).UTC() },
	})
	if err != nil {
		t.Fatalf("receipts.Open: %v", err)
	}

	reg, err := devices.Open(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatalf("devices.Open: %v", err)
	}

	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	if err != nil {
		t.Fatalf("outbox.Open: %v", err)
	}

	svc, err := New(Config{
		CAS:      store,
		Receipts: rec,
		Registry: reg,
		Outbox:   ob,
		OfferDir: filepath.Join(root, "offers"),
	})
	if err != nil {
		t.Fatalf("intake.New: %v", err)
	}

	// The shared builder's fixed key and ID, so a simulated restart keeps the
	// same device identity.
	pub, priv := testbundle.DeviceKey()
	deviceID := testbundle.DeviceID()

	if _, err := reg.Enroll(deviceID, "test-recorder", pub, 0); err != nil {
		t.Fatalf("enroll: %v", err)
	}

	return &harness{
		svc: svc, cas: store, receipts: rec, registry: reg, outbox: ob,
		root: root, devicePriv: priv, deviceID: deviceID,
	}
}

// buildBundle produces a realistic bundle through the shared builder: two
// capture segments plus a journal segment, concatenated in canonical member
// order and split into chunks.
//
// mutate runs after the manifest is built but before it is signed, which is how
// these tests produce a validly signed manifest that is nevertheless wrong.
func (h *harness) buildBundle(t *testing.T, chunkSize int, mutate func(*format.Manifest)) *testbundle.Bundle {
	t.Helper()

	opts := testbundle.Default()
	opts.ChunkSize = chunkSize
	opts.Mutate = mutate

	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatalf("build bundle: %v", err)
	}
	return b
}

// sendAll delivers every chunk and returns the final missing set.
func (h *harness) sendAll(t *testing.T, b *testbundle.Bundle) []uint32 {
	t.Helper()
	var missing []uint32
	for i, chunk := range b.Chunks {
		var err error
		missing, err = h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, chunk)
		if err != nil {
			t.Fatalf("AcceptChunk %d: %v", i, err)
		}
	}
	return missing
}

// ─── happy path ─────────────────────────────────────────────────────────────

func TestOfferTransferCommit(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	offer, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("Offer: %v", err)
	}
	if offer.ExistingReceipt != nil {
		t.Fatal("a fresh bundle reported an existing receipt")
	}
	if len(offer.MissingChunks) != len(b.Chunks) {
		t.Errorf("missing %d chunks, want all %d", len(offer.MissingChunks), len(b.Chunks))
	}
	if offer.BytesExpected != int64(len(b.Stream)) {
		t.Errorf("BytesExpected = %d, want %d", offer.BytesExpected, len(b.Stream))
	}

	if missing := h.sendAll(t, b); len(missing) != 0 {
		t.Errorf("%d chunks still missing after sending all", len(missing))
	}

	result, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// The receipt must verify and must acknowledge precisely what we uploaded.
	if err := result.Receipt.VerifyAcknowledges(h.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Errorf("receipt does not acknowledge the upload: %v", err)
	}
	if result.BytesStored != int64(len(b.Stream)) {
		t.Errorf("BytesStored = %d, want %d", result.BytesStored, len(b.Stream))
	}
	if len(result.MemberDigests) != len(b.Manifest.Members) {
		t.Errorf("stored %d members, want %d", len(result.MemberDigests), len(b.Manifest.Members))
	}

	// Every member must be retrievable from raw storage, byte-exact. Raw data
	// stays authoritative, so this is the property that lets a decoder bug be
	// fixed without re-uploading.
	for _, m := range b.Manifest.Members {
		got, err := h.cas.GetVerified(m.SHA256)
		if err != nil {
			t.Errorf("member %q not in raw storage: %v", m.Name, err)
			continue
		}
		if uint64(len(got)) != m.Length {
			t.Errorf("member %q is %d bytes in storage, manifest says %d", m.Name, len(got), m.Length)
		}
	}

	// Decode work must be queued.
	pending, err := h.outbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d outbox entries, want 1", len(pending))
	}
	if pending[0].BytesStored != result.BytesStored {
		t.Error("outbox entry does not record the stored byte count")
	}
}

// The reassembled members must be the real segments, parseable by the format
// scanner. This is the end-to-end check that chunking and member splitting
// agree with each other: if either is off by a byte, the CRCs will not verify.
//
// Note the two independent chains (spec §3.2.1). Capture segments continue one
// chain across a rotation, so segment 1 must be scanned with segment 0's
// resulting state. The journal is its own chain and is scanned from zero,
// because it records transitions that happen when no capture segment is open.
func TestCommittedMembersAreValidSegments(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 100, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatal(err)
	}

	member := func(name string) []byte {
		t.Helper()
		for _, m := range b.Manifest.Members {
			if m.Name == name {
				data, err := h.cas.GetVerified(m.SHA256)
				if err != nil {
					t.Fatalf("member %q: %v", name, err)
				}
				return data
			}
		}
		t.Fatalf("member %q not in manifest", name)
		return nil
	}

	// The capture chain, scanned with continuity across the rotation.
	captureResults, err := format.ScanBundle([][]byte{
		member("seg-00000000.seg"),
		member("seg-00000001.seg"),
	})
	if err != nil {
		t.Fatalf("scan capture chain: %v", err)
	}
	if len(captureResults) != 2 {
		t.Fatalf("scanned %d capture segments, want 2", len(captureResults))
	}
	total := 0
	for i, res := range captureResults {
		if res.Stop != format.StopEOF {
			t.Errorf("capture segment %d scanned to %v (%s), want EOF", i, res.Stop, res.StopDetail)
		}
		total += len(res.Frames)
	}
	if total != 19 {
		t.Errorf("recovered %d capture frames, want 19", total)
	}

	// The journal chain, independent and scanned from zero.
	journal, err := format.ScanSegment(member("journal.seg"), format.ScanState{})
	if err != nil {
		t.Fatalf("scan journal: %v", err)
	}
	if journal.Stop != format.StopEOF {
		t.Errorf("journal scanned to %v (%s), want EOF", journal.Stop, journal.StopDetail)
	}
	if len(journal.Frames) != 4 {
		t.Errorf("recovered %d journal frames, want 4", len(journal.Frames))
	}
}

// ─── enrolment and authenticity ─────────────────────────────────────────────

func TestOfferRejectsUnenrolledDevice(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.DeviceID[0] ^= 0xFF // a device that was never enrolled
	})

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, devices.ErrUnknown) {
		t.Fatalf("error = %v, want devices.ErrUnknown", err)
	}
}

// Revocation is the control that actually stops a lost or stolen device, since
// its certificate and signing key both remain cryptographically valid.
func TestOfferRejectsRevokedDevice(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	if err := h.registry.Revoke(h.deviceID, "unit reported stolen"); err != nil {
		t.Fatal(err)
	}

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, devices.ErrRevoked) {
		t.Fatalf("error = %v, want devices.ErrRevoked", err)
	}
}

// A manifest may not assert a signing key other than the enrolled one, so key
// rotation stays an administrative act rather than something a device claims.
func TestOfferRejectsKeyIDMismatch(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.DeviceKeyID[0] ^= 0xFF
	})

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, devices.ErrKeyIDMismatch) {
		t.Fatalf("error = %v, want devices.ErrKeyIDMismatch", err)
	}
}

func TestOfferRejectsBadSignature(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	bad := append([]byte(nil), b.Signature...)
	bad[0] ^= 0x01

	if _, err := h.svc.Offer(b.ManifestBytes, bad); err == nil {
		t.Fatal("a tampered signature was accepted")
	}
}

func TestOfferRejectsSignatureFromAnotherKey(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	other := ed25519.NewKeyFromSeed([]byte("a completely different device ke"))
	_, foreignSig, err := b.Manifest.Sign(other)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.svc.Offer(b.ManifestBytes, foreignSig); err == nil {
		t.Fatal("a manifest signed by an unenrolled key was accepted")
	}
}

// ─── manifest coherence ─────────────────────────────────────────────────────

// A signature attests to authorship, not to coherence. A validly signed
// manifest whose chunk and member totals disagree cannot describe a real
// bundle, so it must be rejected on its contents.
func TestOfferRejectsChunkMemberByteMismatch(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.ChunkDescriptors[0].ByteLength += 1
	})

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

// A content root that does not match the manifest's own member list is
// self-contradictory, even when correctly signed.
func TestOfferRejectsContentRootNotMatchingMembers(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.ContentRoot[0] ^= 0xFF
	})

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

func TestOfferRejectsReversedSequenceRange(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.FirstSeq, m.LastSeq = 100, 5
	})

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

func TestOfferRejectsCaptureEndingBeforeStart(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.CaptureStartedMonotonicUS = 9_000_000
		m.CaptureEndedMonotonicUS = 1_000_000
	})

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

// The decisive check: a manifest can declare whatever member digests it likes
// and sign them consistently, but the bytes that actually arrive must hash to
// those digests. Otherwise a device could have its manifest describe one bundle
// while uploading another.
func TestCommitRejectsMemberDigestMismatch(t *testing.T) {
	h := newHarness(t)

	// Declare a wrong digest for one member and recompute the content root
	// around it, so the manifest is internally consistent and validly signed.
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.Members[1].SHA256 = sha256.Sum256([]byte("not what will actually arrive"))
		root, err := format.ContentRoot(m.Members)
		if err != nil {
			t.Fatal(err)
		}
		m.ContentRoot = root
	})

	// The offer passes: nothing about it is self-contradictory.
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatalf("Offer should succeed on a coherent manifest: %v", err)
	}
	h.sendAll(t, b)

	_, err := h.svc.Commit(b.Manifest.BundleID)
	if !errors.Is(err, ErrMemberDigestMismatch) {
		t.Fatalf("error = %v, want ErrMemberDigestMismatch", err)
	}

	// Nothing may be receipted when verification fails.
	if _, _, err := h.receipts.Lookup(b.Manifest.ContentRoot); !errors.Is(err, receipts.ErrNotFound) {
		t.Error("a receipt was issued for a bundle that failed verification")
	}
}

// ─── chunk handling ─────────────────────────────────────────────────────────

func TestAcceptChunkRejectsUnknownBundle(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	// No offer made.
	_, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[0].SHA256, b.Chunks[0])
	if !errors.Is(err, ErrUnknownBundle) {
		t.Fatalf("error = %v, want ErrUnknownBundle", err)
	}
}

// A device must not be able to deposit arbitrary objects in the raw store by
// uploading chunks the manifest never declared.
func TestAcceptChunkRejectsChunkNotInManifest(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	rogue := []byte("an object the manifest never mentioned")
	_, err := h.svc.AcceptChunk(b.Manifest.BundleID, sha256.Sum256(rogue), rogue)
	if !errors.Is(err, ErrChunkNotInManifest) {
		t.Fatalf("error = %v, want ErrChunkNotInManifest", err)
	}
}

func TestAcceptChunkRejectsCorruptedData(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	corrupted := append([]byte(nil), b.Chunks[0]...)
	corrupted[10] ^= 0xFF

	// The digest still matches a declared chunk, but the bytes do not hash to
	// it — so this is caught at acceptance rather than discovered at commit.
	_, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[0].SHA256, corrupted)
	if !errors.Is(err, cas.ErrDigestMismatch) {
		t.Fatalf("error = %v, want cas.ErrDigestMismatch", err)
	}
}

func TestAcceptChunkRejectsWrongLength(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	short := b.Chunks[0][:len(b.Chunks[0])-1]
	if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[0].SHA256, short); err == nil {
		t.Fatal("a chunk of the wrong length was accepted")
	}
}

// Duplicate delivery must be a no-op. A device retrying after a timeout it
// never saw answered is the common case, not an error.
func TestDuplicateChunkDeliveryIsHarmless(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	d := b.Manifest.ChunkDescriptors[0]
	for i := 0; i < 3; i++ {
		if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, d.SHA256, b.Chunks[0]); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}

	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatalf("Commit after duplicate deliveries: %v", err)
	}
}

// Progress is derived from the raw store rather than tracked, so a re-offer
// mid-transfer reports exactly what is still outstanding with no bookkeeping to
// go stale.
func TestReOfferReportsOnlyOutstandingChunks(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 128, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	if len(b.Chunks) < 4 {
		t.Fatalf("need at least 4 chunks for this test, got %d", len(b.Chunks))
	}

	// Deliver the first two.
	for i := 0; i < 2; i++ {
		if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, b.Chunks[i]); err != nil {
			t.Fatal(err)
		}
	}

	again, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.MissingChunks) != len(b.Chunks)-2 {
		t.Errorf("missing %d chunks, want %d", len(again.MissingChunks), len(b.Chunks)-2)
	}
	for _, idx := range again.MissingChunks {
		if idx < 2 {
			t.Errorf("chunk %d reported missing after delivery", idx)
		}
	}
}

func TestCommitRejectsIncompleteTransfer(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 128, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	// Deliver all but the last chunk.
	for i := 0; i < len(b.Chunks)-1; i++ {
		if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, b.Chunks[i]); err != nil {
			t.Fatal(err)
		}
	}

	_, err := h.svc.Commit(b.Manifest.BundleID)
	if !errors.Is(err, ErrChunksMissing) {
		t.Fatalf("error = %v, want ErrChunksMissing", err)
	}
	if _, _, err := h.receipts.Lookup(b.Manifest.ContentRoot); !errors.Is(err, receipts.ErrNotFound) {
		t.Error("an incomplete bundle was receipted")
	}
}

// Chunks are content-addressed, so two bundles that happen to share bytes
// share storage, and the second device never re-sends what the first already
// delivered.
func TestChunksDeduplicateAcrossBundles(t *testing.T) {
	h := newHarness(t)

	first := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(first.ManifestBytes, first.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, first)
	if _, err := h.svc.Commit(first.Manifest.BundleID); err != nil {
		t.Fatal(err)
	}

	// A second bundle with identical content but a different bundle ID.
	second := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.BundleID[0] ^= 0xFF
	})

	offer, err := h.svc.Offer(second.ManifestBytes, second.Signature)
	if err != nil {
		t.Fatal(err)
	}

	// Identical content means the same content root, so idempotency returns the
	// original receipt rather than asking for a single byte.
	if offer.ExistingReceipt == nil {
		t.Fatal("identical content did not return the existing receipt")
	}
	if len(offer.MissingChunks) != 0 {
		t.Errorf("%d chunks requested for content already committed", len(offer.MissingChunks))
	}
}

// ─── idempotency ────────────────────────────────────────────────────────────

func TestCommitIsIdempotent(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)

	first, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatal(err)
	}

	// A device that never saw the first response retries. It must get the same
	// receipt: a second, different receipt would mean the proof it eventually
	// holds might not match the server's record.
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	second, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}

	if second.Receipt.ReceiptID != first.Receipt.ReceiptID {
		t.Error("a retried commit minted a second receipt")
	}
	if !bytes.Equal(second.ReceiptBytes, first.ReceiptBytes) {
		t.Error("retried receipt bytes differ")
	}
	if !second.AlreadyCommitted {
		t.Error("AlreadyCommitted was not reported on the retry")
	}

	// And exactly one decode job, not two.
	pending, err := h.outbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Errorf("%d outbox entries after a retried commit, want 1", len(pending))
	}
}

func TestOfferAfterCommitReturnsReceiptWithoutRequestingChunks(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	committed, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatal(err)
	}

	offer, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if offer.ExistingReceipt == nil {
		t.Fatal("no existing receipt reported for committed content")
	}
	if offer.ExistingReceipt.ReceiptID != committed.Receipt.ReceiptID {
		t.Error("a different receipt came back")
	}
	if len(offer.MissingChunks) != 0 {
		t.Error("chunks requested for already-committed content")
	}
}

// ─── restart durability ─────────────────────────────────────────────────────

// An offer must survive a restart mid-transfer, or a device that reboots during
// a sync would have to start over.
func TestOfferSurvivesRestartMidTransfer(t *testing.T) {
	root := t.TempDir()
	h := newHarnessAt(t, root)
	b := h.buildBundle(t, 128, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	// Deliver half.
	half := len(b.Chunks) / 2
	for i := 0; i < half; i++ {
		if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, b.Chunks[i]); err != nil {
			t.Fatal(err)
		}
	}

	// Restart: a brand-new service over the same directories.
	restarted := newHarnessAt(t, root)

	// The remaining chunks can be delivered without re-offering.
	for i := half; i < len(b.Chunks); i++ {
		if _, err := restarted.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, b.Chunks[i]); err != nil {
			t.Fatalf("AcceptChunk %d after restart: %v", i, err)
		}
	}

	result, err := restarted.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("Commit after restart: %v", err)
	}
	if err := result.Receipt.VerifyAcknowledges(restarted.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Errorf("receipt from a restarted server does not verify: %v", err)
	}
}

// A receipt issued before a restart must still be found and still verify,
// because a device holding it has already earned the right to prune.
func TestReceiptSurvivesRestart(t *testing.T) {
	root := t.TempDir()
	h := newHarnessAt(t, root)
	b := h.buildBundle(t, 256, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	original, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatal(err)
	}

	restarted := newHarnessAt(t, root)
	offer, err := restarted.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if offer.ExistingReceipt == nil {
		t.Fatal("receipt lost across restart")
	}
	if offer.ExistingReceipt.ReceiptID != original.Receipt.ReceiptID {
		t.Error("a different receipt came back after restart")
	}
	if err := offer.ExistingReceipt.Verify(restarted.receipts.PublicKey()); err != nil {
		t.Errorf("receipt no longer verifies after restart: %v", err)
	}
}

// ─── size limits ────────────────────────────────────────────────────────────

func TestOfferRejectsOversizedManifest(t *testing.T) {
	h := newHarness(t)
	huge := make([]byte, MaxManifestSize+1)

	if _, err := h.svc.Offer(huge, make([]byte, 64)); err == nil {
		t.Fatal("an oversized manifest was accepted")
	}
}

func TestOfferRejectsOversizedChunkDescriptor(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.ChunkDescriptors[0].ByteLength = MaxChunkSize + 1
	})

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

func TestOfferRejectsZeroLengthChunk(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, func(m *format.Manifest) {
		m.ChunkDescriptors = append(m.ChunkDescriptors, format.ChunkDescriptor{
			Index:      uint32(len(m.ChunkDescriptors)),
			ByteLength: 0,
			SHA256:     sha256.Sum256(nil),
		})
	})

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); !errors.Is(err, ErrManifestInconsistent) {
		t.Fatalf("error = %v, want ErrManifestInconsistent", err)
	}
}

// A single chunk covering the whole stream must work: chunk and member
// boundaries are deliberately independent.
func TestSingleChunkBundle(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 1<<20, nil)

	if len(b.Chunks) != 1 {
		t.Fatalf("expected a single chunk, got %d", len(b.Chunks))
	}

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

// Chunks far smaller than a member exercise the member-splitting arithmetic at
// boundaries that do not align with chunk edges.
func TestTinyChunksCrossMemberBoundaries(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 7, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	result, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if result.BytesStored != int64(len(b.Stream)) {
		t.Errorf("BytesStored = %d, want %d", result.BytesStored, len(b.Stream))
	}
}

// Chunks may arrive in any order: they are addressed by hash, not by position.
func TestChunksMayArriveOutOfOrder(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 128, nil)
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}

	for i := len(b.Chunks) - 1; i >= 0; i-- {
		if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[i].SHA256, b.Chunks[i]); err != nil {
			t.Fatalf("AcceptChunk %d: %v", i, err)
		}
	}

	result, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("Commit after reverse-order delivery: %v", err)
	}
	if err := result.Receipt.VerifyAcknowledges(h.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Errorf("receipt does not acknowledge the upload: %v", err)
	}
}

// ─── offer housekeeping ─────────────────────────────────────────────────────

// Sweeping reclaims offer records for bundles that are provably safe to forget:
// their content root is already receipted, so a device re-offering will get the
// receipt back from the idempotency path without needing the record.
func TestSweepOffersReclaimsCommittedRecords(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatal(err)
	}

	// Nothing is swept while the record is younger than the minimum age.
	swept, err := h.svc.SweepOffers(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if swept != 0 {
		t.Errorf("swept %d records despite the age floor", swept)
	}

	swept, err = h.svc.SweepOffers(0)
	if err != nil {
		t.Fatal(err)
	}
	if swept != 1 {
		t.Errorf("swept %d records, want 1", swept)
	}

	// The receipt is still returned after the record is gone, because
	// idempotency is keyed on content root rather than on the offer record.
	offer, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("Offer after sweep: %v", err)
	}
	if offer.ExistingReceipt == nil {
		t.Error("sweeping an offer record lost the receipt")
	}
}

// An in-flight transfer must never be swept, however old. Discarding it would
// force the device to start over, throwing away chunks it already delivered.
func TestSweepOffersPreservesUncommittedTransfers(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 128, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	// Deliver one chunk, then stop — as a device losing Wi-Fi would.
	if _, err := h.svc.AcceptChunk(b.Manifest.BundleID, b.Manifest.ChunkDescriptors[0].SHA256, b.Chunks[0]); err != nil {
		t.Fatal(err)
	}

	swept, err := h.svc.SweepOffers(0)
	if err != nil {
		t.Fatal(err)
	}
	if swept != 0 {
		t.Fatalf("swept %d in-flight transfers, want 0", swept)
	}

	// The transfer can still be resumed and committed.
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatalf("resumed commit after sweep: %v", err)
	}
}

// A device written to always call Commit, even after an offer told it the
// bundle was already receipted, must get the receipt rather than an error.
// Not seeing a response is the most ordinary failure there is.
func TestCommitAfterReceiptedOfferReturnsReceipt(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	h.sendAll(t, b)
	original, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatal(err)
	}

	// Re-offer, which short-circuits on the existing receipt, then Commit again.
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	again, err := h.svc.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("Commit after a receipted offer: %v", err)
	}
	if again.Receipt.ReceiptID != original.Receipt.ReceiptID {
		t.Error("a different receipt came back")
	}
	if !again.AlreadyCommitted {
		t.Error("AlreadyCommitted was not reported")
	}
}

// ─── quotas ─────────────────────────────────────────────────────────────────

// The quota is enforced at offer time rather than at commit, so a device over
// its allowance learns before transferring a whole bundle — and keeps its local
// copy rather than being told the upload succeeded.
func TestOfferRejectsOverQuota(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	// A quota smaller than this bundle.
	pub, _ := testbundle.DeviceKey()
	if _, err := h.registry.Enroll(h.deviceID, "tiny-quota", pub, 100); err != nil {
		t.Fatal(err)
	}

	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, devices.ErrQuotaExceeded) {
		t.Fatalf("error = %v, want devices.ErrQuotaExceeded", err)
	}

	// Nothing may be receipted when the offer is refused.
	if _, _, err := h.receipts.Lookup(b.Manifest.ContentRoot); !errors.Is(err, receipts.ErrNotFound) {
		t.Error("a refused offer produced a receipt")
	}
}

// Usage accumulates across bundles, so a device that fits one bundle but not
// two is stopped on the second.
func TestQuotaAccumulatesAcrossBundles(t *testing.T) {
	h := newHarness(t)

	first := h.buildBundle(t, 256, nil)

	// Room for this bundle but not a second one.
	pub, _ := testbundle.DeviceKey()
	quota := int64(len(first.Stream)) + 100
	if _, err := h.registry.Enroll(h.deviceID, "one-bundle", pub, quota); err != nil {
		t.Fatal(err)
	}

	if _, err := h.svc.Offer(first.ManifestBytes, first.Signature); err != nil {
		t.Fatalf("the first bundle should fit: %v", err)
	}
	h.sendAll(t, first)
	if _, err := h.svc.Commit(first.Manifest.BundleID); err != nil {
		t.Fatal(err)
	}

	// A second bundle with genuinely different content must now be refused.
	//
	// The content has to differ in the segment bytes, not merely in the
	// manifest: identical content yields the same content root, and the
	// idempotency path would then return the existing receipt without consuming
	// any new space — correctly, since nothing new would be stored.
	opts := testbundle.Default()
	opts.ChunkSize = 256
	opts.GNSSSamples = 20 // more samples, so different segments and a new root
	second, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Manifest.ContentRoot == first.Manifest.ContentRoot {
		t.Fatal("the second bundle must have different content for this test to mean anything")
	}

	_, err = h.svc.Offer(second.ManifestBytes, second.Signature)
	if !errors.Is(err, devices.ErrQuotaExceeded) {
		t.Fatalf("error = %v, want devices.ErrQuotaExceeded", err)
	}
}

// Re-offering content that is already stored must not be charged against the
// quota a second time: nothing new would be written.
func TestReOfferOfStoredContentIsNotChargedAgain(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	pub, _ := testbundle.DeviceKey()
	// Room for exactly one copy of this bundle.
	if _, err := h.registry.Enroll(h.deviceID, "exact-fit", pub, int64(len(b.Stream))); err != nil {
		t.Fatal(err)
	}

	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatalf("the first offer should fit exactly: %v", err)
	}
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatal(err)
	}

	// The device did not see the response and retries. It must not be refused
	// for exceeding a quota it has not actually exceeded.
	offer, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("a retry of already-stored content was refused: %v", err)
	}
	if offer.ExistingReceipt == nil {
		t.Error("the retry did not return the existing receipt")
	}
}

// A device with no configured quota is unlimited, which is the common
// single-vehicle case and must skip the usage scan entirely.
func TestZeroQuotaImposesNoLimit(t *testing.T) {
	h := newHarness(t)
	b := h.buildBundle(t, 256, nil)

	// The harness enrols with quota 0 already; confirm a large bundle passes.
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatalf("an unlimited device was refused: %v", err)
	}
}
