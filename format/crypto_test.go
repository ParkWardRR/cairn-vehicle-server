package format

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
)

// ─── vector: merkle-empty ───────────────────────────────────────────────────

func TestMerkleEmpty(t *testing.T) {
	want := sha256.Sum256([]byte{domainEmpty})
	if got := MerkleRoot(nil); got != want {
		t.Errorf("empty root = %x, want %x", got, want)
	}

	// The empty root must not collide with the root of a single empty leaf.
	single := MerkleRoot([][32]byte{LeafHash(nil)})
	if single == want {
		t.Error("empty tree and single-empty-leaf tree share a root; domain separation failed")
	}
}

// ─── vector: merkle-odd-leaves ──────────────────────────────────────────────

// An odd final node is promoted unchanged, not duplicated. Duplicating admits
// two distinct leaf lists with the same root, which would let a bundle's member
// list be altered without changing its content root.
func TestMerkleOddLeavesPromoteNotDuplicate(t *testing.T) {
	a := LeafHash([]byte("a"))
	b := LeafHash([]byte("b"))
	c := LeafHash([]byte("c"))

	got := MerkleRoot([][32]byte{a, b, c})
	wantPromoted := internalHash(internalHash(a, b), c)
	if got != wantPromoted {
		t.Errorf("root = %x, want %x (promotion)", got, wantPromoted)
	}

	wantDuplicated := internalHash(internalHash(a, b), internalHash(c, c))
	if got == wantDuplicated {
		t.Error("root matches the duplicating construction; promotion was not applied")
	}

	// The second-preimage consequence: [a,b,c] and [a,b,c,c] must differ.
	// Under duplication they would be identical.
	three := MerkleRoot([][32]byte{a, b, c})
	four := MerkleRoot([][32]byte{a, b, c, c})
	if three == four {
		t.Error("leaf lists [a,b,c] and [a,b,c,c] share a root; the tree is second-preimage weak")
	}
}

// A leaf must never be reinterpretable as an internal node.
func TestMerkleDomainSeparation(t *testing.T) {
	l := LeafHash([]byte("x"))
	r := LeafHash([]byte("y"))

	node := internalHash(l, r)
	leafOverSameBytes := LeafHash(append(append([]byte{}, l[:]...), r[:]...))

	if node == leafOverSameBytes {
		t.Error("internal node collides with a leaf over the same bytes; domain tags are not applied")
	}
}

// ─── vector: content-root-member-order ──────────────────────────────────────

// Member ordering is canonical, by raw name bytes, so a permuted input yields
// the same identity. Identity must depend on content, not on the order a
// directory happened to be walked in.
func TestContentRootIsOrderIndependent(t *testing.T) {
	mk := func(name string, n byte) Member {
		var h [32]byte
		for i := range h {
			h[i] = n
		}
		return Member{Name: name, Length: uint64(n) * 100, SHA256: h}
	}

	ordered := []Member{
		mk("journal.seg", 1),
		mk("seg-00000000.seg", 2),
		mk("seg-00000001.seg", 3),
	}
	permuted := []Member{ordered[2], ordered[0], ordered[1]}

	rootA, err := ContentRoot(ordered)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := ContentRoot(permuted)
	if err != nil {
		t.Fatal(err)
	}

	if rootA != rootB {
		t.Errorf("permuted members produced a different root:\n  %x\n  %x", rootA, rootB)
	}

	// ContentRoot must not mutate its input.
	if permuted[0].Name != "seg-00000001.seg" {
		t.Error("ContentRoot reordered the caller's slice")
	}

	// A changed member digest must change the root.
	altered := append([]Member(nil), ordered...)
	altered[1].SHA256[0] ^= 0xFF
	rootC, err := ContentRoot(altered)
	if err != nil {
		t.Fatal(err)
	}
	if rootC == rootA {
		t.Error("altering a member digest did not change the content root")
	}

	// A renamed member must change the root: the name is part of the leaf.
	renamed := append([]Member(nil), ordered...)
	renamed[0].Name = "journal2.seg"
	rootD, err := ContentRoot(renamed)
	if err != nil {
		t.Fatal(err)
	}
	if rootD == rootA {
		t.Error("renaming a member did not change the content root")
	}
}

func TestContentRootRejectsDuplicateNames(t *testing.T) {
	var h [32]byte
	members := []Member{
		{Name: "seg-00000000.seg", Length: 10, SHA256: h},
		{Name: "seg-00000000.seg", Length: 20, SHA256: h},
	}
	if _, err := ContentRoot(members); err == nil {
		t.Error("duplicate member names accepted, want rejection")
	}
}

// ─── manifest fixtures ──────────────────────────────────────────────────────

func testManifest(t *testing.T) *Manifest {
	t.Helper()

	members := []Member{
		{Name: "seg-00000000.seg", Length: 4096, SHA256: sha256.Sum256([]byte("seg0"))},
		{Name: "seg-00000001.seg", Length: 2048, SHA256: sha256.Sum256([]byte("seg1"))},
		{Name: "journal.seg", Length: 512, SHA256: sha256.Sum256([]byte("journal"))},
	}
	root, err := ContentRoot(members)
	if err != nil {
		t.Fatal(err)
	}

	var bundleID, deviceID, bootID [16]byte
	for i := range bundleID {
		bundleID[i] = byte(i)
		deviceID[i] = byte(0x10 + i)
		bootID[i] = byte(0xA0 + i)
	}

	prev := sha256.Sum256([]byte("previous bundle"))

	return &Manifest{
		ManifestVersion:           ManifestVersion,
		BundleID:                  bundleID,
		DeviceID:                  deviceID,
		DeviceKeyID:               [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		BootID:                    bootID,
		FirmwareVersion:           "cairn-v3.0.0",
		SchemaVersion:             1,
		CaptureStartedMonotonicUS: 1_000_000,
		CaptureEndedMonotonicUS:   1_800_000_000,
		UTCBasisMS:                1_790_000_000_000,
		UTCBasisAccMS:             250,
		FirstSeq:                  0,
		LastSeq:                   1799,
		RecordCounts: map[RecordType]uint32{
			RecordGNSSSample:      1500,
			RecordIMUSummary:      280,
			RecordOBDSnapshot:     15,
			RecordStateTransition: 4,
		},
		Members: members,
		ChunkDescriptors: []ChunkDescriptor{
			{Index: 0, ByteLength: 4096, SHA256: sha256.Sum256([]byte("chunk0"))},
			{Index: 1, ByteLength: 2560, SHA256: sha256.Sum256([]byte("chunk1"))},
		},
		ContentRoot:        root,
		PreviousBundleRoot: &prev,
		PolicyVersion:      3,
		RecoveryState:      RecoveryRecoveredTail,
		DiscardedTailBytes: 42,
		SignatureAlgorithm: SignatureAlgorithmEd25519,

		VehicleID:         testHeader(0).VehicleID,
		AssignmentID:      testHeader(0).AssignmentID,
		DeviceCounter:     7,
		StorageKeyVersion: 1,
		EncryptionSuite:   EncryptionSuiteV1,
	}
}

// ─── vector: manifest-determinism ────────────────────────────────────────────

// The encoding must be byte-identical across repeated encodes. The record
// counts and members are held in a Go map and slice, whose iteration and input
// order must not leak into the signed bytes.
func TestManifestEncodingIsDeterministic(t *testing.T) {
	m := testManifest(t)

	first, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 200; i++ {
		again, err := m.MarshalCBOR()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("encoding differed on attempt %d; map iteration order leaked into the signed bytes", i)
		}
	}

	// A manifest whose members arrive in a different order must encode
	// identically, since members are canonically sorted.
	shuffled := testManifest(t)
	shuffled.Members = []Member{m.Members[2], m.Members[0], m.Members[1]}
	shuffledBytes, err := shuffled.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, shuffledBytes) {
		t.Error("member input order changed the encoding")
	}
}

func TestManifestRoundTrip(t *testing.T) {
	m := testManifest(t)

	encoded, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseManifest(encoded)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}

	if parsed.FirmwareVersion != m.FirmwareVersion {
		t.Errorf("FirmwareVersion = %q, want %q", parsed.FirmwareVersion, m.FirmwareVersion)
	}
	if parsed.ContentRoot != m.ContentRoot {
		t.Errorf("ContentRoot = %x, want %x", parsed.ContentRoot, m.ContentRoot)
	}
	if parsed.PreviousBundleRoot == nil || *parsed.PreviousBundleRoot != *m.PreviousBundleRoot {
		t.Error("PreviousBundleRoot did not round-trip")
	}
	if parsed.RecoveryState != RecoveryRecoveredTail {
		t.Errorf("RecoveryState = %v, want recovered_tail", parsed.RecoveryState)
	}
	if parsed.DiscardedTailBytes != 42 {
		t.Errorf("DiscardedTailBytes = %d, want 42", parsed.DiscardedTailBytes)
	}
	if len(parsed.RecordCounts) != len(m.RecordCounts) {
		t.Errorf("RecordCounts has %d entries, want %d", len(parsed.RecordCounts), len(m.RecordCounts))
	}
	for rt, want := range m.RecordCounts {
		if parsed.RecordCounts[rt] != want {
			t.Errorf("RecordCounts[%s] = %d, want %d", rt, parsed.RecordCounts[rt], want)
		}
	}
	if err := parsed.VerifyContentRoot(); err != nil {
		t.Errorf("VerifyContentRoot on a round-tripped manifest: %v", err)
	}
}

// A nil PreviousBundleRoot must encode as null and survive the round trip,
// since the first bundle on a device has no predecessor.
func TestManifestNilPreviousRoot(t *testing.T) {
	m := testManifest(t)
	m.PreviousBundleRoot = nil

	encoded, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseManifest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PreviousBundleRoot != nil {
		t.Error("nil PreviousBundleRoot did not round-trip as null")
	}
}

func TestManifestContentRootMismatchDetected(t *testing.T) {
	m := testManifest(t)
	m.ContentRoot[0] ^= 0xFF

	if err := m.VerifyContentRoot(); !errors.Is(err, ErrContentRootMismatch) {
		t.Fatalf("error = %v, want ErrContentRootMismatch", err)
	}
}

// ─── vector: manifest-bad-signature ─────────────────────────────────────────

func TestManifestSignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	m := testManifest(t)
	m.DeviceKeyID = DeviceKeyID(pub)

	encoded, sig, err := m.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := VerifyManifest(encoded, sig, pub)
	if err != nil {
		t.Fatalf("VerifyManifest on a good signature: %v", err)
	}
	if parsed.DeviceKeyID != DeviceKeyID(pub) {
		t.Error("DeviceKeyID did not round-trip")
	}

	// A flipped signature bit must be rejected.
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	if _, err := VerifyManifest(encoded, badSig, pub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered signature: error = %v, want ErrBadSignature", err)
	}

	// A flipped manifest bit must be rejected against the original signature.
	badManifest := append([]byte(nil), encoded...)
	badManifest[len(badManifest)-1] ^= 0x01
	if _, err := VerifyManifest(badManifest, sig, pub); err == nil {
		t.Error("tampered manifest accepted, want rejection")
	}

	// A different key must not verify.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(encoded, sig, otherPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: error = %v, want ErrBadSignature", err)
	}
}

// ─── receipts ───────────────────────────────────────────────────────────────

func testReceipt(contentRoot [32]byte) *Receipt {
	var receiptID, deviceID, bundleID [16]byte
	for i := range receiptID {
		receiptID[i] = byte(0x40 + i)
		deviceID[i] = byte(0x10 + i)
		bundleID[i] = byte(i)
	}

	return &Receipt{
		ReceiptVersion:      ReceiptVersion,
		ReceiptID:           receiptID,
		DeviceID:            deviceID,
		BundleID:            bundleID,
		ContentRoot:         contentRoot,
		ServerIngestUTCMS:   1_790_000_123_456,
		ServerKeyID:         [8]byte{9, 8, 7, 6, 5, 4, 3, 2},
		IngestSchemaVersion: 1,
		StoredObjectIDs:     []string{"cas/ab/abcdef0123", "cas/cd/cdef456789"},
		SignatureAlgorithm:  SignatureAlgorithmEd25519,
	}
}

func TestReceiptRoundTripAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	root := sha256.Sum256([]byte("the bundle we uploaded"))
	r := testReceipt(root)

	encoded, err := r.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseReceipt(encoded)
	if err != nil {
		t.Fatalf("ParseReceipt: %v", err)
	}
	if parsed.ContentRoot != root {
		t.Errorf("ContentRoot = %x, want %x", parsed.ContentRoot, root)
	}
	if len(parsed.StoredObjectIDs) != 2 {
		t.Errorf("StoredObjectIDs has %d entries, want 2", len(parsed.StoredObjectIDs))
	}

	if err := parsed.Verify(pub); err != nil {
		t.Errorf("Verify on a good receipt: %v", err)
	}
	if err := parsed.VerifyAcknowledges(pub, root); err != nil {
		t.Errorf("VerifyAcknowledges with the matching root: %v", err)
	}
}

// ─── vector: receipt-wrong-content-root ─────────────────────────────────────

// A validly signed receipt for a different bundle is not an acknowledgement of
// this one. Treating it as one would let a misconfigured or hostile server
// induce deletion of data it never received.
func TestReceiptWrongContentRootRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	otherRoot := sha256.Sum256([]byte("some other bundle"))
	r := testReceipt(otherRoot)
	encoded, err := r.Sign(priv)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParseReceipt(encoded)
	if err != nil {
		t.Fatal(err)
	}

	// The signature is genuine.
	if err := parsed.Verify(pub); err != nil {
		t.Fatalf("the receipt signature should be valid: %v", err)
	}

	// But it does not acknowledge what we uploaded.
	uploaded := sha256.Sum256([]byte("the bundle we uploaded"))
	err = parsed.VerifyAcknowledges(pub, uploaded)
	if !errors.Is(err, ErrReceiptRootMismatch) {
		t.Fatalf("error = %v, want ErrReceiptRootMismatch", err)
	}
}

func TestReceiptBadSignatureRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	root := sha256.Sum256([]byte("bundle"))
	r := testReceipt(root)
	if _, err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}

	r.Signature[0] ^= 0x01
	if err := r.Verify(pub); !errors.Is(err, ErrBadReceiptSignature) {
		t.Errorf("error = %v, want ErrBadReceiptSignature", err)
	}

	// A server key rotation must not let an old receipt justify a prune.
	rotatedPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh := testReceipt(root)
	if _, err := fresh.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Verify(rotatedPub); !errors.Is(err, ErrBadReceiptSignature) {
		t.Errorf("rotated key: error = %v, want ErrBadReceiptSignature", err)
	}
}

// Tampering with a signature-covered field must invalidate the receipt even
// though the signature bytes themselves are untouched.
func TestReceiptFieldTamperingDetected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	root := sha256.Sum256([]byte("bundle"))
	r := testReceipt(root)
	if _, err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}

	r.ServerIngestUTCMS += 1
	if err := r.Verify(pub); !errors.Is(err, ErrBadReceiptSignature) {
		t.Errorf("altered ingest timestamp: error = %v, want ErrBadReceiptSignature", err)
	}
}

// ─── canonical encoding guards ──────────────────────────────────────────────

// The decoder must reject any input it would not itself have produced. A
// non-minimal integer width is the easiest such input to construct, and
// accepting it would mean verifying bytes other than those received.
func TestDecoderRejectsNonMinimalIntegers(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"1-byte form for a value that fits the immediate form", []byte{0x18, 0x05}},
		{"2-byte form for a value that fits 1", []byte{0x19, 0x00, 0x20}},
		{"4-byte form for a value that fits 2", []byte{0x1a, 0x00, 0x00, 0x01, 0x00}},
		{"8-byte form for a value that fits 4", []byte{0x1b, 0, 0, 0, 0, 0, 1, 0, 0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &cborDecoder{buf: tc.input}
			if _, _, err := d.head(); !errors.Is(err, ErrNonCanonical) {
				t.Errorf("error = %v, want ErrNonCanonical", err)
			}
		})
	}
}

func TestDecoderRejectsIndefiniteLength(t *testing.T) {
	d := &cborDecoder{buf: []byte{0x9f}} // indefinite-length array
	if _, _, err := d.head(); !errors.Is(err, ErrCBORUnsupported) {
		t.Errorf("error = %v, want ErrCBORUnsupported", err)
	}
}

func TestDecoderRejectsTruncation(t *testing.T) {
	for _, input := range [][]byte{
		{},
		{0x18},
		{0x19, 0x01},
		{0x1b, 0, 0, 0},
	} {
		d := &cborDecoder{buf: input}
		if _, _, err := d.head(); !errors.Is(err, ErrCBORTruncated) {
			t.Errorf("input %x: error = %v, want ErrCBORTruncated", input, err)
		}
	}
}

// Truncating a signed manifest at every offset must never panic and must never
// parse successfully.
func TestManifestTruncationIsSafe(t *testing.T) {
	m := testManifest(t)
	encoded, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	for cut := 0; cut < len(encoded); cut++ {
		if _, err := ParseManifest(encoded[:cut]); err == nil {
			t.Fatalf("manifest truncated to %d of %d bytes parsed successfully", cut, len(encoded))
		}
	}
}

func TestManifestTrailingBytesRejected(t *testing.T) {
	m := testManifest(t)
	encoded, err := m.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseManifest(append(encoded, 0x00)); err == nil {
		t.Error("manifest with trailing bytes accepted, want rejection")
	}
}

// Writing map keys out of order is a programming error that would silently
// produce a non-canonical signature, so it must fail loudly.
func TestEncoderPanicsOnDescendingKeys(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("out-of-order map keys did not panic")
		}
	}()

	e := &cborEncoder{}
	e.mapHeader(2)
	e.key(5)
	e.key(3)
}
