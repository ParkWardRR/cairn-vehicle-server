package format

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// ─── known answers ──────────────────────────────────────────────────────────

// RFC 5869 appendix A, test cases 1 and 2, against the HKDF this package
// derives segment keys with. A known-answer test is the only thing that catches
// a derivation that is merely self-consistent: a wrong KDF still round-trips
// through our own reader.
func TestHKDFRFC5869KnownAnswers(t *testing.T) {
	seq := func(from, to int) []byte {
		var b []byte
		for i := from; i <= to; i++ {
			b = append(b, byte(i))
		}
		return b
	}

	cases := []struct {
		name            string
		ikm, salt, info []byte
		length          int
		okm             string
	}{
		{
			name:   "A.1 basic",
			ikm:    bytes.Repeat([]byte{0x0b}, 22),
			salt:   seq(0x00, 0x0c),
			info:   seq(0xf0, 0xf9),
			length: 42,
			okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
				"34007208d5b887185865",
		},
		{
			name:   "A.2 longer inputs",
			ikm:    seq(0x00, 0x4f),
			salt:   seq(0x60, 0xaf),
			info:   seq(0xb0, 0xff),
			length: 82,
			okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c" +
				"59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71" +
				"cc30c58179ec3e87c14c01d5c1f3434f1d87",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := hkdf.Key(sha256.New, c.ikm, c.salt, string(c.info), c.length)
			if err != nil {
				t.Fatal(err)
			}
			if want := mustHex(t, c.okm); !bytes.Equal(got, want) {
				t.Errorf("OKM = %x, want %x", got, want)
			}
			if ref := rfc5869(c.ikm, c.salt, c.info, c.length); !bytes.Equal(ref, got) {
				t.Errorf("reference HKDF from HMAC = %x, library = %x", ref, got)
			}
		})
	}
}

// rfc5869 is HKDF written out from HMAC-SHA256 exactly as the RFC states it.
// It is the independent implementation DeriveSegmentKey is checked against, so
// the info layout is verified against the spec text rather than against itself.
func rfc5869(ikm, salt, info []byte, length int) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(ikm)
	prk := ext.Sum(nil)

	var okm, prev []byte
	for i := byte(1); len(okm) < length; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{i})
		prev = m.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

// draft-irtf-cfrg-xchacha appendix A.3.1. The 24-byte nonce is what separates
// XChaCha20-Poly1305 from plain ChaCha20-Poly1305; a library that silently
// truncated it would still round-trip, and this is what would catch that.
func TestXChaCha20Poly1305KnownAnswer(t *testing.T) {
	plaintext := mustHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a2049662049"+
		"20636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	want := mustHex(t, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39"+
		"ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"+
		"21f9664c97637da9768812f615c68b13b52e"+"c0875924c1c7987947deafd8780acf49")

	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Seal(nil, nonce, plaintext, aad); !bytes.Equal(got, want) {
		t.Errorf("sealed = %x\nwant     %x", got, want)
	}
	pt, err := a.Open(nil, nonce, want, aad)
	if err != nil || !bytes.Equal(pt, plaintext) {
		t.Errorf("Open = %v, %v", pt, err)
	}

	if a.NonceSize() != NonceSize || a.Overhead() != TagSize {
		t.Errorf("AEAD geometry nonce=%d tag=%d disagrees with the format's %d and %d",
			a.NonceSize(), a.Overhead(), NonceSize, TagSize)
	}
}

// The geometry constants are arithmetic over each other; pin the results the
// firmware and emulator will hard-code.
func TestFrameGeometry(t *testing.T) {
	if AEADOverhead != 40 || FrameOverhead != 68 || MinFrameLen != 68 || MaxFrameLen != 4096 || MaxPayloadSize != 4028 {
		t.Errorf("geometry: AEAD %d, overhead %d, min %d, max %d, max payload %d",
			AEADOverhead, FrameOverhead, MinFrameLen, MaxFrameLen, MaxPayloadSize)
	}
	if SegmentHeaderSize != 128 || offHdrCRC != 124 {
		t.Errorf("segment header %d bytes, CRC at %d; want 128 and 124", SegmentHeaderSize, offHdrCRC)
	}
}

// ─── key derivation ─────────────────────────────────────────────────────────

// DeriveSegmentKey must equal an independent HKDF over the spec's literal info
// layout. This pins the order and width of every field in info.
func TestDeriveSegmentKeyMatchesSpecLayout(t *testing.T) {
	h := testHeader(5)

	info := []byte("cairn/segment/v3")
	info = append(info, h.DeviceID[:]...)
	info = append(info, h.AssignmentID[:]...)
	info = append(info, h.BootID[:]...)
	info = binary.LittleEndian.AppendUint32(info, 5)
	want := rfc5869(testRoot[:], h.VehicleID[:], info, 32)

	got, err := DeriveSegmentKey(testRoot, &h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Errorf("K_seg = %x, want %x", got, want)
	}
}

// Every identity input must change the key. If one did not, data sealed for one
// vehicle (or segment, or device) would be readable under another's key.
func TestKeySeparation(t *testing.T) {
	base := testHeader(1)
	baseKey, err := DeriveSegmentKey(testRoot, &base)
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*SegmentHeader){
		"vehicle":     func(h *SegmentHeader) { h.VehicleID[15] ^= 1 },
		"assignment":  func(h *SegmentHeader) { h.AssignmentID[0] ^= 1 },
		"device":      func(h *SegmentHeader) { h.DeviceID[7] ^= 1 },
		"boot":        func(h *SegmentHeader) { h.BootID[3] ^= 1 },
		"segment":     func(h *SegmentHeader) { h.SegmentIndex++ },
		"journal":     func(h *SegmentHeader) { h.SegmentIndex = JournalSegmentIndex },
		"segment-msb": func(h *SegmentHeader) { h.SegmentIndex |= 0x80000000 },
	}

	seen := map[[32]byte]string{baseKey: "base"}
	for name, mutate := range mutations {
		h := base
		mutate(&h)
		k, err := DeriveSegmentKey(testRoot, &h)
		if err != nil {
			t.Fatal(err)
		}
		if k == baseKey {
			t.Errorf("changing %s did not change the segment key", name)
		}
		if prev, dup := seen[k]; dup {
			t.Errorf("%s and %s derive the same key", name, prev)
		}
		seen[k] = name
	}

	// A different root gives different keys for the same header.
	other := testRoot
	other[0] ^= 1
	if k, _ := DeriveSegmentKey(other, &base); k == baseKey {
		t.Error("a different K_root derived the same segment key")
	}

	// And the inputs that are deliberately NOT in the KDF leave it alone:
	// counter and key version bind through the AAD and root selection instead.
	same := base
	same.DeviceCounter += 99
	same.StorageKeyVersion += 1
	same.FirstSeq += 5
	same.OpenedMonotonicUS += 5
	if k, _ := DeriveSegmentKey(testRoot, &same); k != baseKey {
		t.Error("device_counter, key version, first_seq or opened_monotonic_us leaked into the KDF")
	}
}

func TestRootKeyProviderChecksVersion(t *testing.T) {
	h := testHeader(0)
	p := &RootKeyProvider{Root: testRoot, Version: 1}

	if _, err := p.SegmentKey(&h); err != nil {
		t.Fatalf("matching version: %v", err)
	}
	h.StorageKeyVersion = 2
	if _, err := p.SegmentKey(&h); !errors.Is(err, ErrKeyVersionMismatch) {
		t.Errorf("version 2 against a version 1 provider: error = %v, want ErrKeyVersionMismatch", err)
	}
}

type fakeResolver map[[16]byte]*[RootKeySize]byte

func (f fakeResolver) RootKey(dev [16]byte, version uint32) ([RootKeySize]byte, error) {
	root, ok := f[dev]
	if !ok {
		return [RootKeySize]byte{}, ErrNoKey
	}
	if version != 1 {
		return [RootKeySize]byte{}, ErrKeyVersionMismatch
	}
	return *root, nil
}

func TestResolverKeyProvider(t *testing.T) {
	h := testHeader(0)
	root := testRoot
	p := ResolverKeyProvider{Resolver: fakeResolver{h.DeviceID: &root}}

	got, err := p.SegmentKey(&h)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := DeriveSegmentKey(testRoot, &h)
	if got != want {
		t.Error("resolver provider derived a different key than the root provider")
	}

	other := h
	other.DeviceID[0] ^= 1
	if _, err := p.SegmentKey(&other); !errors.Is(err, ErrNoKey) {
		t.Errorf("unknown device: error = %v, want ErrNoKey", err)
	}
}

// ─── nonces ─────────────────────────────────────────────────────────────────

func extractNonces(t *testing.T, seg []byte) [][NonceSize]byte {
	t.Helper()
	res, err := ScanSegment(seg, ScanState{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out [][NonceSize]byte
	for _, f := range res.Frames {
		out = append(out, [NonceSize]byte(f.Sealed[:NonceSize]))
	}
	return out
}

// With random 192-bit nonces a collision across this many frames is a
// probability of about 2^-120; any repeat means the nonce source is broken.
func TestNonceUniquenessOverManyFrames(t *testing.T) {
	seen := map[[NonceSize]byte]bool{}

	const segments, frames = 20, 500
	for s := 0; s < segments; s++ {
		w := newTestWriter(t, testHeader(uint32(s)), ScanState{})
		for i := 0; i < frames; i++ {
			if err := w.Append(RecordGNSSSample, 1, 0, uint32(i), make([]byte, 32)); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range extractNonces(t, w.Bytes()) {
			if seen[n] {
				t.Fatalf("nonce %x reused", n)
			}
			seen[n] = true
		}
	}
	if len(seen) != segments*frames {
		t.Errorf("collected %d nonces, want %d", len(seen), segments*frames)
	}
}

// After a torn-tail truncation the same seq is rewritten with different
// plaintext under the same key. The nonce must differ, or the two ciphertexts
// would XOR to the XOR of the plaintexts.
func TestRewrittenSeqAfterTruncationUsesFreshNonce(t *testing.T) {
	h := testHeader(0)

	first := newTestWriter(t, h, ScanState{})
	if err := first.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(1, 2)); err != nil {
		t.Fatal(err)
	}
	// Same header, same state, same seq 0, different plaintext: the writer that
	// resumes after a crash.
	second := newTestWriter(t, h, ScanState{})
	if err := second.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(3, 4)); err != nil {
		t.Fatal(err)
	}

	n1 := extractNonces(t, first.Bytes())
	n2 := extractNonces(t, second.Bytes())
	if n1[0] == n2[0] {
		t.Fatal("rewriting seq 0 reused its nonce")
	}
}

// ─── AEAD composition ───────────────────────────────────────────────────────

// The sealed frame must equal the AEAD over exactly the AAD the spec states:
// the 24 header bytes as written, then the segment header minus its CRC. Built
// independently here, so a change to what is authenticated fails this test.
func TestFrameSealedWithSpecAAD(t *testing.T) {
	w := newTestWriter(t, testHeader(2), ScanState{})
	payload := gnssPayload(11, 22)
	if err := w.Append(RecordGNSSSample, 1, FlagDegraded, 777, payload); err != nil {
		t.Fatal(err)
	}
	seg := w.Bytes()

	res, err := ScanSegment(seg, ScanState{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := res.Frames[0]
	frameHeader := seg[SegmentHeaderSize : SegmentHeaderSize+FrameHeaderSize]

	var aad []byte
	aad = append(aad, frameHeader...)
	aad = append(aad, seg[:SegmentHeaderSize-4]...)

	h := testHeader(2)
	key, _ := DeriveSegmentKey(testRoot, &h)
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		t.Fatal(err)
	}
	pt, err := a.Open(nil, f.Sealed[:NonceSize], f.Sealed[NonceSize:], aad)
	if err != nil {
		t.Fatalf("independent AEAD could not open the frame with the spec's AAD: %v", err)
	}
	if !bytes.Equal(pt, payload) {
		t.Error("plaintext differs")
	}
	if len(f.Sealed) != len(payload)+AEADOverhead {
		t.Errorf("sealed length %d, want plaintext %d + %d", len(f.Sealed), len(payload), AEADOverhead)
	}
}

// ─── binding: what a keyless attacker can and cannot do ─────────────────────

func repairHeaderCRCForTest(b []byte) {
	binary.LittleEndian.PutUint32(b[offHdrCRC:], CRC32(b[:offHdrCRC]))
}

func repairFrameCRCForTest(b []byte, offset int) {
	n := int(binary.LittleEndian.Uint16(b[offset:]))
	binary.LittleEndian.PutUint32(b[offset+n-FrameTrailerSize:], CRC32(b[offset:offset+n-FrameTrailerSize]))
}

func newThreeFrameSegment(t *testing.T) []byte {
	w := newTestWriter(t, testHeader(0), ScanState{})
	for i := 0; i < 3; i++ {
		if err := w.Append(RecordGNSSSample, 1, 0, uint32(i*1000), gnssPayload(int32(i), int32(-i))); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), w.Bytes()...)
}

// Every segment-header field except the CRC is authenticated. Changing any one
// of them and repairing the CRC (all a keyless attacker can do) must leave the
// structural scan clean and fail the keyed scan at the first frame. Reserved
// bytes are included: they are zero, but authenticated zero.
func TestSegmentHeaderFieldsAreAuthenticated(t *testing.T) {
	fields := []struct {
		name string
		off  int
	}{
		{"device_id", offHdrDeviceID},
		{"boot_id", offHdrBootID},
		{"vehicle_id", offHdrVehicleID},
		{"assignment_id", offHdrAssignmentID},
		{"segment_index", offHdrSegmentIndex},
		{"opened_monotonic_us", offHdrOpenedMonotonicUS},
		{"device_counter", offHdrDeviceCounter},
		{"reserved first byte", offHdrReserved},
		{"reserved last byte", offHdrCRC - 1},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			b := newThreeFrameSegment(t)
			b[f.off] ^= 0x01
			repairHeaderCRCForTest(b)

			// Structural: the attacker's edit is invisible to every keyless check.
			res, err := ScanSegment(b, ScanState{}, nil)
			if err != nil || res.Stop != StopEOF || len(res.Frames) != 3 {
				t.Fatalf("structural scan: %v, %v", res, err)
			}

			// Keyed: rejected, with nothing retained and nothing skipped past.
			res, err = ScanSegment(b, ScanState{}, testKeys())
			if err != nil {
				t.Fatal(err)
			}
			if res.Stop != StopAuthFailed || len(res.Frames) != 0 {
				t.Errorf("keyed scan: Stop = %v with %d frames, want AUTH_FAILED with none", res.Stop, len(res.Frames))
			}
		})
	}
}

// storage_key_version is authenticated too, but a version the provider does not
// hold is reported as a missing key, not as tampering.
func TestStorageKeyVersionMismatchIsNotAnAuthFailure(t *testing.T) {
	b := newThreeFrameSegment(t)
	binary.LittleEndian.PutUint32(b[offHdrStorageKeyVersion:], 2)
	repairHeaderCRCForTest(b)

	if _, err := ScanSegment(b, ScanState{}, testKeys()); !errors.Is(err, ErrKeyVersionMismatch) {
		t.Errorf("error = %v, want ErrKeyVersionMismatch", err)
	}
	if res, err := ScanSegment(b, ScanState{}, nil); err != nil || res.Stop != StopEOF {
		t.Errorf("structural scan of a differently-versioned segment: %v, %v", res, err)
	}
}

// Every authenticated field of the frame header, edited with the frame CRC
// repaired, must fail the tag. seq and prev_crc32 are exercised through the
// structural checks that precede decryption, so they are covered separately.
func TestFrameHeaderFieldsAreAuthenticated(t *testing.T) {
	fields := []struct {
		name string
		off  int // within the frame
		last bool
	}{
		{"record_type", 2, true},
		{"schema_version", 3, true},
		{"flags", 4, true},
		{"reserved", 6, true},
		{"monotonic_ms", 12, true},
		{"reserved2", 20, true},
	}

	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			b := newThreeFrameSegment(t)

			// Edit the last frame, so the chain after it cannot report first.
			frameLen := FrameOverhead + 32
			start := SegmentHeaderSize + 2*frameLen
			b[start+f.off] ^= 0x01
			repairFrameCRCForTest(b, start)

			res, err := ScanSegment(b, ScanState{}, nil)
			if err != nil || res.Stop != StopEOF || len(res.Frames) != 3 {
				t.Fatalf("structural scan: %v, %v", res, err)
			}
			res, err = ScanSegment(b, ScanState{}, testKeys())
			if err != nil {
				t.Fatal(err)
			}
			if res.Stop != StopAuthFailed || len(res.Frames) != 2 {
				t.Errorf("keyed scan: Stop = %v with %d frames, want AUTH_FAILED with 2", res.Stop, len(res.Frames))
			}
		})
	}
}

// Chain and sequence are authenticated through the header, so they cannot be
// fixed up by someone without the key: re-chaining a frame invalidates its tag.
func TestRechainingAFrameInvalidatesItsTag(t *testing.T) {
	b := newThreeFrameSegment(t)
	frameLen := FrameOverhead + 32

	// Rewrite frame 1's prev_crc32 to something else and repair its CRC, then
	// repair frame 2's prev_crc32 to match the new CRC of frame 1, and its CRC.
	// A keyless attacker can do all of that; the structural scan accepts it.
	f1 := SegmentHeaderSize + frameLen
	f2 := f1 + frameLen
	binary.LittleEndian.PutUint32(b[f1+16:], 0xDEADBEEF)
	repairFrameCRCForTest(b, f1)
	binary.LittleEndian.PutUint32(b[f2+16:], binary.LittleEndian.Uint32(b[f1+frameLen-4:]))
	repairFrameCRCForTest(b, f2)

	// Frame 1's prev_crc32 no longer equals frame 0's CRC, so even the
	// structural scan catches this particular edit; the point is what happens
	// when the attacker also changes frame 0's view. Prove the tag is the
	// backstop by checking the AAD directly instead.
	res, err := ScanSegment(b, ScanState{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Stop != StopChainBreak {
		t.Fatalf("structural Stop = %v, want CHAIN_BREAK", res.Stop)
	}

	// Now make the structural scan accept it by also rewriting frame 0's
	// trailing CRC, which frame 1's prev_crc32 must equal.
	b2 := newThreeFrameSegment(t)
	f0 := SegmentHeaderSize
	b2[f0+20] ^= 0 // frame 0 untouched except below
	// Re-point frame 1 at an arbitrary predecessor value and make frame 0's CRC
	// equal that value by construction is infeasible; instead assert the
	// invariant that matters: for every frame, prev_crc32 is inside the AAD.
	frame1Header := append([]byte(nil), b2[f1:f1+FrameHeaderSize]...)
	binary.LittleEndian.PutUint32(frame1Header[16:], 0xDEADBEEF)
	h := testHeader(0)
	key, _ := DeriveSegmentKey(testRoot, &h)
	c, err := NewSegmentCipher(b2[:SegmentHeaderSize], key, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed := b2[f1+FrameHeaderSize : f1+frameLen-FrameTrailerSize]
	if _, err := c.Open(frame1Header, sealed); !errors.Is(err, ErrAuthFailed) {
		t.Errorf("a frame with a rewritten prev_crc32 still authenticates: %v", err)
	}
}

// A frame lifted out of one segment must not authenticate in another, even one
// that derives the same key and differs only in an AAD field.
func TestFrameMovedBetweenBundlesFailsAuth(t *testing.T) {
	a := newTestWriter(t, testHeader(0), ScanState{})
	if err := a.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(1, 1)); err != nil {
		t.Fatal(err)
	}

	hb := testHeader(0)
	hb.DeviceCounter++ // another bundle from the same device, same boot and index
	b := newTestWriter(t, hb, ScanState{})

	keyA, _ := DeriveSegmentKey(testRoot, &SegmentHeader{})
	_ = keyA

	moved := append([]byte(nil), b.Bytes()[:SegmentHeaderSize]...)
	moved = append(moved, a.Bytes()[SegmentHeaderSize:]...)

	if res, err := ScanSegment(moved, ScanState{}, nil); err != nil || res.Stop != StopEOF || len(res.Frames) != 1 {
		t.Fatalf("structural scan of the moved frame: %v, %v", res, err)
	}
	res, err := ScanSegment(moved, ScanState{}, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if res.Stop != StopAuthFailed {
		t.Errorf("moved frame: Stop = %v, want AUTH_FAILED", res.Stop)
	}
}

// ─── scanner modes ──────────────────────────────────────────────────────────

func TestKeylessScanExposesNoPayload(t *testing.T) {
	b := newThreeFrameSegment(t)

	res, err := ScanSegment(b, ScanState{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decrypted {
		t.Error("a keyless scan reports Decrypted")
	}
	for i, f := range res.Frames {
		if f.Decrypted || f.Payload != nil {
			t.Errorf("frame %d: Decrypted=%v, Payload=%d bytes; want no plaintext", i, f.Decrypted, len(f.Payload))
		}
		if len(f.Sealed) != 32+AEADOverhead {
			t.Errorf("frame %d: Sealed is %d bytes, want %d", i, len(f.Sealed), 32+AEADOverhead)
		}
	}
}

func TestKeyedScanDecrypts(t *testing.T) {
	b := newThreeFrameSegment(t)

	res, err := ScanSegment(b, ScanState{}, testKeys())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Decrypted {
		t.Error("a keyed scan does not report Decrypted")
	}
	for i, f := range res.Frames {
		if !f.Decrypted {
			t.Errorf("frame %d not marked decrypted", i)
		}
		if want := gnssPayload(int32(i), int32(-i)); !bytes.Equal(f.Payload, want) {
			t.Errorf("frame %d plaintext differs", i)
		}
	}
}

// A keyless scan and a keyed scan must agree on every structural verdict for
// every kind of damage that is not an authenticity failure.
func TestStructuralVerdictsAreIndependentOfKey(t *testing.T) {
	full := newThreeFrameSegment(t)
	frameLen := FrameOverhead + 32

	damaged := map[string][]byte{
		"torn":      full[:len(full)-10],
		"bad crc":   func() []byte { b := append([]byte(nil), full...); b[SegmentHeaderSize+40] ^= 1; return b }(),
		"splice":    append(append([]byte(nil), full[:SegmentHeaderSize+frameLen]...), full[SegmentHeaderSize+2*frameLen:]...),
		"intact":    full,
		"truncated": full[:SegmentHeaderSize+frameLen+7],
	}
	for name, b := range damaged {
		a, errA := ScanSegment(b, ScanState{}, nil)
		k, errK := ScanSegment(b, ScanState{}, testKeys())
		if errA != nil || errK != nil {
			t.Fatalf("%s: errors %v / %v", name, errA, errK)
		}
		if a.Stop != k.Stop || len(a.Frames) != len(k.Frames) || a.StopOffset != k.StopOffset {
			t.Errorf("%s: keyless %v/%d@%d, keyed %v/%d@%d", name,
				a.Stop, len(a.Frames), a.StopOffset, k.Stop, len(k.Frames), k.StopOffset)
		}
	}
}

func TestWriterRequiresKeys(t *testing.T) {
	if _, err := NewSegmentWriter(testHeader(0), ScanState{}, nil, nil); err == nil {
		t.Error("a writer was built with no key provider; there must be no plaintext path")
	}
}

func TestWriterSurfacesKeyErrors(t *testing.T) {
	h := testHeader(0)
	h.StorageKeyVersion = 9
	if _, err := NewSegmentWriter(h, ScanState{}, testKeys(), nil); !errors.Is(err, ErrKeyVersionMismatch) {
		t.Errorf("error = %v, want ErrKeyVersionMismatch", err)
	}
}

func TestSegmentHeaderRoundTripAndLayout(t *testing.T) {
	h := testHeader(9)
	h.FormatVersion = FormatVersion
	h.FirstSeq = 123
	h.OpenedMonotonicUS = 0x1122334455667788
	h.DeviceCounter = 0x0102030405060708
	h.StorageKeyVersion = 0xA1B2C3D4

	b := AppendSegmentHeader(nil, &h)
	if len(b) != SegmentHeaderSize {
		t.Fatalf("header is %d bytes, want %d", len(b), SegmentHeaderSize)
	}
	if string(b[:4]) != "CRN3" {
		t.Errorf("magic = %q", b[:4])
	}
	if !bytes.Equal(b[offHdrReserved:offHdrCRC], make([]byte, 24)) {
		t.Error("reserved bytes are not zero")
	}

	got, n, err := ParseSegmentHeader(b)
	if err != nil || n != SegmentHeaderSize {
		t.Fatalf("parse: %v, header_len %d", err, n)
	}
	if got != h {
		t.Errorf("round trip:\n got %+v\nwant %+v", got, h)
	}

	// Offsets, as the firmware and emulator will hard-code them.
	wantOffsets := map[string][2]int{
		"magic": {0, 4}, "format_version": {4, 2}, "header_len": {6, 2},
		"device_id": {8, 16}, "boot_id": {24, 16}, "vehicle_id": {40, 16}, "assignment_id": {56, 16},
		"segment_index": {72, 4}, "first_seq": {76, 4}, "opened_monotonic_us": {80, 8},
		"storage_key_version": {88, 4}, "device_counter": {92, 8}, "reserved": {100, 24}, "header_crc32": {124, 4},
	}
	end := 0
	for _, name := range []string{"magic", "format_version", "header_len", "device_id", "boot_id", "vehicle_id",
		"assignment_id", "segment_index", "first_seq", "opened_monotonic_us", "storage_key_version",
		"device_counter", "reserved", "header_crc32"} {
		o := wantOffsets[name]
		if o[0] != end {
			t.Errorf("%s at %d, previous field ends at %d", name, o[0], end)
		}
		end = o[0] + o[1]
	}
	if end != SegmentHeaderSize {
		t.Errorf("fields end at %d, want %d", end, SegmentHeaderSize)
	}
	if binary.LittleEndian.Uint64(b[92:]) != h.DeviceCounter || binary.LittleEndian.Uint32(b[88:]) != h.StorageKeyVersion {
		t.Error("device_counter / storage_key_version not at offsets 92 / 88")
	}
}
