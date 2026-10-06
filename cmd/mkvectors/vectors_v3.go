package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// Vectors specific to format v3: the journal chain, authentication failures,
// key binding, and manifest-to-segment binding.

// headerCRCOffset is where a segment header's CRC lives. Tampering with a header
// field and then repairing this is exactly what an attacker without the key can
// do, which is the point of the vectors that use it: the structural scan must
// pass and the keyed scan must not.
const headerCRCOffset = format.SegmentHeaderSize - 4

func repairHeaderCRC(b []byte) {
	crc := format.CRC32(b[:headerCRCOffset])
	b[headerCRCOffset] = byte(crc)
	b[headerCRCOffset+1] = byte(crc >> 8)
	b[headerCRCOffset+2] = byte(crc >> 16)
	b[headerCRCOffset+3] = byte(crc >> 24)
}

// repairFrameCRC recomputes the CRC of the frame at offset with length frameLen.
// A holder of no key can do this, so a frame edit that survives the structural
// scan is the interesting case.
func repairFrameCRC(b []byte, offset, frameLen int) {
	crc := format.CRC32(b[offset : offset+frameLen-format.FrameTrailerSize])
	at := offset + frameLen - format.FrameTrailerSize
	b[at] = byte(crc)
	b[at+1] = byte(crc >> 8)
	b[at+2] = byte(crc >> 16)
	b[at+3] = byte(crc >> 24)
}

func journalHeader() format.SegmentHeader {
	h := testHeader(0)
	h.SegmentIndex = format.JournalSegmentIndex
	return h
}

func vectorJournalSegment(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(journalHeader(), format.ScanState{})
	if err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		p := make([]byte, 20)
		p[0] = 1 // capture region
		p[2] = uint8(i)
		if err := w.Append(format.RecordStateTransition, 1, 0, uint32(i*500), p); err != nil {
			return err
		}
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "journal-segment", &expectation{
		Description: "journal.seg: segment_index 0xFFFFFFFF, four STATE_TRANSITION frames, seq 0 and prev_crc32 0.",
		Asserts: "The journal is its own chain and scans from the zero state. Its reserved " +
			"segment_index is an input to the segment key, so its key differs from capture " +
			"segment 0's even though every other header field is the same; compare segment_key_hex " +
			"with the capture vectors.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(w.Bytes()))
}

func vectorAuthTagTampered(dir string, _, _ ed25519.PrivateKey) error {
	const frames = 4
	w, err := buildSegment(0, format.ScanState{}, frames)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	// Flip one ciphertext bit in the last frame, then repair its CRC. Nothing a
	// holder of no key checks can tell: the CRC is valid, the chain is intact (no
	// frame follows), the sequence is right.
	frameLen := format.FrameOverhead + 32
	start := format.SegmentHeaderSize + (frames-1)*frameLen
	b[start+format.FrameHeaderSize+format.NonceSize+3] ^= 0x01
	repairFrameCRC(b, start, frameLen)

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	if exp.StopReason != "EOF" || keyed.StopReason != "AUTH_FAILED" {
		return fmt.Errorf("auth-tag-tampered: structural %s, keyed %s; want EOF and AUTH_FAILED",
			exp.StopReason, keyed.StopReason)
	}
	return writeVector(dir, "auth-tag-tampered", &expectation{
		Description: "One ciphertext bit flipped in the last of four frames, with the frame CRC recomputed.",
		Asserts: "A structural scan (no key) reaches EOF with four frames: the CRC is valid, so " +
			"nothing keyless can detect this edit, which is why the CRC is only a damage detector " +
			"and never an integrity guarantee. A keyed scan stops at the frame with AUTH_FAILED and " +
			"retains the three before it. An auth failure is never skipped past or silently dropped.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(b))
}

// A frame sealed for one bundle must not authenticate in another, even when the
// segment key is identical. The two headers here differ only in device_counter,
// which is AAD but not a KDF input, so the key is the same and the AAD alone is
// what rejects the frames.
func vectorFrameMoved(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 3)
	if err != nil {
		return err
	}
	donor := w.Bytes()

	other := testHeader(0)
	other.FormatVersion = format.FormatVersion
	other.DeviceCounter = vectorDeviceCounter + 1
	hdr := format.AppendSegmentHeader(nil, &other)

	b := append(hdr, donor[format.SegmentHeaderSize:]...)

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	if exp.StopReason != "EOF" || keyed.StopReason != "AUTH_FAILED" {
		return fmt.Errorf("frame-moved: structural %s, keyed %s; want EOF and AUTH_FAILED",
			exp.StopReason, keyed.StopReason)
	}

	// Prove the vector isolates the AAD: both headers derive the same key.
	h0, _, _ := format.ParseSegmentHeader(donor)
	h1, _, _ := format.ParseSegmentHeader(b)
	k0, _ := format.DeriveSegmentKey(rootKey, &h0)
	k1, _ := format.DeriveSegmentKey(rootKey, &h1)
	if k0 != k1 {
		return errors.New("frame-moved: the two headers derive different keys; the vector would not isolate the AAD")
	}

	return writeVector(dir, "frame-moved-between-segments", &expectation{
		Description: fmt.Sprintf("Three valid frames from a segment with device_counter %d, placed under a "+
			"header with device_counter %d (everything else identical, header CRC valid).",
			vectorDeviceCounter, vectorDeviceCounter+1),
		Asserts: "Structurally clean (EOF, three frames): the CRCs and the chain are untouched. " +
			"Keyed: AUTH_FAILED at frame 0. Both headers derive the same segment key, so the " +
			"rejection comes from the AAD alone: every frame authenticates the segment header, " +
			"so frames cannot be replayed into another bundle, vehicle, device or counter.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(b))
}

func vectorWrongVehicleKey(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 4)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	// Re-point the segment at a different vehicle and repair the header CRC.
	for i := 0; i < 16; i++ {
		b[40+i] = byte(0x90 + i)
	}
	repairHeaderCRC(b)

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	if exp.StopReason != "EOF" || keyed.StopReason != "AUTH_FAILED" || *keyed.FramesRetained != 0 {
		return fmt.Errorf("wrong-vehicle-key: structural %s, keyed %s/%d frames", exp.StopReason,
			keyed.StopReason, *keyed.FramesRetained)
	}
	return writeVector(dir, "wrong-vehicle-key", &expectation{
		Description: "A segment whose header vehicle_id was changed (header CRC repaired) after the frames were sealed.",
		Asserts: "The header is valid and the structural scan is clean. Keyed: the vehicle_id is the " +
			"HKDF salt and part of every frame's AAD, so the derived key is wrong and the very first " +
			"frame fails: AUTH_FAILED with zero frames retained. Re-labelling data as another vehicle's " +
			"is not possible without the storage root.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(b))
}

func vectorWrongKeyVersion(dir string, _, _ ed25519.PrivateKey) error {
	h := testHeader(0)
	h.StorageKeyVersion = altKeyVersion
	alt := &format.RootKeyProvider{Root: altRootKey, Version: altKeyVersion}

	writerSeq++
	w, err := format.NewSegmentWriter(h, format.ScanState{}, alt,
		testbundle.NonceReader(fmt.Sprintf("%s/%d", vecName, writerSeq)))
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		p := gnssPayload(int32(340_000_000+i*100), int32(-1_185_000_000+i*100))
		if err := w.Append(format.RecordGNSSSample, 1, 0, uint32(i*1000), p); err != nil {
			return err
		}
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	if keyed.Error != "KEY_VERSION_MISMATCH" {
		return fmt.Errorf("wrong-key-version: keyed verdict %+v, want KEY_VERSION_MISMATCH", keyed)
	}
	return writeVector(dir, "wrong-key-version", &expectation{
		Description: "A segment genuinely sealed under storage_key_version 2, scanned by a verifier that holds only version 1.",
		Asserts: "Structurally clean. Keyed: the provider refuses before deriving anything, with " +
			"KEY_VERSION_MISMATCH, rather than deriving a version-1 key that would fail every tag. " +
			"The difference matters: a version mismatch means a key is missing, a tag failure means " +
			"tampering, and an operator must be told which. The segment is not damaged and must not " +
			"be deleted.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(w.Bytes()))
}

// ─── bundle binding vectors ─────────────────────────────────────────────────

// vectorBundle is a real manifest over real segments, so the member digests, the
// content root and the segment headers all agree except where a vector breaks
// one deliberately.
type vectorBundle struct {
	files    map[string][]byte
	manifest *format.Manifest
	encoded  []byte
	sig      []byte
}

// buildVectorBundle writes seg-00000000.seg and journal.seg and a signed
// manifest over them. captureHeader adjusts the capture segment's header before
// it is written, which is how a vector makes a segment disagree with the manifest.
func buildVectorBundle(devicePriv ed25519.PrivateKey, captureHeader func(*format.SegmentHeader)) (*vectorBundle, error) {
	h0 := testHeader(0)
	if captureHeader != nil {
		captureHeader(&h0)
	}
	w0, err := newWriter(h0, format.ScanState{})
	if err != nil {
		return nil, err
	}
	for i := 0; i < 3; i++ {
		p := gnssPayload(int32(340_000_000+i*100), int32(-1_185_000_000+i*100))
		if err := w0.Append(format.RecordGNSSSample, 1, 0, uint32(i*1000), p); err != nil {
			return nil, err
		}
	}

	wj, err := newWriter(journalHeader(), format.ScanState{})
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		if err := wj.Append(format.RecordStateTransition, 1, 0, uint32(i*500), make([]byte, 20)); err != nil {
			return nil, err
		}
	}

	files := map[string][]byte{
		"seg-00000000.seg": append([]byte(nil), w0.Bytes()...),
		"journal.seg":      append([]byte(nil), wj.Bytes()...),
	}

	members := make([]format.Member, 0, len(files))
	for name, data := range files {
		members = append(members, format.Member{Name: name, Length: uint64(len(data)), SHA256: sha256.Sum256(data)})
	}
	format.SortMembers(members)

	var stream []byte
	for _, m := range members {
		stream = append(stream, files[m.Name]...)
	}

	root, err := format.ContentRoot(members)
	if err != nil {
		return nil, err
	}

	m, err := sampleManifest()
	if err != nil {
		return nil, err
	}
	m.Members = members
	m.ContentRoot = root
	m.ChunkDescriptors = []format.ChunkDescriptor{{Index: 0, ByteLength: uint32(len(stream)), SHA256: sha256.Sum256(stream)}}
	m.FirstSeq, m.LastSeq = 0, 2
	m.RecordCounts = map[format.RecordType]uint32{format.RecordGNSSSample: 3, format.RecordStateTransition: 2}

	encoded, sig, err := m.Sign(devicePriv)
	if err != nil {
		return nil, err
	}
	files["manifest.cbor"] = encoded
	files["manifest.sig"] = sig
	return &vectorBundle{files: files, manifest: m, encoded: encoded, sig: sig}, nil
}

func (vb *vectorBundle) manifestExpectation(devicePriv ed25519.PrivateKey) *manifestExpectation {
	digest := sha256.Sum256(vb.encoded)
	return &manifestExpectation{
		Valid:              true,
		SignatureValid:     true,
		ContentRootHex:     hex.EncodeToString(vb.manifest.ContentRoot[:]),
		DevicePublicKeyHex: hex.EncodeToString(devicePriv.Public().(ed25519.PublicKey)),
		CanonicalBytesHex:  hex.EncodeToString(digest[:]),
	}
}

func (vb *vectorBundle) segments() map[string][]byte {
	return map[string][]byte{
		"seg-00000000.seg": vb.files["seg-00000000.seg"],
		"journal.seg":      vb.files["journal.seg"],
	}
}

func vectorManifestMembersMatch(dir string, devicePriv, _ ed25519.PrivateKey) error {
	vb, err := buildVectorBundle(devicePriv, nil)
	if err != nil {
		return err
	}
	if err := format.VerifyMembersAgainstManifest(vb.manifest, vb.segments()); err != nil {
		return fmt.Errorf("the matching bundle does not match: %w", err)
	}
	return writeVector(dir, "manifest-members-match", &expectation{
		Description: "A signed manifest over a capture segment and a journal whose headers agree with it.",
		Asserts: "device_id, boot_id, vehicle_id, assignment_id, device_counter and storage_key_version " +
			"in every segment header equal the manifest's, the capture segment's index matches its file " +
			"name, and the journal carries the reserved index 0xFFFFFFFF. Binding checks pass.",
		Manifest: vb.manifestExpectation(devicePriv),
		Binding:  &bindingExpectation{Match: true},
	}, vb.files)
}

func vectorManifestSegmentMismatch(dir string, devicePriv, _ ed25519.PrivateKey) error {
	vb, err := buildVectorBundle(devicePriv, func(h *format.SegmentHeader) {
		// A segment captured under a different assignment, as if from the same
		// device before it was moved to another vehicle.
		for i := range h.AssignmentID {
			h.AssignmentID[i] = byte(0x70 + i)
		}
	})
	if err != nil {
		return err
	}
	err = format.VerifyMembersAgainstManifest(vb.manifest, vb.segments())
	if !errors.Is(err, format.ErrManifestBindingMismatch) {
		return fmt.Errorf("mismatching bundle verified as %v", err)
	}
	return writeVector(dir, "manifest-segment-header-mismatch", &expectation{
		Description: "A correctly signed manifest whose capture segment header carries a different assignment_id.",
		Asserts: "The manifest signature, content root and member digests are all valid; the segment " +
			"is simply not the one the manifest describes. Verification of members against the manifest " +
			"must fail on assignment_id. A valid signature binds the manifest to the device key, not " +
			"the manifest to its segments: that is this check's job.",
		Manifest: vb.manifestExpectation(devicePriv),
		Binding:  &bindingExpectation{Match: false, Field: "assignment_id"},
	}, vb.files)
}

// ─── keys.json ──────────────────────────────────────────────────────────────

func writeKeys(dir string) error {
	h := testHeader(0)
	k0, err := format.DeriveSegmentKey(rootKey, &h)
	if err != nil {
		return err
	}
	jh := journalHeader()
	kj, err := format.DeriveSegmentKey(rootKey, &jh)
	if err != nil {
		return err
	}

	doc := map[string]any{
		"WARNING": "PUBLIC TEST KEYS. These keys are committed to a public repository. They protect " +
			"nothing and must never be provisioned onto a device or loaded into a real keystore.",
		"encryption_suite":        format.EncryptionSuiteV1,
		"root_key_hex":            hex.EncodeToString(rootKey[:]),
		"storage_key_version":     vectorKeyVersion,
		"alt_root_key_hex":        hex.EncodeToString(altRootKey[:]),
		"alt_storage_key_version": altKeyVersion,
		"device_id_hex":           hex.EncodeToString(h.DeviceID[:]),
		"boot_id_hex":             hex.EncodeToString(h.BootID[:]),
		"vehicle_id_hex":          hex.EncodeToString(h.VehicleID[:]),
		"assignment_id_hex":       hex.EncodeToString(h.AssignmentID[:]),
		"device_counter":          vectorDeviceCounter,
		"worked_example": map[string]any{
			"note": "K_seg = HKDF-SHA256(ikm=root_key, salt=vehicle_id, info=\"cairn/segment/v3\" || device_id || " +
				"assignment_id || boot_id || segment_index u32le, L=32), for the identities above.",
			"capture_segment_0_key_hex": hex.EncodeToString(k0[:]),
			"journal_key_hex":           hex.EncodeToString(kj[:]),
		},
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "keys.json"), append(encoded, '\n'), 0o644)
}
