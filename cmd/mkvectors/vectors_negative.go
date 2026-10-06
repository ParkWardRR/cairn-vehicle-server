package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
)

// Negative vectors for the artifacts a verifier acts on: segment headers, frames,
// manifests, receipts, update descriptors. The positive vectors prove an
// implementation accepts what it should; these prove it refuses what it must, and
// refuses it for the stated reason. Every builder asserts, against the reference
// implementation, that the artifact really is refused, so a vector that stops
// being negative fails generation rather than shipping.

// attackerKey is a fixed key for a signer who is not the pinned one. Derived from a
// label so it is obviously not secret.
func attackerKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cairn-format-v3 PUBLIC TEST ATTACKER KEY: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

// ─── segment header and frame ───────────────────────────────────────────────

// headerVector writes a vector whose segment header must be refused with both a
// keyless and a keyed scan, for the named reason.
func headerVector(dir, name, parseError, description, asserts string, b []byte, wantErr func(error) bool) error {
	_, err := format.ScanSegment(b, format.ScanState{}, nil)
	if err == nil || !wantErr(err) {
		return fmt.Errorf("%s: keyless scan error is %v, want %s", name, err, parseError)
	}
	if _, kerr := format.ScanSegment(b, format.ScanState{}, keys); kerr == nil || !wantErr(kerr) {
		return fmt.Errorf("%s: keyed scan error is %v, want %s", name, kerr, parseError)
	}
	return writeVector(dir, name, &expectation{
		Description: description,
		Asserts:     asserts,
		Header:      &headerExpectation{ParseError: parseError, Note: err.Error()},
	}, segmentFiles(b))
}

func validSegmentBytes() ([]byte, error) {
	w, err := buildSegment(0, format.ScanState{}, 3)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), w.Bytes()...), nil
}

func vectorHeaderBadMagic(dir string, _, _ ed25519.PrivateKey) error {
	b, err := validSegmentBytes()
	if err != nil {
		return err
	}
	copy(b, "XRN3")
	repairHeaderCRC(b) // so the magic is the only thing wrong

	return headerVector(dir, "header-bad-magic", "bad_magic",
		"A segment whose first four bytes are not the ASCII magic CRN3, header CRC recomputed.",
		"Not a Cairn v3 segment: refused before any other field is trusted. The CRC is valid, so only "+
			"the magic check can reject it; an implementation that checks the CRC and then reads on has "+
			"accepted arbitrary bytes that happen to carry a matching checksum.",
		b, func(err error) bool { return errors.Is(err, format.ErrBadMagic) })
}

func vectorHeaderUnsupportedVersion(dir string, _, _ ed25519.PrivateKey) error {
	b, err := validSegmentBytes()
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(b[4:], format.FormatVersion+1)
	repairHeaderCRC(b)

	return headerVector(dir, "header-unsupported-format-version", "unsupported_format_version",
		fmt.Sprintf("A well-formed header declaring format_version %d, header CRC recomputed.", format.FormatVersion+1),
		"A newer format than this implementation reads. It must be refused as unsupported, not parsed "+
			"as v3 on a guess and not reported as corruption: the bytes are intact, so the segment must "+
			"not be deleted.",
		b, func(err error) bool { return strings.Contains(err.Error(), "unsupported format version") })
}

func vectorHeaderShort(dir string, _, _ ed25519.PrivateKey) error {
	b, err := validSegmentBytes()
	if err != nil {
		return err
	}
	b = b[:format.SegmentHeaderSize-28]

	return headerVector(dir, "header-short", "short_header",
		fmt.Sprintf("A segment file of %d bytes, shorter than the %d-byte header.", len(b), format.SegmentHeaderSize),
		"There is no complete header to check, so there is nothing to trust: refused, with no read past "+
			"the end of the buffer. The file is not deleted; a torn header is a power-cut shape, not worthless data.",
		b, func(err error) bool { return errors.Is(err, format.ErrShortHeader) })
}

// A frame header edit with the CRC repaired. The header is part of every frame's
// AAD, so a holder of no key can make the keyless scan pass but not the keyed one.
func vectorFrameHeaderTampered(dir string, _, _ ed25519.PrivateKey) error {
	const frames = 4
	w, err := buildSegment(0, format.ScanState{}, frames)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	start := format.SegmentHeaderSize + (frames-1)*frameLen
	b[start+12] ^= 0x01 // monotonic_ms: in no CRC chain, only in the AAD
	repairFrameCRC(b, start, frameLen)

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	if exp.StopReason != "EOF" || keyed.StopReason != "AUTH_FAILED" || *keyed.FramesRetained != frames-1 {
		return fmt.Errorf("frame-header-tampered: structural %s, keyed %s/%d frames; want EOF and AUTH_FAILED/%d",
			exp.StopReason, keyed.StopReason, *keyed.FramesRetained, frames-1)
	}
	return writeVector(dir, "frame-header-tampered", &expectation{
		Description: "The monotonic_ms field of the last of four frames edited, with the frame CRC recomputed.",
		Asserts: "A structural scan reaches EOF with four frames: the CRC is valid and the chain is intact. " +
			"A keyed scan stops at that frame with AUTH_FAILED and retains the three before it, because the " +
			"24-byte frame header is authenticated as AAD. A timestamp cannot be rewritten by anyone without the key.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(b))
}

// ─── manifest ───────────────────────────────────────────────────────────────

// manifestVector writes a manifest vector over files that carry only the manifest
// and its signature.
func manifestVector(dir, name, description, asserts string, exp *manifestExpectation, encoded, sig []byte) error {
	return writeVector(dir, name, &expectation{
		Description: description,
		Asserts:     asserts,
		Manifest:    exp,
	}, map[string][]byte{"manifest.cbor": encoded, "manifest.sig": sig})
}

func manifestDigestHex(encoded []byte) string {
	d := sha256.Sum256(encoded)
	return hex.EncodeToString(d[:])
}

func vectorManifestTamperedBody(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	encoded, sig, err := m.Sign(devicePriv)
	if err != nil {
		return err
	}
	pub := devicePriv.Public().(ed25519.PublicKey)

	tampered := append([]byte(nil), encoded...)
	at := bytes.Index(tampered, []byte(m.FirmwareVersion))
	if at < 0 || bytes.Count(tampered, []byte(m.FirmwareVersion)) != 1 {
		return errors.New("manifest-tampered-body: firmware_version not found exactly once")
	}
	tampered[at+len(m.FirmwareVersion)-1] ^= 0x01 // cairn-v3.0.0 -> cairn-v3.0.1, still canonical

	if _, err := format.ParseManifest(tampered); err != nil {
		return fmt.Errorf("manifest-tampered-body: the edit must keep the manifest well-formed: %w", err)
	}
	if _, err := format.VerifyManifest(tampered, sig, pub); !errors.Is(err, format.ErrBadSignature) {
		return fmt.Errorf("manifest-tampered-body: verified as %v", err)
	}

	return manifestVector(dir, "manifest-tampered-body",
		"A manifest signed as manifest-valid, then one byte of firmware_version edited; the original signature kept.",
		"The edited manifest is still canonical CBOR and still describes the same members, so only the "+
			"signature can reject it. The signature covers every byte of manifest.cbor: no field is editable "+
			"after signing, not even one that no other check reads.",
		&manifestExpectation{
			Valid: true, SignatureValid: false,
			ContentRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			DevicePublicKeyHex: hex.EncodeToString(pub),
			CanonicalBytesHex:  manifestDigestHex(tampered),
		}, tampered, sig)
}

func vectorManifestWrongDeviceKey(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	encoded, sig, err := m.Sign(attackerKey("manifest signer"))
	if err != nil {
		return err
	}
	pub := devicePriv.Public().(ed25519.PublicKey)
	if _, err := format.VerifyManifest(encoded, sig, pub); !errors.Is(err, format.ErrBadSignature) {
		return fmt.Errorf("manifest-wrong-device-key: verified as %v", err)
	}

	return manifestVector(dir, "manifest-wrong-device-key",
		"A well-formed manifest naming the device's identity, genuinely signed by a different Ed25519 key.",
		"The signature is mathematically valid, but not under the device key the verifier has enrolled. "+
			"Anyone can sign a manifest; what makes it the device's is the key. Verification is against the "+
			"enrolled key, never against a key carried by the artifact.",
		&manifestExpectation{
			Valid: true, SignatureValid: false,
			ContentRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			DevicePublicKeyHex: hex.EncodeToString(pub),
			CanonicalBytesHex:  manifestDigestHex(encoded),
		}, encoded, sig)
}

// malformedManifestVector signs bad bytes with the genuine device key, so the
// signature is not what refuses them.
func malformedManifestVector(dir, name, description, asserts string, devicePriv ed25519.PrivateKey, bad []byte) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	if _, err := format.ParseManifest(bad); err == nil {
		return fmt.Errorf("%s: the manifest parses", name)
	}
	sig := ed25519.Sign(devicePriv, bad)
	pub := devicePriv.Public().(ed25519.PublicKey)

	return manifestVector(dir, name, description, asserts,
		&manifestExpectation{
			Valid: false, SignatureValid: false,
			ContentRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			DevicePublicKeyHex: hex.EncodeToString(pub),
		}, bad, sig)
}

const malformedManifestNote = " signature_valid is false because verification is signature and then parse, " +
	"and the parse fails; the Ed25519 signature itself is correct over these bytes, so a verifier that " +
	"stops at the signature has accepted a manifest it cannot read."

func vectorManifestUnsupportedVersion(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	m.ManifestVersion = format.ManifestVersion + 1
	bad, err := m.MarshalCBOR()
	if err != nil {
		return err
	}
	return malformedManifestVector(dir, "manifest-unsupported-version",
		fmt.Sprintf("A canonically encoded manifest declaring manifest_version %d, correctly signed by the device key.", format.ManifestVersion+1),
		"A manifest from a newer schema must be refused as unsupported, not read as v3 with unknown "+
			"semantics. Valid: false."+malformedManifestNote,
		devicePriv, bad)
}

func vectorManifestNonCanonical(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	good, err := m.MarshalCBOR()
	if err != nil {
		return err
	}
	// manifest_version 3 written in two bytes (0x18 0x03) instead of one. Same value,
	// same meaning, different bytes.
	if !bytes.HasPrefix(good, []byte{0xb8, 0x1c, 0x01, 0x03}) {
		return errors.New("manifest-non-canonical: unexpected encoding prefix")
	}
	bad := append([]byte{0xb8, 0x1c, 0x01, 0x18, 0x03}, good[4:]...)

	return malformedManifestVector(dir, "manifest-non-canonical",
		"manifest-valid with manifest_version encoded in two bytes (0x18 0x03) instead of the shortest form, correctly signed by the device key.",
		"The value is unchanged but the bytes are not the deterministic encoding, so they are not the bytes "+
			"any conformant writer would sign. Refused: a verifier that accepts it is verifying bytes it would "+
			"never reproduce, which is how a signature comes to cover two different documents. Valid: false."+malformedManifestNote,
		devicePriv, bad)
}

func vectorManifestMissingField(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	good, err := m.MarshalCBOR()
	if err != nil {
		return err
	}
	// Drop key 28 (encryption_suite), the last entry, and say 27 fields: still
	// well-formed CBOR, still ascending, still deterministic. Only the mandatory
	// field is gone.
	entry := append([]byte{0x18, byte(keyEncryptionSuite), 0x78, byte(len(m.EncryptionSuite))}, m.EncryptionSuite...)
	if !bytes.HasSuffix(good, entry) {
		return errors.New("manifest-missing-mandatory-field: encryption_suite is not the last entry")
	}
	bad := append([]byte{0xb8, 0x1b}, good[2:len(good)-len(entry)]...)

	return malformedManifestVector(dir, "manifest-missing-mandatory-field",
		"A manifest with every field but encryption_suite (key 28), correctly signed by the device key.",
		"Keys 24 to 28 are mandatory so that a reader never has to guess how a bundle was bound or "+
			"protected. A manifest without one is refused outright and the missing field is never "+
			"defaulted. Valid: false."+malformedManifestNote,
		devicePriv, bad)
}

// keyEncryptionSuite is the manifest CBOR key of encryption_suite (spec 5.1).
const keyEncryptionSuite = 28

// ─── manifest binding ───────────────────────────────────────────────────────

// bindingMismatchVector builds a bundle whose manifest is genuine and whose
// members are digest-consistent, but where one binding rule is broken.
func bindingMismatchVector(dir, name, field, description, asserts string, devicePriv ed25519.PrivateKey,
	captureHeader func(*format.SegmentHeader), mutate func(files map[string][]byte)) error {

	vb, err := buildVectorBundleWith(devicePriv, captureHeader, mutate)
	if err != nil {
		return err
	}
	err = format.VerifyMembersAgainstManifest(vb.manifest, vb.segments())
	if !errors.Is(err, format.ErrManifestBindingMismatch) || !strings.Contains(err.Error(), field) {
		return fmt.Errorf("%s: binding verdict is %v, want a mismatch on %s", name, err, field)
	}
	return writeVector(dir, name, &expectation{
		Description: description,
		Asserts: asserts + " The manifest signature, content root and member digests are all valid: " +
			"a valid signature binds the manifest to the device, not the manifest to its segments.",
		Manifest: vb.manifestExpectation(devicePriv),
		Binding:  &bindingExpectation{Match: false, Field: field},
	}, vb.files)
}

// patchSegment edits a segment's header bytes in place and repairs its CRC.
func patchSegment(files map[string][]byte, name string, edit func(hdr []byte)) {
	edit(files[name])
	repairHeaderCRC(files[name])
}

func vectorBindingDeviceID(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-device-id-mismatch", "device_id",
		"A capture segment whose header names a different device than the manifest.",
		"device_id in every segment header must equal the manifest's: data from another unit cannot be "+
			"slipped under this device's signature.",
		devicePriv, func(h *format.SegmentHeader) {
			for i := range h.DeviceID {
				h.DeviceID[i] = byte(0xD0 + i)
			}
		}, nil)
}

func vectorBindingBootID(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-boot-id-mismatch", "boot_id",
		"A capture segment from a different boot than the manifest describes.",
		"boot_id in every segment header must equal the manifest's, journal included: ordering truth is "+
			"(boot_id, seq), so a segment from another boot cannot be spliced into this bundle.",
		devicePriv, func(h *format.SegmentHeader) {
			for i := range h.BootID {
				h.BootID[i] = byte(0xB0 + i)
			}
		}, nil)
}

func vectorBindingVehicleID(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-vehicle-id-mismatch", "vehicle_id",
		"A capture segment bound to a different vehicle than the manifest.",
		"vehicle_id in every segment header must equal the manifest's, so a bundle cannot be attributed "+
			"to one vehicle by its manifest and to another by its data.",
		devicePriv, func(h *format.SegmentHeader) {
			for i := range h.VehicleID {
				h.VehicleID[i] = byte(0x80 + i)
			}
		}, nil)
}

func vectorBindingDeviceCounter(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-device-counter-mismatch", "device_counter",
		"A capture segment carrying a different device_counter than the manifest.",
		"device_counter positions a bundle in the device's monotonic sequence and is what replay and "+
			"quarantine rules key on. A segment from another position must not ride on this bundle's counter.",
		devicePriv, func(h *format.SegmentHeader) { h.DeviceCounter = vectorDeviceCounter + 7 }, nil)
}

func vectorBindingKeyVersion(dir string, devicePriv, _ ed25519.PrivateKey) error {
	// The writer is keyed for version 1, so the header is edited afterwards.
	return bindingMismatchVector(dir, "manifest-key-version-mismatch", "storage_key_version",
		"A capture segment whose header declares a different storage_key_version than the manifest.",
		"storage_key_version selects the escrowed root a bundle is decoded with. A segment that names "+
			"another version than the manifest would be decoded under a key the manifest did not promise.",
		devicePriv, nil, func(files map[string][]byte) {
			patchSegment(files, "seg-00000000.seg", func(h []byte) {
				binary.LittleEndian.PutUint32(h[88:], altKeyVersion)
			})
		})
}

func vectorBindingSegmentIndex(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-segment-index-mismatch", "segment_index",
		"seg-00000000.seg whose header declares segment_index 1.",
		"For a capture segment, segment_index must equal the index in its member name. Without this a "+
			"segment could be renamed into another position while keeping the inputs to its own key derivation.",
		devicePriv, func(h *format.SegmentHeader) { h.SegmentIndex = 1 }, nil)
}

func vectorBindingJournalIndex(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-journal-index-mismatch", "segment_index",
		"journal.seg whose header declares segment_index 0 instead of the reserved 0xFFFFFFFF.",
		"The journal's segment_index is the reserved 0xFFFFFFFF. A journal that claims a capture index "+
			"is a capture segment in disguise.",
		devicePriv, nil, func(files map[string][]byte) {
			patchSegment(files, "journal.seg", func(h []byte) { binary.LittleEndian.PutUint32(h[72:], 0) })
		})
}

func vectorBindingSegmentGap(dir string, devicePriv, _ ed25519.PrivateKey) error {
	return bindingMismatchVector(dir, "manifest-segment-gap", "segment_index",
		"A manifest whose only capture segment is seg-00000002.seg, with segment_index 2 in its header.",
		"Capture segments must be named contiguously from seg-00000000. A gap means a segment, and the "+
			"frames chained through it, was removed, and it must be refused even though the name and the "+
			"header agree with each other and no member is missing from the bytes in hand.",
		devicePriv, func(h *format.SegmentHeader) { h.SegmentIndex = 2 }, func(files map[string][]byte) {
			files["seg-00000002.seg"] = files["seg-00000000.seg"]
			delete(files, "seg-00000000.seg")
		})
}

// ─── receipt ────────────────────────────────────────────────────────────────

// receiptVector writes a receipt vector. A non-empty parseError means the bytes
// themselves must be refused; the signature and acknowledgement fields are then
// both false, because nothing that cannot be read acknowledges anything.
func receiptVector(dir, name, description, asserts string, exp *receiptExpectation, encoded []byte) error {
	return writeVector(dir, name, &expectation{
		Description: description,
		Asserts:     asserts,
		Receipt:     exp,
	}, map[string][]byte{"receipt.cbor": encoded})
}

// checkReceiptRefused asserts the reference implementation does not take the
// receipt as an acknowledgement of uploaded.
func checkReceiptRefused(name string, encoded []byte, pub ed25519.PublicKey, uploaded [32]byte) error {
	r, err := format.ParseReceipt(encoded)
	if err != nil {
		return nil
	}
	if r.VerifyAcknowledges(pub, uploaded) == nil {
		return fmt.Errorf("%s: the receipt is accepted as an acknowledgement", name)
	}
	return nil
}

func vectorReceiptBadSignature(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	r := sampleReceipt(m.ContentRoot)
	encoded, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	// The signature is the trailing 64 bytes (key 11).
	bad := append([]byte(nil), encoded...)
	bad[len(bad)-64] ^= 0x01
	pub := serverPriv.Public().(ed25519.PublicKey)

	if err := checkReceiptRefused("receipt-bad-signature", bad, pub, m.ContentRoot); err != nil {
		return err
	}
	return receiptVector(dir, "receipt-bad-signature",
		"A receipt for the uploaded bundle whose signature has one flipped bit.",
		"The receipt names the right content root and parses, so only the signature check refuses it. "+
			"It is not an acknowledgement and no byte may be pruned on its strength.",
		&receiptExpectation{
			SignatureValid: false, Acknowledges: false,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ReceiptRootHex:     hex.EncodeToString(r.ContentRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		}, bad)
}

func vectorReceiptWrongServerKey(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	r := sampleReceipt(m.ContentRoot)
	encoded, err := r.Sign(attackerKey("receipt signer"))
	if err != nil {
		return err
	}
	pub := serverPriv.Public().(ed25519.PublicKey)

	if err := checkReceiptRefused("receipt-wrong-server-key", encoded, pub, m.ContentRoot); err != nil {
		return err
	}
	return receiptVector(dir, "receipt-wrong-server-key",
		"A receipt for the uploaded bundle, with the right content root, genuinely signed by a key that is not the pinned server key.",
		"The signature is valid under the signer's own key, and the root matches. Verification is "+
			"against the key the device pinned, never one the receipt carries: a forged receipt for a bundle "+
			"the server never stored is exactly how deletion is induced. Not an acknowledgement.",
		&receiptExpectation{
			SignatureValid: false, Acknowledges: false,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ReceiptRootHex:     hex.EncodeToString(r.ContentRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		}, encoded)
}

func vectorReceiptTamperedRoot(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	other := sha256.Sum256([]byte("some other bundle"))
	r := sampleReceipt(other)
	encoded, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	// Rewrite the root to the one the device uploaded, keeping the signature made
	// over the other root.
	if bytes.Count(encoded, other[:]) != 1 {
		return errors.New("receipt-tampered-content-root: root not found exactly once")
	}
	bad := bytes.Replace(encoded, other[:], m.ContentRoot[:], 1)
	pub := serverPriv.Public().(ed25519.PublicKey)

	if err := checkReceiptRefused("receipt-tampered-content-root", bad, pub, m.ContentRoot); err != nil {
		return err
	}
	return receiptVector(dir, "receipt-tampered-content-root",
		"A genuine receipt for another bundle with its content_root rewritten to the uploaded bundle's root; the signature is the original.",
		"The receipt now says exactly what the device wants to hear, which is the point of the attack: "+
			"the root matches the upload, so only the signature, which covers the root, refuses it. Checking "+
			"the root alone would let anyone edit a receipt into an acknowledgement.",
		&receiptExpectation{
			SignatureValid: false, Acknowledges: false,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ReceiptRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		}, bad)
}

// malformedReceiptVector is for bytes that must be refused before any signature
// is considered.
func malformedReceiptVector(dir, name, parseError, description, asserts string, serverPriv ed25519.PrivateKey, bad []byte) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	if _, err := format.ParseReceipt(bad); err == nil {
		return fmt.Errorf("%s: the receipt parses", name)
	}
	pub := serverPriv.Public().(ed25519.PublicKey)

	return receiptVector(dir, name, description,
		asserts+" parse_error names the reason; the expectation's other fields only say that nothing here acknowledges the upload.",
		&receiptExpectation{
			ParseError:     parseError,
			SignatureValid: false, Acknowledges: false,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		}, bad)
}

func vectorReceiptUnsupportedVersion(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	r := sampleReceipt(m.ContentRoot)
	r.ReceiptVersion = format.ReceiptVersion + 1
	bad, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	return malformedReceiptVector(dir, "receipt-unsupported-version", "unsupported_version",
		fmt.Sprintf("A receipt for the uploaded bundle declaring receipt_version %d, canonically encoded and correctly signed by the pinned server key.", format.ReceiptVersion+1),
		"A receipt in a schema this implementation does not read is refused as unsupported, even though the "+
			"signature is genuine: it cannot be known that a field this reader understands still means what "+
			"it did.", serverPriv, bad)
}

func vectorReceiptNonCanonical(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	r := sampleReceipt(m.ContentRoot)
	good, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	// ingest_schema_version (key 8) value 1 written as 0x18 0x01.
	needle := []byte{0x08, 0x01, 0x09, 0x82}
	if bytes.Count(good, needle) != 1 {
		return errors.New("receipt-non-canonical: ingest_schema_version not found exactly once")
	}
	bad := bytes.Replace(good, needle, []byte{0x08, 0x18, 0x01, 0x09, 0x82}, 1)

	return malformedReceiptVector(dir, "receipt-non-canonical", "non_canonical",
		"receipt-valid with ingest_schema_version encoded in two bytes (0x18 0x01) instead of one; the signature is the genuine one.",
		"Verification re-derives the signed bytes from the parsed fields, so a lenient parser would verify "+
			"the signature over bytes other than those received and accept this receipt. The receipt carries "+
			"its signature inline, so a non-canonical receipt must be refused at parse, before verification.",
		serverPriv, bad)
}

func vectorReceiptTruncated(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	good, err := sampleReceipt(m.ContentRoot).Sign(serverPriv)
	if err != nil {
		return err
	}
	return malformedReceiptVector(dir, "receipt-truncated", "truncated",
		"receipt-valid cut short by ten bytes, inside the signature.",
		"A receipt that ends mid-item is refused, with no read past the end of the buffer. A partial "+
			"transfer of a receipt is a normal fault and must not be mistaken for an acknowledgement.",
		serverPriv, good[:len(good)-10])
}

func vectorReceiptTrailingBytes(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}
	good, err := sampleReceipt(m.ContentRoot).Sign(serverPriv)
	if err != nil {
		return err
	}
	return malformedReceiptVector(dir, "receipt-trailing-bytes", "trailing_bytes",
		"receipt-valid followed by one extra zero byte.",
		"A receipt is exactly one CBOR item. Bytes after it are refused rather than ignored: unread "+
			"bytes are somewhere a second, unsigned claim can hide.",
		serverPriv, append(good, 0x00))
}

// ─── update descriptor ──────────────────────────────────────────────────────

func vectorUpdateDescriptorWrongKey(dir string, _, serverPriv ed25519.PrivateKey) error {
	updPub := ed25519.NewKeyFromSeed(updateKeySeed).Public().(ed25519.PublicKey)

	d := buildUpdateDescriptor()
	// Signed by the receipt key: a real signing key, just not the update authority.
	encoded, sig, err := d.Sign(serverPriv)
	if err != nil {
		return err
	}
	if _, err := format.VerifyUpdateDescriptor(encoded, sig, updPub); !errors.Is(err, format.ErrBadUpdateSignature) {
		return fmt.Errorf("update-descriptor-wrong-key: verified as %v", err)
	}

	return writeVector(dir, "update-descriptor-wrong-key", &expectation{
		Description: "A well-formed update descriptor signed by the receipt key instead of the update key.",
		Asserts: "The receipt key says data is safe to delete; the update key says code is safe to run. " +
			"They are different authorities and a signature by one is worthless as the other: a compromised " +
			"or misconfigured ingest server must not be able to push firmware. Refused, nothing installed.",
		Update: &updateExpectation{
			SignatureValid:     false,
			FirmwareVersion:    d.FirmwareVersion,
			MinFirmwareVersion: d.MinFirmwareVersion,
			ImageSHA256Hex:     hex.EncodeToString(d.ImageSHA256[:]),
			ImageLength:        d.ImageLength,
			UpdateKeyHex:       hex.EncodeToString(updPub),
		},
	}, map[string][]byte{"descriptor.cbor": encoded, "descriptor.sig": sig})
}

func vectorUpdateDescriptorTamperedBody(dir string, _, _ ed25519.PrivateKey) error {
	priv := ed25519.NewKeyFromSeed(updateKeySeed)
	pub := priv.Public().(ed25519.PublicKey)

	d := buildUpdateDescriptor()
	encoded, sig, err := d.Sign(priv)
	if err != nil {
		return err
	}
	tampered := append([]byte(nil), encoded...)
	if bytes.Count(tampered, d.ImageSHA256[:]) != 1 {
		return errors.New("update-descriptor-tampered-body: image digest not found exactly once")
	}
	at := bytes.Index(tampered, d.ImageSHA256[:])
	tampered[at] ^= 0x01
	if _, err := format.ParseUpdateDescriptor(tampered); err != nil {
		return fmt.Errorf("update-descriptor-tampered-body: the edit must keep the descriptor well-formed: %w", err)
	}
	if _, err := format.VerifyUpdateDescriptor(tampered, sig, pub); !errors.Is(err, format.ErrBadUpdateSignature) {
		return fmt.Errorf("update-descriptor-tampered-body: verified as %v", err)
	}
	edited := tampered[at : at+len(d.ImageSHA256)]

	return writeVector(dir, "update-descriptor-tampered-body", &expectation{
		Description: "A descriptor signed as update-descriptor-valid, then one bit of image_sha256 edited; the original signature kept.",
		Asserts: "The edited descriptor is well-formed and names a different image digest, so only the signature " +
			"refuses it. This is the substitution attack: the device would download an image and accept it " +
			"against the digest the attacker wrote. Refused before anything is downloaded.",
		Update: &updateExpectation{
			SignatureValid:     false,
			FirmwareVersion:    d.FirmwareVersion,
			MinFirmwareVersion: d.MinFirmwareVersion,
			ImageSHA256Hex:     hex.EncodeToString(edited[:]),
			ImageLength:        d.ImageLength,
			UpdateKeyHex:       hex.EncodeToString(pub),
		},
	}, map[string][]byte{"descriptor.cbor": tampered, "descriptor.sig": sig})
}
