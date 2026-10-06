package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/enroll"
)

// Negative vectors for the sealed enrolment blob (contracts/enrolment/v1).
//
// The positive vectors, vectors.json, are written by `go test ./internal/enroll
// -update`. These are written here, beside the format negatives, into negative.json,
// and derive from the same published inputs as the first positive vector ("first
// enrolment, key version 1") so that each one is that blob with one thing wrong.
//
// A vector is a blob (or its console text), the server enrolment key it is offered
// to, and the fingerprint the operator confirmed. The verdict is the first refusal
// of the acceptance path: decode the text, check structure and signature, check the
// fingerprint, unseal. Sequences add the state a repeat needs, which only a server
// has; the dongle never opens a blob, so no firmware consumer runs them.

type enrolNegative struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	Blob               string `json:"blob,omitempty"`      // hex
	BlobText           string `json:"blob_text,omitempty"` // as the console prints it, instead of blob
	ServerPrivateKey   string `json:"server_private_key"`
	ConfirmFingerprint string `json:"confirm_fingerprint"`
	Error              string `json:"error"`
}

type enrolStep struct {
	Action             string `json:"action"` // enrol, destroy_key, revoke
	Blob               string `json:"blob,omitempty"`
	ConfirmFingerprint string `json:"confirm_fingerprint,omitempty"`
	DeviceID           string `json:"device_id,omitempty"`
	KeyVersion         uint32 `json:"key_version,omitempty"`
	// Error is the refusal class; empty means the step succeeds.
	Error               string `json:"error"`
	RootAlreadyEscrowed *bool  `json:"root_already_escrowed,omitempty"`
}

type enrolSequence struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Steps       []enrolStep `json:"steps"`
}

type enrolNegativeFile struct {
	Description      string          `json:"description"`
	Spec             string          `json:"spec"`
	Notes            []string        `json:"notes"`
	ServerPrivateKey string          `json:"server_private_key"`
	DeviceID         string          `json:"device_id"`
	Fingerprint      string          `json:"fingerprint"`
	Vectors          []enrolNegative `json:"vectors"`
	Sequences        []enrolSequence `json:"sequences"`
}

// enrolLabel is the derivation the positive vectors use: a fixed value from a
// public string, so no input is a real key.
func enrolLabel(s string) [32]byte {
	return sha256.Sum256([]byte("cairn/enroll-v1 PUBLIC TEST VECTOR: " + s))
}

type enrolBase struct {
	devKey     ed25519.PrivateKey
	deviceID   [16]byte
	root       [32]byte
	server     *ecdh.PrivateKey
	serverPub  [32]byte
	eph        [32]byte
	nonce      [24]byte
	keyVersion uint32
}

// newEnrolBase rebuilds the first positive vector's inputs.
func newEnrolBase() (*enrolBase, error) {
	b := &enrolBase{keyVersion: 1}
	seed := enrolLabel("v1 device seed")
	b.devKey = ed25519.NewKeyFromSeed(seed[:])
	b.root = enrolLabel("v1 storage root")
	serverSeed := enrolLabel("v1 server enrolment key")
	var err error
	if b.server, err = ecdh.X25519().NewPrivateKey(serverSeed[:]); err != nil {
		return nil, err
	}
	copy(b.serverPub[:], b.server.PublicKey().Bytes())
	b.eph = enrolLabel("v1 ephemeral key")
	n := enrolLabel("v1 nonce")
	copy(b.nonce[:], n[:])
	for i := range b.deviceID {
		b.deviceID[i] = byte(0xa0 + i)
	}
	return b, nil
}

func (b *enrolBase) params() enroll.SealParams {
	return enroll.SealParams{
		DeviceID: b.deviceID, DeviceKey: b.devKey, KeyVersion: b.keyVersion, Root: b.root,
		ServerPublic: b.serverPub, EphemeralPrivate: b.eph, Nonce: b.nonce,
	}
}

// Blob layout offsets (enrolment spec).
const (
	enrVersion    = 4
	enrDeviceID   = 5
	enrPublicKey  = 21
	enrKeyVersion = 53
	enrEphemeral  = 57
	enrNonce      = 89
	enrCiphertext = 113
	enrTag        = 145
	enrSignature  = 161
)

func resignBlob(blob []byte, key ed25519.PrivateKey) {
	copy(blob[enrSignature:], ed25519.Sign(key, blob[:enrSignature]))
}

func enrolFingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}

// classifyEnrolment names the refusal an acceptance path gave, in the vocabulary
// of negative.json.
func classifyEnrolment(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, enroll.ErrMalformed):
		return "malformed"
	case errors.Is(err, enroll.ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, enroll.ErrUnseal):
		return "unseal"
	case errors.Is(err, enroll.ErrFingerprintMismatch):
		return "fingerprint_mismatch"
	case errors.Is(err, enroll.ErrFingerprintRequired):
		return "fingerprint_required"
	case strings.Contains(err.Error(), "fingerprint must be"):
		return "fingerprint_invalid"
	}
	return "other: " + err.Error()
}

// acceptBlob runs the stateless part of the acceptance path against the reference
// implementation.
func acceptBlob(n *enrolNegative) string {
	var raw []byte
	var err error
	if n.BlobText != "" {
		raw, err = enroll.DecodeText(n.BlobText)
	} else {
		raw, err = hex.DecodeString(n.Blob)
	}
	if err != nil {
		return classifyEnrolment(err)
	}
	if _, err = enroll.NormalizeFingerprint(n.ConfirmFingerprint); err != nil {
		return classifyEnrolment(err)
	}
	h, err := enroll.Parse(raw)
	if err != nil {
		return classifyEnrolment(err)
	}
	if h.Fingerprint() != strings.ToLower(n.ConfirmFingerprint) {
		return "fingerprint_mismatch"
	}
	seed, _ := hex.DecodeString(n.ServerPrivateKey)
	server, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return "other: " + err.Error()
	}
	_, err = enroll.Open(raw, server)
	return classifyEnrolment(err)
}

func writeEnrolmentNegatives(dir string) error {
	base, err := newEnrolBase()
	if err != nil {
		return err
	}
	good, err := enroll.Seal(base.params())
	if err != nil {
		return err
	}
	if err := checkAgainstPositive(dir, good); err != nil {
		return err
	}

	pub := base.devKey.Public().(ed25519.PublicKey)
	genuineFP := enrolFingerprint(pub)
	serverSeed := enrolLabel("v1 server enrolment key")
	serverHex := hex.EncodeToString(serverSeed[:])
	otherServerSeed := enrolLabel("other server enrolment key")
	otherServerHex := hex.EncodeToString(otherServerSeed[:])
	attacker := attackerKey("enrolment device")

	// mutated returns a copy of the genuine blob with edit applied, re-signed by the
	// device key when resign is set.
	mutated := func(edit func(b []byte), resign bool) []byte {
		b := bytes.Clone(good)
		edit(b)
		if resign {
			resignBlob(b, base.devKey)
		}
		return b
	}

	var vectors []enrolNegative
	add := func(name, description string, blob []byte, serverKey, confirm, wantErr string) error {
		if confirm == "" && len(blob) == len(good) {
			confirm = enrolFingerprint(blob[enrPublicKey:enrKeyVersion])
		} else if confirm == "" {
			confirm = genuineFP
		}
		v := enrolNegative{
			Name: name, Description: description, Blob: hex.EncodeToString(blob),
			ServerPrivateKey: serverKey, ConfirmFingerprint: confirm, Error: wantErr,
		}
		return addEnrolVector(&vectors, v)
	}
	addText := func(name, description, text, wantErr string) error {
		return addEnrolVector(&vectors, enrolNegative{
			Name: name, Description: description, BlobText: text,
			ServerPrivateKey: serverHex, ConfirmFingerprint: genuineFP, Error: wantErr,
		})
	}

	type blobCase struct {
		name, description string
		blob              []byte
		serverKey         string
		confirm           string
		err               string
	}
	cases := []blobCase{
		{"signature-bit-flipped", "The genuine blob with one bit of the signature flipped.",
			mutated(func(b []byte) { b[enrSignature+10] ^= 1 }, false), serverHex, "", "bad_signature"},
		{"signed-by-another-key", "The genuine blob re-signed by a different Ed25519 key, the public key field untouched.",
			mutated(func(b []byte) { copy(b[enrSignature:], ed25519.Sign(attacker, b[:enrSignature])) }, false),
			serverHex, "", "bad_signature"},
		{"device-id-edited", "The genuine blob with a device_id bit flipped and the signature left as it was.",
			mutated(func(b []byte) { b[enrDeviceID] ^= 1 }, false), serverHex, "", "bad_signature"},
		{"key-version-edited", "The genuine blob with a storage_key_version bit flipped and the signature left as it was.",
			mutated(func(b []byte) { b[enrKeyVersion+1] ^= 1 }, false), serverHex, "", "bad_signature"},
		{"ciphertext-edited", "The genuine blob with a ciphertext bit flipped and the signature left as it was.",
			mutated(func(b []byte) { b[enrCiphertext+7] ^= 1 }, false), serverHex, "", "bad_signature"},
		{"tag-edited", "The genuine blob with a Poly1305 tag bit flipped and the signature left as it was.",
			mutated(func(b []byte) { b[enrTag] ^= 1 }, false), serverHex, "", "bad_signature"},

		// The signature is valid in each of these; the AEAD is what refuses them.
		{"device-id-edited-resigned", "device_id edited and the blob re-signed with the device key, as someone able to forge the signature would.",
			mutated(func(b []byte) { b[enrDeviceID] ^= 1 }, true), serverHex, "", "unseal"},
		{"key-version-edited-resigned", "storage_key_version edited and re-signed.",
			mutated(func(b []byte) { b[enrKeyVersion+1] ^= 1 }, true), serverHex, "", "unseal"},
		{"ephemeral-key-edited-resigned", "The ephemeral X25519 key edited and re-signed.",
			mutated(func(b []byte) { b[enrEphemeral+3] ^= 0x40 }, true), serverHex, "", "unseal"},
		{"nonce-edited-resigned", "The nonce edited and re-signed.",
			mutated(func(b []byte) { b[enrNonce] ^= 1 }, true), serverHex, "", "unseal"},
		{"ciphertext-edited-resigned", "The ciphertext edited and re-signed.",
			mutated(func(b []byte) { b[enrCiphertext+7] ^= 1 }, true), serverHex, "", "unseal"},
		{"tag-edited-resigned", "The Poly1305 tag edited and re-signed.",
			mutated(func(b []byte) { b[enrTag] ^= 1 }, true), serverHex, "", "unseal"},
		{"low-order-ephemeral-key-resigned", "The ephemeral key replaced by the all-zero point, a low-order point whose shared secret is all zero, and re-signed.",
			mutated(func(b []byte) { clear(b[enrEphemeral:enrNonce]) }, true), serverHex, "", "unseal"},
		{"public-key-swapped-resigned", "The device public key replaced with another key's and re-signed by that key: the proof of possession is genuine, for the wrong key. The operator confirms that key's fingerprint.",
			func() []byte {
				b := bytes.Clone(good)
				copy(b[enrPublicKey:enrKeyVersion], attacker.Public().(ed25519.PublicKey))
				resignBlob(b, attacker)
				return b
			}(), serverHex, "", "unseal"},
		{"sealed-to-another-server-key", "The genuine blob offered to a server whose enrolment key is not the one it was sealed to.",
			good, otherServerHex, "", "unseal"},

		{"bad-magic", "The first four bytes are XENR, not CENR.",
			mutated(func(b []byte) { b[0] = 'X' }, true), serverHex, "", "malformed"},
		{"unsupported-version", "version 2, re-signed.",
			mutated(func(b []byte) { b[enrVersion] = 2 }, true), serverHex, "", "malformed"},
		{"zero-device-id", "An all-zero device_id, re-signed.",
			mutated(func(b []byte) { clear(b[enrDeviceID:enrPublicKey]) }, true), serverHex, "", "malformed"},
		{"zero-key-version", "storage_key_version 0, re-signed.",
			mutated(func(b []byte) { binary.LittleEndian.PutUint32(b[enrKeyVersion:], 0) }, true), serverHex, "", "malformed"},
		{"truncated", "The genuine blob minus its last byte (224 bytes).",
			good[:len(good)-1], serverHex, "", "malformed"},
		{"extended", "The genuine blob plus one zero byte (226 bytes).",
			append(bytes.Clone(good), 0), serverHex, "", "malformed"},
		{"empty", "Zero bytes.", nil, serverHex, "", "malformed"},
	}

	// A device whose RNG produced nothing seals an all-zero root. Every check
	// passes; escrowing it would protect nothing.
	zeroRoot := base.params()
	zeroRoot.Root = [32]byte{}
	zeroRootBlob, err := enroll.Seal(zeroRoot)
	if err != nil {
		return err
	}
	cases = append(cases, blobCase{"zero-root", "A correctly signed and sealed blob whose storage root is 32 zero bytes.",
		zeroRootBlob, serverHex, "", "malformed"})

	for _, c := range cases {
		if err := add(c.name, c.description, c.blob, c.serverKey, c.confirm, c.err); err != nil {
			return err
		}
	}

	// What the operator typed.
	for _, c := range []struct{ name, description, confirm, err string }{
		{"fingerprint-mismatch", "The genuine blob, confirmed with the fingerprint of a different unit (00000000).", "00000000", "fingerprint_mismatch"},
		{"fingerprint-missing", "The genuine blob with no fingerprint confirmed: there is no approve-whatever-arrived mode.", "", "fingerprint_required"},
		{"fingerprint-too-short", "The genuine blob, confirmed with 6 hex characters.", genuineFP[:6], "fingerprint_invalid"},
		{"fingerprint-not-hex", "The genuine blob, confirmed with an 8-character value that is not hex.", genuineFP[:7] + "z", "fingerprint_invalid"},
	} {
		v := enrolNegative{Name: c.name, Description: c.description, Blob: hex.EncodeToString(good),
			ServerPrivateKey: serverHex, ConfirmFingerprint: c.confirm, Error: c.err}
		if err := addEnrolVector(&vectors, v); err != nil {
			return err
		}
	}

	// The console text. A blob has exactly one text form.
	text := base64.StdEncoding.EncodeToString(good)
	if strings.Contains(text, "=") || !strings.ContainsAny(text, "+/") {
		return fmt.Errorf("enrolment negatives: the base blob text no longer exercises padding and the URL alphabet")
	}
	for _, c := range []struct{ name, description, text string }{
		{"text-extra-padding", "The base64 of the genuine blob with a trailing =.", text + "="},
		{"text-inner-space", "The base64 of the genuine blob with a space inside it.", text[:10] + " " + text[10:]},
		{"text-truncated", "The base64 of the genuine blob minus its last four characters (222 bytes).", text[:len(text)-4]},
		{"text-url-alphabet", "The genuine blob in the URL-safe base64 alphabet (- and _ for + and /).", strings.NewReplacer("+", "-", "/", "_").Replace(text)},
		{"text-not-base64", "A console line that is not base64.", "ENROLL-BLOB this is not base64!"},
	} {
		if err := addText(c.name, c.description, c.text, "malformed"); err != nil {
			return err
		}
	}

	seqs, err := enrolSequences(base, good, genuineFP, serverHex)
	if err != nil {
		return err
	}

	doc := enrolNegativeFile{
		Description: "Negative vectors for the sealed enrolment blob. Every key here is a PUBLIC TEST KEY derived from a published label; none protects anything.",
		Spec:        "contracts/enrolment/v1/spec.md",
		Notes: []string{
			"Each vector derives from the 'first enrolment, key version 1' blob in vectors.json with one thing wrong. 'blob' is hex; 'blob_text' is the console line or bare base64 and replaces it.",
			"The verdict is the FIRST refusal of this acceptance path: decode the text; check the fingerprint the operator typed is well formed; parse (length, magic, version, non-zero ids, then the proof-of-possession signature); compare the typed fingerprint with the blob's; unseal with server_private_key and refuse an all-zero root.",
			"error classes: malformed, bad_signature, unseal, fingerprint_mismatch, fingerprint_required, fingerprint_invalid. A conformant opener refuses every vector and names the class.",
			"confirm_fingerprint is what the operator typed: the fingerprint of the device key inside the blob, unless the vector is about the fingerprint.",
			"Sequences carry server state (an escrow, a registry) and are run only by a server. The dongle seals blobs and never opens one, so it has nothing to refuse here. Within a sequence 'error' is empty when the step succeeds.",
			"A replay of the very same blob is NOT refused: re-enrolling an identical blob changes nothing and succeeds, so a half-finished enrolment can be re-run. What a replay cannot do is bring back what has since been destroyed or revoked; see the sequences.",
		},
		ServerPrivateKey: serverHex,
		DeviceID:         hex.EncodeToString(base.deviceID[:]),
		Fingerprint:      genuineFP,
		Vectors:          vectors,
		Sequences:        seqs,
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "negative.json"), append(encoded, '\n'), 0o644)
}

// addEnrolVector appends v after checking that the reference implementation
// really gives the stated refusal, so a vector that stops being negative fails
// generation.
func addEnrolVector(vectors *[]enrolNegative, v enrolNegative) error {
	if got := acceptBlob(&v); got != v.Error {
		return fmt.Errorf("enrolment negative %q: reference refusal is %q, want %q", v.Name, got, v.Error)
	}
	*vectors = append(*vectors, v)
	return nil
}

// checkAgainstPositive refuses to write negatives that no longer derive from the
// published positive vector.
func checkAgainstPositive(dir string, good []byte) error {
	raw, err := os.ReadFile(filepath.Join(dir, "vectors.json"))
	if err != nil {
		return fmt.Errorf("enrolment negatives need the positive vectors beside them: %w", err)
	}
	var f struct {
		Vectors []struct {
			Blob string `json:"blob"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil || len(f.Vectors) == 0 {
		return fmt.Errorf("enrolment negatives: cannot read vectors.json: %v", err)
	}
	if f.Vectors[0].Blob != hex.EncodeToString(good) {
		return fmt.Errorf("enrolment negatives: the base blob differs from vectors.json's first vector; regenerate one or the other")
	}
	return nil
}

// enrolSequences are the refusals that depend on what the server already holds.
func enrolSequences(base *enrolBase, good []byte, genuineFP, serverHex string) ([]enrolSequence, error) {
	idHex := hex.EncodeToString(base.deviceID[:])
	goodHex := hex.EncodeToString(good)

	// Same device, key version and signing key; a different root. The unit was
	// re-keyed, or a clone is claiming its id.
	rekeyed := base.params()
	rekeyed.Root = enrolLabel("v1 storage root, re-keyed")
	rekeyedBlob, err := enroll.Seal(rekeyed)
	if err != nil {
		return nil, err
	}

	// Same device id and key version, another signing key.
	other := attackerKey("enrolment device")
	cloned := base.params()
	cloned.DeviceKey = other
	clonedBlob, err := enroll.Seal(cloned)
	if err != nil {
		return nil, err
	}
	clonedFP := enrolFingerprint(other.Public().(ed25519.PublicKey))

	yes := true
	enrol := func(blob, fp, wantErr string) enrolStep {
		return enrolStep{Action: "enrol", Blob: blob, ConfirmFingerprint: fp, Error: wantErr}
	}
	first := enrol(goodHex, genuineFP, "")
	again := enrol(goodHex, genuineFP, "")
	again.RootAlreadyEscrowed = &yes

	return []enrolSequence{
		{
			Name:        "replay-of-the-same-blob",
			Description: "The same blob enrolled twice. The second succeeds and reports the root already escrowed: a replay changes nothing.",
			Steps:       []enrolStep{first, again},
		},
		{
			Name:        "replay-after-crypto-shred",
			Description: "A blob enrolled, its key version then crypto-shredded, and the captured blob replayed. A destroyed version cannot be brought back by presenting its blob again.",
			Steps: []enrolStep{
				first,
				{Action: "destroy_key", DeviceID: idHex, KeyVersion: base.keyVersion},
				enrol(goodHex, genuineFP, "root_shredded"),
			},
		},
		{
			Name:        "replay-after-revocation",
			Description: "A blob enrolled, the device then revoked, and the captured blob replayed. Re-enrolment must not silently un-revoke a device.",
			Steps: []enrolStep{
				first,
				{Action: "revoke", DeviceID: idHex},
				enrol(goodHex, genuineFP, "revoked_device"),
			},
		},
		{
			Name:        "same-version-different-root",
			Description: "A different storage root offered for a device and key version that already has one escrowed. The escrow is write-once per version.",
			Steps:       []enrolStep{first, enrol(hex.EncodeToString(rekeyedBlob), genuineFP, "root_mismatch")},
		},
		{
			Name:        "same-device-id-different-signing-key",
			Description: "A device id that is already enrolled, offered with another signing key. Refused unless the operator deliberately allows a key change.",
			Steps:       []enrolStep{first, enrol(hex.EncodeToString(clonedBlob), clonedFP, "key_changed")},
		},
	}, nil
}
