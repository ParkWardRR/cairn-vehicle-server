// Package enroll is the server half of device enrolment: the sealed enrolment
// blob a dongle emits on its serial console, and the act of turning one into an
// enrolled device with an escrowed storage root.
//
// # Why a sealed blob
//
// A dongle generates its storage root K_root on first boot and must never let it
// leave in the clear: anyone who sees K_root can read every bundle that device
// ever writes, wherever the ciphertext ends up. The server, however, needs the
// root to decode. So the device seals K_root to a server enrolment public key
// (X25519 ephemeral-static, HKDF-SHA256, XChaCha20-Poly1305) and signs the whole
// blob with its own Ed25519 manifest key as proof of possession. The blob can
// then travel over a serial console, a terminal, ssh and a sudo log without
// exposing the root.
//
// # Layout (version 1, 225 bytes, all integers little-endian)
//
//	off  len  field
//	  0    4  magic "CENR"
//	  4    1  version = 1
//	  5   16  device_id
//	 21   32  device Ed25519 public key
//	 53    4  storage_key_version (u32le)
//	 57   32  ephemeral X25519 public key
//	 89   24  XChaCha20-Poly1305 nonce
//	113   32  ciphertext of K_root
//	145   16  Poly1305 tag
//	161   64  Ed25519 signature by the device key over bytes [0, 161)
//
//	shared = X25519(eph_priv, server_pub)
//	key    = HKDF-SHA256(ikm = shared, salt = eph_pub ‖ server_pub,
//	                     info = "cairn/enroll-seal/v1", L = 32)
//	ct‖tag = XChaCha20-Poly1305(key, nonce, K_root, aad = bytes [0, 113))
//
// The AAD covers every header field, so the identity, key and key version
// cannot be edited without failing the tag even by someone who could forge the
// signature; the signature covers the ciphertext too, so the blob as a whole is
// bound to the device key. Both checks run; neither is relied on alone.
//
// The firmware implementation (lib/cairn_prov/cairn_enroll.c) produces
// byte-identical blobs from the same inputs; contracts/enrolment/v1/vectors pins that.
package enroll

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// Blob layout constants.
const (
	Magic   = "CENR"
	Version = 1

	BlobSize = 225

	offVersion    = 4
	offDeviceID   = 5
	offPublicKey  = 21
	offKeyVersion = 53
	offEphemeral  = 57
	offNonce      = 89
	offCiphertext = 113
	offTag        = 145
	offSignature  = 161

	// HKDFInfo is the domain separator for the seal key. Versioned so that a
	// future blob format can never be opened by this derivation by accident.
	HKDFInfo = "cairn/enroll-seal/v1"

	// TextPrefix is how the device prints a blob on its console.
	TextPrefix = "ENROLL-BLOB "
)

var (
	// ErrMalformed means the bytes are not a version-1 enrolment blob.
	ErrMalformed = errors.New("malformed enrolment blob")
	// ErrBadSignature means the proof of possession does not verify.
	ErrBadSignature = errors.New("enrolment blob signature does not verify against its own public key")
	// ErrUnseal means the root could not be decrypted: the blob was sealed to a
	// different server enrolment key, or it was altered.
	ErrUnseal = errors.New("enrolment blob cannot be unsealed with this server's enrolment key " +
		"(sealed to a different key, or tampered with)")
)

// Opened is a verified, unsealed blob.
type Opened struct {
	DeviceID   [16]byte
	PublicKey  ed25519.PublicKey
	KeyVersion uint32
	Root       [32]byte
}

// Fingerprint is what a human compares between the dongle's console and the
// workstation.
func (o *Opened) Fingerprint() string { return Fingerprint(o.PublicKey) }

// Fingerprint returns the first 4 bytes of SHA-256(public key) as 8 lowercase
// hex characters.
//
// Short on purpose: it is read off one screen and typed into another. It is a
// mix-up check — "the blob I am approving came from the unit on my bench" — not
// a cryptographic authentication of the channel; see docs/device-provisioning.md
// for why a longer value would not buy more on this path.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}

// SealParams is everything a seal depends on. Seal is deterministic in these,
// which is what lets the firmware be checked byte for byte against Go.
type SealParams struct {
	DeviceID         [16]byte
	DeviceKey        ed25519.PrivateKey
	KeyVersion       uint32
	Root             [32]byte
	ServerPublic     [32]byte
	EphemeralPrivate [32]byte // from a CSPRNG, except in published vectors
	Nonce            [24]byte // likewise
}

// Seal builds a blob. Production sealing happens on the device; this exists for
// vectors, tests and the synthetic test device.
func Seal(p SealParams) ([]byte, error) {
	if len(p.DeviceKey) != ed25519.PrivateKeySize {
		return nil, errors.New("device key must be an Ed25519 private key")
	}
	if p.KeyVersion == 0 {
		return nil, errors.New("storage_key_version 0 is not a key version")
	}
	if p.ServerPublic == ([32]byte{}) {
		// Sealing to an all-zero key would "succeed" and lose the root. The
		// firmware refuses the same way.
		return nil, errors.New("server enrolment public key is the all-zero placeholder")
	}

	curve := ecdh.X25519()
	eph, err := curve.NewPrivateKey(p.EphemeralPrivate[:])
	if err != nil {
		return nil, fmt.Errorf("ephemeral key: %w", err)
	}
	serverPub, err := curve.NewPublicKey(p.ServerPublic[:])
	if err != nil {
		return nil, fmt.Errorf("server enrolment key: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()

	key, err := sealKey(eph, serverPub, ephPub, p.ServerPublic[:])
	if err != nil {
		return nil, err
	}

	pub := p.DeviceKey.Public().(ed25519.PublicKey)

	out := make([]byte, 0, BlobSize)
	out = append(out, Magic...)
	out = append(out, Version)
	out = append(out, p.DeviceID[:]...)
	out = append(out, pub...)
	out = binary.LittleEndian.AppendUint32(out, p.KeyVersion)
	out = append(out, ephPub...)
	out = append(out, p.Nonce[:]...)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	out = aead.Seal(out, p.Nonce[:], p.Root[:], out[:offCiphertext])
	out = append(out, ed25519.Sign(p.DeviceKey, out)...)

	if len(out) != BlobSize {
		return nil, fmt.Errorf("internal: sealed %d bytes, want %d", len(out), BlobSize)
	}
	return out, nil
}

func sealKey(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, ephPub, serverPub []byte) ([]byte, error) {
	// ecdh rejects an all-zero shared secret, which is what a low-order
	// ephemeral point produces. A blob carrying one is refused here rather than
	// opened under a key everybody knows.
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("%w: X25519: %w", ErrUnseal, err)
	}
	salt := make([]byte, 0, 64)
	salt = append(salt, ephPub...)
	salt = append(salt, serverPub...)
	return hkdf.Key(sha256.New, shared, salt, HKDFInfo, chacha20poly1305.KeySize)
}

// Header is the public part of a blob, readable without the server key.
type Header struct {
	DeviceID   [16]byte
	PublicKey  ed25519.PublicKey
	KeyVersion uint32
}

// Fingerprint of the blob's device key.
func (h *Header) Fingerprint() string { return Fingerprint(h.PublicKey) }

// Parse checks the structure and the proof of possession, without unsealing.
// Every caller that acts on a blob goes through here first, so an unsigned or
// truncated blob never reaches the key-agreement code.
func Parse(raw []byte) (*Header, error) {
	if len(raw) != BlobSize {
		return nil, fmt.Errorf("%w: %d bytes, want %d", ErrMalformed, len(raw), BlobSize)
	}
	if !bytes.Equal(raw[:4], []byte(Magic)) {
		return nil, fmt.Errorf("%w: bad magic %q", ErrMalformed, raw[:4])
	}
	if raw[offVersion] != Version {
		return nil, fmt.Errorf("%w: version %d, this server reads %d", ErrMalformed, raw[offVersion], Version)
	}

	var h Header
	copy(h.DeviceID[:], raw[offDeviceID:offPublicKey])
	h.PublicKey = ed25519.PublicKey(bytes.Clone(raw[offPublicKey:offKeyVersion]))
	h.KeyVersion = binary.LittleEndian.Uint32(raw[offKeyVersion:offEphemeral])

	if h.DeviceID == ([16]byte{}) {
		return nil, fmt.Errorf("%w: all-zero device_id", ErrMalformed)
	}
	if h.KeyVersion == 0 {
		return nil, fmt.Errorf("%w: storage_key_version 0", ErrMalformed)
	}
	if !ed25519.Verify(h.PublicKey, raw[:offSignature], raw[offSignature:]) {
		return nil, ErrBadSignature
	}
	return &h, nil
}

// Open verifies and unseals a blob with the server's enrolment private key.
func Open(raw []byte, serverKey *ecdh.PrivateKey) (*Opened, error) {
	h, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if serverKey == nil {
		return nil, errors.New("no server enrolment key")
	}

	ephPub := raw[offEphemeral:offNonce]
	peer, err := ecdh.X25519().NewPublicKey(ephPub)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %w", ErrMalformed, err)
	}
	key, err := sealKey(serverKey, peer, ephPub, serverKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, raw[offNonce:offCiphertext], raw[offCiphertext:offSignature], raw[:offCiphertext])
	if err != nil {
		return nil, ErrUnseal
	}

	o := &Opened{DeviceID: h.DeviceID, PublicKey: h.PublicKey, KeyVersion: h.KeyVersion}
	copy(o.Root[:], pt)
	clear(pt)
	if o.Root == ([32]byte{}) {
		// A device whose RNG produced nothing, or a blob built to probe us.
		// Escrowing it would "work" and protect nothing.
		return nil, fmt.Errorf("%w: the sealed storage root is all zero", ErrMalformed)
	}
	return o, nil
}

// EncodeText renders a blob the way the device prints it.
func EncodeText(raw []byte) string {
	return TextPrefix + base64.StdEncoding.EncodeToString(raw)
}

// DecodeText accepts either the device's full console line ("ENROLL-BLOB …")
// or the bare base64, with surrounding whitespace. Strict base64: non-canonical
// padding bits are refused, so one blob has exactly one text form.
func DecodeText(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, TextPrefix)
	s = strings.TrimSpace(s)
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: not base64: %w", ErrMalformed, err)
	}
	return raw, nil
}
