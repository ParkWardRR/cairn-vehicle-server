package format

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Sizes of the key material and AEAD parts. They are constants rather than
// values read from the cipher so the frame geometry in frame.go is a compile-time
// fact: MaxPayloadSize is derived from them, and a mismatch with the AEAD
// implementation is caught by a test, not discovered on a card.
const (
	// RootKeySize is the device storage root K_root.
	RootKeySize = 32
	// SegmentKeySize is a per-segment key K_seg.
	SegmentKeySize = 32
	// NonceSize is the XChaCha20-Poly1305 nonce carried in every frame.
	NonceSize = 24
	// TagSize is the Poly1305 authentication tag.
	TagSize = 16
	// AEADOverhead is what encryption adds to a payload: nonce plus tag.
	AEADOverhead = NonceSize + TagSize // 40
)

// EncryptionSuiteV1 names the AEAD and KDF this format version uses. It is
// recorded in the signed manifest so a future suite is an explicit, detectable
// change rather than something inferred from key length.
const EncryptionSuiteV1 = "xchacha20poly1305+hkdf-sha256/v1"

// hkdfInfoLabel is the fixed prefix of the HKDF info string. The label binds the
// derived key to this purpose: the same K_root is never used for anything else,
// but the label means that stays true even if some later feature derives other
// keys from it.
const hkdfInfoLabel = "cairn/segment/v3"

var (
	// ErrNoKey means the provider holds no key for the segment's device. The
	// segment may still be structurally scanned, but not decrypted.
	ErrNoKey = errors.New("no storage key available for segment")

	// ErrKeyVersionMismatch means the segment was written under a different
	// storage_key_version than the key the provider holds. Deriving anyway would
	// produce a key that fails every tag, which is indistinguishable from
	// tampering; refusing up front says what is actually wrong.
	ErrKeyVersionMismatch = errors.New("segment storage_key_version does not match the provider's key")

	// ErrAuthFailed means a frame's authentication tag did not verify. The frame
	// was structurally valid (CRC, chain, sequence) but its ciphertext, its
	// header, or the segment it sits in is not what the writer sealed.
	ErrAuthFailed = errors.New("frame authentication failed")
)

// KeyProvider supplies the per-segment key for a segment header.
//
// The segment header, not the caller, is the authority on which key applies, so
// the interface takes the parsed header. An implementation that needs a per-device
// lookup (a server holding many escrowed roots) reads h.DeviceID and
// h.StorageKeyVersion; a device holding its own root ignores both after
// checking them.
//
// A nil KeyProvider is meaningful everywhere one is accepted: it requests a
// structural scan only. CRC, chain, sequence, Merkle and chunking all work
// without any key because they are computed over ciphertext.
type KeyProvider interface {
	SegmentKey(h *SegmentHeader) ([SegmentKeySize]byte, error)
}

// DeriveSegmentKey computes K_seg from a storage root and a segment header:
//
//	K_seg = HKDF-SHA256(ikm  = K_root,
//	                    salt = vehicle_id,
//	                    info = "cairn/segment/v3" || device_id || assignment_id
//	                           || boot_id || segment_index u32le,
//	                    L    = 32)
//
// Every identifier is mixed in so that a key is useless anywhere but the one
// segment it was derived for. The vehicle id is the salt rather than part of
// info because it is the identifier that must never be shared between keys for
// different vehicles: a thief who obtains one vehicle's derived keys learns
// nothing about another's even under the same device root.
//
// storage_key_version and device_counter are deliberately not inputs. The
// version selects which K_root to use, and the counter is bound through the AAD
// (see SegmentCipher); keeping them out of the KDF means rotating a counter
// never changes a key.
func DeriveSegmentKey(root [RootKeySize]byte, h *SegmentHeader) ([SegmentKeySize]byte, error) {
	var out [SegmentKeySize]byte

	info := make([]byte, 0, len(hkdfInfoLabel)+16*3+4)
	info = append(info, hkdfInfoLabel...)
	info = append(info, h.DeviceID[:]...)
	info = append(info, h.AssignmentID[:]...)
	info = append(info, h.BootID[:]...)
	info = binary.LittleEndian.AppendUint32(info, h.SegmentIndex)

	k, err := hkdf.Key(sha256.New, root[:], h.VehicleID[:], string(info), SegmentKeySize)
	if err != nil {
		return out, fmt.Errorf("derive segment key: %w", err)
	}
	copy(out[:], k)
	return out, nil
}

// RootKeyProvider derives segment keys from a single device storage root. It is
// what a device uses for its own segments and what a tool uses when given one
// device's escrowed root.
type RootKeyProvider struct {
	Root    [RootKeySize]byte
	Version uint32 // the storage_key_version this root is
}

// SegmentKey implements KeyProvider.
func (p *RootKeyProvider) SegmentKey(h *SegmentHeader) ([SegmentKeySize]byte, error) {
	if h.StorageKeyVersion != p.Version {
		return [SegmentKeySize]byte{}, fmt.Errorf("%w: segment is version %d, provider holds version %d",
			ErrKeyVersionMismatch, h.StorageKeyVersion, p.Version)
	}
	return DeriveSegmentKey(p.Root, h)
}

// RootKeyResolver finds a device's escrowed storage root. The server's keystore
// implements it; this package defines only the shape so format stays free of
// storage concerns.
//
// An implementation returns ErrNoKey for an unknown device and
// ErrKeyVersionMismatch (or any wrapping of it) for a version it does not hold.
type RootKeyResolver interface {
	RootKey(deviceID [16]byte, version uint32) ([RootKeySize]byte, error)
}

// ResolverKeyProvider is a KeyProvider over a RootKeyResolver, for callers that
// handle many devices.
type ResolverKeyProvider struct {
	Resolver RootKeyResolver
}

// SegmentKey implements KeyProvider.
func (p ResolverKeyProvider) SegmentKey(h *SegmentHeader) ([SegmentKeySize]byte, error) {
	root, err := p.Resolver.RootKey(h.DeviceID, h.StorageKeyVersion)
	if err != nil {
		return [SegmentKeySize]byte{}, err
	}
	return DeriveSegmentKey(root, h)
}
