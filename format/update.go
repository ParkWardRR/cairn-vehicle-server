package format

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// UpdateDescriptor names a firmware image and the constraints on installing it
// (docs/ota.md).
//
// Signed by an update key that is deliberately separate from the receipt key:
// the receipt key says "this data is safe to delete", the update key says "this
// code is safe to run". A server compromised enough to issue false receipts
// costs stored trips; one that could also sign firmware owns the device.
type UpdateDescriptor struct {
	DescriptorVersion uint8
	FirmwareVersion   string
	ImageSHA256       [32]byte
	ImageLength       uint32

	// MinFirmwareVersion refuses the install over anything older. Empty means
	// no constraint.
	MinFirmwareVersion string

	// BuildUTCMS is informational only and never an ordering key — the same
	// rule the bundle format applies to wall-clock time.
	BuildUTCMS uint64

	SignatureAlgorithm string
}

// Update descriptor CBOR keys.
const (
	updKeyDescriptorVersion = 1
	updKeyFirmwareVersion   = 2
	updKeyImageSHA256       = 3
	updKeyImageLength       = 4
	updKeyMinFirmware       = 5
	updKeyBuildUTCMS        = 6
	updKeySignatureAlgo     = 7

	updateFieldCount = 7

	// UpdateDescriptorVersion is the only descriptor version this build emits
	// or accepts.
	UpdateDescriptorVersion = 1
)

// ErrBadUpdateSignature means the descriptor signature did not verify against
// the pinned update key.
var ErrBadUpdateSignature = errors.New("update descriptor signature verification failed")

// MarshalCBOR encodes the descriptor deterministically. The result is exactly
// the bytes the signature covers, so there is nothing to strip or re-encode
// before verifying.
func (u *UpdateDescriptor) MarshalCBOR() ([]byte, error) {
	if u.SignatureAlgorithm == "" {
		return nil, errors.New("update descriptor: signature algorithm is empty")
	}
	if u.FirmwareVersion == "" {
		return nil, errors.New("update descriptor: firmware version is empty")
	}
	if u.ImageLength == 0 {
		return nil, errors.New("update descriptor: image length is zero")
	}

	e := &cborEncoder{}
	e.mapHeader(updateFieldCount)

	e.key(updKeyDescriptorVersion)
	e.uint(uint64(u.DescriptorVersion))
	e.key(updKeyFirmwareVersion)
	e.text(u.FirmwareVersion)
	e.key(updKeyImageSHA256)
	e.bytes(u.ImageSHA256[:])
	e.key(updKeyImageLength)
	e.uint(uint64(u.ImageLength))
	e.key(updKeyMinFirmware)
	e.text(u.MinFirmwareVersion)
	e.key(updKeyBuildUTCMS)
	e.uint(u.BuildUTCMS)
	e.key(updKeySignatureAlgo)
	e.text(u.SignatureAlgorithm)

	return e.buf, nil
}

// ParseUpdateDescriptor decodes a descriptor, rejecting anything it would not
// itself have produced.
//
// Strict for the same reason the manifest decoder is: a descriptor whose bytes
// cannot be reproduced cannot have its signature re-checked later, and this is
// the one signature whose failure mode is an unbootable device.
func ParseUpdateDescriptor(b []byte) (*UpdateDescriptor, error) {
	d := &cborDecoder{buf: b}

	n, err := d.mapHeader()
	if err != nil {
		return nil, fmt.Errorf("update descriptor: %w", err)
	}
	if n != updateFieldCount {
		return nil, fmt.Errorf("update descriptor has %d fields, want %d",
			n, updateFieldCount)
	}

	var out UpdateDescriptor

	for i := 0; i < n; i++ {
		key, err := d.uint()
		if err != nil {
			return nil, fmt.Errorf("update descriptor key %d: %w", i, err)
		}

		switch key {
		case updKeyDescriptorVersion:
			v, err := d.uint8()
			if err != nil {
				return nil, fmt.Errorf("descriptor_version: %w", err)
			}
			out.DescriptorVersion = v
		case updKeyFirmwareVersion:
			v, err := d.text()
			if err != nil {
				return nil, fmt.Errorf("firmware_version: %w", err)
			}
			out.FirmwareVersion = v
		case updKeyImageSHA256:
			v, err := d.bytesN(32)
			if err != nil {
				return nil, fmt.Errorf("image_sha256: %w", err)
			}
			copy(out.ImageSHA256[:], v)
		case updKeyImageLength:
			v, err := d.uint32()
			if err != nil {
				return nil, fmt.Errorf("image_length: %w", err)
			}
			out.ImageLength = v
		case updKeyMinFirmware:
			v, err := d.text()
			if err != nil {
				return nil, fmt.Errorf("min_firmware_version: %w", err)
			}
			out.MinFirmwareVersion = v
		case updKeyBuildUTCMS:
			v, err := d.uint()
			if err != nil {
				return nil, fmt.Errorf("build_utc_ms: %w", err)
			}
			out.BuildUTCMS = v
		case updKeySignatureAlgo:
			v, err := d.text()
			if err != nil {
				return nil, fmt.Errorf("signature_algorithm: %w", err)
			}
			out.SignatureAlgorithm = v
		default:
			return nil, fmt.Errorf("update descriptor has unknown key %d", key)
		}
	}

	if !d.atEnd() {
		return nil, fmt.Errorf("update descriptor has %d trailing byte(s)",
			len(b)-d.pos)
	}

	if out.DescriptorVersion != UpdateDescriptorVersion {
		return nil, fmt.Errorf("descriptor version %d is not supported",
			out.DescriptorVersion)
	}
	if out.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("signature algorithm %q is not supported",
			out.SignatureAlgorithm)
	}
	if out.ImageLength == 0 {
		return nil, errors.New("update descriptor declares a zero-length image")
	}

	// Re-encode and compare, so a descriptor that parses but is not canonical
	// is rejected here rather than failing verification on the device for a
	// reason the device cannot explain.
	reencoded, err := out.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("update descriptor will not re-encode: %w", err)
	}
	if string(reencoded) != string(b) {
		return nil, errors.New("update descriptor is not canonically encoded")
	}

	return &out, nil
}

// Sign returns the canonical encoding and its signature.
func (u *UpdateDescriptor) Sign(priv ed25519.PrivateKey) (encoded, signature []byte, err error) {
	encoded, err = u.MarshalCBOR()
	if err != nil {
		return nil, nil, err
	}
	return encoded, ed25519.Sign(priv, encoded), nil
}

// VerifyUpdateDescriptor checks the signature and then the bytes.
//
// Signature first and separately from any use of the contents: the device
// downloads megabytes on the strength of this check, so an unsigned descriptor
// must cost nothing.
func VerifyUpdateDescriptor(encoded, signature []byte, pub ed25519.PublicKey) (*UpdateDescriptor, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("update key is not a valid Ed25519 public key")
	}
	if !ed25519.Verify(pub, encoded, signature) {
		return nil, ErrBadUpdateSignature
	}
	return ParseUpdateDescriptor(encoded)
}
