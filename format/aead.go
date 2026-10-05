package format

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// SegmentCipher seals and opens the frames of one segment.
//
// It is bound to the segment at construction: the AAD prefix is the segment
// header's bytes (everything but its CRC), so a frame sealed here authenticates
// only inside this exact segment. Moving it to another segment, vehicle, device,
// assignment, key version or bundle counter changes the AAD and fails the tag.
//
// Nonces are 24 random bytes per frame, never derived from seq. After a
// torn-tail truncation the writer legitimately rewrites the same seq with
// different plaintext; a seq-derived nonce would then encrypt two plaintexts
// under one (key, nonce) pair, which for a stream cipher leaks their XOR and for
// Poly1305 leaks the authenticator key. A 192-bit random nonce makes collision
// negligible with no counter to persist, and survives a crash at any point
// because there is no state to lose.
type SegmentCipher struct {
	aead   cipher.AEAD
	aad    []byte // segment header bytes [0, header_len-4)
	nonces io.Reader
}

// NewSegmentCipher builds the cipher for a segment from its encoded header and
// its key. nonces supplies the per-frame nonces; nil means crypto/rand, which is
// the only correct choice outside conformance-vector generation. A deterministic
// reader exists solely so published vectors are reproducible.
func NewSegmentCipher(segmentHeader []byte, key [SegmentKeySize]byte, nonces io.Reader) (*SegmentCipher, error) {
	if len(segmentHeader) < SegmentHeaderSize {
		return nil, ErrShortHeader
	}
	headerLen := int(segmentHeader[6]) | int(segmentHeader[7])<<8
	if headerLen < SegmentHeaderSize || headerLen > len(segmentHeader) {
		return nil, fmt.Errorf("header_len %d inconsistent with %d header bytes", headerLen, len(segmentHeader))
	}

	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("init AEAD: %w", err)
	}
	if nonces == nil {
		nonces = rand.Reader
	}
	return &SegmentCipher{
		aead:   a,
		aad:    append([]byte(nil), segmentHeader[:headerLen-4]...),
		nonces: nonces,
	}, nil
}

// frameAAD is the authenticated-but-not-encrypted data for one frame: the
// 24-byte frame header exactly as written, then the segment header minus its
// CRC. Header first so a frame header field can never be reinterpreted as part
// of the segment binding.
func (c *SegmentCipher) frameAAD(frameHeader []byte) []byte {
	aad := make([]byte, 0, FrameHeaderSize+len(c.aad))
	aad = append(aad, frameHeader[:FrameHeaderSize]...)
	return append(aad, c.aad...)
}

// Seal appends nonce || ciphertext || tag to dst. frameHeader is the encoded
// 24-byte frame header, which is authenticated.
func (c *SegmentCipher) Seal(dst, frameHeader, plaintext []byte) ([]byte, error) {
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(c.nonces, nonce[:]); err != nil {
		return dst, fmt.Errorf("read nonce: %w", err)
	}
	dst = append(dst, nonce[:]...)
	return c.aead.Seal(dst, nonce[:], plaintext, c.frameAAD(frameHeader)), nil
}

// Open verifies and decrypts a sealed frame body (nonce || ciphertext || tag).
// It returns ErrAuthFailed if the tag does not verify.
func (c *SegmentCipher) Open(frameHeader, sealed []byte) ([]byte, error) {
	if len(sealed) < AEADOverhead {
		return nil, fmt.Errorf("%w: sealed body of %d bytes is shorter than the %d-byte nonce and tag",
			ErrAuthFailed, len(sealed), AEADOverhead)
	}
	pt, err := c.aead.Open(nil, sealed[:NonceSize], sealed[NonceSize:], c.frameAAD(frameHeader))
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}
