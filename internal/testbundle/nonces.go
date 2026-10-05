package testbundle

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
)

// nonceStream is a deterministic byte stream: SHA-256(label || block counter),
// block after block.
type nonceStream struct {
	label   string
	counter uint64
	buf     []byte
}

// NonceReader returns a deterministic stream for use as a SegmentWriter's nonce
// source.
//
// This exists so conformance vectors and golden digests are reproducible byte
// for byte. It is the opposite of what a real writer does: production nonces are
// random (see format.SegmentCipher), and a deterministic source reused across
// two different plaintexts under one key would break the cipher. Every writer
// here gets its own label, and the keys are test keys, so that cannot happen.
func NonceReader(label string) io.Reader {
	return &nonceStream{label: label}
}

func (s *nonceStream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(s.buf) == 0 {
			h := sha256.New()
			h.Write([]byte("cairn-test-nonce/"))
			h.Write([]byte(s.label))
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], s.counter)
			h.Write(c[:])
			s.counter++
			s.buf = h.Sum(nil)
		}
		k := copy(p[n:], s.buf)
		s.buf = s.buf[k:]
		n += k
	}
	return n, nil
}
