package format

import (
	"errors"
	"fmt"
	"io"
)

// SegmentWriter builds a segment, maintaining the two pieces of state that
// make the format recoverable: the bundle-wide sequence number and the CRC
// chain.
//
// Both run across the whole bundle rather than per segment, so a writer for
// segment N+1 must be seeded from segment N's final state via NextState.
type SegmentWriter struct {
	buf      []byte
	cipher   *SegmentCipher
	seq      uint32
	prevCRC  uint32
	counts   map[RecordType]uint32
	frames   int
	firstSeq uint32
}

// NewSegmentWriter starts a segment. Pass the zero ScanState for a bundle's
// first segment; for later segments pass the preceding writer's or scan's
// NextState.
//
// keys is required: there is no way to write a plaintext frame, by design. The
// segment key is derived from h exactly as a reader will derive it, so h must
// carry the final identity fields (vehicle, assignment, counter, key version)
// before the writer is built; they cannot be amended once frames are sealed
// against them.
//
// nonces supplies frame nonces and is nil (crypto/rand) in every real writer.
// It exists so conformance vectors can be reproduced byte for byte; see
// SegmentCipher for why nonces must otherwise be random.
func NewSegmentWriter(h SegmentHeader, state ScanState, keys KeyProvider, nonces io.Reader) (*SegmentWriter, error) {
	if keys == nil {
		return nil, errors.New("segment writer requires a key provider: every frame is encrypted")
	}

	h.FormatVersion = FormatVersion
	h.FirstSeq = state.ExpectedSeq

	key, err := keys.SegmentKey(&h)
	if err != nil {
		return nil, fmt.Errorf("segment key: %w", err)
	}

	hdr := AppendSegmentHeader(nil, &h)
	c, err := NewSegmentCipher(hdr, key, nonces)
	if err != nil {
		return nil, err
	}

	return &SegmentWriter{
		buf:      hdr,
		cipher:   c,
		seq:      state.ExpectedSeq,
		prevCRC:  state.ExpectedPrev,
		counts:   make(map[RecordType]uint32),
		firstSeq: state.ExpectedSeq,
	}, nil
}

// Append writes one record. The sequence number and chain CRC are assigned
// automatically; a caller cannot set them inconsistently. payload is the
// plaintext record body; it is encrypted before it touches the buffer.
func (w *SegmentWriter) Append(rt RecordType, schemaVersion uint8, flags uint16, monotonicMS uint32, payload []byte) error {
	f := Frame{
		RecordType:    rt,
		SchemaVersion: schemaVersion,
		Flags:         flags,
		Seq:           w.seq,
		MonotonicMS:   monotonicMS,
		PrevCRC32:     w.prevCRC,
		Payload:       payload,
	}

	next, crc, err := AppendFrame(w.buf, &f, w.cipher)
	if err != nil {
		return fmt.Errorf("append %s at seq %d: %w", rt, w.seq, err)
	}

	w.buf = next
	w.prevCRC = crc
	w.seq++
	w.frames++
	w.counts[rt]++
	return nil
}

// Bytes returns the segment's encoded bytes. The slice aliases the writer's
// buffer; copy it if the writer will be used again.
func (w *SegmentWriter) Bytes() []byte { return w.buf }

// NextState returns the continuity state for the following segment.
func (w *SegmentWriter) NextState() ScanState {
	return ScanState{ExpectedSeq: w.seq, ExpectedPrev: w.prevCRC}
}

// Counts returns accepted record counts by type, suitable for a manifest's
// record_counts field.
func (w *SegmentWriter) Counts() map[RecordType]uint32 {
	out := make(map[RecordType]uint32, len(w.counts))
	for k, v := range w.counts {
		out[k] = v
	}
	return out
}

// Frames returns the number of records written.
func (w *SegmentWriter) Frames() int { return w.frames }

// FirstSeq and LastSeq bound the sequence range this segment covers. LastSeq is
// only meaningful when at least one frame has been written.
func (w *SegmentWriter) FirstSeq() uint32 { return w.firstSeq }
func (w *SegmentWriter) LastSeq() uint32  { return w.seq - 1 }

// Cipher returns the segment's cipher. It exists for tooling that must craft
// deliberately invalid frames (conformance vectors, fault-injection tests) and
// still seal them correctly, so that exactly one property of the frame is wrong.
func (w *SegmentWriter) Cipher() *SegmentCipher { return w.cipher }
