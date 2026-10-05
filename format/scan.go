package format

import (
	"encoding/binary"
	"fmt"
)

// StopReason explains why a scan stopped. Every scan ends with exactly one,
// and it is always reported — never silently swallowed.
type StopReason uint8

const (
	// StopEOF is the clean case: the scan consumed the whole segment and every
	// frame validated.
	StopEOF StopReason = iota

	// StopTornTail means the segment ends mid-frame. This is the expected
	// outcome of a power cut during a write. Every frame before the stop is
	// valid and retained; the incomplete tail is discarded.
	StopTornTail

	// StopCorruptFrame means a frame's CRC did not match. Corruption is
	// isolated to that frame; preceding frames remain usable.
	StopCorruptFrame

	// StopChainBreak means a frame's PrevCRC32 did not match its predecessor's
	// CRC, which indicates a record was removed, reordered or spliced.
	StopChainBreak

	// StopSeqGap means the sequence number skipped a value.
	StopSeqGap

	// StopAuthFailed means a frame passed its CRC, chain and sequence checks but
	// its authentication tag did not verify. Only a keyed scan can report it. It
	// stops the scan exactly as StopCorruptFrame does: a frame whose authenticity
	// is in doubt makes everything after it equally doubtful, and unlike a CRC
	// mismatch it is never the expected result of a power cut, so it is always
	// worth an operator's attention.
	StopAuthFailed
)

func (r StopReason) String() string {
	switch r {
	case StopEOF:
		return "EOF"
	case StopTornTail:
		return "TORN_TAIL"
	case StopCorruptFrame:
		return "CORRUPT_FRAME"
	case StopChainBreak:
		return "CHAIN_BREAK"
	case StopSeqGap:
		return "SEQ_GAP"
	case StopAuthFailed:
		return "AUTH_FAILED"
	default:
		return fmt.Sprintf("StopReason(%d)", uint8(r))
	}
}

// Clean reports whether the scan found no damage.
func (r StopReason) Clean() bool { return r == StopEOF }

// ScanState carries continuity across a segment boundary. Sequence numbers and
// the CRC chain both run across the whole bundle, not per segment, so scanning
// segment N+1 requires the result of segment N.
type ScanState struct {
	ExpectedSeq  uint32
	ExpectedPrev uint32
}

// ScanResult is the outcome of scanning one segment.
type ScanResult struct {
	Header SegmentHeader

	// Frames are the valid frames, in file order. Every frame here passed its
	// CRC, chain and sequence checks, and, when Decrypted, its authentication
	// tag.
	Frames []Frame

	// Decrypted reports that the scan was keyed: every retained frame's tag
	// verified and its Payload holds plaintext. False means a structural scan,
	// whose verdicts are real but say nothing about authenticity.
	Decrypted bool

	// Stop is why scanning ended.
	Stop StopReason

	// StopDetail is a human-readable explanation, suitable for an operator or a
	// ledger reason code.
	StopDetail string

	// StopOffset is the byte offset at which scanning stopped.
	StopOffset int

	// DiscardedTailBytes is how many bytes from StopOffset to end-of-segment
	// were discarded. Reported exactly, never rounded.
	DiscardedTailBytes uint32

	// Next carries continuity to the following segment.
	Next ScanState

	// UnknownTypeCount counts frames whose record type this implementation does
	// not understand. These were integrity-checked and skipped, not rejected.
	UnknownTypeCount int

	// RecordCounts tallies accepted frames by record type.
	RecordCounts map[RecordType]int
}

// ScanSegment walks a segment's frames per the specification's recovery
// algorithm, which runs automatically at boot rather than only from a CLI tool.
//
// The behaviour is stop-at-first-invalid. Every frame before the failure point
// is valid and retained; everything from the failure point to end-of-segment is
// discarded as an incomplete tail, with the byte count and reason both
// reported.
//
// Pass the zero ScanState for the first segment of a bundle. For later
// segments, pass the preceding segment's Result.Next.
//
// keys selects the mode. With nil the scan is structural: torn tails, CRCs, the
// chain and sequence are all verified over the stored ciphertext, with no key,
// and frames carry Sealed bytes but no Payload. With a provider each frame is
// additionally authenticated and decrypted; a tag failure ends the scan with
// StopAuthFailed.
//
// A header error is returned as an error: the segment is unusable. So is a key
// error (ErrNoKey, ErrKeyVersionMismatch): the segment is intact but cannot be
// read with what the caller holds. The caller must still not delete either —
// unreadable is not the same as worthless, and the offline salvage tool, or a
// caller with the right key, may yet recover records from it.
func ScanSegment(b []byte, state ScanState, keys KeyProvider) (*ScanResult, error) {
	header, headerLen, err := ParseSegmentHeader(b)
	if err != nil {
		return nil, err
	}

	var cipher *SegmentCipher
	if keys != nil {
		key, err := keys.SegmentKey(&header)
		if err != nil {
			return nil, fmt.Errorf("segment key: %w", err)
		}
		if cipher, err = NewSegmentCipher(b[:headerLen], key, nil); err != nil {
			return nil, err
		}
	}

	res := &ScanResult{
		Header:       header,
		Decrypted:    cipher != nil,
		RecordCounts: make(map[RecordType]int),
	}

	// For the first segment of a chain the caller has no prior state, so the
	// header's own FirstSeq establishes the expectation. The journal is the first
	// and only segment of its own chain.
	expectedSeq := state.ExpectedSeq
	if (header.SegmentIndex == 0 || header.SegmentIndex == JournalSegmentIndex) &&
		state.ExpectedSeq == 0 && state.ExpectedPrev == 0 {
		expectedSeq = header.FirstSeq
	}
	expectedPrev := state.ExpectedPrev

	offset := headerLen

	stop := func(reason StopReason, detail string) (*ScanResult, error) {
		res.Stop = reason
		res.StopDetail = detail
		res.StopOffset = offset
		res.DiscardedTailBytes = uint32(len(b) - offset)
		res.Next = ScanState{ExpectedSeq: expectedSeq, ExpectedPrev: expectedPrev}
		return res, nil
	}

	for {
		remaining := len(b) - offset
		if remaining == 0 {
			return stop(StopEOF, "segment fully consumed")
		}
		if remaining < MinFrameLen {
			return stop(StopTornTail, fmt.Sprintf(
				"%d trailing bytes cannot hold a frame envelope of %d", remaining, MinFrameLen))
		}

		frameLen := int(binary.LittleEndian.Uint16(b[offset : offset+2]))
		if frameLen < MinFrameLen || frameLen > MaxFrameLen {
			return stop(StopTornTail, fmt.Sprintf(
				"frame_len %d outside the valid range [%d, %d]", frameLen, MinFrameLen, MaxFrameLen))
		}
		if offset+frameLen > len(b) {
			return stop(StopTornTail, fmt.Sprintf(
				"frame_len %d at offset %d extends %d bytes past end of segment",
				frameLen, offset, offset+frameLen-len(b)))
		}

		body := b[offset : offset+frameLen]
		storedCRC := binary.LittleEndian.Uint32(body[frameLen-FrameTrailerSize:])
		if computed := CRC32(body[:frameLen-FrameTrailerSize]); computed != storedCRC {
			return stop(StopCorruptFrame, fmt.Sprintf(
				"frame at offset %d: computed CRC %08x, stored %08x", offset, computed, storedCRC))
		}

		f := decodeFrameHeader(body)
		f.CRC32 = storedCRC
		f.Sealed = body[FrameHeaderSize : frameLen-FrameTrailerSize]

		if f.PrevCRC32 != expectedPrev {
			return stop(StopChainBreak, fmt.Sprintf(
				"frame at offset %d (seq %d): prev_crc32 %08x, expected %08x — a record was removed, reordered or spliced",
				offset, f.Seq, f.PrevCRC32, expectedPrev))
		}
		if f.Seq != expectedSeq {
			return stop(StopSeqGap, fmt.Sprintf(
				"frame at offset %d: seq %d, expected %d", offset, f.Seq, expectedSeq))
		}

		// Authentication comes after the structural checks, not before: those
		// need no key and must give the same verdict whether or not one is held,
		// so a damaged frame reports as damage rather than as an auth failure.
		if cipher != nil {
			pt, err := cipher.Open(body[:FrameHeaderSize], f.Sealed)
			if err != nil {
				return stop(StopAuthFailed, fmt.Sprintf(
					"frame at offset %d (seq %d): %v — the ciphertext, frame header or segment binding was altered, or the key is wrong",
					offset, f.Seq, err))
			}
			f.Payload = pt
			f.Decrypted = true
		}

		if !f.RecordType.Known() {
			res.UnknownTypeCount++
		}
		res.RecordCounts[f.RecordType]++
		res.Frames = append(res.Frames, f)

		expectedSeq = f.Seq + 1
		expectedPrev = storedCRC
		offset += frameLen
	}
}

// ScanBundle scans an ordered list of segments, threading continuity between
// them. Segments must be supplied in ascending SegmentIndex order. keys is as
// for ScanSegment.
//
// Scanning stops at the first segment that does not end cleanly: a damaged
// segment means every later segment's chain expectation is unknowable, so
// continuing would produce misleading verdicts rather than more data.
func ScanBundle(segments [][]byte, keys KeyProvider) ([]*ScanResult, error) {
	var (
		results []*ScanResult
		state   ScanState
	)

	for i, seg := range segments {
		res, err := ScanSegment(seg, state, keys)
		if err != nil {
			return results, fmt.Errorf("segment %d: %w", i, err)
		}
		results = append(results, res)
		if !res.Stop.Clean() {
			break
		}
		state = res.Next
	}

	return results, nil
}
