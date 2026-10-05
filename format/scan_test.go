package format

import (
	"encoding/binary"
	"errors"
	"testing"
)

// gnssPayload builds a 32-byte GNSS sample with a 3D fix.
func gnssPayload(latE7, lonE7 int32) []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p[0:], uint32(latE7))
	binary.LittleEndian.PutUint32(p[4:], uint32(lonE7))
	binary.LittleEndian.PutUint32(p[8:], uint32(int32(5000))) // 50 m
	binary.LittleEndian.PutUint16(p[12:], 1200)               // 12 m/s
	binary.LittleEndian.PutUint16(p[14:], 9000)               // 90.00 deg
	binary.LittleEndian.PutUint16(p[16:], 110)                // HDOP 1.10
	binary.LittleEndian.PutUint16(p[18:], 350)                // 3.5 m
	binary.LittleEndian.PutUint16(p[20:], 500)                // 5.0 m
	p[22] = 2                                                 // 3D fix
	p[23] = 9                                                 // sats used
	p[24] = 14                                                // sats visible
	p[25] = 0x01                                              // GNSS
	binary.LittleEndian.PutUint32(p[26:], 0)
	binary.LittleEndian.PutUint16(p[30:], 120) // 120 ms UTC uncertainty
	return p
}

func gnssGapPayload(durationMS uint32, expected uint16, cause uint8) []byte {
	p := make([]byte, 12)
	binary.LittleEndian.PutUint32(p[0:], durationMS)
	binary.LittleEndian.PutUint16(p[4:], expected)
	p[6] = cause
	return p
}

// buildValidSegment writes n GNSS samples at 1 Hz.
func buildValidSegment(t *testing.T, segmentIndex uint32, state ScanState, n int) *SegmentWriter {
	t.Helper()
	w := newTestWriter(t, testHeader(segmentIndex), state)
	for i := 0; i < n; i++ {
		payload := gnssPayload(int32(34_000_000+i*100), int32(-118_500_000+i*100))
		if err := w.Append(RecordGNSSSample, 1, 0, uint32(i*1000), payload); err != nil {
			t.Fatalf("append frame %d: %v", i, err)
		}
	}
	return w
}

func mustScan(t *testing.T, b []byte, state ScanState) *ScanResult {
	t.Helper()
	res, err := ScanSegment(b, state, testKeys())
	if err != nil {
		t.Fatalf("ScanSegment: unexpected error %v", err)
	}
	return res
}

// ─── vector: valid-minimal ──────────────────────────────────────────────────

func TestValidMinimal(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})

	types := []RecordType{
		RecordGNSSSample, RecordIMUSummary, RecordIMURawWindow, RecordOBDSnapshot,
		RecordDeviceHealth, RecordTripEvent, RecordStateTransition, RecordGNSSGap,
		RecordPolicySnapshot,
	}
	for i, rt := range types {
		if err := w.Append(rt, 1, 0, uint32(i*100), make([]byte, 16)); err != nil {
			t.Fatalf("append %s: %v", rt, err)
		}
	}

	res := mustScan(t, w.Bytes(), ScanState{})

	if res.Stop != StopEOF {
		t.Errorf("Stop = %v (%s), want EOF", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != len(types) {
		t.Fatalf("got %d frames, want %d", len(res.Frames), len(types))
	}
	if res.DiscardedTailBytes != 0 {
		t.Errorf("DiscardedTailBytes = %d, want 0", res.DiscardedTailBytes)
	}
	if res.UnknownTypeCount != 0 {
		t.Errorf("UnknownTypeCount = %d, want 0", res.UnknownTypeCount)
	}
	for i, f := range res.Frames {
		if f.Seq != uint32(i) {
			t.Errorf("frame %d: Seq = %d, want %d", i, f.Seq, i)
		}
		if f.RecordType != types[i] {
			t.Errorf("frame %d: RecordType = %s, want %s", i, f.RecordType, types[i])
		}
	}
}

// ─── vector: valid-multi-segment ────────────────────────────────────────────

// Asserts seq continuity and prev_crc32 chaining across a rotation. The chain
// and the sequence both run bundle-wide, so a reader must be able to follow
// them over a segment boundary.
func TestValidMultiSegment(t *testing.T) {
	w0 := buildValidSegment(t, 0, ScanState{}, 5)
	seg0 := append([]byte(nil), w0.Bytes()...)

	w1 := buildValidSegment(t, 1, w0.NextState(), 4)
	seg1 := append([]byte(nil), w1.Bytes()...)

	results, err := ScanBundle([][]byte{seg0, seg1}, testKeys())
	if err != nil {
		t.Fatalf("ScanBundle: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	for i, res := range results {
		if res.Stop != StopEOF {
			t.Errorf("segment %d: Stop = %v (%s), want EOF", i, res.Stop, res.StopDetail)
		}
	}

	// Sequence numbers must be contiguous 0..8 across the boundary.
	var seqs []uint32
	for _, res := range results {
		for _, f := range res.Frames {
			seqs = append(seqs, f.Seq)
		}
	}
	if len(seqs) != 9 {
		t.Fatalf("got %d frames across the bundle, want 9", len(seqs))
	}
	for i, s := range seqs {
		if s != uint32(i) {
			t.Fatalf("frame %d: Seq = %d, want %d", i, s, i)
		}
	}

	// The first frame of segment 1 must chain to the last frame of segment 0.
	last0 := results[0].Frames[len(results[0].Frames)-1]
	first1 := results[1].Frames[0]
	if first1.PrevCRC32 != last0.CRC32 {
		t.Errorf("chain broken across rotation: prev_crc32 %08x, previous frame CRC %08x",
			first1.PrevCRC32, last0.CRC32)
	}

	// Scanning segment 1 without segment 0's state must be detected, not
	// silently accepted.
	res, err := ScanSegment(seg1, ScanState{}, testKeys())
	if err != nil {
		t.Fatalf("ScanSegment: %v", err)
	}
	if res.Stop != StopChainBreak {
		t.Errorf("scanning segment 1 from zero state: Stop = %v, want CHAIN_BREAK", res.Stop)
	}
}

// ─── vector: torn-tail-mid-frame ────────────────────────────────────────────

// The expected outcome of a power cut during a write: every frame before the
// truncation is retained, only the incomplete tail is discarded, and the
// discarded byte count is exact.
func TestTornTailMidFrame(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 10)
	full := append([]byte(nil), w.Bytes()...)

	// Truncate 20 bytes into the final frame's 60-byte extent.
	frameLen := FrameOverhead + 32
	cut := len(full) - frameLen + 20
	truncated := full[:cut]

	res := mustScan(t, truncated, ScanState{})

	if res.Stop != StopTornTail {
		t.Fatalf("Stop = %v (%s), want TORN_TAIL", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 9 {
		t.Errorf("retained %d frames, want 9 — frames before the tear must survive", len(res.Frames))
	}
	if got := int(res.DiscardedTailBytes); got != 20 {
		t.Errorf("DiscardedTailBytes = %d, want 20", got)
	}
	for i, f := range res.Frames {
		if f.Seq != uint32(i) {
			t.Errorf("frame %d: Seq = %d, want %d", i, f.Seq, i)
		}
	}
}

// ─── vector: torn-tail-mid-header ───────────────────────────────────────────

func TestTornTailMidHeader(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 3)
	full := append([]byte(nil), w.Bytes()...)

	// Leave 10 bytes of a frame envelope: too few to even hold one.
	frameLen := FrameOverhead + 32
	truncated := full[:len(full)-frameLen+10]

	res := mustScan(t, truncated, ScanState{})

	if res.Stop != StopTornTail {
		t.Fatalf("Stop = %v (%s), want TORN_TAIL", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 2 {
		t.Errorf("retained %d frames, want 2", len(res.Frames))
	}
	if res.DiscardedTailBytes != 10 {
		t.Errorf("DiscardedTailBytes = %d, want 10", res.DiscardedTailBytes)
	}
}

// ─── vector: bad-frame-crc ──────────────────────────────────────────────────

// A single flipped payload bit must be detected at that frame and not before:
// corruption is isolated, and preceding records stay usable.
func TestBadFrameCRC(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 6)
	b := append([]byte(nil), w.Bytes()...)

	frameLen := FrameOverhead + 32
	// Flip a payload bit inside frame index 3.
	target := SegmentHeaderSize + 3*frameLen + FrameHeaderSize + 4
	b[target] ^= 0x01

	res := mustScan(t, b, ScanState{})

	if res.Stop != StopCorruptFrame {
		t.Fatalf("Stop = %v (%s), want CORRUPT_FRAME", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 3 {
		t.Errorf("retained %d frames, want 3 — corruption must not invalidate earlier records", len(res.Frames))
	}
	wantOffset := SegmentHeaderSize + 3*frameLen
	if res.StopOffset != wantOffset {
		t.Errorf("StopOffset = %d, want %d", res.StopOffset, wantOffset)
	}
}

// ─── vector: chain-break-spliced ────────────────────────────────────────────

// Removing a frame from the middle leaves every remaining frame individually
// CRC-valid. Only the chain detects the splice, which is what prev_crc32 is
// for.
func TestChainBreakSpliced(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 6)
	full := append([]byte(nil), w.Bytes()...)

	frameLen := FrameOverhead + 32
	cutStart := SegmentHeaderSize + 2*frameLen
	cutEnd := cutStart + frameLen

	spliced := make([]byte, 0, len(full)-frameLen)
	spliced = append(spliced, full[:cutStart]...)
	spliced = append(spliced, full[cutEnd:]...)

	res := mustScan(t, spliced, ScanState{})

	if res.Stop != StopChainBreak {
		t.Fatalf("Stop = %v (%s), want CHAIN_BREAK", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 2 {
		t.Errorf("retained %d frames, want 2", len(res.Frames))
	}
}

// ─── vector: seq-gap ────────────────────────────────────────────────────────

// A sequence gap with an intact chain. Constructed by re-encoding a frame with
// a skipped seq but a correct prev_crc32, so only the sequence check can catch
// it.
func TestSeqGap(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})
	if err := w.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		t.Fatal(err)
	}
	b := append([]byte(nil), w.Bytes()...)

	// Append a hand-built frame that skips seq 1 but chains correctly.
	f := Frame{
		RecordType:    RecordGNSSSample,
		SchemaVersion: 1,
		Seq:           5, // gap: should be 1
		MonotonicMS:   1000,
		PrevCRC32:     w.NextState().ExpectedPrev,
		Payload:       gnssPayload(34_000_100, -118_499_900),
	}
	b, _, err := AppendFrame(b, &f, w.cipher)
	if err != nil {
		t.Fatal(err)
	}

	res := mustScan(t, b, ScanState{})

	if res.Stop != StopSeqGap {
		t.Fatalf("Stop = %v (%s), want SEQ_GAP", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 1 {
		t.Errorf("retained %d frames, want 1", len(res.Frames))
	}
}

// ─── vector: bad-header-crc ─────────────────────────────────────────────────

// A corrupt header makes the segment unusable. It must be reported as an error
// so the caller knows not to parse frames — and the caller must not delete it:
// unreadable here is not the same as worthless, since the offline salvage tool
// may still recover records.
func TestBadHeaderCRC(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 3)
	b := append([]byte(nil), w.Bytes()...)

	b[24] ^= 0xFF // corrupt boot_id, which the header CRC covers

	if _, err := ScanSegment(b, ScanState{}, testKeys()); !errors.Is(err, ErrBadHeaderCRC) {
		t.Fatalf("error = %v, want ErrBadHeaderCRC", err)
	}
}

func TestBadMagic(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 1)
	b := append([]byte(nil), w.Bytes()...)
	b[0] = 'X'

	if _, err := ScanSegment(b, ScanState{}, testKeys()); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("error = %v, want ErrBadMagic", err)
	}
}

// ─── vector: unknown-record-type ────────────────────────────────────────────

// An unknown record type is skipped via frame_len, counted, and the remainder
// of the segment still parses. This is how a newer device stays partially
// readable by an older decoder.
func TestUnknownRecordType(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})
	if err := w.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordType(0x7F), 1, 0, 1000, []byte("record from the future")); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordGNSSSample, 1, 0, 2000, gnssPayload(34_000_100, -118_499_900)); err != nil {
		t.Fatal(err)
	}

	res := mustScan(t, w.Bytes(), ScanState{})

	if res.Stop != StopEOF {
		t.Fatalf("Stop = %v (%s), want EOF — an unknown type is not an error", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 3 {
		t.Errorf("got %d frames, want 3", len(res.Frames))
	}
	if res.UnknownTypeCount != 1 {
		t.Errorf("UnknownTypeCount = %d, want 1", res.UnknownTypeCount)
	}
	if res.Frames[2].RecordType != RecordGNSSSample {
		t.Errorf("frame after the unknown record = %s, want GNSS_SAMPLE", res.Frames[2].RecordType)
	}
}

// ─── vector: clock-jump ─────────────────────────────────────────────────────

// A UTC estimate that jumps backwards must not disturb ordering, because
// ordering truth is (boot_id, seq) and UTC is only an annotation.
func TestClockJump(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})

	var utcAhead int32 = 5_000
	forward := gnssPayload(34_000_000, -118_500_000)
	binary.LittleEndian.PutUint32(forward[26:], uint32(utcAhead))
	if err := w.Append(RecordGNSSSample, 1, 0, 0, forward); err != nil {
		t.Fatal(err)
	}

	// UTC estimate jumps 30 seconds backwards; monotonic time still advances.
	var utcBehind int32 = -25_000
	backward := gnssPayload(34_000_100, -118_499_900)
	binary.LittleEndian.PutUint32(backward[26:], uint32(utcBehind))
	binary.LittleEndian.PutUint16(backward[30:], 0xFFFF) // uncertainty unknown
	if err := w.Append(RecordGNSSSample, 1, FlagEstimatedUTC, 1000, backward); err != nil {
		t.Fatal(err)
	}

	res := mustScan(t, w.Bytes(), ScanState{})

	if res.Stop != StopEOF {
		t.Fatalf("Stop = %v (%s), want EOF — a clock jump is not corruption", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 2 {
		t.Fatalf("got %d frames, want 2 — the record must be retained", len(res.Frames))
	}
	if res.Frames[0].Seq != 0 || res.Frames[1].Seq != 1 {
		t.Errorf("sequence disturbed by a clock jump: %d, %d", res.Frames[0].Seq, res.Frames[1].Seq)
	}
	if res.Frames[1].MonotonicMS <= res.Frames[0].MonotonicMS {
		t.Error("monotonic time must still advance across a UTC jump")
	}
	if res.Frames[1].Flags&FlagEstimatedUTC == 0 {
		t.Error("the jumped sample must carry FlagEstimatedUTC")
	}
}

// ─── vector: gnss-gap ───────────────────────────────────────────────────────

// A gap is recorded explicitly and preserved, so a decoder can render a
// discontinuity rather than joining the route across missing data.
func TestGNSSGapPreserved(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})
	if err := w.Append(RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordGNSSGap, 1, 0, 1000, gnssGapPayload(42_000, 42, 4)); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(RecordGNSSSample, 1, 0, 43_000, gnssPayload(34_010_000, -118_490_000)); err != nil {
		t.Fatal(err)
	}

	res := mustScan(t, w.Bytes(), ScanState{})

	if res.Stop != StopEOF {
		t.Fatalf("Stop = %v (%s), want EOF", res.Stop, res.StopDetail)
	}
	if res.RecordCounts[RecordGNSSGap] != 1 {
		t.Errorf("gap record count = %d, want 1", res.RecordCounts[RecordGNSSGap])
	}

	gap := res.Frames[1]
	if gap.RecordType != RecordGNSSGap {
		t.Fatalf("frame 1 = %s, want GNSS_GAP", gap.RecordType)
	}
	if d := binary.LittleEndian.Uint32(gap.Payload[0:]); d != 42_000 {
		t.Errorf("gap duration = %d ms, want 42000", d)
	}
	if c := gap.Payload[6]; c != 4 {
		t.Errorf("gap cause = %d, want 4 (tunnel/obstruction)", c)
	}
}

// ─── vector: empty-segment ──────────────────────────────────────────────────

func TestEmptySegment(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})

	res := mustScan(t, w.Bytes(), ScanState{})

	if res.Stop != StopEOF {
		t.Errorf("Stop = %v (%s), want EOF", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 0 {
		t.Errorf("got %d frames, want 0", len(res.Frames))
	}
	if res.DiscardedTailBytes != 0 {
		t.Errorf("DiscardedTailBytes = %d, want 0", res.DiscardedTailBytes)
	}
}

// ─── vector: max-frame ──────────────────────────────────────────────────────

func TestMaxFrame(t *testing.T) {
	w := newTestWriter(t, testHeader(0), ScanState{})

	if err := w.Append(RecordIMURawWindow, 1, 0, 0, make([]byte, MaxPayloadSize)); err != nil {
		t.Fatalf("maximum-size payload rejected: %v", err)
	}
	res := mustScan(t, w.Bytes(), ScanState{})
	if res.Stop != StopEOF {
		t.Fatalf("Stop = %v (%s), want EOF", res.Stop, res.StopDetail)
	}
	if got := res.Frames[0].Len(); got != MaxFrameLen {
		t.Errorf("frame length = %d, want %d", got, MaxFrameLen)
	}

	w2 := newTestWriter(t, testHeader(0), ScanState{})
	if err := w2.Append(RecordIMURawWindow, 1, 0, 0, make([]byte, MaxPayloadSize+1)); err == nil {
		t.Error("oversized payload accepted, want rejection")
	}
}

// A frame_len field claiming more than MaxFrameLen must be treated as a torn
// tail rather than trusted.
func TestOversizedFrameLenRejected(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 2)
	b := append([]byte(nil), w.Bytes()...)

	binary.LittleEndian.PutUint16(b[SegmentHeaderSize:], MaxFrameLen+1)

	res := mustScan(t, b, ScanState{})
	if res.Stop != StopTornTail {
		t.Errorf("Stop = %v (%s), want TORN_TAIL", res.Stop, res.StopDetail)
	}
	if len(res.Frames) != 0 {
		t.Errorf("got %d frames, want 0", len(res.Frames))
	}
}

// A frame_len below the envelope minimum would otherwise cause a zero- or
// negative-progress loop.
func TestUndersizedFrameLenRejected(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 2)
	b := append([]byte(nil), w.Bytes()...)

	binary.LittleEndian.PutUint16(b[SegmentHeaderSize:], MinFrameLen-1)

	res := mustScan(t, b, ScanState{})
	if res.Stop != StopTornTail {
		t.Errorf("Stop = %v (%s), want TORN_TAIL", res.Stop, res.StopDetail)
	}
}

// Every byte of a segment truncated at every possible length must either parse
// cleanly or report a tail, and must never panic or over-report frames. This
// is the property a power cut actually exercises.
func TestTruncationAtEveryOffsetIsSafe(t *testing.T) {
	w := buildValidSegment(t, 0, ScanState{}, 8)
	full := w.Bytes()

	for cut := SegmentHeaderSize; cut <= len(full); cut++ {
		res, err := ScanSegment(full[:cut], ScanState{}, testKeys())
		if err != nil {
			t.Fatalf("truncated to %d bytes: unexpected error %v", cut, err)
		}
		if res.Stop != StopEOF && res.Stop != StopTornTail {
			t.Fatalf("truncated to %d bytes: Stop = %v (%s), want EOF or TORN_TAIL",
				cut, res.Stop, res.StopDetail)
		}

		frameLen := FrameOverhead + 32
		wantFrames := (cut - SegmentHeaderSize) / frameLen
		if len(res.Frames) != wantFrames {
			t.Fatalf("truncated to %d bytes: got %d frames, want %d",
				cut, len(res.Frames), wantFrames)
		}
		if got := int(res.DiscardedTailBytes); got != cut-res.StopOffset {
			t.Fatalf("truncated to %d bytes: DiscardedTailBytes = %d, want %d",
				cut, got, cut-res.StopOffset)
		}
	}
}
