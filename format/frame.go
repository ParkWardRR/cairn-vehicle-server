package format

import (
	"encoding/binary"
	"fmt"
)

// Frame envelope geometry. frame_len counts the whole frame, including the
// frame_len field itself, the sealed payload (nonce, ciphertext, tag) and the
// trailing CRC.
//
// Every frame is encrypted, so even an empty record costs the 40-byte AEAD
// overhead and the minimum frame is 68 bytes. MaxFrameLen is unchanged, which
// is why the largest plaintext payload shrank from 4068 to 4028.
const (
	FrameHeaderSize   = 24
	FrameTrailerSize  = 4
	FrameEnvelopeSize = FrameHeaderSize + FrameTrailerSize // 28: header + CRC, no payload
	FrameOverhead     = FrameEnvelopeSize + AEADOverhead   // 68: envelope + nonce + tag
	MinFrameLen       = FrameOverhead
	MaxFrameLen       = 4096
	MaxPayloadSize    = MaxFrameLen - FrameOverhead // 4028, plaintext bytes
)

// RecordType identifies a payload schema.
type RecordType uint8

const (
	RecordGNSSSample      RecordType = 0x01
	RecordIMUSummary      RecordType = 0x02
	RecordIMURawWindow    RecordType = 0x03
	RecordOBDSnapshot     RecordType = 0x04
	RecordDeviceHealth    RecordType = 0x05
	RecordTripEvent       RecordType = 0x06
	RecordStateTransition RecordType = 0x07
	RecordGNSSGap         RecordType = 0x08
	RecordPolicySnapshot  RecordType = 0x09
	RecordOBDExtended     RecordType = 0x0A
)

// Known reports whether this implementation understands the record type.
// Unknown types are not errors: they are skipped via frame_len, counted and
// reported, which is how a newer device stays partially readable by an older
// decoder. The frame CRC still applies, so a skipped record remains
// integrity-checked.
func (t RecordType) Known() bool {
	return t >= RecordGNSSSample && t <= RecordOBDExtended
}

func (t RecordType) String() string {
	switch t {
	case RecordGNSSSample:
		return "GNSS_SAMPLE"
	case RecordIMUSummary:
		return "IMU_SUMMARY"
	case RecordIMURawWindow:
		return "IMU_RAW_WINDOW"
	case RecordOBDSnapshot:
		return "OBD_SNAPSHOT"
	case RecordDeviceHealth:
		return "DEVICE_HEALTH"
	case RecordTripEvent:
		return "TRIP_EVENT"
	case RecordStateTransition:
		return "STATE_TRANSITION"
	case RecordGNSSGap:
		return "GNSS_GAP"
	case RecordPolicySnapshot:
		return "POLICY_SNAPSHOT"
	case RecordOBDExtended:
		return "OBD_EXTENDED"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(t))
	}
}

// Frame flags.
const (
	FlagPretrip      uint16 = 1 << 0 // from the pre-roll buffer, precedes trip confirmation
	FlagDegraded     uint16 = 1 << 1 // captured while a degraded health state was active
	FlagEstimatedUTC uint16 = 1 << 2 // UTC basis was an estimate; no valid fix at write time
	FlagPostRecovery uint16 = 1 << 3 // first record written after a boot recovery
)

// Frame is one framed record.
//
// A scanned frame is in one of two states. Decrypted is false after a
// structural (keyless) scan: the CRC, chain and sequence checks passed, Payload
// is nil and Sealed holds the nonce, ciphertext and tag as stored. Decrypted is
// true after a keyed scan: the tag verified and Payload holds the plaintext.
//
// Payload is nil rather than ciphertext when undecrypted on purpose. Ciphertext
// is exactly as long as plaintext, so a payload parser handed it would not fail
// on length: it would return a plausible-looking record of random numbers.
type Frame struct {
	RecordType    RecordType
	SchemaVersion uint8
	Flags         uint16
	Seq           uint32
	MonotonicMS   uint32 // milliseconds since the segment header's OpenedMonotonicUS
	PrevCRC32     uint32 // crc32 of the preceding frame; 0 for the bundle's first frame

	// Payload is the plaintext record body. It is the input to AppendFrame and,
	// when Decrypted, the output of a keyed scan.
	Payload []byte

	// Sealed is nonce[24] || ciphertext || tag[16] as stored in the frame. It is
	// populated by the scanner and ignored by AppendFrame. It aliases the scanned
	// segment's bytes.
	Sealed []byte

	// Decrypted reports that Payload holds an authenticated plaintext.
	Decrypted bool

	// CRC32 is the frame's own checksum. It is computed by AppendFrame and
	// populated by the scanner; it is ignored as an input to AppendFrame.
	CRC32 uint32
}

// Len returns the encoded frame_len for the frame's plaintext payload.
func (f *Frame) Len() int { return FrameOverhead + len(f.Payload) }

// appendFrameHeader encodes the 24-byte envelope header for a frame whose
// plaintext payload is n bytes.
func appendFrameHeader(dst []byte, f *Frame, n int) []byte {
	dst = binary.LittleEndian.AppendUint16(dst, uint16(FrameOverhead+n))
	dst = append(dst, uint8(f.RecordType), f.SchemaVersion)
	dst = binary.LittleEndian.AppendUint16(dst, f.Flags)
	dst = binary.LittleEndian.AppendUint16(dst, 0) // reserved
	dst = binary.LittleEndian.AppendUint32(dst, f.Seq)
	dst = binary.LittleEndian.AppendUint32(dst, f.MonotonicMS)
	dst = binary.LittleEndian.AppendUint32(dst, f.PrevCRC32)
	dst = binary.LittleEndian.AppendUint32(dst, 0) // reserved2, keeps the sealed payload 4-byte aligned
	return dst
}

// AppendFrame seals f.Payload with c and appends the encoded frame to dst,
// returning the extended slice and the frame's CRC. The returned CRC is the next
// frame's PrevCRC32.
//
// The CRC covers the ciphertext frame, not the plaintext. That is what lets a
// holder of no key verify torn tails, the chain and the Merkle root.
func AppendFrame(dst []byte, f *Frame, c *SegmentCipher) ([]byte, uint32, error) {
	if len(f.Payload) > MaxPayloadSize {
		return dst, 0, fmt.Errorf("payload %d bytes exceeds maximum %d", len(f.Payload), MaxPayloadSize)
	}

	start := len(dst)
	dst = appendFrameHeader(dst, f, len(f.Payload))

	// The header is authenticated exactly as written, including prev_crc32, so a
	// frame cannot be re-chained or reordered without invalidating its tag.
	dst, err := c.Seal(dst, dst[start:start+FrameHeaderSize], f.Payload)
	if err != nil {
		return dst[:start], 0, err
	}

	crc := CRC32(dst[start:])
	dst = binary.LittleEndian.AppendUint32(dst, crc)
	f.CRC32 = crc

	return dst, crc, nil
}

// decodeFrameHeader reads the 24-byte envelope from b, which must be at least
// FrameHeaderSize long.
func decodeFrameHeader(b []byte) Frame {
	return Frame{
		RecordType:    RecordType(b[2]),
		SchemaVersion: b[3],
		Flags:         binary.LittleEndian.Uint16(b[4:6]),
		Seq:           binary.LittleEndian.Uint32(b[8:12]),
		MonotonicMS:   binary.LittleEndian.Uint32(b[12:16]),
		PrevCRC32:     binary.LittleEndian.Uint32(b[16:20]),
	}
}
