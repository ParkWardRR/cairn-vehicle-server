package format

import (
	"encoding/binary"
	"fmt"
)

// Frame envelope geometry. frame_len counts the whole frame, including the
// frame_len field itself and the trailing CRC.
const (
	FrameHeaderSize  = 24
	FrameTrailerSize = 4
	FrameOverhead    = FrameHeaderSize + FrameTrailerSize // 28
	MinFrameLen      = FrameOverhead
	MaxFrameLen      = 4096
	MaxPayloadSize   = MaxFrameLen - FrameOverhead // 4068
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
)

// Known reports whether this implementation understands the record type.
// Unknown types are not errors: they are skipped via frame_len, counted and
// reported, which is how a newer device stays partially readable by an older
// decoder. The frame CRC still applies, so a skipped record remains
// integrity-checked.
func (t RecordType) Known() bool {
	return t >= RecordGNSSSample && t <= RecordPolicySnapshot
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
type Frame struct {
	RecordType    RecordType
	SchemaVersion uint8
	Flags         uint16
	Seq           uint32
	MonotonicMS   uint32 // milliseconds since the segment header's OpenedMonotonicUS
	PrevCRC32     uint32 // crc32 of the preceding frame; 0 for the bundle's first frame
	Payload       []byte

	// CRC32 is the frame's own checksum. It is computed by AppendFrame and
	// populated by the scanner; it is ignored as an input to AppendFrame.
	CRC32 uint32
}

// Len returns the encoded frame_len.
func (f *Frame) Len() int { return FrameOverhead + len(f.Payload) }

// AppendFrame encodes f and appends it to dst, returning the extended slice and
// the frame's CRC. The returned CRC is the next frame's PrevCRC32.
func AppendFrame(dst []byte, f *Frame) ([]byte, uint32, error) {
	if len(f.Payload) > MaxPayloadSize {
		return dst, 0, fmt.Errorf("payload %d bytes exceeds maximum %d", len(f.Payload), MaxPayloadSize)
	}

	start := len(dst)
	frameLen := f.Len()

	dst = binary.LittleEndian.AppendUint16(dst, uint16(frameLen))
	dst = append(dst, uint8(f.RecordType), f.SchemaVersion)
	dst = binary.LittleEndian.AppendUint16(dst, f.Flags)
	dst = binary.LittleEndian.AppendUint16(dst, 0) // reserved
	dst = binary.LittleEndian.AppendUint32(dst, f.Seq)
	dst = binary.LittleEndian.AppendUint32(dst, f.MonotonicMS)
	dst = binary.LittleEndian.AppendUint32(dst, f.PrevCRC32)
	dst = binary.LittleEndian.AppendUint32(dst, 0) // reserved2, aligns payload to 4 bytes
	dst = append(dst, f.Payload...)

	crc := CRC32(dst[start : start+FrameHeaderSize+len(f.Payload)])
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
