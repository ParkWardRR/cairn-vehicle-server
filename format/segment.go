package format

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SegmentHeaderSize is fixed at 128 bytes. The encoded header_len field lets a
// reader skip a longer header from a future version without misparsing frames;
// it does not make a future format readable.
const SegmentHeaderSize = 128

// JournalSegmentIndex is the reserved segment_index of journal.seg. The journal
// is a separate chain from the capture segments (spec section 3.2.1), and
// segment_index is an input to the segment key, so giving it a value no capture
// segment can have also gives it a key no capture segment can share.
const JournalSegmentIndex uint32 = 0xFFFFFFFF

// SegmentMagic is ASCII "CRN3".
var SegmentMagic = [4]byte{'C', 'R', 'N', '3'}

// Byte offsets within the segment header. Spelled out because the firmware and
// emulator ports serialize field by field, and an off-by-one here would be
// invisible until two implementations disagree on a card.
const (
	offHdrMagic             = 0
	offHdrFormatVersion     = 4
	offHdrHeaderLen         = 6
	offHdrDeviceID          = 8
	offHdrBootID            = 24
	offHdrVehicleID         = 40
	offHdrAssignmentID      = 56
	offHdrSegmentIndex      = 72
	offHdrFirstSeq          = 76
	offHdrOpenedMonotonicUS = 80
	offHdrStorageKeyVersion = 88
	offHdrDeviceCounter     = 92
	offHdrReserved          = 100 // 24 bytes, zero
	offHdrCRC               = SegmentHeaderSize - 4
)

// SegmentHeader is the fixed header at the start of every segment file.
//
// Everything in it except the CRC is authenticated as AAD on every frame of the
// segment, so the identity fields are not merely labels: altering any of them
// without the key makes every frame fail its tag.
type SegmentHeader struct {
	FormatVersion uint16
	DeviceID      [16]byte
	BootID        [16]byte

	// VehicleID and AssignmentID bind the segment to the vehicle the device was
	// assigned to when the bundle was captured, and to that specific assignment
	// (a device moved between vehicles gets a new one).
	VehicleID    [16]byte
	AssignmentID [16]byte

	// SegmentIndex is 0-based within a bundle, or JournalSegmentIndex.
	SegmentIndex      uint32
	FirstSeq          uint32
	OpenedMonotonicUS uint64

	// StorageKeyVersion selects which escrowed K_root the segment key derives
	// from.
	StorageKeyVersion uint32

	// DeviceCounter is the device's monotonic bundle counter for the bundle this
	// segment belongs to. Every segment of one bundle, journal included, carries
	// the same value; the manifest repeats it. A card restored to an older state
	// presents a counter the server has already passed.
	DeviceCounter uint64
}

var (
	// ErrBadMagic means the file is not a Cairn v3 segment.
	ErrBadMagic = errors.New("bad segment magic")
	// ErrBadHeaderCRC means the segment header is corrupt. The segment is
	// unusable, but must not be deleted.
	ErrBadHeaderCRC = errors.New("segment header CRC mismatch")
	// ErrShortHeader means the file is too small to contain a header.
	ErrShortHeader = errors.New("segment shorter than header")
)

// AppendSegmentHeader encodes h and appends it to dst.
func AppendSegmentHeader(dst []byte, h *SegmentHeader) []byte {
	start := len(dst)

	dst = append(dst, SegmentMagic[:]...)
	dst = binary.LittleEndian.AppendUint16(dst, h.FormatVersion)
	dst = binary.LittleEndian.AppendUint16(dst, SegmentHeaderSize)
	dst = append(dst, h.DeviceID[:]...)
	dst = append(dst, h.BootID[:]...)
	dst = append(dst, h.VehicleID[:]...)
	dst = append(dst, h.AssignmentID[:]...)
	dst = binary.LittleEndian.AppendUint32(dst, h.SegmentIndex)
	dst = binary.LittleEndian.AppendUint32(dst, h.FirstSeq)
	dst = binary.LittleEndian.AppendUint64(dst, h.OpenedMonotonicUS)
	dst = binary.LittleEndian.AppendUint32(dst, h.StorageKeyVersion)
	dst = binary.LittleEndian.AppendUint64(dst, h.DeviceCounter)
	dst = append(dst, make([]byte, offHdrCRC-offHdrReserved)...) // reserved, zero

	dst = binary.LittleEndian.AppendUint32(dst, CRC32(dst[start:start+offHdrCRC]))
	return dst
}

// ParseSegmentHeader decodes and verifies a segment header. It returns the
// header and the encoded header_len, which is where frame scanning begins.
func ParseSegmentHeader(b []byte) (SegmentHeader, int, error) {
	var h SegmentHeader

	if len(b) < SegmentHeaderSize {
		return h, 0, ErrShortHeader
	}
	if [4]byte(b[offHdrMagic:offHdrMagic+4]) != SegmentMagic {
		return h, 0, ErrBadMagic
	}

	want := binary.LittleEndian.Uint32(b[offHdrCRC : offHdrCRC+4])
	if got := CRC32(b[0:offHdrCRC]); got != want {
		return h, 0, fmt.Errorf("%w: computed %08x, stored %08x", ErrBadHeaderCRC, got, want)
	}

	h.FormatVersion = binary.LittleEndian.Uint16(b[offHdrFormatVersion:])
	headerLen := int(binary.LittleEndian.Uint16(b[offHdrHeaderLen:]))
	copy(h.DeviceID[:], b[offHdrDeviceID:offHdrDeviceID+16])
	copy(h.BootID[:], b[offHdrBootID:offHdrBootID+16])
	copy(h.VehicleID[:], b[offHdrVehicleID:offHdrVehicleID+16])
	copy(h.AssignmentID[:], b[offHdrAssignmentID:offHdrAssignmentID+16])
	h.SegmentIndex = binary.LittleEndian.Uint32(b[offHdrSegmentIndex:])
	h.FirstSeq = binary.LittleEndian.Uint32(b[offHdrFirstSeq:])
	h.OpenedMonotonicUS = binary.LittleEndian.Uint64(b[offHdrOpenedMonotonicUS:])
	h.StorageKeyVersion = binary.LittleEndian.Uint32(b[offHdrStorageKeyVersion:])
	h.DeviceCounter = binary.LittleEndian.Uint64(b[offHdrDeviceCounter:])

	if h.FormatVersion != FormatVersion {
		return h, headerLen, fmt.Errorf("unsupported format version %d (this implementation reads %d only)",
			h.FormatVersion, FormatVersion)
	}
	if headerLen < SegmentHeaderSize {
		return h, headerLen, fmt.Errorf("header_len %d is below the minimum %d", headerLen, SegmentHeaderSize)
	}
	if headerLen > len(b) {
		return h, headerLen, fmt.Errorf("header_len %d extends past the %d-byte segment", headerLen, len(b))
	}

	return h, headerLen, nil
}
