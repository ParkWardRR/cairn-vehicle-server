package format

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// SegmentHeaderSize is fixed at 64 bytes. The encoded header_len field lets a
// reader skip a longer header from a future version without misparsing frames;
// it does not make a future format readable.
const SegmentHeaderSize = 64

// SegmentMagic is ASCII "CRN2".
var SegmentMagic = [4]byte{'C', 'R', 'N', '2'}

// SegmentHeader is the fixed header at the start of every segment file.
type SegmentHeader struct {
	FormatVersion     uint16
	DeviceID          [16]byte
	BootID            [16]byte
	SegmentIndex      uint32
	FirstSeq          uint32
	OpenedMonotonicUS uint64
}

var (
	// ErrBadMagic means the file is not a Cairn v2 segment.
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
	dst = binary.LittleEndian.AppendUint32(dst, h.SegmentIndex)
	dst = binary.LittleEndian.AppendUint32(dst, h.FirstSeq)
	dst = binary.LittleEndian.AppendUint64(dst, h.OpenedMonotonicUS)
	dst = binary.LittleEndian.AppendUint32(dst, 0) // reserved

	dst = binary.LittleEndian.AppendUint32(dst, CRC32(dst[start:start+60]))
	return dst
}

// ParseSegmentHeader decodes and verifies a segment header. It returns the
// header and the encoded header_len, which is where frame scanning begins.
func ParseSegmentHeader(b []byte) (SegmentHeader, int, error) {
	var h SegmentHeader

	if len(b) < SegmentHeaderSize {
		return h, 0, ErrShortHeader
	}
	if [4]byte(b[0:4]) != SegmentMagic {
		return h, 0, ErrBadMagic
	}

	want := binary.LittleEndian.Uint32(b[60:64])
	if got := CRC32(b[0:60]); got != want {
		return h, 0, fmt.Errorf("%w: computed %08x, stored %08x", ErrBadHeaderCRC, got, want)
	}

	h.FormatVersion = binary.LittleEndian.Uint16(b[4:6])
	headerLen := int(binary.LittleEndian.Uint16(b[6:8]))
	copy(h.DeviceID[:], b[8:24])
	copy(h.BootID[:], b[24:40])
	h.SegmentIndex = binary.LittleEndian.Uint32(b[40:44])
	h.FirstSeq = binary.LittleEndian.Uint32(b[44:48])
	h.OpenedMonotonicUS = binary.LittleEndian.Uint64(b[48:56])

	if h.FormatVersion != FormatVersion {
		return h, headerLen, fmt.Errorf("unsupported format version %d (this implementation reads %d only)",
			h.FormatVersion, FormatVersion)
	}
	if headerLen < SegmentHeaderSize {
		return h, headerLen, fmt.Errorf("header_len %d is below the minimum %d", headerLen, SegmentHeaderSize)
	}

	return h, headerLen, nil
}
