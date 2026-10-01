package format

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Deterministic CBOR, RFC 8949 section 4.2.1 core deterministic encoding,
// restricted to the subset the manifest and receipt need:
//
//   - definite-length maps, arrays, byte strings and text strings only;
//   - unsigned integer map keys, written in ascending order;
//   - smallest-width integer encoding;
//   - null for absent optional values;
//   - no tags, no floats, no indefinite lengths, no negative integers.
//
// A specified encoding is what makes the signed byte sequence reproducible
// across implementations and firmware versions. An ad hoc serialization that
// varied between versions would invalidate historical signatures, so both the
// encoder and the decoder here are strict: the decoder rejects any input it
// would not itself have produced.

const (
	majorUint   byte = 0
	majorBytes  byte = 2
	majorText   byte = 3
	majorArray  byte = 4
	majorMap    byte = 5
	majorSimple byte = 7

	simpleNull byte = 22 // 0xf6
)

var (
	// ErrNonCanonical means the input is valid CBOR but not in the
	// deterministic encoding, so its bytes are not reproducible.
	ErrNonCanonical = errors.New("non-canonical CBOR encoding")
	// ErrCBORTruncated means the input ended mid-item.
	ErrCBORTruncated = errors.New("truncated CBOR")
	// ErrCBORUnsupported means the input uses a feature outside the permitted
	// subset.
	ErrCBORUnsupported = errors.New("unsupported CBOR feature")
)

// ─── encoder ────────────────────────────────────────────────────────────────

type cborEncoder struct {
	buf []byte

	// lastKey guards against a map written with out-of-order keys, which would
	// silently produce a non-canonical signature. Encoding is hand-written in
	// key order, so a violation is a programming error and should fail loudly.
	inMap   bool
	lastKey int64
}

func (e *cborEncoder) head(major byte, arg uint64) {
	switch {
	case arg < 24:
		e.buf = append(e.buf, major<<5|byte(arg))
	case arg <= math.MaxUint8:
		e.buf = append(e.buf, major<<5|24, byte(arg))
	case arg <= math.MaxUint16:
		e.buf = append(e.buf, major<<5|25)
		e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(arg))
	case arg <= math.MaxUint32:
		e.buf = append(e.buf, major<<5|26)
		e.buf = binary.BigEndian.AppendUint32(e.buf, uint32(arg))
	default:
		e.buf = append(e.buf, major<<5|27)
		e.buf = binary.BigEndian.AppendUint64(e.buf, arg)
	}
}

func (e *cborEncoder) uint(v uint64) { e.head(majorUint, v) }
func (e *cborEncoder) bytes(b []byte) {
	e.head(majorBytes, uint64(len(b)))
	e.buf = append(e.buf, b...)
}
func (e *cborEncoder) text(s string)     { e.head(majorText, uint64(len(s))); e.buf = append(e.buf, s...) }
func (e *cborEncoder) arrayHeader(n int) { e.head(majorArray, uint64(n)) }
func (e *cborEncoder) null()             { e.buf = append(e.buf, majorSimple<<5|simpleNull) }

func (e *cborEncoder) mapHeader(n int) {
	e.head(majorMap, uint64(n))
	e.inMap = true
	e.lastKey = -1
}

// key writes a map key, enforcing ascending order.
func (e *cborEncoder) key(k uint64) {
	if e.inMap && int64(k) <= e.lastKey {
		panic(fmt.Sprintf("format: CBOR map key %d written after %d; keys must ascend", k, e.lastKey))
	}
	e.lastKey = int64(k)
	e.uint(k)
}

// ─── decoder ────────────────────────────────────────────────────────────────

type cborDecoder struct {
	buf []byte
	pos int
}

func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if d.pos >= len(d.buf) {
		return 0, 0, ErrCBORTruncated
	}
	ib := d.buf[d.pos]
	d.pos++

	major = ib >> 5
	ai := ib & 0x1f

	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		if d.pos+1 > len(d.buf) {
			return 0, 0, ErrCBORTruncated
		}
		arg = uint64(d.buf[d.pos])
		d.pos++
		if arg < 24 {
			return 0, 0, fmt.Errorf("%w: value %d encoded in 1 byte but fits the immediate form", ErrNonCanonical, arg)
		}
		return major, arg, nil
	case ai == 25:
		if d.pos+2 > len(d.buf) {
			return 0, 0, ErrCBORTruncated
		}
		arg = uint64(binary.BigEndian.Uint16(d.buf[d.pos:]))
		d.pos += 2
		if arg <= math.MaxUint8 {
			return 0, 0, fmt.Errorf("%w: value %d encoded in 2 bytes but fits 1", ErrNonCanonical, arg)
		}
		return major, arg, nil
	case ai == 26:
		if d.pos+4 > len(d.buf) {
			return 0, 0, ErrCBORTruncated
		}
		arg = uint64(binary.BigEndian.Uint32(d.buf[d.pos:]))
		d.pos += 4
		if arg <= math.MaxUint16 {
			return 0, 0, fmt.Errorf("%w: value %d encoded in 4 bytes but fits 2", ErrNonCanonical, arg)
		}
		return major, arg, nil
	case ai == 27:
		if d.pos+8 > len(d.buf) {
			return 0, 0, ErrCBORTruncated
		}
		arg = binary.BigEndian.Uint64(d.buf[d.pos:])
		d.pos += 8
		if arg <= math.MaxUint32 {
			return 0, 0, fmt.Errorf("%w: value %d encoded in 8 bytes but fits 4", ErrNonCanonical, arg)
		}
		return major, arg, nil
	case ai == 31:
		return 0, 0, fmt.Errorf("%w: indefinite-length item", ErrCBORUnsupported)
	default:
		return 0, 0, fmt.Errorf("%w: reserved additional-information value %d", ErrCBORUnsupported, ai)
	}
}

func (d *cborDecoder) expect(want byte) (uint64, error) {
	major, arg, err := d.head()
	if err != nil {
		return 0, err
	}
	if major != want {
		return 0, fmt.Errorf("expected CBOR major type %d, got %d", want, major)
	}
	return arg, nil
}

func (d *cborDecoder) uint() (uint64, error) { return d.expect(majorUint) }

func (d *cborDecoder) mapHeader() (int, error) {
	n, err := d.expect(majorMap)
	return int(n), err
}

func (d *cborDecoder) arrayHeader() (int, error) {
	n, err := d.expect(majorArray)
	return int(n), err
}

func (d *cborDecoder) bytes() ([]byte, error) {
	n, err := d.expect(majorBytes)
	if err != nil {
		return nil, err
	}
	if d.pos+int(n) > len(d.buf) {
		return nil, ErrCBORTruncated
	}
	out := d.buf[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return out, nil
}

// bytesN reads a byte string of exactly n bytes into a fixed-size array.
func (d *cborDecoder) bytesN(n int) ([]byte, error) {
	b, err := d.bytes()
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("expected %d-byte string, got %d", n, len(b))
	}
	return b, nil
}

func (d *cborDecoder) text() (string, error) {
	n, err := d.expect(majorText)
	if err != nil {
		return "", err
	}
	if d.pos+int(n) > len(d.buf) {
		return "", ErrCBORTruncated
	}
	out := string(d.buf[d.pos : d.pos+int(n)])
	d.pos += int(n)
	return out, nil
}

// isNull consumes a null if present and reports whether it did.
func (d *cborDecoder) isNull() bool {
	if d.pos < len(d.buf) && d.buf[d.pos] == majorSimple<<5|simpleNull {
		d.pos++
		return true
	}
	return false
}

func (d *cborDecoder) atEnd() bool { return d.pos >= len(d.buf) }

// uint8 reads an unsigned integer that must fit in a uint8.
func (d *cborDecoder) uint8() (uint8, error) {
	v, err := d.uint()
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint8 {
		return 0, fmt.Errorf("value %d exceeds uint8", v)
	}
	return uint8(v), nil
}

// uint32 reads an unsigned integer that must fit in a uint32.
func (d *cborDecoder) uint32() (uint32, error) {
	v, err := d.uint()
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, fmt.Errorf("value %d exceeds uint32", v)
	}
	return uint32(v), nil
}
