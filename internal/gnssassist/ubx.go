package gnssassist

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UBX framing, and the handful of messages this package has to recognise.
//
// The receiver speaks UBX: 0xB5 0x62, class, id, a little-endian u16 length,
// the payload, and a two-byte Fletcher checksum over class..payload. AssistNow
// returns a plain concatenation of such frames, and the registration call wants
// two of the receiver's own replies verbatim, so framing is the only parsing
// the server needs.

const (
	ubxSync1 = 0xB5
	ubxSync2 = 0x62

	classMGA = 0x13
	classMON = 0x0A
	classSEC = 0x27

	idMONVER    = 0x04
	idSECUNIQID = 0x03
	idMGAANO    = 0x20
	idMGAINI    = 0x40

	// frameOverhead is sync, class, id, length and checksum.
	frameOverhead = 8
)

// Frame is one checksummed UBX message. Raw is the whole frame, sync to checksum.
type Frame struct {
	Class, ID byte
	Payload   []byte
	Raw       []byte
}

// ErrNotUBX is returned for bytes that are not a clean sequence of UBX frames.
var ErrNotUBX = errors.New("not a sequence of UBX frames")

func checksum(b []byte) (byte, byte) {
	var a, c byte
	for _, x := range b {
		a += x
		c += a
	}
	return a, c
}

// Encode builds a frame. Used by tests and by nothing on the request path.
func Encode(class, id byte, payload []byte) []byte {
	out := make([]byte, 0, len(payload)+frameOverhead)
	out = append(out, ubxSync1, ubxSync2, class, id, byte(len(payload)), byte(len(payload)>>8))
	out = append(out, payload...)
	a, c := checksum(out[2:])
	return append(out, a, c)
}

// SplitFrames parses data as back-to-back UBX frames and fails on anything else:
// a stray byte, a truncated tail or a bad checksum. AssistNow's error replies are
// text, so this is also what tells a 200 carrying an error string from data.
func SplitFrames(data []byte) ([]Frame, error) {
	var frames []Frame
	for off := 0; off < len(data); {
		rest := data[off:]
		if len(rest) < frameOverhead {
			return nil, fmt.Errorf("%w: %d trailing bytes at offset %d", ErrNotUBX, len(rest), off)
		}
		if rest[0] != ubxSync1 || rest[1] != ubxSync2 {
			return nil, fmt.Errorf("%w: no sync at offset %d", ErrNotUBX, off)
		}
		n := int(rest[4]) | int(rest[5])<<8
		if len(rest) < n+frameOverhead {
			return nil, fmt.Errorf("%w: frame at offset %d claims %d bytes, %d remain", ErrNotUBX, off, n, len(rest)-frameOverhead)
		}
		raw := rest[:n+frameOverhead]
		a, c := checksum(raw[2 : 6+n])
		if raw[6+n] != a || raw[7+n] != c {
			return nil, fmt.Errorf("%w: bad checksum at offset %d", ErrNotUBX, off)
		}
		frames = append(frames, Frame{Class: raw[2], ID: raw[3], Payload: raw[6 : 6+n], Raw: raw})
		off += len(raw)
	}
	return frames, nil
}

// singleFrame parses hex that must be exactly one frame of the given class and id.
func singleFrame(hexText string, class, id byte, what string) (Frame, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexText))
	if err != nil {
		return Frame{}, fmt.Errorf("%s is not hex: %w", what, err)
	}
	frames, err := SplitFrames(raw)
	if err != nil {
		return Frame{}, fmt.Errorf("%s: %w", what, err)
	}
	if len(frames) != 1 {
		return Frame{}, fmt.Errorf("%s: %d frames, want exactly one", what, len(frames))
	}
	f := frames[0]
	if f.Class != class || f.ID != id {
		return Frame{}, fmt.Errorf("%s: frame is class 0x%02X id 0x%02X, want 0x%02X 0x%02X", what, f.Class, f.ID, class, id)
	}
	return f, nil
}

// Identity is a receiver's two replies that ZTP registration needs, verbatim.
type Identity struct {
	SecUniqID []byte // the whole UBX-SEC-UNIQID frame
	MonVer    []byte // the whole UBX-MON-VER frame

	// UniqueID is the chip id in lowercase hex: 5 bytes on a u-blox M9
	// (message version 1), 6 on an M10 (version 2). Thingstream names the
	// device's Thing after it, which is why it is safe to log and is used as the
	// directory name.
	UniqueID string
}

// ParseIdentity validates the two frames as hex text, as the device reports them.
func ParseIdentity(secHex, monHex string) (Identity, error) {
	sec, err := singleFrame(secHex, classSEC, idSECUNIQID, "UBX-SEC-UNIQID")
	if err != nil {
		return Identity{}, err
	}
	// version, three reserved bytes, then the id: 9 bytes (5-byte id) or 10 (6-byte).
	if n := len(sec.Payload); n != 9 && n != 10 {
		return Identity{}, fmt.Errorf("UBX-SEC-UNIQID: %d-byte payload, want 9 or 10", n)
	}
	mon, err := singleFrame(monHex, classMON, idMONVER, "UBX-MON-VER")
	if err != nil {
		return Identity{}, err
	}
	if n := len(mon.Payload); n < 40 || (n-40)%30 != 0 {
		return Identity{}, fmt.Errorf("UBX-MON-VER: %d-byte payload is not 40 + 30n", n)
	}
	return Identity{
		SecUniqID: append([]byte(nil), sec.Raw...),
		MonVer:    append([]byte(nil), mon.Raw...),
		UniqueID:  hex.EncodeToString(sec.Payload[4:]),
	}, nil
}

// Describe summarises MON-VER for a log line: software, hardware and the
// extension strings, among them MOD= (the module) on the receivers that have it.
func (id Identity) Describe() string {
	frames, err := SplitFrames(id.MonVer)
	if err != nil || len(frames) != 1 || len(frames[0].Payload) < 40 {
		return "unknown"
	}
	p := frames[0].Payload
	cstr := func(b []byte) string {
		if i := bytes.IndexByte(b, 0); i >= 0 {
			b = b[:i]
		}
		return strings.TrimSpace(string(b))
	}
	parts := []string{"sw=" + cstr(p[0:30]), "hw=" + cstr(p[30:40])}
	for off := 40; off+30 <= len(p); off += 30 {
		if s := cstr(p[off : off+30]); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// anoDay is the UTC date a UBX-MGA-ANO message predicts for. The payload is
// type, version, svId, gnssId, then year since 2000, month and day.
func anoDay(f Frame) (time.Time, bool) {
	if f.Class != classMGA || f.ID != idMGAANO || len(f.Payload) < 7 {
		return time.Time{}, false
	}
	y, m, d := int(f.Payload[4])+2000, int(f.Payload[5]), int(f.Payload[6])
	if m < 1 || m > 12 || d < 1 || d > 31 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC), true
}

// isINI is any UBX-MGA-INI message. AssistNow puts INI-TIME_UTC first when the
// request includes Galileo or GLONASS almanacs, and that time is the moment the
// server answered. Kept in a cache it would later be injected hours or days late
// while still claiming its +/- 10 s, which is worse than sending no time at all.
func isINI(f Frame) bool { return f.Class == classMGA && f.ID == idMGAINI }

// Summary counts what a stream holds, for logs and the status mode.
type Summary struct {
	Bytes      int
	Frames     int
	ANO        int
	Almanac    int // every other MGA message, which for this request is almanacs
	FirstDay   time.Time
	LastDay    time.Time
	DroppedINI int
}

func summarise(frames []Frame) Summary {
	var s Summary
	for _, f := range frames {
		s.Frames++
		s.Bytes += len(f.Raw)
		if day, ok := anoDay(f); ok {
			s.ANO++
			if s.FirstDay.IsZero() || day.Before(s.FirstDay) {
				s.FirstDay = day
			}
			if day.After(s.LastDay) {
				s.LastDay = day
			}
		} else if f.Class == classMGA {
			s.Almanac++
		}
	}
	return s
}

// cleanForCache keeps the MGA messages and drops INI (see isINI) and anything
// that is not MGA at all, which AssistNow does not send but a cache must not keep.
func cleanForCache(frames []Frame) ([]Frame, int) {
	out := frames[:0:0]
	dropped := 0
	for _, f := range frames {
		if f.Class != classMGA || isINI(f) {
			dropped++
			continue
		}
		out = append(out, f)
	}
	return out, dropped
}

// forDevice is what one device request gets: predictions for days before today
// dropped (the receiver would discard them, and on LTE every byte is paid for),
// everything else in the order AssistNow delivered it, then whole days dropped
// from the end until the stream fits in max bytes. Almanacs are kept first
// because they are small and stay valid for weeks.
func forDevice(frames []Frame, today time.Time, max int) []byte {
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	var keep []Frame
	for _, f := range frames {
		if day, ok := anoDay(f); ok && day.Before(today) {
			continue
		}
		keep = append(keep, f)
	}
	size := func(fs []Frame) int {
		n := 0
		for _, f := range fs {
			n += len(f.Raw)
		}
		return n
	}
	for size(keep) > max {
		var last time.Time
		for _, f := range keep {
			if day, ok := anoDay(f); ok && day.After(last) {
				last = day
			}
		}
		if last.IsZero() {
			// Nothing but almanacs and still too big: cannot happen with the sizes
			// AssistNow publishes (~7 KB for four constellations), so refuse
			// rather than truncate mid-set.
			return nil
		}
		trimmed := keep[:0:0]
		for _, f := range keep {
			if day, ok := anoDay(f); ok && day.Equal(last) {
				continue
			}
			trimmed = append(trimmed, f)
		}
		keep = trimmed
	}
	var buf bytes.Buffer
	for _, f := range keep {
		buf.Write(f.Raw)
	}
	return buf.Bytes()
}
