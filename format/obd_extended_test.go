package format

import (
	"encoding/binary"
	"testing"
)

// Round-trips the layout the firmware writes, and checks the derived values a
// tuning question actually asks: how much boost, and how is the mixture.
func TestOBDExtendedRoundTrip(t *testing.T) {
	// 230 kPa manifold against 101 kPa ambient = 129 kPa gauge ≈ 18.7 psi,
	// which is a plausible full-boost reading on a tuned N20.
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], 230)  // MAP kPa absolute
	binary.LittleEndian.PutUint16(p[2:], 4500) // 45.00 g/s
	binary.LittleEndian.PutUint16(p[4:], 8800) // lambda 0.88, rich under load as expected
	binary.LittleEndian.PutUint16(p[6:], 1420) // 142.0% absolute load
	p[8] = 101                                 // barometric
	p[9] = byte(int8(24))                      // ambient
	p[10] = byte(uint8(0xFD))                  // -3 as int8
	p[11] = byte(int8(5))
	binary.LittleEndian.PutUint32(p[12:], 8)
	binary.LittleEndian.PutUint32(p[16:], 8)
	binary.LittleEndian.PutUint16(p[20:], 2000)

	o, err := ParseOBDExtended(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if o.MAPkPa == nil || *o.MAPkPa != 230 {
		t.Fatal("MAP did not decode")
	}

	gauge, ok := o.BoostGaugeKPa()
	if !ok || gauge != 129 {
		t.Errorf("gauge = %.1f kPa (ok=%v), want 129", gauge, ok)
	}

	psi, ok := o.BoostPSI()
	if !ok || psi < 18.6 || psi > 18.8 {
		t.Errorf("boost = %.2f psi (ok=%v), want about 18.7", psi, ok)
	}

	lambda, ok := o.Lambda()
	if !ok || lambda < 0.879 || lambda > 0.881 {
		t.Errorf("lambda = %.4f (ok=%v), want 0.88", lambda, ok)
	}

	if o.FuelTrimShortPct == nil || *o.FuelTrimShortPct != -3 {
		t.Error("negative short fuel trim did not survive")
	}
	if o.AbsLoadPctE1 == nil || *o.AbsLoadPctE1 != 1420 {
		t.Error("absolute load above 100% did not survive, which is the whole " +
			"reason it is scaled rather than a percentage byte")
	}
}

// An ECU that answers none of these must decode to absent values, not to zeroes
// that read as a measurement — and boost must refuse to be computed rather than
// assume sea level.
func TestOBDExtendedSentinelsAreAbsent(t *testing.T) {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], sentinelU16)
	binary.LittleEndian.PutUint16(p[2:], sentinelU16)
	binary.LittleEndian.PutUint16(p[4:], sentinelU16)
	binary.LittleEndian.PutUint16(p[6:], sentinelU16)
	p[8] = sentinelU8
	p[9] = 0x80
	p[10] = 0x80
	p[11] = 0x80

	o, err := ParseOBDExtended(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if o.MAPkPa != nil || o.BaroKPa != nil || o.LambdaE4 != nil ||
		o.MAFcgps != nil || o.AbsLoadPctE1 != nil ||
		o.AmbientTempC != nil || o.FuelTrimShortPct != nil ||
		o.FuelTrimLongPct != nil {
		t.Error("a sentinel decoded to a value; an unanswered PID must be absent")
	}

	if _, ok := o.BoostPSI(); ok {
		t.Error("boost was computed with no manifold reading; it must refuse " +
			"rather than assume an ambient pressure")
	}
}

// Barometric present but manifold missing must still refuse.
func TestBoostNeedsBothPressures(t *testing.T) {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], sentinelU16)
	p[8] = 101

	o, err := ParseOBDExtended(p)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := o.BoostGaugeKPa(); ok {
		t.Error("gauge pressure computed from barometric alone")
	}
}

func TestOBDExtendedRejectsWrongLength(t *testing.T) {
	if _, err := ParseOBDExtended(make([]byte, 23)); err == nil {
		t.Error("a 23-byte payload was accepted")
	}
}
