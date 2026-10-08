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
	binary.LittleEndian.PutUint16(p[6:], 362)  // 142.0% absolute load
	p[8] = 101                                 // barometric
	p[9] = byte(int8(24))                      // ambient
	p[10] = byte(uint8(0xFD))                  // -3 as int8
	p[11] = byte(int8(5))
	binary.LittleEndian.PutUint32(p[12:], 8)
	binary.LittleEndian.PutUint32(p[16:], 8)
	binary.LittleEndian.PutUint16(p[20:], 2000)
	p[22] = 72 // fuel level 72%

	o, err := ParseOBDExtended(p, OBDExtendedPedalSchema)
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
	// Raw 362 is 362 * 100 / 255 ≈ 142%, the sort of absolute load a
	// turbocharged engine reaches under boost — and the value the library's
	// one-byte path would have reported as about 5%.
	if o.AbsLoadRaw == nil || *o.AbsLoadRaw != 362 {
		t.Error("the raw absolute-load pair did not survive")
	}
	if pct, ok := o.AbsoluteLoadPct(); !ok || pct < 141.9 || pct > 142.1 {
		t.Errorf("absolute load = %.1f%% (ok=%v), want about 142 — values above "+
			"100 are normal under boost and must not be clamped", pct, ok)
	}
	if o.FuelLevelPct == nil || *o.FuelLevelPct != 72 {
		t.Error("fuel level did not decode")
	}
}

// PID 0x0B is one byte, so it hard-stops at 255 kPa absolute — roughly 22.3 psi
// of gauge boost. That ceiling sits inside the range a tuned car operates in,
// and the log shows a flat plateau rather than a rollover, which reads exactly
// like a boost controller holding steady. Saying so is the difference between
// "my tune is flat-lining" and "my logger is".
func TestMAPSaturationIsFlagged(t *testing.T) {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], 255)
	p[8] = 101

	o, err := ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !o.MAPSaturated() {
		t.Error("255 kPa was not flagged as saturated")
	}

	// A stock-ish peak must not be flagged.
	binary.LittleEndian.PutUint16(p[0:], 221)
	o, _ = ParseOBDExtended(p, OBDExtendedPedalSchema)
	if o.MAPSaturated() {
		t.Error("221 kPa was flagged as saturated; that is a real reading")
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
	p[22] = sentinelU8
	p[23] = sentinelU8

	o, err := ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if o.MAPkPa != nil || o.BaroKPa != nil || o.LambdaE4 != nil ||
		o.MAFcgps != nil || o.AbsLoadRaw != nil ||
		o.AmbientTempC != nil || o.FuelTrimShortPct != nil ||
		o.FuelTrimLongPct != nil || o.FuelLevelPct != nil || o.PedalPct != nil {
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

	o, err := ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := o.BoostGaugeKPa(); ok {
		t.Error("gauge pressure computed from barometric alone")
	}
}

func TestOBDExtendedRejectsWrongLength(t *testing.T) {
	if _, err := ParseOBDExtended(make([]byte, 23), OBDExtendedPedalSchema); err == nil {
		t.Error("a 23-byte payload was accepted")
	}
}

// Byte 23 is pedal position only from schema_version 2. Version 1 put a reserved
// zero there, and that zero cannot be told from a genuine 0% pedal by value — so
// the version, not the byte, decides whether the field means anything.
//
// pids_requested would be the natural discriminator and is documented as a
// bitmap, but the firmware has always written a plain count, so it cannot say
// which PIDs were asked for.
func TestPedalNeedsSchemaVersion2(t *testing.T) {
	p := make([]byte, 24)
	p[23] = 42

	o, err := ParseOBDExtended(p, 1)
	if err != nil {
		t.Fatalf("parse v1: %v", err)
	}
	if o.PedalPct != nil {
		t.Errorf("a version 1 record yielded pedal_pct = %d; byte 23 is reserved there",
			*o.PedalPct)
	}

	o, err = ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if o.PedalPct == nil || *o.PedalPct != 42 {
		t.Errorf("a version 2 record did not yield pedal_pct = 42")
	}

	// A real closed pedal is zero and must survive as a measurement, which is the
	// whole reason the version gate exists rather than treating 0 as absent.
	p[23] = 0
	o, err = ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse zero: %v", err)
	}
	if o.PedalPct == nil || *o.PedalPct != 0 {
		t.Error("a genuine 0% pedal was dropped; closed throttle is a measurement")
	}

	// And the sentinel is still absent.
	p[23] = sentinelU8
	o, err = ParseOBDExtended(p, OBDExtendedPedalSchema)
	if err != nil {
		t.Fatalf("parse sentinel: %v", err)
	}
	if o.PedalPct != nil {
		t.Error("the unavailable sentinel decoded to a value")
	}
}
