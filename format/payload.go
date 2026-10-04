package format

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Typed payload decoders for the record schemas in docs/bundle-format-v2.md
// section 4.
//
// Every "unavailable" sentinel the specification defines is honoured and
// surfaced as a nil pointer rather than a zero value. The distinction is not
// pedantic: "the ECU reported 0 kph" and "the ECU did not answer" are different
// facts, and collapsing them fabricates data. The same applies to GNSS
// accuracy — where the receiver supplied no estimate the field is nil, never a
// plausible guess, because a consumer must not infer a precision the hardware
// did not claim.

// Sentinels meaning "not available", per the specification.
const (
	sentinelU16 = 0xFFFF
	sentinelI16 = -0x8000 // 0x8000 read as int16
	sentinelU8  = 0xFF
	sentinelI8  = -0x80 // 0x80 read as int8
)

// UnavailableU16 and UnavailableI8 report whether a field carries the
// specification's "unavailable" sentinel rather than a measurement.
//
// Exported because DEVICE_HEALTH is parsed into plain integers rather than
// pointers — the parser stays faithful to the bytes and leaves the semantics to
// its caller — so every caller needs a way to ask. Without these the sentinel
// travels onward as a number: 65535 mV of supply, or −128 °C, both of which
// read as measurements and neither of which is one.
func UnavailableU16(v uint16) bool { return v == sentinelU16 }

// UnavailableI8 reports the int8 sentinel, used by temperature and RSSI.
func UnavailableI8(v int8) bool { return v == sentinelI8 }

// GNSSSample is a decoded position observation (§4.1).
type GNSSSample struct {
	LatE7 int32
	LonE7 int32
	AltCM int32

	SpeedCMPS   uint16
	HeadingCDeg uint16

	// HDOPe2 is HDOP × 100. Nil when the receiver did not report it.
	HDOPe2 *uint16
	// HAccCM and VAccCM are nil when the receiver supplied no estimate.
	HAccCM *uint16
	VAccCM *uint16

	// FixType: 0 none, 1 2D, 2 3D, 3 DGPS, 4 RTK-float, 5 RTK-fixed.
	FixType     uint8
	SatsUsed    uint8
	SatsVisible uint8
	SourceFlags uint8

	// UTCOffsetMS is a signed delta from the manifest's utc_basis_ms.
	UTCOffsetMS int32
	// UTCAccMS is nil when the uncertainty is unknown.
	UTCAccMS *uint16
}

// HasFix reports whether this sample carries a usable position.
//
// A sample without a fix must not be plotted. The specification requires the
// coordinates be written as zero in that case, but a consumer should rely on
// this rather than on the coordinate values.
func (s *GNSSSample) HasFix() bool { return s.FixType != 0 }

// LatDeg and LonDeg convert the fixed-point coordinates to degrees.
func (s *GNSSSample) LatDeg() float64 { return float64(s.LatE7) / 1e7 }
func (s *GNSSSample) LonDeg() float64 { return float64(s.LonE7) / 1e7 }

// SpeedMPS converts the stored cm/s to m/s.
func (s *GNSSSample) SpeedMPS() float64 { return float64(s.SpeedCMPS) / 100.0 }

// HeadingDeg converts centidegrees to degrees.
func (s *GNSSSample) HeadingDeg() float64 { return float64(s.HeadingCDeg) / 100.0 }

// AltitudeM converts centimetres to metres.
func (s *GNSSSample) AltitudeM() float64 { return float64(s.AltCM) / 100.0 }

// ParseGNSSSample decodes a 32-byte GNSS payload.
func ParseGNSSSample(p []byte) (*GNSSSample, error) {
	const want = 32
	if len(p) != want {
		return nil, fmt.Errorf("GNSS_SAMPLE payload is %d bytes, want %d", len(p), want)
	}

	s := &GNSSSample{
		LatE7:       int32(binary.LittleEndian.Uint32(p[0:4])),
		LonE7:       int32(binary.LittleEndian.Uint32(p[4:8])),
		AltCM:       int32(binary.LittleEndian.Uint32(p[8:12])),
		SpeedCMPS:   binary.LittleEndian.Uint16(p[12:14]),
		HeadingCDeg: binary.LittleEndian.Uint16(p[14:16]),
		FixType:     p[22],
		SatsUsed:    p[23],
		SatsVisible: p[24],
		SourceFlags: p[25],
		UTCOffsetMS: int32(binary.LittleEndian.Uint32(p[26:30])),
	}

	if v := binary.LittleEndian.Uint16(p[16:18]); v != sentinelU16 {
		s.HDOPe2 = &v
	}
	if v := binary.LittleEndian.Uint16(p[18:20]); v != sentinelU16 {
		s.HAccCM = &v
	}
	if v := binary.LittleEndian.Uint16(p[20:22]); v != sentinelU16 {
		s.VAccCM = &v
	}
	if v := binary.LittleEndian.Uint16(p[30:32]); v != sentinelU16 {
		s.UTCAccMS = &v
	}

	if s.FixType > 5 {
		return nil, fmt.Errorf("GNSS_SAMPLE fix_type %d is not defined", s.FixType)
	}
	if s.HeadingCDeg > 35999 {
		return nil, fmt.Errorf("GNSS_SAMPLE heading %d centidegrees exceeds 35999", s.HeadingCDeg)
	}

	return s, nil
}

// IMUSummary is a decoded motion window (§4.2).
type IMUSummary struct {
	WindowMS     uint16
	AccelRMSmg   uint16
	AccelPeakXmg int16
	AccelPeakYmg int16
	AccelPeakZmg int16
	// GyroPeakDPSe1 is deg/s × 10.
	GyroPeakDPSe1 int16
	Variance      uint16
	SampleCount   uint16
	EventFlags    uint8
}

// IMU event flags.
const (
	IMUEventImpact    uint8 = 1 << 0
	IMUEventHardBrake uint8 = 1 << 1
	IMUEventSharpTurn uint8 = 1 << 2
	IMUEventPothole   uint8 = 1 << 3
)

// GyroPeakDPS converts the stored tenths to deg/s.
func (s *IMUSummary) GyroPeakDPS() float64 { return float64(s.GyroPeakDPSe1) / 10.0 }

// ParseIMUSummary decodes a 20-byte IMU summary payload.
func ParseIMUSummary(p []byte) (*IMUSummary, error) {
	const want = 20
	if len(p) != want {
		return nil, fmt.Errorf("IMU_SUMMARY payload is %d bytes, want %d", len(p), want)
	}

	return &IMUSummary{
		WindowMS:      binary.LittleEndian.Uint16(p[0:2]),
		AccelRMSmg:    binary.LittleEndian.Uint16(p[2:4]),
		AccelPeakXmg:  int16(binary.LittleEndian.Uint16(p[4:6])),
		AccelPeakYmg:  int16(binary.LittleEndian.Uint16(p[6:8])),
		AccelPeakZmg:  int16(binary.LittleEndian.Uint16(p[8:10])),
		GyroPeakDPSe1: int16(binary.LittleEndian.Uint16(p[10:12])),
		Variance:      binary.LittleEndian.Uint16(p[12:14]),
		SampleCount:   binary.LittleEndian.Uint16(p[14:16]),
		EventFlags:    p[16],
	}, nil
}

// OBDSnapshot is a decoded engine observation (§4.4).
//
// Every field is a pointer: nil means the ECU did not answer. PIDsRequested and
// PIDsAnswered make that attributable rather than guessed.
type OBDSnapshot struct {
	SpeedKPH         *int16
	RPM              *int16
	FuelPressureKPa  *uint16
	ThrottlePct      *uint8
	EngineLoadPct    *uint8
	CoolantTempC     *int8
	IntakeTempC      *int8
	TimingAdvanceDeg *int8

	PIDErrorCount uint8
	PIDsRequested uint32
	PIDsAnswered  uint32

	// PollCadenceMS is the cadence actually measured, not the target.
	PollCadenceMS uint16
}

// ParseOBDSnapshot decodes a 24-byte OBD payload.
func ParseOBDSnapshot(p []byte) (*OBDSnapshot, error) {
	const want = 24
	if len(p) != want {
		return nil, fmt.Errorf("OBD_SNAPSHOT payload is %d bytes, want %d", len(p), want)
	}

	s := &OBDSnapshot{
		PIDErrorCount: p[11],
		PIDsRequested: binary.LittleEndian.Uint32(p[12:16]),
		PIDsAnswered:  binary.LittleEndian.Uint32(p[16:20]),
		PollCadenceMS: binary.LittleEndian.Uint16(p[20:22]),
	}

	if v := int16(binary.LittleEndian.Uint16(p[0:2])); v != sentinelI16 {
		s.SpeedKPH = &v
	}
	if v := int16(binary.LittleEndian.Uint16(p[2:4])); v != sentinelI16 {
		s.RPM = &v
	}
	if v := binary.LittleEndian.Uint16(p[4:6]); v != sentinelU16 {
		s.FuelPressureKPa = &v
	}
	if v := p[6]; v != sentinelU8 {
		s.ThrottlePct = &v
	}
	if v := p[7]; v != sentinelU8 {
		s.EngineLoadPct = &v
	}
	if v := int8(p[8]); v != sentinelI8 {
		s.CoolantTempC = &v
	}
	if v := int8(p[9]); v != sentinelI8 {
		s.IntakeTempC = &v
	}
	if v := int8(p[10]); v != sentinelI8 {
		s.TimingAdvanceDeg = &v
	}

	return s, nil
}

// DeviceHealth is a decoded health snapshot (§4.5).
type DeviceHealth struct {
	BatteryMV     uint16
	SDWriteErrors uint16
	SDFreeMiB     uint16
	DeviceTempC   int8
	RSSIdBm       int8
	ExtSensor1    uint16
	ExtSensor2    uint16
	HealthState   uint8
	RebootCount   uint8
}

// Degraded-state bits in DeviceHealth.HealthState (§4.10).
//
// A bitmap rather than a severity because degradation is not ordered: a low
// battery, a missing fix and a full card are different problems with different
// fixes, and a scalar would force a priority between them and discard the rest.
const (
	HealthDegradedGNSS     uint8 = 0x01
	HealthDegradedStorage  uint8 = 0x02
	HealthDegradedTime     uint8 = 0x04
	HealthDegradedNetwork  uint8 = 0x08
	HealthLowPower         uint8 = 0x10
	HealthRecoveryRequired uint8 = 0x20
	HealthDegradedSensing  uint8 = 0x40
	// 0x80 is reserved.
)

var healthBitNames = []struct {
	bit  uint8
	name string
}{
	{HealthDegradedGNSS, "DEGRADED_GNSS"},
	{HealthDegradedStorage, "DEGRADED_STORAGE"},
	{HealthDegradedTime, "DEGRADED_TIME"},
	{HealthDegradedNetwork, "DEGRADED_NETWORK"},
	{HealthLowPower, "LOW_POWER"},
	{HealthRecoveryRequired, "RECOVERY_REQUIRED"},
	{HealthDegradedSensing, "DEGRADED_SENSING"},
}

// HealthStateNames renders a degraded-state bitmap as a list of names.
//
// Unknown bits are rendered as hex rather than masked away, so a bundle from
// newer firmware stays interpretable for the conditions this build does
// understand — which is what §4.10 requires of a decoder.
func HealthStateNames(state uint8) []string {
	if state == 0 {
		return nil
	}

	var (
		out  []string
		seen uint8
	)
	for _, b := range healthBitNames {
		if state&b.bit != 0 {
			out = append(out, b.name)
			seen |= b.bit
		}
	}
	if unknown := state & ^seen; unknown != 0 {
		out = append(out, fmt.Sprintf("0x%02x", unknown))
	}
	return out
}

// HealthStateString is HealthStateNames joined with "|", or "OK" when clear.
func HealthStateString(state uint8) string {
	names := HealthStateNames(state)
	if len(names) == 0 {
		return "OK"
	}
	return strings.Join(names, "|")
}

// ParseDeviceHealth decodes a 16-byte health payload.
func ParseDeviceHealth(p []byte) (*DeviceHealth, error) {
	const want = 16
	if len(p) != want {
		return nil, fmt.Errorf("DEVICE_HEALTH payload is %d bytes, want %d", len(p), want)
	}

	return &DeviceHealth{
		BatteryMV:     binary.LittleEndian.Uint16(p[0:2]),
		SDWriteErrors: binary.LittleEndian.Uint16(p[2:4]),
		SDFreeMiB:     binary.LittleEndian.Uint16(p[4:6]),
		DeviceTempC:   int8(p[6]),
		RSSIdBm:       int8(p[7]),
		ExtSensor1:    binary.LittleEndian.Uint16(p[8:10]),
		ExtSensor2:    binary.LittleEndian.Uint16(p[10:12]),
		HealthState:   p[12],
		RebootCount:   p[13],
	}, nil
}

// GNSSGap is a recorded absence of position (§4.8).
//
// This record is the mechanism by which the format keeps its promise that
// honest incompleteness beats fabricated continuity. A consumer renders a gap
// as a discontinuity and must never join a route across it.
type GNSSGap struct {
	DurationMS      uint32
	ExpectedSamples uint16
	Cause           uint8
}

// Gap causes.
const (
	GapCauseNoFix         uint8 = 1
	GapCauseReceiverReset uint8 = 2
	GapCausePoweredDown   uint8 = 3
	GapCauseObstruction   uint8 = 4
	GapCauseTimeJump      uint8 = 5
)

// CauseName returns a readable cause.
func (g *GNSSGap) CauseName() string {
	switch g.Cause {
	case GapCauseNoFix:
		return "no_fix"
	case GapCauseReceiverReset:
		return "receiver_reset"
	case GapCausePoweredDown:
		return "powered_down"
	case GapCauseObstruction:
		return "obstruction"
	case GapCauseTimeJump:
		return "time_jump"
	default:
		return fmt.Sprintf("unknown(%d)", g.Cause)
	}
}

// ParseGNSSGap decodes a 12-byte gap payload.
func ParseGNSSGap(p []byte) (*GNSSGap, error) {
	const want = 12
	if len(p) != want {
		return nil, fmt.Errorf("GNSS_GAP payload is %d bytes, want %d", len(p), want)
	}

	g := &GNSSGap{
		DurationMS:      binary.LittleEndian.Uint32(p[0:4]),
		ExpectedSamples: binary.LittleEndian.Uint16(p[4:6]),
		Cause:           p[6],
	}
	if g.Cause < 1 || g.Cause > 5 {
		return nil, fmt.Errorf("GNSS_GAP cause %d is not defined", g.Cause)
	}
	return g, nil
}

// StateTransition is a decoded lifecycle journal record (§4.7).
//
// Recording the evidence scores and the policy version at every transition is
// what makes a threshold retune attributable, and what lets a replay prove why
// a trip started, continued, split, finalized, retried or was retained.
type StateTransition struct {
	Region        uint8
	FromState     uint8
	ToState       uint8
	TriggerEvent  uint8
	ReasonCode    uint8
	PolicyVersion uint8

	// StartScoreE2 and StopScoreE2 are the evidence scores × 100.
	StartScoreE2 uint16
	StopScoreE2  uint16

	WakeCause uint32
}

// Lifecycle regions.
const (
	RegionCapture      uint8 = 1
	RegionBundle       uint8 = 2
	RegionConnectivity uint8 = 3
	RegionHealth       uint8 = 4
)

// StartScore and StopScore convert the stored hundredths to a score.
func (t *StateTransition) StartScore() float64 { return float64(t.StartScoreE2) / 100.0 }
func (t *StateTransition) StopScore() float64  { return float64(t.StopScoreE2) / 100.0 }

// ParseStateTransition decodes a 20-byte transition payload.
func ParseStateTransition(p []byte) (*StateTransition, error) {
	const want = 20
	if len(p) != want {
		return nil, fmt.Errorf("STATE_TRANSITION payload is %d bytes, want %d", len(p), want)
	}

	return &StateTransition{
		Region:        p[0],
		FromState:     p[1],
		ToState:       p[2],
		TriggerEvent:  p[3],
		ReasonCode:    p[4],
		PolicyVersion: p[5],
		StartScoreE2:  binary.LittleEndian.Uint16(p[8:10]),
		StopScoreE2:   binary.LittleEndian.Uint16(p[10:12]),
		WakeCause:     binary.LittleEndian.Uint32(p[12:16]),
	}, nil
}

// TripEvent is a decoded in-band event marker (§4.6).
type TripEvent struct {
	EventType uint8
	LatE7     int32
	LonE7     int32
	Detail    string
}

// HasPosition reports whether the event carries coordinates.
//
// Zero coordinates mean no valid fix was available. Position validity belongs to
// the nearest GNSS sample and is never assumed from an event.
func (e *TripEvent) HasPosition() bool { return e.LatE7 != 0 || e.LonE7 != 0 }

// TRIP_EVENT types (§4.6).
const (
	EventTripStart         uint8 = 1
	EventTripEnd           uint8 = 2
	EventHarshBrake        uint8 = 3
	EventHarshAcceleration uint8 = 4
	EventHarshCornering    uint8 = 5
	EventImpact            uint8 = 6
	// EventHarshMotion is decisive dynamics the device could not attribute.
	// Attribution needs the mounting orientation or a speed signal; with
	// neither, the motion is real and honestly unlabelled. A guess would be
	// indistinguishable from a measurement.
	EventHarshMotion      uint8 = 7
	EventCaptureRecovered uint8 = 8
)

// EventTypeName names an event type, or reports the number for one this build
// does not know.
//
// Unknown types are named rather than discarded: a newer device's events should
// still appear in an older decoder's output with their position and timing
// intact, which is what §4.6 requires.
func EventTypeName(t uint8) string {
	switch t {
	case EventTripStart:
		return "TRIP_START"
	case EventTripEnd:
		return "TRIP_END"
	case EventHarshBrake:
		return "HARSH_BRAKE"
	case EventHarshAcceleration:
		return "HARSH_ACCELERATION"
	case EventHarshCornering:
		return "HARSH_CORNERING"
	case EventImpact:
		return "IMPACT"
	case EventHarshMotion:
		return "HARSH_MOTION"
	case EventCaptureRecovered:
		return "CAPTURE_RECOVERED"
	default:
		return fmt.Sprintf("UNKNOWN_EVENT(%d)", t)
	}
}

// MaxEventDetail bounds the detail string, matching the firmware's field.
const MaxEventDetail = 48

// EncodeTripEvent builds a TRIP_EVENT payload (§4.6).
//
// A detail longer than MaxEventDetail is truncated rather than rejected: the
// event itself matters more than its annotation, and refusing to record a hard
// stop because its description was long would be the wrong trade.
func EncodeTripEvent(eventType uint8, latE7, lonE7 int32, detail string) ([]byte, error) {
	if len(detail) > MaxEventDetail {
		detail = detail[:MaxEventDetail]
	}

	out := make([]byte, 12+len(detail))
	out[0] = eventType
	out[1] = uint8(len(detail))
	// out[2:4] reserved, zero
	binary.LittleEndian.PutUint32(out[4:8], uint32(latE7))
	binary.LittleEndian.PutUint32(out[8:12], uint32(lonE7))
	copy(out[12:], detail)

	return out, nil
}

// ParseTripEvent decodes a variable-length trip event payload.
func ParseTripEvent(p []byte) (*TripEvent, error) {
	const minLen = 12
	if len(p) < minLen {
		return nil, fmt.Errorf("TRIP_EVENT payload is %d bytes, want at least %d", len(p), minLen)
	}

	detailLen := int(p[1])
	if minLen+detailLen > len(p) {
		return nil, fmt.Errorf("TRIP_EVENT detail_len %d exceeds the %d bytes available",
			detailLen, len(p)-minLen)
	}

	return &TripEvent{
		EventType: p[0],
		LatE7:     int32(binary.LittleEndian.Uint32(p[4:8])),
		LonE7:     int32(binary.LittleEndian.Uint32(p[8:12])),
		Detail:    string(p[minLen : minLen+detailLen]),
	}, nil
}

// OBDExtended is the boosted-engine and mixture record (§4.10).
//
// Pressures are absolute, as the ECU reports them. Gauge boost — what a boost
// gauge shows — is MAPkPa minus BaroKPa; see BoostPSI. Storing gauge on the
// device would have baked one barometric reading permanently into the data,
// and the whole point of this format is that the raw measurement survives for
// someone to reinterpret later.
type OBDExtended struct {
	// MAPkPa is intake manifold absolute pressure, PID 0x0B.
	MAPkPa *uint16
	// MAFcgps is mass air flow in centigrams per second, PID 0x10. Scaled so a
	// u16 covers a turbocharged engine's range without losing idle resolution.
	MAFcgps *uint16
	// LambdaE4 is the equivalence ratio times 10000, PID 0x44. 10000 is
	// stoichiometric; below is rich. Independent of the fuel's actual
	// stoichiometric ratio, which is what makes it the right mixture signal.
	LambdaE4 *uint16
	// AbsLoadRaw is the raw 16-bit pair from PID 0x43. Percent is
	// raw * 100 / 255 — see AbsoluteLoadPct — which spans the standard's full
	// 0..25700% range rather than the 0..100 a one-byte read would give.
	AbsLoadRaw *uint16

	BaroKPa          *uint8
	AmbientTempC     *int8
	FuelTrimShortPct *int8
	FuelTrimLongPct  *int8

	PIDsRequested uint32
	PIDsAnswered  uint32
	PollCadenceMS uint16

	FuelLevelPct *uint8
}

// BoostGaugeKPa returns gauge pressure — boost above ambient — and whether it
// could be computed. Needs both the manifold and barometric readings; with
// either missing the answer is unknown rather than guessed from a sea-level
// assumption.
func (o *OBDExtended) BoostGaugeKPa() (float64, bool) {
	if o.MAPkPa == nil || o.BaroKPa == nil {
		return 0, false
	}
	return float64(*o.MAPkPa) - float64(*o.BaroKPa), true
}

// BoostPSI is BoostGaugeKPa in pounds per square inch, the unit boost is
// usually discussed in. Negative values are vacuum, which is what a throttled
// engine off boost actually reads.
func (o *OBDExtended) BoostPSI() (float64, bool) {
	kpa, ok := o.BoostGaugeKPa()
	if !ok {
		return 0, false
	}
	return kpa * 0.1450377, true
}

// Lambda returns the equivalence ratio as a float, and whether it was reported.
func (o *OBDExtended) Lambda() (float64, bool) {
	if o.LambdaE4 == nil {
		return 0, false
	}
	return float64(*o.LambdaE4) / 10000.0, true
}

// ParseOBDExtended decodes §4.10.
func ParseOBDExtended(p []byte) (*OBDExtended, error) {
	const want = 24
	if len(p) != want {
		return nil, fmt.Errorf("OBD_EXTENDED payload is %d bytes, want %d", len(p), want)
	}

	var o OBDExtended

	if v := binary.LittleEndian.Uint16(p[0:2]); v != sentinelU16 {
		o.MAPkPa = &v
	}
	if v := binary.LittleEndian.Uint16(p[2:4]); v != sentinelU16 {
		o.MAFcgps = &v
	}
	if v := binary.LittleEndian.Uint16(p[4:6]); v != sentinelU16 {
		o.LambdaE4 = &v
	}
	if v := binary.LittleEndian.Uint16(p[6:8]); v != sentinelU16 {
		o.AbsLoadRaw = &v
	}
	if v := p[8]; v != sentinelU8 {
		o.BaroKPa = &v
	}
	if v := int8(p[9]); v != sentinelI8 {
		o.AmbientTempC = &v
	}
	if v := int8(p[10]); v != sentinelI8 {
		o.FuelTrimShortPct = &v
	}
	if v := int8(p[11]); v != sentinelI8 {
		o.FuelTrimLongPct = &v
	}

	o.PIDsRequested = binary.LittleEndian.Uint32(p[12:16])
	o.PIDsAnswered = binary.LittleEndian.Uint32(p[16:20])
	o.PollCadenceMS = binary.LittleEndian.Uint16(p[20:22])

	if v := p[22]; v != sentinelU8 {
		o.FuelLevelPct = &v
	}

	return &o, nil
}

// AbsoluteLoadPct converts the raw PID 0x43 pair to a percentage, and reports
// whether it was present.
//
// The standard formula is ((A*256)+B) * 100 / 255, which reaches 25700%. Values
// above 100% are normal on a turbocharged engine — one reference puts an N20
// near 190% under full boost — so a reader must not treat anything over 100 as
// corrupt.
func (o *OBDExtended) AbsoluteLoadPct() (float64, bool) {
	if o.AbsLoadRaw == nil {
		return 0, false
	}
	return float64(*o.AbsLoadRaw) * 100.0 / 255.0, true
}

// MAPSaturated reports whether manifold pressure is pinned at the top of PID
// 0x0B's one-byte range.
//
// 0x0B is a single byte, so it hard-stops at 255 kPa absolute — roughly 22.3
// psi of gauge boost at sea level. That ceiling falls inside the range a tuned
// car operates in: a stock N20 peaks near 221 kPa, a Stage 2 tune around 253,
// and some maps target 260 and above. Past the limit the log shows a flat
// plateau at exactly 255 rather than a rollover, which reads like a boost
// controller holding steady instead of an instrument running out of scale.
//
// Saying so explicitly is the difference between "my tune is flat-lining" and
// "my logger is". PID 0x4F byte D declares the vehicle's own IMAP maximum and
// is the standard way to learn the real ceiling.
func (o *OBDExtended) MAPSaturated() bool {
	return o.MAPkPa != nil && *o.MAPkPa >= 255
}
