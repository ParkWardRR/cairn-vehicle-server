package format

import "fmt"

// PolicySnapshot is the active capture policy a bundle was produced under
// (§4.9).
//
// Recorded because a version number identifies a policy without describing one.
// Interpreting an old bundle from PolicyVersion alone would mean finding the
// firmware build that defined that version; the values make a trip captured
// under thresholds nobody remembers explainable from the trip.
type PolicySnapshot struct {
	PolicyVersion uint8

	GNSSPeriodMS   uint16
	IMUWindowMS    uint16
	OBDPeriodMS    uint16
	HealthPeriodMS uint32

	StartScoreThresholdE2 uint16
	StopScoreThresholdE2  uint16
	StartDwellMS          uint32
	StopDwellMS           uint32

	MotionAccelRMSmg uint16
	MotionSpeedCMPS  uint16

	PrerollWindowMS    uint32
	PrerollRingSamples uint16
	SegmentMaxBytes    uint32

	// AdaptiveSampling means the periods above are upper bounds during a trip
	// rather than fixed rates (§4.9.1). Adaptation may only add detail, so a
	// reader's floor of one record per nominal period still holds.
	AdaptiveSampling bool
}

// Policy snapshot CBOR keys.
const (
	polKeyPolicyVersion    = 1
	polKeyGNSSPeriod       = 2
	polKeyIMUWindow        = 3
	polKeyOBDPeriod        = 4
	polKeyHealthPeriod     = 5
	polKeyStartScore       = 6
	polKeyStopScore        = 7
	polKeyStartDwell       = 8
	polKeyStopDwell        = 9
	polKeyMotionAccel      = 10
	polKeyMotionSpeed      = 11
	polKeyPrerollWindow    = 12
	polKeyPrerollSamples   = 13
	polKeySegmentMax       = 14
	polKeyAdaptiveSampling = 15

	policyFieldCount = 15
)

// ParsePolicySnapshot decodes a POLICY_SNAPSHOT payload.
//
// Strict about canonical encoding for the same reason the manifest decoder is:
// a map this implementation would not itself have produced cannot be compared
// byte-for-byte against another bundle's, which is what makes grouping bundles
// by policy meaningful without trusting the version number.
func ParsePolicySnapshot(p []byte) (*PolicySnapshot, error) {
	d := &cborDecoder{buf: p}

	n, err := d.mapHeader()
	if err != nil {
		return nil, fmt.Errorf("policy snapshot: %w", err)
	}
	if n != policyFieldCount {
		return nil, fmt.Errorf("policy snapshot has %d fields, want %d",
			n, policyFieldCount)
	}

	var out PolicySnapshot

	for i := 0; i < n; i++ {
		key, err := d.uint()
		if err != nil {
			return nil, fmt.Errorf("policy snapshot key %d: %w", i, err)
		}

		v, err := d.uint()
		if err != nil {
			return nil, fmt.Errorf("policy snapshot value for key %d: %w", key, err)
		}

		switch key {
		case polKeyPolicyVersion:
			out.PolicyVersion = uint8(v)
		case polKeyGNSSPeriod:
			out.GNSSPeriodMS = uint16(v)
		case polKeyIMUWindow:
			out.IMUWindowMS = uint16(v)
		case polKeyOBDPeriod:
			out.OBDPeriodMS = uint16(v)
		case polKeyHealthPeriod:
			out.HealthPeriodMS = uint32(v)
		case polKeyStartScore:
			out.StartScoreThresholdE2 = uint16(v)
		case polKeyStopScore:
			out.StopScoreThresholdE2 = uint16(v)
		case polKeyStartDwell:
			out.StartDwellMS = uint32(v)
		case polKeyStopDwell:
			out.StopDwellMS = uint32(v)
		case polKeyMotionAccel:
			out.MotionAccelRMSmg = uint16(v)
		case polKeyMotionSpeed:
			out.MotionSpeedCMPS = uint16(v)
		case polKeyPrerollWindow:
			out.PrerollWindowMS = uint32(v)
		case polKeyPrerollSamples:
			out.PrerollRingSamples = uint16(v)
		case polKeySegmentMax:
			out.SegmentMaxBytes = uint32(v)
		case polKeyAdaptiveSampling:
			out.AdaptiveSampling = v != 0
		default:
			// An unknown key means newer firmware. Refuse rather than ignore:
			// the field count is fixed, so an unexpected key means this decoder
			// does not understand the policy it is being asked to describe, and
			// reporting a partial policy as complete would be worse than
			// reporting none.
			return nil, fmt.Errorf("policy snapshot has unknown key %d; this "+
				"build does not understand the policy", key)
		}
	}

	// Trailing bytes would mean the payload carries something this decoder did
	// not account for, which is the same hazard as an unknown key.
	if !d.atEnd() {
		return nil, fmt.Errorf("policy snapshot has %d trailing byte(s)",
			len(p)-d.pos)
	}

	return &out, nil
}
