package format

import "testing"

// firmwarePolicyBytes is what the C implementation's cairn_policy_encode emits
// for its compiled-in defaults, captured verbatim.
//
// A cross-implementation check on real output rather than on a round trip
// through this package alone: the point of a deterministic encoding is that two
// implementations agree byte-for-byte, and only bytes from the other one can
// demonstrate that.
var firmwarePolicyBytes = []byte{
	0xaf, 0x01, 0x01, 0x02, 0x19, 0x03, 0xe8, 0x03, 0x19, 0x03, 0xe8, 0x04,
	0x19, 0x07, 0xd0, 0x05, 0x19, 0x75, 0x30, 0x06, 0x18, 0x96, 0x07, 0x18,
	0x28, 0x08, 0x19, 0x0b, 0xb8, 0x09, 0x1a, 0x00, 0x01, 0xd4, 0xc0, 0x0a,
	0x18, 0x78, 0x0b, 0x19, 0x01, 0x18, 0x0c, 0x19, 0xaf, 0xc8, 0x0d, 0x18,
	0x80, 0x0e, 0x1a, 0x00, 0x10, 0x00, 0x00, 0x0f, 0x01,
}

func TestParsePolicySnapshotFromFirmwareBytes(t *testing.T) {
	p, err := ParsePolicySnapshot(firmwarePolicyBytes)
	if err != nil {
		t.Fatalf("ParsePolicySnapshot on firmware output: %v", err)
	}

	for _, c := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"PolicyVersion", uint64(p.PolicyVersion), 1},
		{"GNSSPeriodMS", uint64(p.GNSSPeriodMS), 1000},
		{"IMUWindowMS", uint64(p.IMUWindowMS), 1000},
		{"OBDPeriodMS", uint64(p.OBDPeriodMS), 2000},
		{"HealthPeriodMS", uint64(p.HealthPeriodMS), 30000},
		{"StartScoreThresholdE2", uint64(p.StartScoreThresholdE2), 150},
		{"StopScoreThresholdE2", uint64(p.StopScoreThresholdE2), 40},
		{"StartDwellMS", uint64(p.StartDwellMS), 3000},
		{"StopDwellMS", uint64(p.StopDwellMS), 120000},
		{"MotionAccelRMSmg", uint64(p.MotionAccelRMSmg), 120},
		{"MotionSpeedCMPS", uint64(p.MotionSpeedCMPS), 280},
		{"PrerollWindowMS", uint64(p.PrerollWindowMS), 45000},
		{"PrerollRingSamples", uint64(p.PrerollRingSamples), 128},
		{"SegmentMaxBytes", uint64(p.SegmentMaxBytes), 1048576},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	if !p.AdaptiveSampling {
		t.Error("AdaptiveSampling = false, want true")
	}
}

// Trailing bytes and unknown keys are both refused, because reporting a partial
// policy as a complete one is worse than reporting none.
func TestParsePolicySnapshotRejectsMalformed(t *testing.T) {
	withTrailing := append(append([]byte{}, firmwarePolicyBytes...), 0x00)
	if _, err := ParsePolicySnapshot(withTrailing); err == nil {
		t.Error("trailing byte accepted")
	}

	short := firmwarePolicyBytes[:len(firmwarePolicyBytes)-2]
	if _, err := ParsePolicySnapshot(short); err == nil {
		t.Error("truncated snapshot accepted")
	}

	// Map claiming 15 fields but using key 99.
	unknown := append([]byte{}, firmwarePolicyBytes...)
	unknown[1] = 99
	if _, err := ParsePolicySnapshot(unknown); err == nil {
		t.Error("unknown key accepted")
	}
}
