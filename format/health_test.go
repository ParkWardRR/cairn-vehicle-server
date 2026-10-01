package format

import (
	"strings"
	"testing"
)

// The bitmap exists so that simultaneous conditions all survive. A scalar
// severity would force a priority between them and discard the rest, which is
// the behaviour this test pins down.
func TestHealthStateReportsEveryActiveCondition(t *testing.T) {
	state := HealthLowPower | HealthDegradedGNSS | HealthDegradedStorage

	got := HealthStateString(state)

	for _, want := range []string{"LOW_POWER", "DEGRADED_GNSS", "DEGRADED_STORAGE"} {
		if !strings.Contains(got, want) {
			t.Errorf("HealthStateString(%#02x) = %q, missing %s — a simultaneous "+
				"condition was lost, which is the failure the bitmap exists to prevent",
				state, got, want)
		}
	}

	if n := len(HealthStateNames(state)); n != 3 {
		t.Errorf("got %d names, want 3", n)
	}
}

func TestHealthStateZeroIsOK(t *testing.T) {
	if got := HealthStateString(0); got != "OK" {
		t.Errorf("HealthStateString(0) = %q, want OK", got)
	}
	if names := HealthStateNames(0); names != nil {
		t.Errorf("HealthStateNames(0) = %v, want nil", names)
	}
}

// §4.10 requires a decoder to preserve unknown bits rather than masking them
// off, so a bundle from newer firmware stays interpretable for the conditions
// this build does understand.
func TestHealthStatePreservesUnknownBits(t *testing.T) {
	const reserved = 0x80
	state := HealthDegradedTime | reserved

	got := HealthStateString(state)

	if !strings.Contains(got, "DEGRADED_TIME") {
		t.Errorf("HealthStateString(%#02x) = %q, lost the known bit", state, got)
	}
	if !strings.Contains(got, "0x80") {
		t.Errorf("HealthStateString(%#02x) = %q, silently dropped the unknown "+
			"bit; §4.10 requires it to be preserved", state, got)
	}
}

// Every defined bit must be distinct and name itself, or two conditions would
// be indistinguishable in the data.
func TestHealthStateBitsAreDistinct(t *testing.T) {
	seen := map[uint8]string{}

	for _, b := range healthBitNames {
		if b.bit == 0 || b.bit&(b.bit-1) != 0 {
			t.Errorf("%s has value %#02x, which is not a single bit", b.name, b.bit)
		}
		if prev, dup := seen[b.bit]; dup {
			t.Errorf("%s and %s share bit %#02x", prev, b.name, b.bit)
		}
		seen[b.bit] = b.name

		if got := HealthStateString(b.bit); got != b.name {
			t.Errorf("HealthStateString(%#02x) = %q, want %q", b.bit, got, b.name)
		}
	}
}

// The parsed payload must carry the byte through unchanged, since interpreting
// it is the caller's job and a decoder that normalized it would destroy
// information.
func TestParseDeviceHealthCarriesStateByteVerbatim(t *testing.T) {
	p := make([]byte, 16)
	p[12] = HealthDegradedGNSS | HealthLowPower | 0x80

	h, err := ParseDeviceHealth(p)
	if err != nil {
		t.Fatalf("ParseDeviceHealth: %v", err)
	}
	if h.HealthState != p[12] {
		t.Errorf("HealthState = %#02x, want %#02x", h.HealthState, p[12])
	}
}
