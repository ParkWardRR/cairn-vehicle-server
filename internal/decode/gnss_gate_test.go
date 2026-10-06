package decode

import (
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
)

func fix(seq uint32, ms uint32, lat, lon float64) Position {
	return Position{Seq: seq, MonotonicMS: ms, Latitude: lat, Longitude: lon, FixType: 3}
}

// A weak 5-6 satellite fix teleported the position ~2.4 km while reporting
// 65 m/s, which slipped under the old 67 m/s speed cap. Real recorded values.
func TestGateDropsTeleportBurst(t *testing.T) {
	in := []Position{
		fix(1, 3046729, 33.9775, -118.4159),
		fix(2, 3047940, 33.9774, -118.4152),
		// The Westchester/LAX burst.
		fix(3, 3099502, 33.9584, -118.4015),
		fix(4, 3099693, 33.9583, -118.4015),
		fix(5, 3101289, 33.9570, -118.4017),
		// Back where the car actually was, ~35 minutes later.
		fix(6, 5212183, 33.9784, -118.4159),
	}

	got, dropped := gateJumps(in, nil)
	if dropped != 3 {
		t.Fatalf("dropped %d fixes, want 3", dropped)
	}
	for _, p := range got {
		if p.Latitude < 33.97 {
			t.Errorf("fix seq %d at lat %.4f survived the gate", p.Seq, p.Latitude)
		}
	}
	if len(got) != 3 {
		t.Errorf("kept %d fixes, want 3", len(got))
	}
}

func TestGateKeepsOrdinaryDriving(t *testing.T) {
	// 30 m/s due north, one fix per second, with metre-scale jitter.
	var in []Position
	for i := 0; i < 60; i++ {
		in = append(in, fix(uint32(i), uint32(i)*1000, 34.0+float64(i)*30/110540, -118.4))
	}
	if _, dropped := gateJumps(in, nil); dropped != 0 {
		t.Errorf("dropped %d fixes from steady driving", dropped)
	}
}

func TestGateIgnoresJitterOnDenseFixes(t *testing.T) {
	// 5 Hz fixes bouncing ~8 m apart while parked must not read as a jump.
	in := []Position{
		fix(1, 1000, 34.0, -118.4),
		fix(2, 1200, 34.00007, -118.4),
		fix(3, 1400, 34.0, -118.4),
	}
	if _, dropped := gateJumps(in, nil); dropped != 0 {
		t.Errorf("dropped %d jittering fixes", dropped)
	}
}

// If the very first fix is wrong, every real fix looks like a jump. The gate
// must give up after a few rejects and rebase rather than discard the trip.
func TestGateRecoversFromBadReference(t *testing.T) {
	in := []Position{fix(0, 0, 33.0, -117.0)}
	for i := 1; i <= 20; i++ {
		in = append(in, fix(uint32(i), uint32(i)*1000, 34.0, -118.4))
	}
	got, dropped := gateJumps(in, nil)
	if dropped != maxConsecutiveRejects {
		t.Errorf("dropped %d, want %d", dropped, maxConsecutiveRejects)
	}
	if len(got) != 1+20-maxConsecutiveRejects {
		t.Errorf("kept %d fixes", len(got))
	}
}

func TestNewPositionRejectsImplausibleSpeed(t *testing.T) {
	mf := &format.Manifest{UTCBasisMS: 1700000000000}
	f := &format.Frame{Seq: 1, MonotonicMS: 1000}
	s := &format.GNSSSample{FixType: 3, LatE7: 339584000, LonE7: -1184015000, SpeedCMPS: 6560}
	if _, ok := newPosition(mf, f, s); ok {
		t.Error("a 65.6 m/s fix was accepted")
	}
	s.SpeedCMPS = 3400
	if _, ok := newPosition(mf, f, s); !ok {
		t.Error("a 34 m/s fix was rejected")
	}
}

// After a recorded gap the vehicle legitimately reappears elsewhere; the gate
// must not discard that as a jump.
func TestGateTrustsRecordedGap(t *testing.T) {
	in := []Position{
		fix(1, 1000, 34.0, -118.4),
		fix(3, 3000, 34.05, -118.35),
	}
	if _, dropped := gateJumps(in, nil); dropped != 1 {
		t.Fatalf("without a gap dropped %d, want 1", dropped)
	}
	if _, dropped := gateJumps(in, []Gap{{Seq: 2}}); dropped != 0 {
		t.Errorf("with a gap record dropped %d, want 0", dropped)
	}
}
