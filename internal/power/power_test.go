package power

import (
	"testing"

	"github.com/ParkWardRR/Cairn/server/internal/decode"
)

func enter(seq, ms uint32) decode.Transition {
	return decode.Transition{
		Seq: seq, MonotonicMS: ms,
		Region: regionHealth, TriggerEvent: triggerPower,
		FromState: stateAwake, ToState: stateStandby,
	}
}

func exit(seq, ms uint32, reason uint8) decode.Transition {
	return decode.Transition{
		Seq: seq, MonotonicMS: ms,
		Region: regionHealth, TriggerEvent: triggerPower,
		FromState: stateStandby, ToState: stateAwake,
		ReasonCode: reason,
	}
}

func health(seq, ms uint32, mv int32) decode.Status {
	return decode.Status{Seq: seq, MonotonicMS: ms, BatteryMV: &mv}
}

func TestPairsStandbyWindows(t *testing.T) {
	s := Summarize([]decode.Transition{
		enter(1, 1_000),
		exit(2, 21_600_000+1_000, WakePeriodicHealth),
		enter(3, 21_900_000),
		exit(4, 21_900_000+60_000, WakeMotion),
	}, nil)

	if len(s.Windows) != 2 {
		t.Fatalf("got %d windows, want 2", len(s.Windows))
	}
	if s.UnmatchedWindows != 0 {
		t.Errorf("got %d unmatched, want 0", s.UnmatchedWindows)
	}

	if got := s.Windows[0].DurationMS; got != 21_600_000 {
		t.Errorf("first window %d ms, want 21600000 (6 h heartbeat)", got)
	}
	if got := s.Windows[0].WakeReason; got != WakePeriodicHealth {
		t.Errorf("first wake reason %d, want periodic health", got)
	}
	if got := s.Windows[1].DurationMS; got != 60_000 {
		t.Errorf("second window %d ms, want 60000", got)
	}
	if got := s.Windows[1].WakeReason; got != WakeMotion {
		t.Errorf("second wake reason %d, want motion", got)
	}

	if want := uint64(21_660_000); s.StandbyMS != want {
		t.Errorf("total standby %d, want %d", s.StandbyMS, want)
	}
}

// The property that makes parked draw attributable at all: an entry with no exit
// must be reported, not closed by assuming the device woke. An unmatched entry
// means power was lost while asleep, which is precisely the outcome worth
// knowing about.
func TestUnmatchedEntryIsReportedNotRepaired(t *testing.T) {
	s := Summarize([]decode.Transition{enter(1, 5_000)}, nil)

	if len(s.Windows) != 1 {
		t.Fatalf("got %d windows, want 1", len(s.Windows))
	}
	if !s.Windows[0].Unmatched {
		t.Error("an entry with no exit was not flagged unmatched")
	}
	if s.UnmatchedWindows != 1 {
		t.Errorf("got %d unmatched, want 1", s.UnmatchedWindows)
	}
	if s.StandbyMS != 0 {
		t.Errorf("an unmatched window contributed %d ms of standby; its "+
			"duration is unknown and must not be guessed", s.StandbyMS)
	}
}

// Two consecutive entries means the first window never closed.
func TestSecondEntryClosesNothing(t *testing.T) {
	s := Summarize([]decode.Transition{
		enter(1, 1_000),
		enter(2, 9_000),
		exit(3, 12_000, WakeMotion),
	}, nil)

	if s.UnmatchedWindows != 1 {
		t.Errorf("got %d unmatched, want 1", s.UnmatchedWindows)
	}
	if len(s.Windows) != 2 {
		t.Fatalf("got %d windows, want 2", len(s.Windows))
	}
	if !s.Windows[0].Unmatched {
		t.Error("the superseded entry was not flagged unmatched")
	}
	if s.Windows[1].DurationMS != 3_000 {
		t.Errorf("surviving window %d ms, want 3000", s.Windows[1].DurationMS)
	}
}

func TestDrainRateFromVoltageSeries(t *testing.T) {
	// Two samples twelve hours apart, 120 mV lower: 10 mV/h of decay.
	s := Summarize(nil, []decode.Status{
		health(1, 0, 12_600),
		health(2, 12*3600*1000, 12_480),
	})

	if s.VoltageSamples != 2 {
		t.Fatalf("got %d samples, want 2", s.VoltageSamples)
	}
	if s.DropMV != 120 {
		t.Errorf("drop %d mV, want 120", s.DropMV)
	}
	if got := s.DrainMVPerHour; got < -10.01 || got > -9.99 {
		t.Errorf("drain %.3f mV/h, want about -10", got)
	}
}

// A parked device reports supply voltage with no ECU answering, but a sample can
// still be unavailable. Those must not be read as zero volts, which would show
// as a catastrophic drain.
func TestUnknownVoltageSamplesAreSkipped(t *testing.T) {
	s := Summarize(nil, []decode.Status{
		{Seq: 1, MonotonicMS: 0, BatteryMV: nil},
		health(2, 3600*1000, 12_500),
		{Seq: 3, MonotonicMS: 2 * 3600 * 1000, BatteryMV: nil},
		health(4, 3*3600*1000, 12_450),
	})

	if s.VoltageSamples != 2 {
		t.Fatalf("got %d samples, want 2 (unknowns skipped)", s.VoltageSamples)
	}
	if s.FirstVoltageMV != 12_500 || s.LastVoltageMV != 12_450 {
		t.Errorf("bracketed %d..%d mV, want 12500..12450",
			s.FirstVoltageMV, s.LastVoltageMV)
	}
	// Two hours between the two real samples, 50 mV: 25 mV/h.
	if got := s.DrainMVPerHour; got < -25.01 || got > -24.99 {
		t.Errorf("drain %.3f mV/h, want about -25", got)
	}
}

func TestStandbyFractionUsesTheObservedSpan(t *testing.T) {
	// Awake 0..1000, asleep 1000..9000, awake to 10000.
	s := Summarize([]decode.Transition{
		enter(1, 1_000),
		exit(2, 9_000, WakePeriodicHealth),
	}, []decode.Status{health(3, 0, 12_600), health(4, 10_000, 12_600)})

	if s.ObservedSpanMS != 10_000 {
		t.Fatalf("span %d ms, want 10000", s.ObservedSpanMS)
	}
	if got := s.StandbyFraction; got < 0.79 || got > 0.81 {
		t.Errorf("standby fraction %.3f, want about 0.80", got)
	}
}

// Non-power transitions in the health region must not be mistaken for standby.
func TestIgnoresUnrelatedTransitions(t *testing.T) {
	s := Summarize([]decode.Transition{
		{Seq: 1, MonotonicMS: 100, Region: regionHealth, TriggerEvent: 0,
			FromState: 0, ToState: 1},
		{Seq: 2, MonotonicMS: 200, Region: 1, TriggerEvent: triggerPower,
			FromState: stateAwake, ToState: stateStandby},
	}, nil)

	if len(s.Windows) != 0 {
		t.Errorf("got %d windows from unrelated transitions, want 0", len(s.Windows))
	}
}
