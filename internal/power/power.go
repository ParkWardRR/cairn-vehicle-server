// Package power derives how a device spent its time and what that cost, from
// the health-region power transitions and the supply voltage series a bundle
// already carries.
//
// It exists because parked current draw was the last claim in the system with no
// evidence behind it. The firmware cannot measure current — there is no shunt on
// the board and the vendor library exposes only getVoltage — so the honest
// substitute is the supply voltage's decay across a known-duration park.
//
// What this package will not do is convert that decay into milliamps. A battery's
// voltage-to-charge relationship is non-linear, temperature dependent and
// different for every battery, and the measured decay includes the vehicle's own
// parasitic draw, which is typically larger than anything a dongle contributes.
// Reporting a confident mA figure derived from two voltage readings would be
// inventing precision. The rate, the duration and the duty cycle are real; the
// attribution to this device specifically requires a control park with the
// dongle unplugged, or a meter.
package power

import (
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/decode"
)

// Wake reasons, matching cairn_power.h and §4.7.1 of the format specification.
const (
	WakeNone           uint8 = 0
	WakeMotion         uint8 = 1
	WakeEngineVoltage  uint8 = 2
	WakePeriodicHealth uint8 = 3
)

// Power-dimension states within the health region (§4.7.1).
const (
	stateAwake   uint8 = 0
	stateStandby uint8 = 1

	regionHealth uint8 = 4
	triggerPower uint8 = 4
)

// WakeReasonName renders a wake reason for an operator.
func WakeReasonName(r uint8) string {
	switch r {
	case WakeNone:
		return "none"
	case WakeMotion:
		return "motion"
	case WakeEngineVoltage:
		return "engine voltage"
	case WakePeriodicHealth:
		return "periodic health"
	default:
		return "unknown"
	}
}

// Window is one standby period, recovered from a matched pair of transitions.
type Window struct {
	EnterMonotonicMS uint32
	ExitMonotonicMS  uint32
	DurationMS       uint32
	WakeReason       uint8

	// Unmatched means the device announced standby and never recorded a
	// return. That is not a decoding failure — it means it lost power while
	// asleep, or reset instead of waking. Reported, never repaired by
	// assuming a wake.
	Unmatched bool

	EnterAt time.Time
	ExitAt  time.Time
}

// Summary is what a bundle can say about power.
type Summary struct {
	Windows []Window

	// StandbyMS and ObservedSpanMS are both derived from monotonic_ms, never
	// UTC: ordering truth on this device is (boot_id, seq) and the wall clock
	// may step when a fix arrives.
	StandbyMS      uint64
	ObservedSpanMS uint32

	// StandbyFraction is StandbyMS / ObservedSpanMS, 0 when the span is zero.
	StandbyFraction float64

	UnmatchedWindows int

	// Voltage series, present only when at least two samples carried a
	// reading. A parked device with no ECU answering still reports supply
	// voltage, which is the whole reason this is measurable.
	VoltageSamples int
	FirstVoltageMV int32
	LastVoltageMV  int32
	FirstVoltageAt uint32
	LastVoltageAt  uint32

	// DropMV is positive when the supply fell over the observed span.
	DropMV int32

	// DrainMVPerHour is the mean rate of change, negative while discharging.
	// Zero when fewer than two samples or no elapsed time.
	DrainMVPerHour float64
}

// elapsed subtracts two monotonic millisecond counters, tolerating the uint32
// wrap at roughly 49.7 days. A park long enough to wrap is unlikely but a silent
// negative duration would be worse than handling it.
func elapsed(from, to uint32) uint32 { return to - from }

// Summarize pairs the power transitions and attributes the voltage series.
//
// Transitions are expected in sequence order, which is how the decoder emits
// them; it does not sort, because reordering the journal would discard the one
// ordering the device guarantees.
func Summarize(transitions []decode.Transition, statuses []decode.Status) Summary {
	var s Summary

	// Pair entries with the next exit. A second entry before any exit means
	// the first window never closed.
	var open *Window

	for _, t := range transitions {
		if t.Region != regionHealth || t.TriggerEvent != triggerPower {
			continue
		}

		switch {
		case t.FromState == stateAwake && t.ToState == stateStandby:
			if open != nil {
				open.Unmatched = true
				s.Windows = append(s.Windows, *open)
				s.UnmatchedWindows++
			}
			open = &Window{
				EnterMonotonicMS: t.MonotonicMS,
				EnterAt:          t.ObservedAt,
			}

		case t.FromState == stateStandby && t.ToState == stateAwake:
			if open == nil {
				// An exit with no entry: the bundle begins mid-standby,
				// which a sealed-boundary split can legitimately produce.
				// Nothing to measure, so it is skipped rather than
				// invented.
				continue
			}
			open.ExitMonotonicMS = t.MonotonicMS
			open.DurationMS = elapsed(open.EnterMonotonicMS, t.MonotonicMS)
			open.WakeReason = t.ReasonCode
			open.ExitAt = t.ObservedAt

			s.StandbyMS += uint64(open.DurationMS)
			s.Windows = append(s.Windows, *open)
			open = nil
		}
	}

	if open != nil {
		open.Unmatched = true
		s.Windows = append(s.Windows, *open)
		s.UnmatchedWindows++
	}

	// Voltage series across whatever the bundle observed.
	var first, last *decode.Status
	for i := range statuses {
		if statuses[i].BatteryMV == nil {
			continue
		}
		s.VoltageSamples++
		if first == nil {
			first = &statuses[i]
		}
		last = &statuses[i]
	}

	if first != nil && last != nil {
		s.FirstVoltageMV = *first.BatteryMV
		s.LastVoltageMV = *last.BatteryMV
		s.FirstVoltageAt = first.MonotonicMS
		s.LastVoltageAt = last.MonotonicMS
		s.DropMV = s.FirstVoltageMV - s.LastVoltageMV

		if ms := elapsed(first.MonotonicMS, last.MonotonicMS); ms > 0 {
			hours := float64(ms) / 3600000.0
			s.DrainMVPerHour = float64(s.LastVoltageMV-s.FirstVoltageMV) / hours
		}
	}

	// The observed span is the widest thing the bundle covers, so the duty
	// cycle is not overstated by measuring it against the standby windows
	// alone.
	s.ObservedSpanMS = spanOf(transitions, statuses)
	if s.ObservedSpanMS > 0 {
		s.StandbyFraction = float64(s.StandbyMS) / float64(s.ObservedSpanMS)
	}

	return s
}

func spanOf(transitions []decode.Transition, statuses []decode.Status) uint32 {
	var lo, hi uint32
	seen := false

	consider := func(ms uint32) {
		if !seen {
			lo, hi, seen = ms, ms, true
			return
		}
		if ms < lo {
			lo = ms
		}
		if ms > hi {
			hi = ms
		}
	}

	for _, t := range transitions {
		consider(t.MonotonicMS)
	}
	for _, st := range statuses {
		consider(st.MonotonicMS)
	}

	if !seen {
		return 0
	}
	return hi - lo
}
