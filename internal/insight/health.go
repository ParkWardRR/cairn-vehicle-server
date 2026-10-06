// Package insight turns the store's statistics into what an owner can act on: a plain
// sentence per metric saying whether the car is doing what it normally does.
//
// The store (v_health_stats) holds the numbers; the engine profile holds what counts as
// normal for this engine; this package is the only place the two meet, so a sentence is
// never written from a number alone.
//
// Three rules keep the summary honest:
//
//   - Unknown is not "ok". A metric whose engine states no limit (a stub profile) is not
//     called normal on its absolute value, because nothing says what normal is. It can
//     still be judged against the car's own earlier readings, which needs no knowledge of
//     the engine, and it is left out when neither applies.
//   - A thin sample is not a verdict. A metric needs enough observations in the recent
//     window before a sentence is written about it; with fewer it is omitted, and an empty
//     list means "not enough driving yet", not "all fine".
//   - A tune is not a fault. The baseline the store reports starts at the latest tune, so
//     fuel trim that moved because the car was retuned is not reported as drift.
package insight

import (
	"fmt"
	"math"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/engine"
)

// Status is how much a finding matters.
type Status string

const (
	OK    Status = "ok"
	Watch Status = "watch"
	Check Status = "check"
)

func (s Status) rank() int {
	switch s {
	case Check:
		return 2
	case Watch:
		return 1
	}
	return 0
}

// Metrics, in the order a summary lists them. They are the engine profile's signal keys.
const (
	Boost  = "boost_psi"
	Lambda = "lambda"
	LTFT   = "ltft_pct"
	STFT   = "stft_pct"
)

var order = []string{Boost, Lambda, LTFT, STFT}

// DefaultMinObservations is how many observations the recent window needs before a metric
// is described: pulls for boost and lambda, boots for the trims (see v_metric_samples).
const DefaultMinObservations = 3

// Stat is one row of v_health_stats.
type Stat struct {
	Metric         string
	RecentMedian   *float64
	RecentN        int64
	BaselineMedian *float64
	BaselineN      int64
	LastObserved   time.Time
	TunedAt        *time.Time
}

// Finding is one line of the summary, in the shape the web layer reads.
type Finding struct {
	Metric   string `json:"metric"`
	Status   Status `json:"status"`
	Sentence string `json:"sentence"`
}

// Health summarises one vehicle. profile is the vehicle's engine profile, or nil for an
// engine with none, in which case only what holds for every engine is applied.
func Health(profile *engine.Profile, stats []Stat) []Finding {
	if profile == nil {
		profile = engine.Generic()
	}
	by := map[string]Stat{}
	for _, s := range stats {
		by[s.Metric] = s
	}
	minObs := int64(profile.Threshold("min_observations", DefaultMinObservations))

	out := []Finding{}
	for _, m := range order {
		st, ok := by[m]
		if !ok || st.RecentMedian == nil || st.RecentN < minObs {
			continue
		}
		sig, hasSig := profile.Signal(m)
		if f, ok := judge(profile, sig, hasSig, st); ok {
			out = append(out, f)
		}
	}
	return out
}

// judge applies the absolute limits, then the drift against the car's own baseline, and
// reports the more serious of the two. It reports nothing when neither could be applied.
func judge(p *engine.Profile, sig engine.Signal, hasSig bool, st Stat) (Finding, bool) {
	v := *st.RecentMedian
	var best *Finding
	consider := func(f Finding) {
		if best == nil || f.Status.rank() > best.Status.rank() {
			best = &f
		}
	}

	if hasSig {
		if v < sig.Min || v > sig.Max {
			consider(Finding{st.Metric, Check, fmt.Sprintf(
				"%s is reading %s, which is outside what the sensor can report. A sensor or its wiring may be at fault; have it looked at.",
				capital(label(st.Metric, sig)), format(st.Metric, v))})
		} else if f, stated := absolute(sig, st.Metric, v); stated {
			consider(f)
		}
	}

	if f, moved := drift(p, st); moved {
		consider(f)
	} else if best == nil && hasBaseline(p, st) {
		// Held up against its own history and found where it was: a real "ok", and the
		// only one a stub profile can give.
		consider(Finding{st.Metric, OK, steady(st, v)})
	}

	if best == nil {
		return Finding{}, false
	}
	return *best, true
}

// hasBaseline reports whether the car has enough earlier readings of a trim to compare
// the recent ones with.
func hasBaseline(p *engine.Profile, st Stat) bool {
	return driftApplies(st.Metric) && st.BaselineMedian != nil &&
		st.BaselineN >= int64(p.Threshold("min_observations", DefaultMinObservations))
}

// absolute judges a value against the profile's stated limits. The second result is false
// when the profile states none for this signal, which is not the same as "within them".
func absolute(sig engine.Signal, metric string, v float64) (Finding, bool) {
	hasHigh := sig.WarnHigh != nil || sig.CheckHigh != nil
	hasLow := sig.WarnLow != nil || sig.CheckLow != nil
	if !hasHigh && !hasLow {
		return Finding{}, false
	}
	name := label(metric, sig)

	switch {
	case sig.CheckHigh != nil && v > *sig.CheckHigh:
		return Finding{metric, Check, high(metric, name, v, *sig.CheckHigh, true)}, true
	case sig.CheckLow != nil && v < *sig.CheckLow:
		return Finding{metric, Check, low(metric, name, v, *sig.CheckLow, true)}, true
	case sig.WarnHigh != nil && v > *sig.WarnHigh:
		return Finding{metric, Watch, high(metric, name, v, *sig.WarnHigh, false)}, true
	case sig.WarnLow != nil && v < *sig.WarnLow:
		return Finding{metric, Watch, low(metric, name, v, *sig.WarnLow, false)}, true
	}
	return Finding{metric, OK, normal(metric, name, v)}, true
}

func driftApplies(metric string) bool { return metric == LTFT || metric == STFT }

// drift compares the recent median with the baseline, for the trims only: they are
// relative to the engine's own learned fuelling, so a move from the car's own earlier
// value means something on any engine. The thresholds are in percentage points.
func drift(p *engine.Profile, st Stat) (Finding, bool) {
	if !hasBaseline(p, st) {
		return Finding{}, false
	}
	watch := p.Threshold("ltft_drift_watch_pct", 3)
	check := p.Threshold("ltft_drift_check_pct", 6)
	moved := *st.RecentMedian - *st.BaselineMedian
	size := math.Abs(moved)

	switch {
	case size >= check:
		return Finding{st.Metric, Check, driftSentence(st, moved, true)}, true
	case size >= watch:
		return Finding{st.Metric, Watch, driftSentence(st, moved, false)}, true
	}
	return Finding{}, false
}

// ─── wording ────────────────────────────────────────────────────────────────

func label(metric string, sig engine.Signal) string {
	switch metric {
	case Boost:
		return "boost on hard acceleration"
	case Lambda:
		return "the air-fuel mix under load"
	case LTFT:
		return "the engine's long-term fuel adjustment"
	case STFT:
		return "the engine's short-term fuel adjustment"
	}
	return sig.Label
}

func format(metric string, v float64) string {
	switch metric {
	case Boost:
		return fmt.Sprintf("%.1f psi", v)
	case Lambda:
		return fmt.Sprintf("%.2f", v)
	}
	return fmt.Sprintf("%+.0f%%", v)
}

func normal(metric, name string, v float64) string {
	switch metric {
	case Boost:
		return fmt.Sprintf("Boost on hard acceleration is steady around %s, which is normal for this engine.", format(metric, v))
	case Lambda:
		return fmt.Sprintf("The air-fuel mix under load is %s, which is normal for this engine.", format(metric, v))
	}
	return fmt.Sprintf("%s is %s, inside the normal range.", capital(name), format(metric, v))
}

func high(metric, name string, v, limit float64, check bool) string {
	switch metric {
	case Boost:
		s := fmt.Sprintf("Boost on hard acceleration is running high, around %s; this engine normally stays under %s.",
			format(metric, v), format(metric, limit))
		return s + advice(check)
	case Lambda:
		return fmt.Sprintf("Under load the engine is running leaner than expected (air-fuel mix %s, normally under %s): more air for the fuel it is getting.%s",
			format(metric, v), format(metric, limit), advice(check))
	}
	return fmt.Sprintf("%s is %s: the engine is adding fuel to make up for something, beyond the %s it normally stays inside.%s",
		capital(name), format(metric, v), format(metric, limit), cause(check))
}

func low(metric, name string, v, limit float64, check bool) string {
	switch metric {
	case Boost:
		return fmt.Sprintf("Boost on hard acceleration is lower than usual, around %s; this engine normally makes at least %s.%s",
			format(metric, v), format(metric, limit), advice(check))
	case Lambda:
		return fmt.Sprintf("Under load the engine is running richer than expected (air-fuel mix %s, normally above %s).%s",
			format(metric, v), format(metric, limit), advice(check))
	}
	return fmt.Sprintf("%s is %s: the engine is taking fuel away, beyond the %s it normally stays inside.%s",
		capital(name), format(metric, v), format(metric, limit), cause(check))
}

func advice(check bool) string {
	if check {
		return " Worth having looked at."
	}
	return " Worth keeping an eye on."
}

func cause(check bool) string {
	if check {
		return " That can point to an air leak, a fuel delivery problem or a faulty sensor; worth having looked at."
	}
	return " Worth keeping an eye on."
}

func driftSentence(st Stat, moved float64, check bool) string {
	dir := "more"
	if moved < 0 {
		dir = "less"
	}
	since := "before"
	if st.TunedAt != nil {
		since = "since the last tune"
	}
	s := fmt.Sprintf("%s has moved from %s to %s over the last two weeks compared with %s: the engine is adding %s fuel than it used to.",
		capital(label(st.Metric, engine.Signal{})), format(st.Metric, *st.BaselineMedian), format(st.Metric, *st.RecentMedian), since, dir)
	if dir == "less" {
		s = fmt.Sprintf("%s has moved from %s to %s over the last two weeks compared with %s: the engine is taking away more fuel than it used to.",
			capital(label(st.Metric, engine.Signal{})), format(st.Metric, *st.BaselineMedian), format(st.Metric, *st.RecentMedian), since)
	}
	return s + advice(check)
}

func steady(st Stat, v float64) string {
	since := "before"
	if st.TunedAt != nil {
		since = "since the last tune"
	}
	return fmt.Sprintf("%s is steady at %s, the same as %s.", capital(label(st.Metric, engine.Signal{})), format(st.Metric, v), since)
}

func capital(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 'a' - 'A'
	}
	return string(r)
}
