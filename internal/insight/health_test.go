package insight

import (
	"strings"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/engine"
)

func f(v float64) *float64 { return &v }

func stat(metric string, recent float64, n int64, base *float64, baseN int64) Stat {
	return Stat{Metric: metric, RecentMedian: &recent, RecentN: n, BaselineMedian: base, BaselineN: baseN,
		LastObserved: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
}

func profiles(t *testing.T) (n20, b58 *engine.Profile) {
	t.Helper()
	c, err := engine.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	return c.For("N20"), c.For("B58")
}

func one(t *testing.T, p *engine.Profile, s Stat) (Finding, bool) {
	t.Helper()
	got := Health(p, []Stat{s})
	if len(got) > 1 {
		t.Fatalf("one metric produced %d findings", len(got))
	}
	if len(got) == 0 {
		return Finding{}, false
	}
	return got[0], true
}

func TestN20BoostAgainstItsLimit(t *testing.T) {
	n20, _ := profiles(t)
	if g, ok := one(t, n20, stat(Boost, 17.8, 5, nil, 0)); !ok || g.Status != OK ||
		!strings.Contains(g.Sentence, "17.8 psi") || !strings.Contains(g.Sentence, "normal") {
		t.Fatalf("within the limit: %+v", g)
	}
	g, ok := one(t, n20, stat(Boost, 21.4, 5, nil, 0))
	if !ok || g.Status != Watch || !strings.Contains(g.Sentence, "21.4 psi") || !strings.Contains(g.Sentence, "20.0 psi") {
		t.Fatalf("over the limit: %+v", g)
	}
	// 20.0 is the limit itself, and the dashboard's rule was "> 20".
	if g, _ := one(t, n20, stat(Boost, 20, 5, nil, 0)); g.Status != OK {
		t.Fatalf("at the limit: %+v", g)
	}
}

func TestLongTermTrimBands(t *testing.T) {
	n20, _ := profiles(t)
	cases := []struct {
		v    float64
		want Status
		in   string
	}{
		{2, OK, "inside the normal range"},
		{11, Watch, "adding fuel"},
		{-11, Watch, "taking fuel away"},
		{21, Check, "air leak"},
		{-21, Check, "air leak"},
	}
	for _, c := range cases {
		g, ok := one(t, n20, stat(LTFT, c.v, 6, nil, 0))
		if !ok || g.Status != c.want || !strings.Contains(g.Sentence, c.in) {
			t.Errorf("ltft %v: %+v (want %s containing %q)", c.v, g, c.want, c.in)
		}
	}
}

func TestOutsideTheSensorRangeIsACheck(t *testing.T) {
	n20, _ := profiles(t)
	g, ok := one(t, n20, stat(LTFT, 40, 6, nil, 0))
	if !ok || g.Status != Check || !strings.Contains(g.Sentence, "outside what the sensor can report") {
		t.Fatalf("%+v", g)
	}
}

func TestDriftAgainstTheCarsOwnBaseline(t *testing.T) {
	n20, _ := profiles(t)
	// Inside the absolute band (4 and 8 are both under 10) but moved 4 points.
	g, ok := one(t, n20, stat(LTFT, 8, 6, f(4), 8))
	if !ok || g.Status != Watch || !strings.Contains(g.Sentence, "+4%") || !strings.Contains(g.Sentence, "+8%") ||
		!strings.Contains(g.Sentence, "adding more fuel than it used to") {
		t.Fatalf("watch drift: %+v", g)
	}
	if g, _ := one(t, n20, stat(LTFT, 9.5, 6, f(2), 8)); g.Status != Check {
		t.Fatalf("a 7.5-point move is a check: %+v", g)
	}
	// Steady: both inside the band, moved less than the watch threshold.
	if g, ok := one(t, n20, stat(LTFT, 3, 6, f(2.5), 8)); !ok || g.Status != OK {
		t.Fatalf("steady: %+v", g)
	}
}

func TestDriftNeedsAThickBaseline(t *testing.T) {
	n20, _ := profiles(t)
	g, ok := one(t, n20, stat(LTFT, 8, 6, f(1), 2)) // two boots is not a baseline
	if !ok || g.Status != OK {
		t.Fatalf("a thin baseline must not raise drift: %+v", g)
	}
}

func TestTooFewRecentObservationsSaysNothing(t *testing.T) {
	n20, _ := profiles(t)
	if got := Health(n20, []Stat{stat(Boost, 30, 2, nil, 0), stat(LTFT, 30, 1, nil, 0)}); len(got) != 0 {
		t.Fatalf("two pulls is not a verdict: %+v", got)
	}
	if got := Health(n20, nil); got == nil || len(got) != 0 {
		t.Fatalf("no statistics must be an empty list, not null: %#v", got)
	}
	if got := Health(n20, []Stat{{Metric: Boost, RecentN: 9}}); len(got) != 0 {
		t.Fatal("a metric with no median is not described")
	}
}

// The B58 profile states no limit, so its absolute readings are not called normal. Only
// its own history can say something.
func TestAStubProfileIsNeverCalledNormalOnAbsoluteValues(t *testing.T) {
	_, b58 := profiles(t)
	if got := Health(b58, []Stat{stat(Boost, 17.8, 9, nil, 0), stat(Lambda, 0.9, 9, nil, 0), stat(LTFT, 2, 9, nil, 0)}); len(got) != 0 {
		t.Fatalf("a stub engine has no basis for judging these: %+v", got)
	}
	g, ok := one(t, b58, stat(LTFT, 8, 9, f(2), 9))
	if !ok || g.Status != Check || !strings.Contains(g.Sentence, "compared with before") {
		t.Fatalf("drift is engine-independent: %+v", g)
	}
	if g, ok := one(t, b58, stat(LTFT, 2.2, 9, f(2), 9)); !ok || g.Status != OK || !strings.Contains(g.Sentence, "steady") {
		t.Fatalf("steady against its own history: %+v", g)
	}
}

func TestNoProfileFallsBackToWhatEveryEngineShares(t *testing.T) {
	// Fuel trim limits hold for any engine; boost does not, so boost is not judged.
	got := Health(nil, []Stat{stat(Boost, 40, 9, nil, 0), stat(LTFT, 21, 9, nil, 0)})
	if len(got) != 1 || got[0].Metric != LTFT || got[0].Status != Check {
		t.Fatalf("%+v", got)
	}
}

func TestDriftMentionsTheTuneItIsMeasuredFrom(t *testing.T) {
	n20, _ := profiles(t)
	tuned := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s := stat(LTFT, 8, 6, f(4), 8)
	s.TunedAt = &tuned
	g, _ := one(t, n20, s)
	if !strings.Contains(g.Sentence, "since the last tune") {
		t.Fatalf("%q", g.Sentence)
	}
}

func TestFindingsFollowTheListedOrderAndStayInPlainLanguage(t *testing.T) {
	n20, _ := profiles(t)
	got := Health(n20, []Stat{
		stat(STFT, 1, 9, nil, 0), stat(LTFT, 12, 9, nil, 0), stat(Boost, 18, 9, nil, 0),
	})
	var metrics []string
	for _, g := range got {
		metrics = append(metrics, g.Metric)
		for _, jargon := range []string{"lambda", "LTFT", "STFT", "kPa", "ECU"} {
			if strings.Contains(g.Sentence, jargon) {
				t.Errorf("%s sentence uses %q: %s", g.Metric, jargon, g.Sentence)
			}
		}
		if !strings.HasSuffix(g.Sentence, ".") {
			t.Errorf("%s sentence is not a sentence: %q", g.Metric, g.Sentence)
		}
	}
	if strings.Join(metrics, ",") != "boost_psi,ltft_pct" {
		t.Fatalf("metrics = %v (STFT has no limit on the N20 and no baseline, so it is left out)", metrics)
	}
}
