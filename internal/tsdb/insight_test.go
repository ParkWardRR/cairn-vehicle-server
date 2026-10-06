package tsdb

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

// addBoot inserts one boot that began at start: `pulls` wide-open-throttle pulls, each
// peaking at peakPsi with mean lambda lam, and 30 boost readings with constant trims.
func addBoot(t *testing.T, db *DB, vehicle, boot string, start time.Time, pulls int, peakPsi, lam float64, ltft, stft int) {
	t.Helper()
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	at := func(ms int) string {
		return start.Add(time.Duration(ms) * time.Millisecond).Format("2006-01-02 15:04:05")
	}

	for i := 0; i < pulls; i++ {
		base := 100_000 + i*20_000
		// Two throttle-open OBD samples with rpm rising 1000: one pull (see v_pulls).
		for j, rpm := range []int{3000, 4000} {
			exec(fmt.Sprintf(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, observed_at, rpm, throttle_pct, load_pct, speed_kph)
				VALUES ('%s', '%s', %d, '%s', %d, 90, 80, 100)`, vehicle, boot, base+j*1000, at(base+j*1000), rpm))
		}
		exec(fmt.Sprintf(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, observed_at, boost_psi, lambda_ratio, map_kpa)
			VALUES ('%s', '%s', %d, '%s', %v, %v, 180)`, vehicle, boot, base+500, at(base+500), peakPsi, lam))
		// Lifting off ends the run; without it consecutive pulls would be one island.
		exec(fmt.Sprintf(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, observed_at, rpm, throttle_pct, load_pct, speed_kph)
			VALUES ('%s', '%s', %d, '%s', 2000, 10, 20, 60)`, vehicle, boot, base+5000, at(base+5000)))
	}
	for i := 0; i < 30; i++ {
		exec(fmt.Sprintf(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, observed_at, ltft_pct, stft_pct, map_kpa)
			VALUES ('%s', '%s', %d, '%s', %d, %d, 100)`, vehicle, boot, 1000+i*1000, at(1000+i*1000), ltft, stft))
	}
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 9, 0, 0, 0, time.UTC) }

func effect(t *testing.T, db *DB, vehicle, tune, metric string) (bm, am *float64, bn, an int64) {
	t.Helper()
	err := db.db.QueryRow(`SELECT before_median, after_median, before_n, after_n FROM v_tune_effect
		WHERE vehicle_id = ? AND tune_id = ? AND metric = ?`, vehicle, tune, metric).Scan(&bm, &am, &bn, &an)
	if err != nil {
		t.Fatalf("v_tune_effect %s/%s: %v", tune, metric, err)
	}
	return
}

func near(t *testing.T, what string, got *float64, want float64) {
	t.Helper()
	if got == nil || math.Abs(*got-want) > 1e-9 {
		t.Fatalf("%s = %v, want %v", what, deref(got), want)
	}
}

func deref(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// One tune, three boots before and two after: the before and after medians and counts are
// computed over the right boots, and every metric gets a row.
func TestTuneEffectSplitsAtTheTuneDay(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	addBoot(t, db, v, "b1", day(2026, 7, 1), 2, 15, 0.95, 8, -2)
	addBoot(t, db, v, "b2", day(2026, 7, 10), 2, 16, 0.96, 9, -1)
	addBoot(t, db, v, "b3", day(2026, 7, 20), 2, 17, 0.97, 10, 0)
	// The tune day itself counts as "after": a boot that began at 09:00 on the day.
	addBoot(t, db, v, "b4", day(2026, 8, 1), 3, 19, 0.90, 3, 1)
	addBoot(t, db, v, "b5", day(2026, 8, 9), 3, 21, 0.88, 2, 2)
	if _, err := db.db.Exec(`INSERT INTO tune VALUES (?, 't1', '2026-08-01 00:00:00', 'Stage 2')`, v); err != nil {
		t.Fatal(err)
	}

	bm, am, bn, an := effect(t, db, v, "t1", "boost_psi")
	near(t, "boost before", bm, 16) // pulls: 15,15,16,16,17,17
	near(t, "boost after", am, 20)  // pulls: 19x3, 21x3, median of six
	if bn != 6 || an != 6 {
		t.Fatalf("boost n = %d/%d, want 6/6 (one observation per pull)", bn, an)
	}

	bm, am, bn, an = effect(t, db, v, "t1", "ltft_pct")
	near(t, "ltft before", bm, 9) // per-boot medians 8,9,10
	near(t, "ltft after", am, 2.5)
	if bn != 3 || an != 2 {
		t.Fatalf("ltft n = %d/%d, want 3/2 (one observation per boot)", bn, an)
	}

	bm, am, _, _ = effect(t, db, v, "t1", "lambda")
	near(t, "lambda before", bm, 0.96)
	near(t, "lambda after", am, 0.89)

	var metrics int
	if err := db.db.QueryRow(`SELECT count(*) FROM v_tune_effect WHERE tune_id = 't1'`).Scan(&metrics); err != nil || metrics != 4 {
		t.Fatalf("metrics per tune = %d (%v), want boost, lambda, ltft, stft", metrics, err)
	}
}

// With two tunes the second tune's "before" is the stretch under the first, not
// everything that came earlier.
func TestTuneEffectUsesThePreviousTuneAsBaseline(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	addBoot(t, db, v, "stock", day(2026, 5, 1), 1, 12, 1.0, 12, 0)
	addBoot(t, db, v, "s1", day(2026, 6, 10), 1, 17, 0.95, 6, 0)
	addBoot(t, db, v, "s2", day(2026, 7, 20), 1, 22, 0.90, 1, 0)
	db.db.Exec(`INSERT INTO tune VALUES (?, 't1', '2026-06-01 00:00:00', 'Stage 1')`, v)
	db.db.Exec(`INSERT INTO tune VALUES (?, 't2', '2026-07-01 00:00:00', 'Stage 2')`, v)

	bm, am, bn, an := effect(t, db, v, "t1", "boost_psi")
	near(t, "t1 before", bm, 12)
	near(t, "t1 after", am, 17) // stops at t2: the 22 psi boot belongs to the next tune
	if bn != 1 || an != 1 {
		t.Fatalf("t1 n = %d/%d", bn, an)
	}
	bm, am, _, _ = effect(t, db, v, "t2", "boost_psi")
	near(t, "t2 before", bm, 17) // the stretch under t1, not the stock 12 psi boot
	near(t, "t2 after", am, 22)
}

func TestTuneEffectIsEmptyNotMissingWithoutData(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	db.db.Exec(`INSERT INTO tune VALUES (?, 't1', '2026-08-01 00:00:00', '')`, v)
	bm, am, bn, an := effect(t, db, v, "t1", "boost_psi")
	if bm != nil || am != nil || bn != 0 || an != 0 {
		t.Fatalf("got %v %v %d %d: no data should be NULL medians and zero counts", deref(bm), deref(am), bn, an)
	}
}

// A tune on one car must not shape another's comparison.
func TestTuneEffectIsPerVehicle(t *testing.T) {
	db := emptyDB(t)
	const a, b = "70707070707070707070707070707070", "80808080808080808080808080808080"
	addBoot(t, db, a, "x", day(2026, 7, 1), 1, 15, 1, 5, 0)
	addBoot(t, db, a, "y", day(2026, 8, 5), 1, 19, 1, 5, 0)
	addBoot(t, db, b, "x", day(2026, 7, 1), 1, 30, 1, 5, 0) // same boot id, another car
	addBoot(t, db, b, "y", day(2026, 8, 5), 1, 30, 1, 5, 0)
	db.db.Exec(`INSERT INTO tune VALUES (?, 'ta', '2026-08-01 00:00:00', '')`, a)

	bm, am, _, _ := effect(t, db, a, "ta", "boost_psi")
	near(t, "A before", bm, 15)
	near(t, "A after", am, 19)
	var n int
	db.db.QueryRow(`SELECT count(*) FROM v_tune_effect WHERE vehicle_id = ?`, b).Scan(&n)
	if n != 0 {
		t.Fatalf("car B has no tune but v_tune_effect returned %d rows for it", n)
	}
}

func TestShortBootsDoNotCountTowardTrim(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	for i := 0; i < 19; i++ { // one reading short of the 20 a boot needs
		db.db.Exec(fmt.Sprintf(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, observed_at, ltft_pct)
			VALUES ('%s', 'short', %d, '2026-07-01 09:00:%02d', 30)`, v, i*1000, i))
	}
	var n int
	db.db.QueryRow(`SELECT count(*) FROM v_metric_samples WHERE metric = 'ltft_pct'`).Scan(&n)
	if n != 0 {
		t.Fatalf("a 19-reading boot produced %d trim observations", n)
	}
}

func TestHealthStatsCompareRecentToBaselineSinceTheLatestTune(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	// Before the tune: ltft 2. After it: 4, 4, then a fortnight later 9.
	addBoot(t, db, v, "pre", day(2026, 5, 1), 0, 0, 0, 2, 0)
	addBoot(t, db, v, "p1", day(2026, 6, 5), 0, 0, 0, 4, 0)
	addBoot(t, db, v, "p2", day(2026, 6, 20), 0, 0, 0, 4, 0)
	addBoot(t, db, v, "r1", day(2026, 9, 20), 0, 0, 0, 9, 0)
	addBoot(t, db, v, "r2", day(2026, 9, 28), 0, 0, 0, 9, 0)
	db.db.Exec(`INSERT INTO tune VALUES (?, 't1', '2026-06-01 00:00:00', '')`, v)

	var recent, base *float64
	var rn, bn int64
	var last, tuned time.Time
	err := db.db.QueryRow(`SELECT recent_median, recent_n, baseline_median, baseline_n, last_observed_at, tuned_at
		FROM v_health_stats WHERE vehicle_id = ? AND metric = 'ltft_pct'`, v).Scan(&recent, &rn, &base, &bn, &last, &tuned)
	if err != nil {
		t.Fatal(err)
	}
	near(t, "recent", recent, 9)
	near(t, "baseline", base, 4) // the 2 from before the tune is not part of the baseline
	if rn != 2 || bn != 2 {
		t.Fatalf("n = %d recent, %d baseline", rn, bn)
	}
	// A boot begins at its first sample, which the helper stamps one second in.
	if !last.Equal(day(2026, 9, 28).Add(time.Second)) || !tuned.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("last = %v, tuned = %v", last, tuned)
	}
}

// "Recent" is relative to the car's last drive, so a car that has sat for a month is still
// described by its last fortnight of driving rather than by nothing.
func TestHealthStatsAreRelativeToTheLastDriveNotTheClock(t *testing.T) {
	db := emptyDB(t)
	const v = "70707070707070707070707070707070"
	addBoot(t, db, v, "old1", day(2025, 1, 5), 0, 0, 0, 5, 0)
	addBoot(t, db, v, "old2", day(2025, 1, 12), 0, 0, 0, 5, 0)
	var rn int64
	if err := db.db.QueryRow(`SELECT recent_n FROM v_health_stats WHERE vehicle_id = ? AND metric = 'ltft_pct'`, v).Scan(&rn); err != nil {
		t.Fatal(err)
	}
	if rn != 2 {
		t.Fatalf("recent_n = %d, want 2", rn)
	}
}

func TestInsightViewsAreInTheContract(t *testing.T) {
	db, err := BuildSynthetic(context.Background(), func(Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	caps, err := db.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string][]string{}
	for k, v := range caps.Columns {
		have[k] = v
	}
	want := map[string][]string{
		"tune":             {"vehicle_id", "tune_id", "tuned_at", "note"},
		"v_tune_effect":    {"vehicle_id", "tune_id", "metric", "before_median", "after_median", "before_n", "after_n"},
		"v_health_stats":   {"vehicle_id", "metric", "recent_median", "recent_n", "baseline_median", "baseline_n", "last_observed_at", "tuned_at"},
		"v_boot_start":     {"vehicle_id", "boot_id", "started_at"},
		"v_metric_samples": {"vehicle_id", "boot_id", "metric", "value", "started_at"},
	}
	for obj, cols := range want {
		got := have[obj]
		if fmt.Sprint(got) != fmt.Sprint(cols) {
			t.Errorf("%s columns = %v, want %v", obj, got, cols)
		}
	}
	// The bundles columns the Device page reads are the tail of the table, so the
	// positional appender stays compatible with older rows.
	b := have["bundles"]
	if tail := b[len(b)-4:]; fmt.Sprint(tail) != "[path size_bytes duration_ms received_at]" {
		t.Errorf("bundles tail = %v", tail)
	}
}
