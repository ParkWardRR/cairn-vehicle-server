package tsdb

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

// A trip is a run of one fix a second walking north 0.001 degree (111.195 m on the
// 6371 km sphere v_trip_summary uses), with an OBD reading each second at a fixed
// speed, so its distance, duration and maxima are known without running the view.
type periodTrip struct {
	vehicle, boot string
	start         string // UTC, "2006-01-02 15:04:05"
	fixes         int
	kph           float64
	noClock       bool // observed_at is NULL: the device never had a wall-clock estimate
}

func (p periodTrip) startedAt(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse("2006-01-02 15:04:05", p.start)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

const stepM = 6371000.0 * math.Pi / 180 * 0.001

func (p periodTrip) durationMS() int64  { return int64(p.fixes-1) * 1000 }
func (p periodTrip) distanceM() float64 { return float64(p.fixes-1) * stepM }

// The trips straddle every boundary the period tests care about. The two cars share
// boot ids and start times, so only vehicle_id can tell their trips apart.
var periodTrips = []periodTrip{
	{n20, "dec", "2025-12-31 23:59:50", 21, 50, false},  // 20 s, ends in 2026
	{n20, "jan", "2026-01-01 00:00:00", 11, 60, false},  // starts on the first instant of 2026
	{n20, "feb", "2026-02-15 12:00:00", 31, 70, false},  // Sunday, ISO week of Monday 9 Feb
	{n20, "mar", "2026-03-31 23:59:00", 121, 90, false}, // 120 s, ends on 1 April
	{n20, "apr", "2026-04-01 00:00:00", 61, 100, false}, // starts on the first instant of Q2
	{n20, "may", "2026-05-20 08:00:00", 41, 110, false},
	{n20, "noclock", "2026-05-20 09:00:00", 11, 200, true}, // in no period at all
	{b58, "feb", "2026-02-15 12:00:00", 51, 130, false},
	{b58, "mar", "2026-03-31 23:59:00", 21, 140, false},
}

func periodDB(t *testing.T) *DB {
	t.Helper()
	db := emptyDB(t)
	for _, tr := range periodTrips {
		at := "TIMESTAMP '" + tr.start + "' + i * INTERVAL 1 SECOND"
		if tr.noClock {
			at = "NULL"
		}
		q := fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, observed_at, lat, lon, speed_mps, fix_type)
			SELECT '%[1]s', '%[2]s', i * 1000, i, %[3]s, 36.0 + i * 0.001, -121.9, %[4]s / 3.6, 3 FROM range(%[5]d) t(i)`,
			tr.vehicle, tr.boot, at, ftoa(tr.kph), tr.fixes)
		if _, err := db.db.Exec(q); err != nil {
			t.Fatal(err)
		}
		q = fmt.Sprintf(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, seq, observed_at, speed_kph)
			SELECT '%[1]s', '%[2]s', i * 1000, i, %[3]s, %[4]s FROM range(%[5]d) t(i)`,
			tr.vehicle, tr.boot, at, ftoa(tr.kph), tr.fixes)
		if _, err := db.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// periodRow is one period_summary row.
type periodRow struct {
	trips      int
	durationMS int64
	distanceM  float64
	obdKph     float64
	gnssKph    float64
}

func summary(t *testing.T, db *DB, from, to string) map[string]periodRow {
	t.Helper()
	rows := query(t, db, fmt.Sprintf(
		`SELECT vehicle_id, trips, duration_ms, distance_m, max_obd_speed_kph, max_gnss_speed_kph FROM period_summary('%s', '%s')`, from, to))
	out := map[string]periodRow{}
	for _, r := range rows {
		if _, dup := out[fmt.Sprint(r[0])]; dup {
			t.Fatalf("period_summary(%s, %s) has two rows for %v", from, to, r[0])
		}
		out[fmt.Sprint(r[0])] = periodRow{int(num(t, r[1])), int64(num(t, r[2])), num(t, r[3]), num(t, r[4]), num(t, r[5])}
	}
	return out
}

// want derives the expected summary from periodTrips: a trip is in [from, to) when it
// started there, whole, whichever day it ended.
func wantSummary(t *testing.T, from, to string) map[string]periodRow {
	t.Helper()
	lo, err := time.Parse("2006-01-02", from)
	if err != nil {
		t.Fatal(err)
	}
	hi, err := time.Parse("2006-01-02", to)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]periodRow{}
	for _, tr := range periodTrips {
		if s := tr.startedAt(t); tr.noClock || s.Before(lo) || !s.Before(hi) {
			continue
		}
		r := out[tr.vehicle]
		r.trips++
		r.durationMS += tr.durationMS()
		r.distanceM += tr.distanceM()
		r.obdKph = math.Max(r.obdKph, tr.kph)
		r.gnssKph = math.Max(r.gnssKph, tr.kph)
		out[tr.vehicle] = r
	}
	return out
}

func sameSummary(t *testing.T, what string, got, wantRows map[string]periodRow) {
	t.Helper()
	if len(got) != len(wantRows) {
		t.Errorf("%s: vehicles %v, want %v", what, got, wantRows)
		return
	}
	for v, w := range wantRows {
		g, ok := got[v]
		if !ok {
			t.Errorf("%s: no row for %s", what, v[:2])
			continue
		}
		if g.trips != w.trips || g.durationMS != w.durationMS || math.Abs(g.distanceM-w.distanceM) > 0.5 ||
			g.obdKph != w.obdKph || math.Abs(g.gnssKph-w.gnssKph) > 0.001 {
			t.Errorf("%s: %s = %+v, want %+v", what, v[:2], g, w)
		}
	}
}

func TestPeriodSummary(t *testing.T) {
	db := periodDB(t)

	// trips per vehicle is written out, so the expected-value helper cannot agree with a
	// wrong boundary by sharing its mistake.
	for _, c := range []struct {
		name, from, to string
		n20, b58       int
	}{
		{"year 2026", "2026-01-01", "2027-01-01", 5, 2},
		{"year 2025", "2025-01-01", "2026-01-01", 1, 0},
		{"quarter Q1 2026", "2026-01-01", "2026-04-01", 3, 2},
		{"quarter Q2 2026", "2026-04-01", "2026-07-01", 2, 0},
		{"month March", "2026-03-01", "2026-04-01", 1, 1},
		{"month April", "2026-04-01", "2026-05-01", 1, 0},
		{"week of Monday 30 March", "2026-03-30", "2026-04-06", 2, 1},
		{"week of Monday 9 February", "2026-02-09", "2026-02-16", 1, 1},
		{"custom 10 Feb to 28 Feb inclusive", "2026-02-10", "2026-03-01", 1, 1},
		{"custom ending the day a trip starts", "2026-03-01", "2026-03-31", 0, 0},
		{"the first instant of 2026 is in", "2026-01-01", "2026-01-02", 1, 0},
		{"a trip at 23:59:50 is in the day it started", "2025-12-31", "2026-01-01", 1, 0},
		{"empty range", "2027-01-01", "2027-02-01", 0, 0},
		{"inverted range", "2026-04-01", "2026-01-01", 0, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := summary(t, db, c.from, c.to)
			if got[n20].trips != c.n20 || got[b58].trips != c.b58 {
				t.Errorf("trips n20=%d b58=%d, want %d and %d (%v)", got[n20].trips, got[b58].trips, c.n20, c.b58, got)
			}
			if len(got) != btoi(c.n20 > 0)+btoi(c.b58 > 0) {
				t.Errorf("a vehicle with no trip must have no row, got %v", got)
			}
			sameSummary(t, c.name, got, wantSummary(t, c.from, c.to))
		})
	}

	t.Run("a trip across a boundary counts whole, in the period it started", func(t *testing.T) {
		// "mar" starts 23:59:00 on 31 March and ends 00:01:00 on 1 April.
		march := summary(t, db, "2026-03-01", "2026-04-01")[n20]
		if march.trips != 1 || march.durationMS != 120000 || math.Abs(march.distanceM-120*stepM) > 0.5 {
			t.Errorf("March = %+v, want the whole 120 s trip", march)
		}
		april := summary(t, db, "2026-04-01", "2026-05-01")[n20]
		if april.trips != 1 || april.durationMS != 60000 {
			t.Errorf("April = %+v, want only the trip that started in April, not the March one's last minute", april)
		}
		// 2025's trip ends in 2026 and stays in 2025.
		if y := summary(t, db, "2025-01-01", "2026-01-01")[n20]; y.trips != 1 || y.durationMS != 20000 {
			t.Errorf("2025 = %+v", y)
		}
	})

	t.Run("two cars with the same boot id and start time are not merged", func(t *testing.T) {
		got := summary(t, db, "2026-03-31", "2026-04-01")
		if got[n20].trips != 1 || got[n20].obdKph != 90 || got[n20].durationMS != 120000 {
			t.Errorf("N20 = %+v, want its own trip: 90 kph, 120 s", got[n20])
		}
		if got[b58].trips != 1 || got[b58].obdKph != 140 || got[b58].durationMS != 20000 {
			t.Errorf("B58 = %+v, want its own trip: 140 kph, 20 s", got[b58])
		}
	})

	t.Run("adjacent ranges tile: twelve months are the year", func(t *testing.T) {
		months := map[string]periodRow{}
		for m := 1; m <= 12; m++ {
			from := fmt.Sprintf("2026-%02d-01", m)
			to := fmt.Sprintf("2026-%02d-01", m+1)
			if m == 12 {
				to = "2027-01-01"
			}
			for v, r := range summary(t, db, from, to) {
				a := months[v]
				a.trips += r.trips
				a.durationMS += r.durationMS
				a.distanceM += r.distanceM
				months[v] = a
			}
		}
		year := summary(t, db, "2026-01-01", "2027-01-01")
		for v, y := range year {
			if m := months[v]; m.trips != y.trips || m.durationMS != y.durationMS || math.Abs(m.distanceM-y.distanceM) > 0.5 {
				t.Errorf("%s: months sum to %+v, the year is %+v", v[:2], m, y)
			}
		}
	})

	t.Run("a DATE argument and a string argument agree", func(t *testing.T) {
		a := query(t, db, `SELECT vehicle_id, trips FROM period_summary(DATE '2026-01-01', DATE '2027-01-01') ORDER BY 1`)
		b := query(t, db, `SELECT vehicle_id, trips FROM period_summary('2026-01-01', '2027-01-01') ORDER BY 1`)
		if fmt.Sprint(a) != fmt.Sprint(b) || len(a) != 2 {
			t.Errorf("DATE %v, string %v", a, b)
		}
	})

	t.Run("a vehicle filter on the macro is exact", func(t *testing.T) {
		rows := query(t, db, `SELECT trips FROM period_summary('2026-01-01', '2027-01-01') WHERE vehicle_id = '`+b58+`'`)
		if len(rows) != 1 || num(t, rows[0][0]) != 2 {
			t.Errorf("B58 year = %v, want 2 trips", rows)
		}
	})

	t.Run("the session time zone does not move a trip across a boundary", func(t *testing.T) {
		ctx := context.Background()
		conn, err := db.db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		for _, tz := range []string{"America/Los_Angeles", "Pacific/Auckland"} {
			if _, err := conn.ExecContext(ctx, "SET TimeZone = '"+tz+"'"); err != nil {
				t.Fatal(err)
			}
			var n int
			if err := conn.QueryRowContext(ctx, `SELECT trips FROM period_summary('2026-04-01', '2026-05-01') WHERE vehicle_id = '`+n20+`'`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 1 {
				t.Errorf("under %s April has %d trips, want 1", tz, n)
			}
		}
	})
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

// v_trip_period is how a caller groups by calendar period, so its keys must be the
// period starts and its measures must be v_trip_summary's.
func TestTripPeriodView(t *testing.T) {
	db := periodDB(t)

	t.Run("period starts", func(t *testing.T) {
		rows := query(t, db, `SELECT strftime(started_at, '%Y-%m-%d %H:%M:%S'), started_on::VARCHAR, week_start::VARCHAR, month_start::VARCHAR, quarter_start::VARCHAR, year_start::VARCHAR
			FROM v_trip_period WHERE vehicle_id = '`+n20+`' ORDER BY started_at`)
		wantRows := [][]string{
			{"2025-12-31 23:59:50", "2025-12-31", "2025-12-29", "2025-12-01", "2025-10-01", "2025-01-01"},
			{"2026-01-01 00:00:00", "2026-01-01", "2025-12-29", "2026-01-01", "2026-01-01", "2026-01-01"},
			{"2026-02-15 12:00:00", "2026-02-15", "2026-02-09", "2026-02-01", "2026-01-01", "2026-01-01"},
			{"2026-03-31 23:59:00", "2026-03-31", "2026-03-30", "2026-03-01", "2026-01-01", "2026-01-01"},
			{"2026-04-01 00:00:00", "2026-04-01", "2026-03-30", "2026-04-01", "2026-04-01", "2026-01-01"},
			{"2026-05-20 08:00:00", "2026-05-20", "2026-05-18", "2026-05-01", "2026-04-01", "2026-01-01"},
		}
		if len(rows) != len(wantRows) {
			t.Fatalf("got %d trips, want %d (the trip with no wall-clock time is in no period): %v", len(rows), len(wantRows), rows)
		}
		for i, w := range wantRows {
			for j := range w {
				if fmt.Sprint(rows[i][j]) != w[j] {
					t.Errorf("trip %d column %d = %v, want %s", i, j, rows[i][j], w[j])
				}
			}
		}
	})

	t.Run("grouping by quarter agrees with the macro", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, quarter_start::VARCHAR, count(*), sum(distance_m) FROM v_trip_period
			WHERE year_start = DATE '2026-01-01' GROUP BY 1, 2 ORDER BY 1, 2`)
		got := map[string]int{}
		for _, r := range rows {
			got[fmt.Sprint(r[0])[:2]+" "+fmt.Sprint(r[1])] = int(num(t, r[2]))
		}
		w := map[string]int{"70 2026-01-01": 3, "70 2026-04-01": 2, "80 2026-01-01": 2}
		if fmt.Sprint(got) != fmt.Sprint(w) {
			t.Errorf("trips per quarter = %v, want %v", got, w)
		}
	})

	t.Run("measures are v_trip_summary's", func(t *testing.T) {
		rows := query(t, db, `SELECT count(*) FROM v_trip_period p JOIN v_trip_summary s USING (vehicle_id, boot_id)
			WHERE p.duration_ms IS NOT DISTINCT FROM s.duration_ms AND p.distance_m IS NOT DISTINCT FROM s.distance_m
			  AND p.max_obd_speed_kph IS NOT DISTINCT FROM s.max_obd_speed_kph AND p.started_at = s.started_at`)
		if num(t, rows[0][0]) != 8 {
			t.Errorf("%v trips match v_trip_summary, want the 8 that have a wall-clock time", rows[0][0])
		}
	})

	t.Run("an empty store answers with no rows", func(t *testing.T) {
		e := emptyDB(t)
		if r := query(t, e, `SELECT * FROM period_summary('2026-01-01', '2027-01-01')`); len(r) != 0 {
			t.Errorf("empty store gave %v", r)
		}
		if r := query(t, e, `SELECT * FROM v_trip_period`); len(r) != 0 {
			t.Errorf("empty store gave %v", r)
		}
	})
}
