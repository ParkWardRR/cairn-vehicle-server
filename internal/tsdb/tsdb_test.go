package tsdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

func emptyDB(t testing.TB) *DB {
	t.Helper()
	c, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Fatal(err)
	}
	sdb := sql.OpenDB(c)
	t.Cleanup(func() { sdb.Close() })
	for _, s := range []string{schemaSQL, viewsSQL} {
		if _, err := sdb.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	return &DB{db: sdb}
}

func TestCheckReadOnly(t *testing.T) {
	ok := []string{
		"SELECT 1",
		"select * from obd;",
		"WITH x AS (SELECT 1) SELECT * FROM x",
		"FROM boost SELECT boost_psi",
		"DESCRIBE obd",
		"SELECT replace(boot_id, 'a', 'b') FROM obd",
	}
	for _, q := range ok {
		if err := checkReadOnly(q); err != nil {
			t.Errorf("%q refused: %v", q, err)
		}
	}

	bad := []string{
		"",
		"DROP TABLE obd",
		"SELECT 1; DROP TABLE obd",
		"WITH x AS (SELECT 1) DELETE FROM obd",
		"INSERT INTO obd SELECT * FROM obd",
		"COPY obd TO '/tmp/x'",
		"ATTACH '/tmp/x.db'",
		"SET enable_external_access = true",
		"PRAGMA database_list",
		"CREATE TABLE x AS SELECT 1",
	}
	for _, q := range bad {
		if err := checkReadOnly(q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
}

// ASOF must pick the latest row at or before the anchor, never one after it, and
// must not cross a boot. The age column has to say how stale the pick was.
func TestTelemetryASOF(t *testing.T) {
	db := emptyDB(t)

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// Two boots. Boost samples at 1000 and 2000 on boot A, 500 on boot B.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm) VALUES
		('v1', 'A', 999, 1000), ('v1', 'A', 1000, 2000), ('v1', 'A', 1900, 3000), ('v1', 'A', 2500, 4000), ('v1', 'B', 400, 900), ('v1', 'B', 600, 1100)`)
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, boost_psi) VALUES
		('v1', 'A', 1000, 5.0), ('v1', 'A', 2000, 9.0), ('v1', 'B', 500, 1.5)`)

	res, err := db.Query(context.Background(),
		"SELECT boot_id, mono_ms, boost_psi, boost_age_ms FROM v_telemetry ORDER BY boot_id, mono_ms", 0)
	if err != nil {
		t.Fatal(err)
	}

	type row struct {
		boot string
		mono uint32
		psi  *float64
		age  *int64
	}
	f := func(v float64) *float64 { return &v }
	i := func(v int64) *int64 { return &v }
	want := []row{
		{"A", 999, nil, nil},      // nothing at or before it on this boot
		{"A", 1000, f(5.0), i(0)}, // an exact match counts
		{"A", 1900, f(5.0), i(900)},
		{"A", 2500, f(9.0), i(500)},
		{"B", 400, nil, nil}, // boot A's samples must not leak across
		{"B", 600, f(1.5), i(100)},
	}
	if len(res.Rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %v", len(res.Rows), len(want), res.Rows)
	}
	for n, w := range want {
		got := res.Rows[n]
		if got[0] != w.boot {
			t.Errorf("row %d boot = %v, want %v", n, got[0], w.boot)
		}
		if (got[2] == nil) != (w.psi == nil) || (w.psi != nil && got[2] != *w.psi) {
			t.Errorf("row %d psi = %v, want %v", n, got[2], w.psi)
		}
		if (got[3] == nil) != (w.age == nil) {
			t.Errorf("row %d age = %v, want %v", n, got[3], w.age)
		}
	}
}

func TestQueryRefusesWrites(t *testing.T) {
	db := emptyDB(t)
	_, err := db.Query(context.Background(), "DELETE FROM obd", 0)
	if !errors.Is(err, ErrNotReadOnly) {
		t.Fatalf("err = %v, want ErrNotReadOnly", err)
	}
}

func TestDriveSummary(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, speed_kph, rpm) VALUES
		('v1', 'A', 1000, 60, 3000), ('v1', 'A', 5000, 80, 4000), ('v1', 'A', 11000, 40, 2000),
		('v1', 'B', 2000, 30, 1500), ('v1', 'B', 8000, 50, 2500)`)
	mustExec(`INSERT INTO position (vehicle_id, boot_id, mono_ms, lat, lon, fix_type, speed_mps) VALUES
		('v1', 'A', 1000, 37.0, -122.0, 2, 16.0), ('v1', 'A', 5000, 37.1, -122.1, 0, NULL)`)
	mustExec(`INSERT INTO gap (vehicle_id, boot_id, seq, duration_ms, expected_samples, cause) VALUES
		('v1', 'A', 1, 42000, 42, 4)`)
	mustExec(`INSERT INTO bundles (vehicle_id, content_root, boot_id, warnings) VALUES
		('v1', 'abc', 'A', 'MAPSaturated'), ('v1', 'def', 'B', '')`)

	res, err := db.Query(ctx,
		"SELECT boot_id, duration_s, max_speed_kph, max_rpm, obd_samples, gnss_samples, fix_samples, gap_count, gap_duration_ms, warnings FROM v_drive_summary ORDER BY boot_id", 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(res.Rows))
	}

	// Boot A: duration 10s, max speed 80, max rpm 4000, 3 obd, 2 gnss (1 with fix), 1 gap, warning
	a := res.Rows[0]
	if a[0] != "A" {
		t.Errorf("boot = %v, want A", a[0])
	}
	if a[1] != 10.0 {
		t.Errorf("duration_s = %v, want 10.0", a[1])
	}
	if a[2] != int16(80) {
		t.Errorf("max_speed = %v (%T), want 80", a[2], a[2])
	}
	if a[4] != int64(3) {
		t.Errorf("obd_samples = %v (%T), want 3", a[4], a[4])
	}
	if a[5] != int64(2) {
		t.Errorf("gnss_samples = %v (%T), want 2", a[5], a[5])
	}
	if a[6] != int64(1) {
		t.Errorf("fix_samples = %v (%T), want 1", a[6], a[6])
	}
	if a[7] != int64(1) {
		t.Errorf("gap_count = %v (%T), want 1", a[7], a[7])
	}
	if a[9] != "MAPSaturated" {
		t.Errorf("warnings = %v, want MAPSaturated", a[9])
	}

	// Boot B: no gnss, no gaps, no warnings
	b := res.Rows[1]
	if b[5] != int64(0) {
		t.Errorf("B gnss_samples = %v, want 0", b[5])
	}
	if b[7] != int64(0) {
		t.Errorf("B gap_count = %v, want 0", b[7])
	}
	if b[9] != nil {
		t.Errorf("B warnings = %v, want nil", b[9])
	}
}

func TestTrimMap(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// OBD at known RPM/load, boost with trims within 2s.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm, load_pct) VALUES
		('v1', 'A', 1000, 2200, 45), ('v1', 'A', 2000, 2700, 55), ('v1', 'A', 3000, 3100, 45)`)
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, stft_pct, ltft_pct) VALUES
		('v1', 'A',  500, -2, 14), ('v1', 'A', 1500, -4, 16), ('v1', 'A', 2800,  0, 12)`)

	res, err := db.Query(ctx,
		"SELECT boot_id, rpm_bin, load_bin, avg_stft, avg_ltft, samples FROM v_trim_map ORDER BY rpm_bin, load_bin", 0)
	if err != nil {
		t.Fatal(err)
	}

	// OBD@1000 rpm=2200 load=45 → ASOF picks boost@500 (age 500 < 2000) → bin 2000/40, stft=-2, ltft=14
	// OBD@2000 rpm=2700 load=55 → ASOF picks boost@1500 (age 500 < 2000) → bin 2500/50, stft=-4, ltft=16
	// OBD@3000 rpm=3100 load=45 → ASOF picks boost@2800 (age 200 < 2000) → bin 3000/40, stft=0, ltft=12
	if len(res.Rows) != 3 {
		t.Fatalf("got %d rows, want 3: %v", len(res.Rows), res.Rows)
	}

	type want struct {
		rpm, load int16
		stft      float64
		ltft      float64
	}
	wants := []want{
		{2000, 40, -2.0, 14.0},
		{2500, 50, -4.0, 16.0},
		{3000, 40, 0.0, 12.0},
	}
	for i, w := range wants {
		row := res.Rows[i]
		if row[1] != w.rpm {
			t.Errorf("row %d rpm_bin = %v (%T), want %d", i, row[1], row[1], w.rpm)
		}
		if row[2] != w.load {
			t.Errorf("row %d load_bin = %v (%T), want %d", i, row[2], row[2], w.load)
		}
	}
}

func TestTrimMapAgeFilter(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Boost at t=0, OBD at t=5000 — boost is 5s stale, exceeds the 2s threshold.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm, load_pct) VALUES ('v1', 'A', 5000, 2000, 40)`)
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, stft_pct, ltft_pct) VALUES ('v1', 'A', 0, -3, 10)`)

	res, err := db.Query(ctx, "SELECT count(*) FROM v_trim_map", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(0) {
		t.Errorf("stale boost appeared in trim map: count = %v", res.Rows[0][0])
	}
}

func TestBoostCurve(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm) VALUES
		('v1', 'A', 1000, 3000), ('v1', 'A', 2000, 4000), ('v1', 'A', 3000, 5000)`)
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, boost_psi, map_kpa) VALUES
		('v1', 'A',  900, 8.5, 200), ('v1', 'A', 1900, 12.0, 255), ('v1', 'A', 2900, 10.0, 230)`)

	res, err := db.Query(ctx,
		"SELECT rpm, boost_psi, map_kpa, boost_age_ms FROM v_boost_curve ORDER BY mono_ms", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Row at t=1000: boost@900 (age 100, map 200 OK) — included
	// Row at t=2000: boost@1900 (age 100, map 255 SATURATED) — excluded
	// Row at t=3000: boost@2900 (age 100, map 230 OK) — included
	if len(res.Rows) != 2 {
		t.Fatalf("got %d rows, want 2 (one saturated excluded): %v", len(res.Rows), res.Rows)
	}
	if res.Rows[0][0] != int16(3000) {
		t.Errorf("first rpm = %v, want 3000", res.Rows[0][0])
	}
	if res.Rows[1][0] != int16(5000) {
		t.Errorf("second rpm = %v, want 5000", res.Rows[1][0])
	}
}

func TestBoostCurveStaleExcluded(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Boost at t=0, OBD at t=5000 — 5s stale, exceeds the 2s threshold.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm) VALUES ('v1', 'A', 5000, 3000)`)
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, boost_psi, map_kpa) VALUES ('v1', 'A', 0, 8.0, 200)`)

	res, err := db.Query(ctx, "SELECT count(*) FROM v_boost_curve", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(0) {
		t.Errorf("stale boost appeared: count = %v", res.Rows[0][0])
	}
}

func TestPulls(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Simulate a WOT pull: throttle >= 70%, RPM rising by > 500.
	// Non-WOT samples before and after.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm, throttle_pct, load_pct, speed_kph) VALUES
		('v1', 'A', 1000,  2000, 20, 30, 40),
		('v1', 'A', 2000,  2500, 85, 80, 50),
		('v1', 'A', 3000,  3500, 90, 90, 70),
		('v1', 'A', 4000,  4200, 95, 95, 90),
		('v1', 'A', 5000,  2000, 15, 20, 60)`)
	// Boost during the pull window.
	mustExec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, boost_psi, lambda_ratio, stft_pct, ltft_pct, map_kpa) VALUES
		('v1', 'A', 2100, 8.0,  0.82, -2, 14, 200),
		('v1', 'A', 3100, 12.0, 0.80,  0, 14, 230),
		('v1', 'A', 3900, 14.0, 0.78,  1, 14, 250)`)

	res, err := db.Query(ctx,
		"SELECT boot_id, start_ms, end_ms, min_rpm, max_rpm, obd_samples, peak_boost_psi, avg_lambda, avg_stft, avg_ltft FROM v_pulls", 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Rows) != 1 {
		t.Fatalf("got %d pulls, want 1: %v", len(res.Rows), res.Rows)
	}
	pull := res.Rows[0]
	if pull[3] != int16(2500) {
		t.Errorf("min_rpm = %v, want 2500", pull[3])
	}
	if pull[4] != int16(4200) {
		t.Errorf("max_rpm = %v, want 4200", pull[4])
	}
	if pull[5] != int64(3) {
		t.Errorf("obd_samples = %v, want 3", pull[5])
	}
	if pull[6] != 14.0 {
		t.Errorf("peak_boost_psi = %v, want 14.0", pull[6])
	}
}

func TestPullsNoPull(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Throttle high but RPM doesn't rise enough — no pull detected.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm, throttle_pct, load_pct) VALUES
		('v1', 'A', 1000, 2000, 80, 50),
		('v1', 'A', 2000, 2300, 85, 55),
		('v1', 'A', 3000, 2100, 75, 45)`)

	res, err := db.Query(ctx, "SELECT count(*) FROM v_pulls", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(0) {
		t.Errorf("false pull detected: %v", res.Rows[0][0])
	}
}

func TestSpeedAgreement(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// OBD speed 100 kph, GNSS speed 100/3.6 mps at similar time. Fix type 2 (3D).
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, speed_kph) VALUES ('v1', 'A', 1000, 100)`)
	mustExec(`INSERT INTO position (vehicle_id, boot_id, mono_ms, speed_mps, fix_type, lat, lon) VALUES
		('v1', 'A', 800, 27.78, 2, 37.0, -122.0)`)

	res, err := db.Query(ctx,
		"SELECT obd_speed_kph, gnss_speed_kph, ratio, gnss_age_ms FROM v_speed_agreement", 0)
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(res.Rows))
	}
	row := res.Rows[0]
	if row[0] != int16(100) {
		t.Errorf("obd_speed = %v, want 100", row[0])
	}
	// Ratio should be ~1.0 (100 / (27.78*3.6) ≈ 1.0)
	ratio, ok := row[2].(float64)
	if !ok || ratio < 0.95 || ratio > 1.05 {
		t.Errorf("ratio = %v, want ~1.0", row[2])
	}
	if row[3] != int64(200) && row[3] != uint64(200) && row[3] != uint32(200) {
		t.Errorf("gnss_age_ms = %v (%T), want 200", row[3], row[3])
	}
}

func TestSpeedAgreementNoFixExcluded(t *testing.T) {
	db := emptyDB(t)
	ctx := context.Background()

	mustExec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// fix_type = 0 (no fix) — excluded from v_speed_agreement.
	mustExec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, speed_kph) VALUES ('v1', 'A', 1000, 60)`)
	mustExec(`INSERT INTO position (vehicle_id, boot_id, mono_ms, speed_mps, fix_type, lat, lon) VALUES
		('v1', 'A', 800, 16.7, 0, 0.0, 0.0)`)

	res, err := db.Query(ctx, "SELECT count(*) FROM v_speed_agreement", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(0) {
		t.Errorf("no-fix row appeared: %v", res.Rows[0][0])
	}
}

// BenchmarkScale loads synthetic OBD, boost and GNSS streams and times the
// queries the real data is asked. Rows per table come from CAIRN_BENCH_ROWS
// (default 1,000,000); the point is to show the headroom, since the real data
// today is a few thousand rows.
//
//	CAIRN_BENCH_ROWS=20000000 go test ./internal/tsdb -run '^$' -bench Scale -benchtime 1x
func BenchmarkScale(b *testing.B) {
	n := 1_000_000
	if s := os.Getenv("CAIRN_BENCH_ROWS"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil {
			b.Fatal(err)
		}
		n = v
	}

	for iter := 0; iter < b.N; iter++ {
		db := emptyDB(b)
		ctx := context.Background()

		loadStart := time.Now()
		conn, err := db.db.Conn(ctx)
		if err != nil {
			b.Fatal(err)
		}
		err = conn.Raw(func(dc any) error {
			dconn := dc.(driver.Conn)
			obd, _ := duckdb.NewAppenderFromConn(dconn, "", "obd")
			boost, _ := duckdb.NewAppenderFromConn(dconn, "", "boost")
			pos, _ := duckdb.NewAppenderFromConn(dconn, "", "position")
			now := time.Unix(1_790_000_000, 0).UTC()

			// OBD at ~10 Hz, boost at ~25 Hz, GNSS at ~5 Hz: deliberately
			// unaligned, so the ASOF join does real work. Boots rotate every
			// 100k obd rows.
			for i := 0; i < n; i++ {
				boot := "boot-" + strconv.Itoa(i/100_000)
				ms := uint32(i%100_000) * 100
				rpm := int16(800 + (i*37)%5800)
				if err := obd.AppendRow("v", "r", boot, ms, uint32(i), now,
					int16(i%140), rpm, int16(i%100), int16(i%95), int16(80+i%20), int16(30),
					nil, int16(i%40), uint8(0), uint32(0), uint32(0), int32(100), uint16(0)); err != nil {
					return err
				}
				if err := boost.AppendRow("v", "r", boot, ms/4*4+uint32(i%3), uint32(i), now,
					uint16(100+i%160), uint8(100), uint16(2000), uint16(10000), uint16(30000), int8(30),
					int8(i%10-5), int8(i%6-3), float64(i%20)-2, 1.0+float64(i%10)/100,
					uint32(0), uint32(0), uint16(40)); err != nil {
					return err
				}
				if i%2 == 0 {
					if err := pos.AppendRow("v", "r", boot, ms, uint32(i), now,
						37.0, -122.0, 10.0, float64(i%60), 90.0, uint8(3),
						int16(12), int16(14), 0.9, 1.2, 2.0, int32(20), uint8(0), uint16(0)); err != nil {
						return err
					}
				}
			}
			for _, a := range []*duckdb.Appender{obd, boost, pos} {
				if err := a.Close(); err != nil {
					return err
				}
			}
			return nil
		})
		conn.Close()
		if err != nil {
			b.Fatal(err)
		}
		for _, tbl := range []string{"obd", "boost", "position"} {
			if _, err := db.db.Exec("CREATE OR REPLACE TABLE " + tbl + " AS SELECT * FROM " + tbl + " ORDER BY vehicle_id, boot_id, mono_ms, seq"); err != nil {
				b.Fatal(err)
			}
		}
		loadDur := time.Since(loadStart)
		total := float64(n) * 3.5
		b.Logf("loaded+sorted %d rows (obd %d, boost %d, position %d) in %v = %.1f M rows/s",
			int(total), n, n, n/2, loadDur.Round(time.Millisecond), total/loadDur.Seconds()/1e6)

		queries := []struct{ name, sql string }{
			{"scan_agg", "SELECT count(*), avg(rpm), max(speed_kph) FROM obd"},
			{"filter_range", "SELECT count(*) FROM obd WHERE boot_id = 'boot-3' AND mono_ms BETWEEN 2000000 AND 3000000"},
			{"group_rpm_bins", "SELECT rpm//500*500 AS b, count(*), avg(load_pct) FROM obd GROUP BY 1 ORDER BY 1"},
			{"asof_view_agg", "SELECT count(*), max(boost_psi), avg(stft_pct) FROM v_telemetry WHERE boost_age_ms < 1000"},
			{"asof_group", "SELECT rpm//500*500 AS b, avg(boost_psi), avg(stft_pct), count(*) FROM v_telemetry WHERE boost_age_ms < 1000 GROUP BY 1 ORDER BY 1"},
		}
		for _, q := range queries {
			// One warm-up, then the median of five.
			if _, err := db.Query(ctx, q.sql, 0); err != nil {
				b.Fatalf("%s: %v", q.name, err)
			}
			var us []int64
			for k := 0; k < 5; k++ {
				r, err := db.Query(ctx, q.sql, 0)
				if err != nil {
					b.Fatalf("%s: %v", q.name, err)
				}
				us = append(us, r.ElapsedUS)
			}
			for x := 1; x < len(us); x++ {
				for y := x; y > 0 && us[y] < us[y-1]; y-- {
					us[y], us[y-1] = us[y-1], us[y]
				}
			}
			b.Logf("%-16s median %8.2f ms", q.name, float64(us[2])/1000)
		}
	}
}
