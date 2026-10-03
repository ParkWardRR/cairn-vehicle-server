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
	mustExec(`INSERT INTO obd (boot_id, mono_ms, rpm) VALUES
		('A', 999, 1000), ('A', 1000, 2000), ('A', 1900, 3000), ('A', 2500, 4000), ('B', 400, 900), ('B', 600, 1100)`)
	mustExec(`INSERT INTO boost (boot_id, mono_ms, boost_psi) VALUES
		('A', 1000, 5.0), ('A', 2000, 9.0), ('B', 500, 1.5)`)

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
				if err := obd.AppendRow("r", boot, ms, uint32(i), now,
					int16(i%140), rpm, int16(i%100), int16(i%95), int16(80+i%20), int16(30),
					nil, int16(i%40), uint8(0), uint32(0), uint32(0), int32(100), uint16(0)); err != nil {
					return err
				}
				if err := boost.AppendRow("r", boot, ms/4*4+uint32(i%3), uint32(i), now,
					uint16(100+i%160), uint8(100), uint16(2000), uint16(10000), uint16(30000), int8(30),
					int8(i%10-5), int8(i%6-3), float64(i%20)-2, 1.0+float64(i%10)/100,
					uint32(0), uint32(0), uint16(40)); err != nil {
					return err
				}
				if i%2 == 0 {
					if err := pos.AppendRow("r", boot, ms, uint32(i), now,
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
			if _, err := db.db.Exec("CREATE OR REPLACE TABLE " + tbl + " AS SELECT * FROM " + tbl + " ORDER BY boot_id, mono_ms, seq"); err != nil {
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
