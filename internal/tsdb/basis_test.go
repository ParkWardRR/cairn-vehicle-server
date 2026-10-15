package tsdb

import (
	"context"
	"fmt"
	"testing"
)

// The 2026-10-14 shape: a boot whose bundles alternate between dated and signed with no
// basis. Basis 1792030000000 is UTC at monotonic zero for the whole boot.
func TestUndatedBundlesTakeTheirBootsBasis(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const basis = int64(1792030000000)
	// One bundle's rows: obd, imu and a fix each second over [from, to) seconds of uptime.
	bundle := func(vehicle, boot, root string, from, to int, basisMS int64) {
		for s := from; s < to; s++ {
			at := fmt.Sprintf("make_timestamp(CAST(%d AS BIGINT) * 1000)", basisMS+int64(s)*1000)
			exec(fmt.Sprintf(`INSERT INTO obd (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at, speed_kph) VALUES ('%s','%s','%s',%d,%d,%s,40)`, vehicle, root, boot, s*1000, s, at))
			exec(fmt.Sprintf(`INSERT INTO imu (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at, accel_rms_mg) VALUES ('%s','%s','%s',%d,%d,%s,120)`, vehicle, root, boot, s*1000, s, at))
			exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at, lat, lon, speed_mps, fix_type) VALUES ('%s','%s','%s',%d,%d,%s,34.0,-118.0,11.0,3)`, vehicle, root, boot, s*1000, s, at))
		}
	}
	// Boot A: dated, undated, dated -- and an undated bundle an hour past the dated range.
	bundle("v1", "A", "a1", 600, 660, basis)
	bundle("v1", "A", "a2", 661, 700, 0)
	bundle("v1", "A", "a3", 701, 760, basis+40) // 40 ms of drift between observations
	bundle("v1", "A", "a4", 5000, 5010, 0)
	// Boot B: nothing dated at all.
	bundle("v1", "B", "b1", 100, 110, 0)
	// Boot C: two dated bundles a minute apart in basis -- not one clock -- and an undated one.
	bundle("v1", "C", "c1", 100, 110, basis)
	bundle("v1", "C", "c2", 111, 120, 0)
	bundle("v1", "C", "c3", 121, 130, basis+60000)
	// Boot D: a capture resumed across a reboot -- one dated bundle on the next boot's
	// clock, a day out, at the start -- then the boot's own dated and undated bundles.
	bundle("v1", "D", "d0", 100, 120, basis+86400000)
	bundle("v1", "D", "d1", 125, 130, 0) // beside the foreign clock: not guessed at
	bundle("v1", "D", "d2", 400, 430, basis)
	bundle("v1", "D", "d3", 431, 460, 0) // between two agreeing bundles
	bundle("v1", "D", "d4", 461, 490, basis)
	bundle("v1", "D", "d5", 491, 500, 0) // after the last, within reach
	bundle("v1", "D", "d6", 501, 520, basis)
	// d0 also holds parked status records that run through the whole range, as the real
	// mixed bundle does; they must not make d0 look as if its clock were everywhere.
	exec(fmt.Sprintf(`INSERT INTO status (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at) SELECT 'v1','d0','D', i * 1000, i, make_timestamp((%d + i * 1000) * 1000) FROM range(100, 600) t(i)`, basis+86400000))
	exec(`INSERT INTO gap (vehicle_id, content_root, boot_id, seq, started_at, duration_ms) VALUES ('v1','a2','A',1, make_timestamp(CAST(670000 AS BIGINT) * 1000), 5000)`)

	report := &Report{}
	if err := repairUndatedBundles(context.Background(), db.db, report); err != nil {
		t.Fatal(err)
	}

	dated := func(root string) (n, of int64) {
		t.Helper()
		res, err := db.Query(context.Background(), fmt.Sprintf(
			`SELECT count(*) FILTER (WHERE observed_at >= TIMESTAMP '2000-01-01'), count(*) FROM obd WHERE content_root = '%s'`, root), 0)
		if err != nil {
			t.Fatal(err)
		}
		return res.Rows[0][0].(int64), res.Rows[0][1].(int64)
	}
	if n, of := dated("a2"); n != of || n == 0 {
		t.Errorf("a2: %d of %d rows dated, want all", n, of)
	}
	for _, root := range []string{"d3", "d5"} {
		if n, of := dated(root); n != of || n == 0 {
			t.Errorf("%s: %d of %d rows dated, want all", root, n, of)
		}
	}
	for _, root := range []string{"a4", "b1", "c2", "d1"} {
		if n, _ := dated(root); n != 0 {
			t.Errorf("%s: %d rows dated, want none: it must be left as the device signed it", root, n)
		}
	}

	// Exactly the time a correctly signed bundle would have decoded to: the boot's
	// median basis plus the monotonic. The median of {basis, basis+40} is basis+20.
	res, err := db.Query(context.Background(),
		`SELECT epoch_ms(observed_at) FROM obd WHERE content_root = 'a2' AND mono_ms = 661000`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.Rows[0][0].(int64), basis+20+661000; got != want {
		t.Errorf("a2 at mono 661 s = %d, want %d", got, want)
	}
	res, err = db.Query(context.Background(), `SELECT epoch_ms(started_at) FROM gap WHERE content_root = 'a2'`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := res.Rows[0][0].(int64), basis+20+670000; got != want {
		t.Errorf("gap started_at = %d, want %d", got, want)
	}

	// Boot A's first three bundles are now one trip, not a trip and a 1970 fragment.
	res, err = db.Query(context.Background(),
		`SELECT count(*) FROM v_trip_summary WHERE started_at >= TIMESTAMP '2000-01-01' AND ended_at - started_at >= INTERVAL 150 SECOND`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(1) {
		t.Errorf("trips spanning boot A's dated range = %v, want 1", res.Rows[0][0])
	}
	if len(report.Notes) != 1 {
		t.Errorf("notes = %v, want one line saying how many bundles were dated", report.Notes)
	}
}
