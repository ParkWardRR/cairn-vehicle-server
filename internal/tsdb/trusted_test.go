package tsdb

import (
	"context"
	"fmt"
	"testing"
)

// The 2026-10-14 receiver run: a car parked at idle (IMU 9 mg) while the receiver reported
// 40+ m/s. Fixes are 1 s apart here, each with an IMU window in the same second.
func TestPositionTrustedRejectsMotionTheAccelerometerContradicts(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// 0-9 s: driving at 15 m/s, IMU 120 mg. 20-24 s: parked, IMU 9 mg, receiver says 42 m/s.
	for s := 0; s < 10; s++ {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, lat, lon, fix_type, speed_mps) VALUES ('v1','A',%d,%d,34.0,-118.0,3,15.0)`, s*1000, s))
		exec(fmt.Sprintf(`INSERT INTO imu (vehicle_id, boot_id, mono_ms, seq, accel_rms_mg) VALUES ('v1','A',%d,%d,120)`, s*1000, s))
	}
	for s := 20; s < 25; s++ {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, lat, lon, fix_type, speed_mps) VALUES ('v1','A',%d,%d,34.1,-118.1,3,42.0)`, s*1000, s))
		exec(fmt.Sprintf(`INSERT INTO imu (vehicle_id, boot_id, mono_ms, seq, accel_rms_mg) VALUES ('v1','A',%d,%d,9)`, s*1000, s))
	}
	res, err := db.Query(context.Background(),
		"SELECT count(*) FILTER (WHERE trusted AND mono_ms < 10000), count(*) FILTER (WHERE NOT trusted AND mono_ms >= 20000), count(*) FROM v_position_trusted", 0)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r[0] != int64(10) || r[1] != int64(5) || r[2] != int64(15) {
		t.Errorf("trusted driving, untrusted parked, total = %v, %v, %v; want 10, 5, 15", r[0], r[1], r[2])
	}
}

// A fix the IMU never saw is not contradicted; only the kinematic rule can speak to it.
func TestPositionTrustedKinematicRule(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	// 12 -> 13 -> 14 m/s is ordinary; 14 -> 40 m/s in one second is not, and the pair is
	// untrusted because the data cannot say which end is wrong. The fixes either side stay.
	for i, v := range []float64{12, 13, 14, 40, 13, 12} {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, lat, lon, fix_type, speed_mps) VALUES ('v1','A',%d,%d,34.0,-118.0,3,%v)`, i*1000, i, v))
	}
	res, err := db.Query(context.Background(),
		"SELECT mono_ms / 1000 AS i, trusted FROM v_position_trusted ORDER BY mono_ms", 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, true, false, false, false, true}
	for i, row := range res.Rows {
		if row[1] != want[i] {
			t.Errorf("fix %d trusted = %v, want %v", i, row[1], want[i])
		}
	}
}

// Legs and the trip's distance and max speed are built from trusted fixes, so a phantom
// receiver run neither opens a leg nor sets the max.
func TestTripViewsIgnoreUntrustedFixes(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	base := "TIMESTAMP '2026-10-15 03:00:00'"
	// A genuine 10 s drive at 15 m/s, then a stationary phantom run 5 minutes later.
	for s := 0; s < 10; s++ {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, observed_at, lat, lon, fix_type, speed_mps) VALUES ('v1','A',%d,%d,%s + INTERVAL %d SECOND,34.0,-118.0,3,15.0)`, s*1000, s, base, s))
		exec(fmt.Sprintf(`INSERT INTO imu (vehicle_id, boot_id, mono_ms, seq, observed_at, accel_rms_mg) VALUES ('v1','A',%d,%d,%s + INTERVAL %d SECOND,120)`, s*1000, s, base, s))
	}
	for s := 300; s < 305; s++ {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, observed_at, lat, lon, fix_type, speed_mps) VALUES ('v1','A',%d,%d,%s + INTERVAL %d SECOND,34.1,-118.1,3,45.0)`, s*1000, s, base, s))
		exec(fmt.Sprintf(`INSERT INTO imu (vehicle_id, boot_id, mono_ms, seq, observed_at, accel_rms_mg) VALUES ('v1','A',%d,%d,%s + INTERVAL %d SECOND,9)`, s*1000, s, base, s))
	}
	res, err := db.Query(context.Background(), "SELECT count(*) FROM v_trip_leg", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != int64(1) {
		t.Errorf("legs = %v, want 1: the phantom run must not open one", res.Rows[0][0])
	}
	res, err = db.Query(context.Background(), "SELECT max_gnss_speed_mps FROM v_trip_summary", 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0][0] != 15.0 {
		t.Errorf("max_gnss_speed_mps = %v, want 15", res.Rows[0][0])
	}
}

// 2026-10-25, the M240i pulling into a garage: OBD 3-6 km/h, the receiver at 3-5
// satellites running 8 -> 28 km/h. And the case that must stay trusted: hard acceleration
// with OBD a second behind.
func TestPositionTrustedRefusesLowSatellitesAndFixesFasterThanTheWheels(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	fix := func(ms, seq int, speed float64, sats int) {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, lat, lon, fix_type, speed_mps, sats_used) VALUES ('v1','A',%d,%d,34.0,-118.0,3,%f,%d)`, ms, seq, speed, sats))
	}
	obd := func(ms, seq, kph int) {
		exec(fmt.Sprintf(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, seq, speed_kph) VALUES ('v1','A',%d,%d,%d)`, ms, seq, kph))
	}
	// 0-9 s: creeping at 5 km/h, OBD every second, 12 satellites, receiver agrees.
	for s := 0; s < 10; s++ {
		obd(s*1000+500, s, 5)
		fix(s*1000, s, 1.4, 12)
	}
	// 10-19 s: the garage. OBD 5 km/h; receiver at 9 sats says 8 m/s (spur), then 4 sats.
	for s := 10; s < 20; s++ {
		obd(s*1000+500, s, 5)
		sats := 9
		if s >= 15 {
			sats = 4
		}
		fix(s*1000, s, 8.0, sats)
	}
	// 30-39 s: a hard launch. OBD lags the receiver by up to 3.5 m/s: still trusted.
	for s := 30; s < 40; s++ {
		obd(s*1000+500, s, (s-30)*20) // 0..180 km/h-ish ramp in km/h steps of 20
		fix(s*1000, s, float64(s-30)*20/3.6+2.0, 11)
	}
	res, err := db.Query(context.Background(), `SELECT
		count(*) FILTER (WHERE mono_ms < 10000 AND trusted),
		count(*) FILTER (WHERE mono_ms BETWEEN 10000 AND 19999 AND NOT trusted),
		count(*) FILTER (WHERE mono_ms >= 30000 AND trusted)
		FROM v_position_trusted`, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r[0] != int64(10) || r[1] != int64(10) || r[2] != int64(10) {
		t.Errorf("creep trusted, garage spur untrusted, launch trusted = %v, %v, %v; want 10, 10, 10", r[0], r[1], r[2])
	}
}
