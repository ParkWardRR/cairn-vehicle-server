package tsdb

import (
	"context"
	"fmt"
	"strconv"
	"testing"
)

// Two cars that share a dongle model, a boot id and every timestamp, but not
// their physics. This is the worst case for cross-vehicle contamination: nothing
// but vehicle_id can tell their rows apart, so each assertion below fails the
// moment a join or a grouping forgets it.
//
// The N20 runs rich-ish and leans on long-term trim; the B58 makes much more
// boost and runs trims near zero. If a view ever blended them, the averages would
// land between the two and match neither car.
const (
	n20 = "70707070707070707070707070707070"
	b58 = "80808080808080808080808080808080"
)

func twoVehicles(t *testing.T) *DB {
	t.Helper()
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// Same boot id "A", same mono_ms, different cars.
	for _, v := range []struct {
		id         string
		rpmBase    int
		stft, ltft int
		psi        float64
		speed      float64
	}{
		{n20, 2200, -6, 18, 8.0, 80},
		{b58, 2200, 1, 2, 17.0, 120},
	} {
		exec(`INSERT INTO obd (vehicle_id, boot_id, mono_ms, rpm, load_pct, speed_kph, throttle_pct) VALUES
			('` + v.id + `', 'A', 1000, ` + itoa(v.rpmBase) + `, 45, ` + ftoa(v.speed) + `, 80),
			('` + v.id + `', 'A', 2000, ` + itoa(v.rpmBase+800) + `, 45, ` + ftoa(v.speed) + `, 80)`)
		exec(`INSERT INTO boost (vehicle_id, boot_id, mono_ms, stft_pct, ltft_pct, boost_psi, map_kpa) VALUES
			('` + v.id + `', 'A', 500, ` + itoa(v.stft) + `, ` + itoa(v.ltft) + `, ` + ftoa(v.psi) + `, 180),
			('` + v.id + `', 'A', 1500, ` + itoa(v.stft) + `, ` + itoa(v.ltft) + `, ` + ftoa(v.psi) + `, 180)`)
		exec(`INSERT INTO position (vehicle_id, boot_id, mono_ms, lat, lon, fix_type, speed_mps) VALUES
			('` + v.id + `', 'A', 900, 36.5, -121.9, 3, ` + ftoa(v.speed/3.6) + `),
			('` + v.id + `', 'A', 1900, 36.5, -121.9, 3, ` + ftoa(v.speed/3.6) + `)`)
		exec(`INSERT INTO bundles (vehicle_id, content_root, boot_id, warnings) VALUES ('` + v.id + `', 'root-` + v.id[:2] + `', 'A', [])`)
	}
	return db
}

func itoa(n int) string     { return strconv.Itoa(n) }
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// num reads any numeric result as a float64: DuckDB hands back int8, int16, int64
// or float64 depending on the column's type, and a test about values should not
// be about that.
func num(t *testing.T, v any) float64 {
	t.Helper()
	f, err := strconv.ParseFloat(fmt.Sprint(v), 64)
	if err != nil {
		t.Fatalf("%v (%T) is not numeric", v, v)
	}
	return f
}

func query(t *testing.T, db *DB, q string) [][]any {
	t.Helper()
	res, err := db.Query(context.Background(), q, 0)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return res.Rows
}

func TestEveryAnalysisViewKeepsTheCarsApart(t *testing.T) {
	db := twoVehicles(t)

	t.Run("telemetry gives each car its own boost reading", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, mono_ms, boost_psi FROM v_telemetry ORDER BY vehicle_id, mono_ms`)
		if len(rows) != 4 {
			t.Fatalf("got %d rows, want 4: %v", len(rows), rows)
		}
		for _, r := range rows {
			want := 8.0
			if r[0] == b58 {
				want = 17.0
			}
			if num(t, r[2]) != want {
				t.Errorf("%v at %v has boost %v, want %v — another car's reading leaked in", r[0], r[1], r[2], want)
			}
		}
	})

	t.Run("trim map never averages two engines together", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, avg(avg_stft), avg(avg_ltft), sum(samples) FROM v_trim_map GROUP BY vehicle_id ORDER BY vehicle_id`)
		if len(rows) != 2 {
			t.Fatalf("got %d vehicles in the trim map, want 2: %v", len(rows), rows)
		}
		if rows[0][0] != n20 || num(t, rows[0][1]) != -6 || num(t, rows[0][2]) != 18 || num(t, rows[0][3]) != 2 {
			t.Errorf("N20 trim = %v, want stft -6, ltft 18, 2 samples", rows[0])
		}
		if rows[1][0] != b58 || num(t, rows[1][1]) != 1 || num(t, rows[1][2]) != 2 || num(t, rows[1][3]) != 2 {
			t.Errorf("B58 trim = %v, want stft 1, ltft 2, 2 samples", rows[1])
		}
	})

	t.Run("boost curve carries each car's own pressure", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, min(boost_psi), max(boost_psi) FROM v_boost_curve GROUP BY vehicle_id ORDER BY vehicle_id`)
		if len(rows) != 2 || num(t, rows[0][1]) != 8 || num(t, rows[0][2]) != 8 || num(t, rows[1][1]) != 17 || num(t, rows[1][2]) != 17 {
			t.Fatalf("boost curve = %v, want N20 8.0 and B58 17.0 only", rows)
		}
	})

	t.Run("speed agreement compares a car with its own GNSS", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, min(ratio), max(ratio) FROM v_speed_agreement GROUP BY vehicle_id ORDER BY vehicle_id`)
		if len(rows) != 2 {
			t.Fatalf("speed agreement covers %d vehicles, want 2: %v", len(rows), rows)
		}
		for _, r := range rows {
			// OBD speed equals the GNSS speed within each car, so the ratio is
			// ~1. Pairing the N20's OBD with the B58's GNSS gives 80/33 or 120/22.
			lo, hi := num(t, r[1]), num(t, r[2])
			if lo < 0.99 || hi > 1.01 {
				t.Errorf("%v ratio is %v..%v, want ~1.0; OBD was paired with the other car's GNSS", r[0], lo, hi)
			}
		}
	})

	t.Run("drive summary has one row per car", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id, max_speed_kph FROM v_drive_summary ORDER BY vehicle_id`)
		if len(rows) != 2 || num(t, rows[0][1]) != 80 || num(t, rows[1][1]) != 120 {
			t.Fatalf("drive summary = %v, want N20 80 and B58 120 as separate rows", rows)
		}
	})

	t.Run("v_vehicles lists both cars", func(t *testing.T) {
		rows := query(t, db, `SELECT vehicle_id FROM v_vehicles ORDER BY vehicle_id`)
		if len(rows) != 2 || rows[0][0] != n20 || rows[1][0] != b58 {
			t.Fatalf("v_vehicles = %v", rows)
		}
	})
}
