package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"regexp"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

// The demo store feeds the web layer's staging and acceptance runs and the README
// screenshots. It drifted once: columns were added to the production schema and the
// generator kept appending the old row shape, so it failed on start and nothing noticed.
// This builds the whole synthetic store, so a schema change that the demo does not follow
// fails here instead.

func buildDemo(t *testing.T) *tsdb.DB {
	t.Helper()
	var routes map[string]route
	if err := json.Unmarshal(routesJSON, &routes); err != nil {
		t.Fatal(err)
	}
	db, err := tsdb.BuildSynthetic(context.Background(), func(apps tsdb.Appenders) error {
		return generate(apps, routes, rand.New(rand.NewPCG(7, 1)), false)
	})
	if err != nil {
		t.Fatalf("building the synthetic store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func scalar(t *testing.T, db *tsdb.DB, q string) float64 {
	t.Helper()
	res, err := db.Query(context.Background(), q, 10)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if len(res.Rows) != 1 || len(res.Rows[0]) != 1 {
		t.Fatalf("%s: want one value, got %v", q, res.Rows)
	}
	switch v := res.Rows[0][0].(type) {
	case int64:
		return float64(v)
	case int16:
		return float64(v)
	case float64:
		return v
	default:
		t.Fatalf("%s: unexpected %T", q, v)
		return 0
	}
}

func TestDemoStoreIsComplete(t *testing.T) {
	db := buildDemo(t)

	for _, table := range []string{"bundles", "position", "imu", "obd", "boost", "status", "transition"} {
		if n := scalar(t, db, "SELECT count(*) FROM "+table); n == 0 {
			t.Errorf("table %s is empty", table)
		}
	}
	if n := scalar(t, db, "SELECT count(*) FROM v_drive_summary"); n < 10 {
		t.Errorf("v_drive_summary has %v trips, want the demo's two weeks of them", n)
	}
	if n := scalar(t, db, "SELECT count(*) FROM v_vehicles"); n != 1 {
		t.Errorf("v_vehicles has %v vehicles, want the one invented vehicle", n)
	}
	// every row of every sample table belongs to a vehicle that has a bundle
	for _, table := range []string{"position", "imu", "obd", "boost", "status", "transition"} {
		q := fmt.Sprintf("SELECT count(*) FROM %s WHERE vehicle_id NOT IN (SELECT vehicle_id FROM bundles)", table)
		if n := scalar(t, db, q); n != 0 {
			t.Errorf("%s has %v rows of a vehicle with no bundle", table, n)
		}
	}
}

// The period objects are what the web layer's statistics read, so the demo store must answer
// them, and what they report must be what the per-trip views already say: a period summary
// over every date is the sum of v_trip_summary, and its weeks add up to it.
func TestDemoStoreAnswersThePeriodObjects(t *testing.T) {
	db := buildDemo(t)

	trips := scalar(t, db, "SELECT count(*) FROM v_trip_summary WHERE started_at IS NOT NULL")
	if trips < 10 {
		t.Fatalf("v_trip_summary has %v dated trips", trips)
	}
	if n := scalar(t, db, "SELECT count(*) FROM v_trip_period"); n != trips {
		t.Errorf("v_trip_period has %v trips, v_trip_summary %v", n, trips)
	}
	all := " FROM period_summary('1970-01-01', '2100-01-01')"
	if n := scalar(t, db, "SELECT sum(trips)::BIGINT"+all); n != trips {
		t.Errorf("period_summary counts %v trips over all time, want %v", n, trips)
	}
	for _, col := range []string{"duration_ms", "distance_m"} {
		want := scalar(t, db, "SELECT coalesce(sum("+col+"), 0)::DOUBLE FROM v_trip_summary WHERE started_at IS NOT NULL")
		if got := scalar(t, db, "SELECT sum("+col+")::DOUBLE"+all); math.Abs(got-want) > 0.001*math.Max(1, want) {
			t.Errorf("period_summary %s = %v, v_trip_summary says %v", col, got, want)
		}
	}
	if got, want := scalar(t, db, "SELECT max(max_obd_speed_kph)"+all), scalar(t, db, "SELECT max(max_speed_kph) FROM v_drive_summary"); got != want {
		t.Errorf("max OBD speed = %v, v_drive_summary says %v", got, want)
	}
	// the demo's trips fall in more than one calendar week, and the weeks tile the whole
	if scalar(t, db, "SELECT count(DISTINCT week_start) FROM v_trip_period") < 2 {
		t.Error("the demo's trips are all in one week, so period grouping is untested")
	}
	perWeek := "SELECT sum(trips)::BIGINT FROM (SELECT DISTINCT week_start AS w FROM v_trip_period), period_summary(w, w + 7)"
	if n := scalar(t, db, perWeek); n != trips {
		t.Errorf("the weeks hold %v trips, want %v", n, trips)
	}
}

func TestDemoVehicleIDHasTheManifestShape(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(demoVehicleID) {
		t.Fatalf("demoVehicleID %q is not 32 lowercase hex", demoVehicleID)
	}
}

// -empty serves the schema and views with no rows, which is the web layer's empty-store case.
func TestEmptyStoreAnswersEveryViewWithZeroRows(t *testing.T) {
	db, err := tsdb.BuildSynthetic(context.Background(), func(tsdb.Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, view := range []string{"v_drive_summary", "v_vehicles", "v_telemetry", "v_trip_period", "period_summary('2026-01-01', '2027-01-01')"} {
		if n := scalar(t, db, "SELECT count(*) FROM "+view); n != 0 {
			t.Errorf("%s has %v rows in an empty store", view, n)
		}
	}
}
