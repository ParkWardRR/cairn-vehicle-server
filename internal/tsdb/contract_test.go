package tsdb

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// The identity /healthz reports is only worth anything if it moves when the schema does.
func TestStoreContractMatchesSchema(t *testing.T) {
	db, err := BuildSynthetic(context.Background(), func(Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()

	caps, err := db.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Fingerprint != schemaFingerprint {
		t.Fatalf("the schema this package builds is not the one %s describes.\n"+
			"  built:    %s\n  declared: %s\n"+
			"If the change is additive (a new view or column), bump the minor in StoreContract and set\n"+
			"schemaFingerprint to the built value, and add it to contracts store/v1. If it removes or\n"+
			"repurposes anything, that is store/v2, not a minor.", StoreContract, caps.Fingerprint, schemaFingerprint)
	}
	if !strings.HasPrefix(StoreContract, "store/v1.") {
		t.Fatalf("StoreContract %q: this package implements store/v1", StoreContract)
	}
}

// The contract's own list is what the dashboard depends on; the capabilities response
// must contain at least those, and every one must carry vehicle_id.
func TestCapabilitiesCoverTheContract(t *testing.T) {
	db, err := BuildSynthetic(context.Background(), func(Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	caps, err := db.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, n := range append(append([]string{}, caps.Tables...), caps.Views...) {
		have[n] = true
	}
	for _, n := range []string{
		"bundles", "position", "imu", "obd", "boost", "status", "transition", "gap",
		"v_telemetry", "v_reproducibility", "v_vehicles", "v_drive_summary", "v_trip_summary",
		"v_trim_map", "v_boost_curve", "v_pulls", "v_speed_agreement", "v_gnss_sources",
	} {
		if !have[n] {
			t.Errorf("capabilities lack %s", n)
		}
		found := false
		for _, c := range caps.Columns[n] {
			found = found || c == "vehicle_id"
		}
		if !found {
			t.Errorf("%s has no vehicle_id column", n)
		}
	}
}

// A fingerprint that did not depend on the schema would pass the test above forever.
func TestFingerprintMovesWithTheSchema(t *testing.T) {
	ctx := context.Background()
	db, err := BuildSynthetic(ctx, func(Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.db.Close()
	before, _ := db.Capabilities(ctx)

	// Use a fresh, unlocked database: the serving store refuses DDL by design.
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := sql.OpenDB(connector)
	defer raw.Close()
	if _, err := raw.ExecContext(ctx, schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, viewsSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "ALTER TABLE gap ADD COLUMN extra INTEGER"); err != nil {
		t.Fatal(err)
	}
	changed, err := (&DB{db: raw}).Capabilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint == before.Fingerprint {
		t.Fatal("adding a column did not change the fingerprint")
	}
}
