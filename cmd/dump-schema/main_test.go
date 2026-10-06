package main

import (
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/storeschema"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

// What the command writes is a schema.json the comparison accepts, and it names the
// objects the web layer depends on, so an empty or truncated dump cannot pass.
func TestDumpWritesALoadableSchema(t *testing.T) {
	out := filepath.Join(t.TempDir(), "schema.json")
	if err := run(out); err != nil {
		t.Fatal(err)
	}
	s, err := storeschema.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if s.StoreContract != tsdb.StoreContract {
		t.Fatalf("store_contract %q, want %q", s.StoreContract, tsdb.StoreContract)
	}
	for _, n := range []string{"position", "obd", "boost", "imu", "status", "gap", "transition"} {
		if _, ok := s.Tables[n]; !ok {
			t.Errorf("no table %s", n)
		}
	}
	for _, n := range []string{"v_drive_summary", "v_telemetry", "v_vehicles", "v_trim_map", "v_pulls", "v_speed_agreement", "v_boost_curve", "v_reproducibility"} {
		if _, ok := s.Views[n]; !ok {
			t.Errorf("no view %s", n)
		}
	}
	if got := storeschema.Compare(s, s); len(got) != 0 {
		t.Fatal(got)
	}
}
