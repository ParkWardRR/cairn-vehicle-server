package vehicles

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func fixedClock(t *testing.T) (*Registry, string) {
	t.Helper()
	dir := t.TempDir()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	r, err := Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "vehicles.key"),
		WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func TestTunesAreKeptOldestFirstAndSurviveReopen(t *testing.T) {
	r, dir := fixedClock(t)
	n20, _ := twoCars(t, r)

	b, err := r.AddTune(n20.ID, "2026-08-01", "Stage 2 flash", "alfa")
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.AddTune(n20.ID, "2026-03-14", "  Stage 1  ", "alfa")
	if err != nil {
		t.Fatal(err)
	}
	if a.Note != "Stage 1" || a.VehicleID != n20.ID || a.ID == b.ID {
		t.Fatalf("a = %+v", a)
	}

	got, _ := r.Tunes(n20.ID)
	if len(got) != 2 || got[0].ID != a.ID || got[1].ID != b.ID {
		t.Fatalf("tunes are ordered by date, not by when they were entered: %+v", got)
	}

	again, err := Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "vehicles.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got2, _ := again.Tunes(n20.ID); len(got2) != 2 || got2[0].Note != "Stage 1" {
		t.Fatalf("not persisted: %+v", got2)
	}
}

func TestTuneRefusals(t *testing.T) {
	r, _ := fixedClock(t)
	n20, _ := twoCars(t, r)

	for name, c := range map[string]struct{ at, note string }{
		"not a date":     {"yesterday", ""},
		"wrong layout":   {"05/10/2026", ""},
		"far future":     {"2026-12-01", ""},
		"before any car": {"1960-01-01", ""},
		"note too long":  {"2026-08-01", string(make([]rune, MaxTuneNote+1))},
	} {
		if _, err := r.AddTune(n20.ID, c.at, c.note, "x"); !errors.Is(err, ErrBadTune) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Tomorrow is fine: an owner east of UTC records today's tune.
	if _, err := r.AddTune(n20.ID, "2026-10-06", "", "x"); err != nil {
		t.Errorf("tomorrow: %v", err)
	}
	if _, err := r.AddTune("00000000000000000000000000000000", "2026-08-01", "", "x"); !errors.Is(err, ErrUnknownVehicle) {
		t.Errorf("unknown vehicle: %v", err)
	}
}

func TestTuneLimitPerVehicle(t *testing.T) {
	r, _ := fixedClock(t)
	n20, _ := twoCars(t, r)
	for i := 0; i < MaxTunesPerVehicle; i++ {
		if _, err := r.AddTune(n20.ID, "2026-08-01", "", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.AddTune(n20.ID, "2026-08-01", "", "x"); !errors.Is(err, ErrBadTune) {
		t.Fatalf("the limit holds: %v", err)
	}
}

func TestUpdateAndDeleteTune(t *testing.T) {
	r, _ := fixedClock(t)
	n20, b58 := twoCars(t, r)
	tune, _ := r.AddTune(n20.ID, "2026-08-01", "first", "alfa")

	up, err := r.UpdateTune(n20.ID, tune.ID, "2026-08-03", "moved")
	if err != nil || up.At != "2026-08-03" || up.Note != "moved" || up.CreatedBy != "alfa" {
		t.Fatalf("update = %+v, %v", up, err)
	}
	// A tune belongs to one vehicle: the other car's registry entry cannot reach it.
	if _, err := r.UpdateTune(b58.ID, tune.ID, "2026-08-04", "x"); !errors.Is(err, ErrUnknownTune) {
		t.Fatalf("cross-vehicle update: %v", err)
	}
	if err := r.DeleteTune(b58.ID, tune.ID); !errors.Is(err, ErrUnknownTune) {
		t.Fatalf("cross-vehicle delete: %v", err)
	}
	if err := r.DeleteTune(n20.ID, tune.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Tunes(n20.ID); len(got) != 0 {
		t.Fatalf("still there: %+v", got)
	}
	if err := r.DeleteTune(n20.ID, tune.ID); !errors.Is(err, ErrUnknownTune) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestArchivedVehicleKeepsTunesButTakesNoChange(t *testing.T) {
	r, _ := fixedClock(t)
	n20, _ := twoCars(t, r)
	tune, _ := r.AddTune(n20.ID, "2026-08-01", "", "x")
	if err := r.Archive(n20.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.AddTune(n20.ID, "2026-08-02", "", "x"); !errors.Is(err, ErrVehicleArchived) {
		t.Errorf("add: %v", err)
	}
	if _, err := r.UpdateTune(n20.ID, tune.ID, "2026-08-02", ""); !errors.Is(err, ErrVehicleArchived) {
		t.Errorf("update: %v", err)
	}
	if err := r.DeleteTune(n20.ID, tune.ID); !errors.Is(err, ErrVehicleArchived) {
		t.Errorf("delete: %v", err)
	}
	if got, _ := r.Tunes(n20.ID); len(got) != 1 {
		t.Errorf("history is kept: %+v", got)
	}
}

// A caller that edits a returned vehicle must not edit the registry.
func TestReturnedVehicleDoesNotAliasTheRegistry(t *testing.T) {
	r, _ := fixedClock(t)
	n20, _ := twoCars(t, r)
	r.AddTune(n20.ID, "2026-08-01", "keep", "x")
	v, _ := r.Vehicle(n20.ID)
	v.Tunes[0].Note = "scribbled"
	if got, _ := r.Tunes(n20.ID); got[0].Note != "keep" {
		t.Fatalf("aliased: %+v", got)
	}
}

func TestTuneTime(t *testing.T) {
	if got := (Tune{At: "2026-08-01"}).Time(); !got.Equal(time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("got %v", got)
	}
}
