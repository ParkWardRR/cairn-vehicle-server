package vehicles

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	deviceA = "8777228e000000000000000000000001"
	deviceB = "8777228e000000000000000000000002"
)

func open(t *testing.T) (*Registry, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "vehicles.key"))
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

func twoCars(t *testing.T, r *Registry) (n20, b58 *Vehicle) {
	t.Helper()
	var err error
	n20, err = r.CreateVehicle(NewVehicleSpec{DisplayName: "2014 BMW 428i — N20", Year: 2014, EngineCode: "N20"})
	if err != nil {
		t.Fatal(err)
	}
	b58, err = r.CreateVehicle(NewVehicleSpec{DisplayName: "2017 BMW M240i — B58", Year: 2017, EngineCode: "B58",
		VIN: "WBA1J7C50HV123456"})
	if err != nil {
		t.Fatal(err)
	}
	return n20, b58
}

func TestVINIsNeverStoredInTheClear(t *testing.T) {
	r, dir := open(t)
	_, b58 := twoCars(t, r)

	raw, err := os.ReadFile(filepath.Join(dir, "vehicles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "WBA1J7C50HV123456") || strings.Contains(string(raw), "WBA1J7C50HV") {
		t.Fatal("the VIN appears in the registry file in the clear")
	}
	if b58.VINLast4 != "3456" {
		t.Fatalf("last four = %q", b58.VINLast4)
	}

	vin, err := r.RevealVIN(b58.ID)
	if err != nil || vin != "WBA1J7C50HV123456" {
		t.Fatalf("RevealVIN = %q, %v", vin, err)
	}

	// A different key cannot open it: the registry key is what protects a copy
	// of the file.
	other := filepath.Join(dir, "other.key")
	r2, err := Open(filepath.Join(dir, "vehicles.json"), other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r2.RevealVIN(b58.ID); err == nil {
		t.Fatal("a VIN opened under the wrong key")
	}
}

func TestKeyFileIsPrivate(t *testing.T) {
	_, dir := open(t)
	info, err := os.Stat(filepath.Join(dir, "vehicles.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestBadVINRejected(t *testing.T) {
	r, _ := open(t)
	if _, err := r.CreateVehicle(NewVehicleSpec{DisplayName: "x", VIN: "SHORT"}); err == nil {
		t.Fatal("a 5-character VIN was accepted")
	}
}

func TestEngineCodeDoesNotIdentifyAVehicle(t *testing.T) {
	r, _ := open(t)
	a, _ := r.CreateVehicle(NewVehicleSpec{DisplayName: "first B58", EngineCode: "B58"})
	b, _ := r.CreateVehicle(NewVehicleSpec{DisplayName: "second B58", EngineCode: "B58"})
	if a.ID == b.ID {
		t.Fatal("two cars with the same engine code share an ID")
	}
}

func TestAssignAndReassignEndsThePreviousOne(t *testing.T) {
	r, _ := open(t)
	n20, b58 := twoCars(t, r)

	first, err := r.Assign(deviceA, n20.ID, "test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Assign(deviceA, b58.ID, "test")
	if err != nil {
		t.Fatal(err)
	}

	if active := r.ActiveFor(deviceA); active == nil || active.ID != second.ID {
		t.Fatalf("active = %+v, want the second assignment", active)
	}
	history := r.Assignments(deviceA)
	if len(history) != 2 || history[0].ID != first.ID || history[0].Open() || history[1].Seq != 2 {
		t.Fatalf("history wrong: %+v", history)
	}
}

func TestOneRecorderPerVehicle(t *testing.T) {
	r, _ := open(t)
	n20, _ := twoCars(t, r)

	if _, err := r.Assign(deviceA, n20.ID, "test"); err != nil {
		t.Fatal(err)
	}
	_, err := r.Assign(deviceB, n20.ID, "test")
	if !errors.Is(err, ErrVehicleBusy) {
		t.Fatalf("second device on one car: err = %v, want ErrVehicleBusy", err)
	}

	if err := r.Unassign(deviceA); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Assign(deviceB, n20.ID, "test"); err != nil {
		t.Fatalf("after unassign: %v", err)
	}
}

func TestArchivedVehicleRejectsNewWork(t *testing.T) {
	r, _ := open(t)
	n20, _ := twoCars(t, r)
	a, err := r.Assign(deviceA, n20.ID, "test")
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Archive(n20.ID); err != nil {
		t.Fatal(err)
	}
	if r.ActiveFor(deviceA) != nil {
		t.Fatal("archiving left the device assigned")
	}
	if _, err := r.Assign(deviceA, n20.ID, "test"); !errors.Is(err, ErrVehicleArchived) {
		t.Fatalf("assign to archived: %v", err)
	}
	if err := r.CheckBundle(deviceA, n20.ID, a.ID, 1); !errors.Is(err, ErrVehicleArchived) {
		t.Fatalf("bundle for archived vehicle: %v", err)
	}
}

func TestCheckBundle(t *testing.T) {
	r, _ := open(t)
	n20, b58 := twoCars(t, r)
	a, _ := r.Assign(deviceA, n20.ID, "test")

	cases := []struct {
		name                   string
		device, vehicle, asgmt string
		want                   error
	}{
		{"valid", deviceA, n20.ID, a.ID, nil},
		{"unknown assignment", deviceA, n20.ID, strings.Repeat("0", 32), ErrAssignmentUnknown},
		{"wrong vehicle", deviceA, b58.ID, a.ID, ErrAssignmentMismatch},
		{"wrong device", deviceB, n20.ID, a.ID, ErrAssignmentMismatch},
	}
	for _, c := range cases {
		err := r.CheckBundle(c.device, c.vehicle, c.asgmt, 1)
		if !errors.Is(err, c.want) && !(c.want == nil && err == nil) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// The scenario the supersession rule exists for: a device is moved to another
// car, starts using the new assignment, and then a bundle shows up claiming the
// old one at a later counter — a card swapped, or a forged claim.
func TestSupersededAssignment(t *testing.T) {
	r, _ := open(t)
	n20, b58 := twoCars(t, r)

	old, _ := r.Assign(deviceA, n20.ID, "test")
	if err := r.Observe(old.ID, 10); err != nil {
		t.Fatal(err)
	}

	moved, _ := r.Assign(deviceA, b58.ID, "test")

	// Not yet seen under the new assignment: a late upload of an old bundle is
	// legitimate, because the device may not have heard about the move.
	if err := r.CheckBundle(deviceA, n20.ID, old.ID, 11); err != nil {
		t.Fatalf("old assignment before the switch is observed: %v", err)
	}

	// The device is now demonstrably using the new assignment at counter 12.
	if err := r.Observe(moved.ID, 12); err != nil {
		t.Fatal(err)
	}

	// A bundle captured before the switch still uploads fine...
	if err := r.CheckBundle(deviceA, n20.ID, old.ID, 11); err != nil {
		t.Fatalf("pre-switch bundle rejected: %v", err)
	}
	// ...but one claiming the old car after the switch does not.
	if err := r.CheckBundle(deviceA, n20.ID, old.ID, 13); !errors.Is(err, ErrAssignmentSuperseded) {
		t.Fatalf("post-switch bundle under the old assignment: err = %v, want ErrAssignmentSuperseded", err)
	}
}

func TestObserveTracksCounterRange(t *testing.T) {
	r, _ := open(t)
	n20, _ := twoCars(t, r)
	a, _ := r.Assign(deviceA, n20.ID, "test")

	for _, c := range []uint64{7, 5, 9} {
		if err := r.Observe(a.ID, c); err != nil {
			t.Fatal(err)
		}
	}
	got := r.Assignments(deviceA)[0]
	if got.FirstCounter != 5 || got.LastCounter != 9 {
		t.Fatalf("range = [%d, %d], want [5, 9]", got.FirstCounter, got.LastCounter)
	}
	if err := r.Observe(strings.Repeat("0", 32), 1); !errors.Is(err, ErrAssignmentUnknown) {
		t.Fatalf("observe unknown: %v", err)
	}
}

func TestPersistsAndPicksUpExternalEdits(t *testing.T) {
	r, dir := open(t)
	n20, _ := twoCars(t, r)
	a, _ := r.Assign(deviceA, n20.ID, "test")

	// A second process (the admin CLI) archives the vehicle.
	cli, err := Open(filepath.Join(dir, "vehicles.json"), filepath.Join(dir, "vehicles.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Archive(n20.ID); err != nil {
		t.Fatal(err)
	}

	// The running server sees it on its next check, with no restart.
	if err := r.CheckBundle(deviceA, n20.ID, a.ID, 1); !errors.Is(err, ErrVehicleArchived) {
		t.Fatalf("running server missed the CLI's change: %v", err)
	}
}

func TestNewIDIsUUIDv7AndSorts(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if a[6]>>4 != 7 || a[8]>>6 != 0b10 {
		t.Fatalf("not a UUIDv7: %x", a)
	}
}
