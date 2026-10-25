package tsdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	corrDev   = "8777228e31648b23f6f783d28eee3e26"
	corrOther = "11111111111111111111111111111111"
	corr428   = "01a10dad2a2f797e976089f8854953f0"
	corrM240  = "01a10dad2a427a7eb5866efbf8bf40ab"
	corrBootA = "9261cd5b48d638dc3142a6468b2fc40b"
	corrBootB = "64cdd3b3b583e7c79107875a81a5bee8"
)

// The 2026-10-24 shape: the dongle moved to the M240i still assigned to the 428i.
func TestVehicleCorrectionMovesOnlyTheNamedBoots(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	bundle := func(root, dev, veh, boot string) {
		exec(fmt.Sprintf(`INSERT INTO bundles (content_root, vehicle_id, device_id, boot_id) VALUES ('%s','%s','%s','%s')`, root, veh, dev, boot))
		for s := 0; s < 5; s++ {
			at := fmt.Sprintf("make_timestamp(CAST(%d AS BIGINT) * 1000)", int64(1792874500000)+int64(s)*1000)
			exec(fmt.Sprintf(`INSERT INTO obd (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at, speed_kph) VALUES ('%s','%s','%s',%d,%d,%s,40)`, veh, root, boot, s*1000, s, at))
			exec(fmt.Sprintf(`INSERT INTO transition (vehicle_id, content_root, boot_id, mono_ms, seq, observed_at) VALUES ('%s','%s','%s',%d,%d,%s)`, veh, root, boot, s*1000, s, at))
		}
	}
	bundle("a1", corrDev, corr428, corrBootA)  // recorded in the M240i, signed for the 428i
	bundle("a2", corrDev, corr428, corrBootA)  // likewise
	bundle("a3", corrDev, corrM240, corrBootA) // already signed for the right car
	bundle("b1", corrDev, corr428, corrBootB)  // a 428i boot: not named
	bundle("x1", corrOther, corr428, corrBootA)

	report := &Report{}
	err := applyVehicleCorrections(context.Background(), db.db, []VehicleCorrection{{
		DeviceID: corrDev, BootIDs: []string{corrBootA},
		FromVehicleID: corr428, ToVehicleID: corrM240, Reason: "dongle moved to the M240i before reassignment",
	}}, report)
	if err != nil {
		t.Fatal(err)
	}

	vehicleOf := func(table, root string) string {
		t.Helper()
		res, err := db.Query(context.Background(), fmt.Sprintf(
			`SELECT string_agg(DISTINCT vehicle_id, ',') FROM %s WHERE content_root = '%s'`, table, root), 0)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := res.Rows[0][0].(string)
		return v
	}
	want := map[string]string{"a1": corrM240, "a2": corrM240, "a3": corrM240, "b1": corr428, "x1": corr428}
	for root, w := range want {
		for _, table := range []string{"bundles", "obd", "transition"} {
			if got := vehicleOf(table, root); got != w {
				t.Errorf("%s %s: vehicle %s, want %s", table, root, got, w)
			}
		}
	}
	if len(report.Notes) != 1 || !strings.Contains(report.Notes[0], "2 bundle(s)") {
		t.Errorf("notes = %q, want one note recording 2 bundles moved", report.Notes)
	}

	// The trips follow: a trip id begins with its vehicle.
	res, err := db.Query(context.Background(), fmt.Sprintf(
		`SELECT count(*) FROM obd WHERE vehicle_id = '%s' AND boot_id = '%s'`, corr428, corrBootA), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := res.Rows[0][0].(int64); n != 5 { // only x1, another device's
		t.Errorf("%d obd rows of boot A left under the 428i, want 5 (the other device's)", n)
	}
}

func TestReadCorrectionsRefusesWhatItCannotCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "c.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":["%s"],"from_vehicle_id":"%s","to_vehicle_id":"%s","reason":"moved"}]}`,
		strings.ToUpper(corrDev), corrBootA, corr428, corrM240)
	cs, err := ReadCorrections(write(good))
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].DeviceID != corrDev {
		t.Fatalf("got %+v, want one correction with the device id lower-cased", cs)
	}

	bad := map[string]string{
		"no reason":     fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":["%s"],"from_vehicle_id":"%s","to_vehicle_id":"%s"}]}`, corrDev, corrBootA, corr428, corrM240),
		"no boots":      fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":[],"from_vehicle_id":"%s","to_vehicle_id":"%s","reason":"x"}]}`, corrDev, corr428, corrM240),
		"same vehicle":  fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":["%s"],"from_vehicle_id":"%s","to_vehicle_id":"%s","reason":"x"}]}`, corrDev, corrBootA, corr428, corr428),
		"short boot id": fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":["9261cd5b"],"from_vehicle_id":"%s","to_vehicle_id":"%s","reason":"x"}]}`, corrDev, corr428, corrM240),
		"injection":     fmt.Sprintf(`{"corrections":[{"device_id":"%s","boot_ids":["' OR 1=1 --                     "],"from_vehicle_id":"%s","to_vehicle_id":"%s","reason":"x"}]}`, corrDev, corr428, corrM240),
		"unknown field": fmt.Sprintf(`{"corrections":[{"device":"%s"}]}`, corrDev),
		"not json":      `{`,
	}
	for name, body := range bad {
		if _, err := ReadCorrections(write(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
