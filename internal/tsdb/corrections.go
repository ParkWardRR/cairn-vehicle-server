package tsdb

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Filing a boot's data under the car it was really recorded in.
//
// A bundle names its vehicle, and that name is whatever the device was assigned to when it
// sealed it. Moving the dongle to another car without reassigning it first therefore
// records the second car's drives under the first: measured 2026-10-24, boot 9261cd5b (a
// 2017 M240i, B58) arrived signed for the 428i (N20). The bundles are signed and stay as
// they are; this is the owner saying, after the fact, which car a boot was in.
//
// A correction is narrow and checked: it names the device, the boots, the vehicle the
// bundles must claim (so a stale file cannot move data recorded under a later, correct
// assignment) and the vehicle to file them under, with a reason. It runs after the load
// and reconcile, before the dates are repaired and the views are built, so every table and
// view -- trip ids included, since a trip id begins with the vehicle -- sees the corrected
// vehicle. The decoder's output and its reproducibility digests are untouched, and a
// rebuild repeats it. Each applied correction is recorded in the report's notes.

// VehicleCorrection files the bundles of some of a device's boots under another vehicle.
type VehicleCorrection struct {
	DeviceID      string   `json:"device_id"`
	BootIDs       []string `json:"boot_ids"`
	FromVehicleID string   `json:"from_vehicle_id"`
	ToVehicleID   string   `json:"to_vehicle_id"`
	Reason        string   `json:"reason"`
	By            string   `json:"by,omitempty"`
	At            string   `json:"at,omitempty"`
}

type correctionsFile struct {
	Corrections []VehicleCorrection `json:"corrections"`
}

// ReadCorrections loads and checks a corrections file. A file that exists but does not
// parse or check is an error, not an empty list: serving a store without a correction the
// owner wrote would put a car's drives back under the wrong car.
func ReadCorrections(path string) ([]VehicleCorrection, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var f correctionsFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for i := range f.Corrections {
		c := &f.Corrections[i]
		c.DeviceID = strings.ToLower(c.DeviceID)
		c.FromVehicleID = strings.ToLower(c.FromVehicleID)
		c.ToVehicleID = strings.ToLower(c.ToVehicleID)
		for j := range c.BootIDs {
			c.BootIDs[j] = strings.ToLower(c.BootIDs[j])
		}
		if err := c.check(); err != nil {
			return nil, fmt.Errorf("%s: correction %d: %w", path, i+1, err)
		}
	}
	return f.Corrections, nil
}

func isID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (c *VehicleCorrection) check() error {
	switch {
	case !isID(c.DeviceID):
		return errors.New("device_id must be 32 hex digits")
	case !isID(c.FromVehicleID) || !isID(c.ToVehicleID):
		return errors.New("from_vehicle_id and to_vehicle_id must be 32 hex digits")
	case c.FromVehicleID == c.ToVehicleID:
		return errors.New("from_vehicle_id and to_vehicle_id are the same")
	case len(c.BootIDs) == 0:
		return errors.New("boot_ids is empty: a correction names the boots it moves")
	case strings.TrimSpace(c.Reason) == "":
		return errors.New("reason is empty")
	}
	for _, b := range c.BootIDs {
		if !isID(b) {
			return fmt.Errorf("boot_id %q must be 32 hex digits", b)
		}
	}
	return nil
}

// vehicleTables are the tables that carry a vehicle_id, bundles first.
var vehicleTables = []string{"bundles", "position", "imu", "obd", "boost", "status", "transition", "gap", "time_obs"}

func applyVehicleCorrections(ctx context.Context, sdb *sql.DB, cs []VehicleCorrection, report *Report) error {
	for _, c := range cs {
		if err := c.check(); err != nil {
			return fmt.Errorf("vehicle correction: %w", err)
		}
		tx, err := sdb.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		n, err := applyOne(ctx, tx, c)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("vehicle correction %s -> %s: %w", c.FromVehicleID, c.ToVehicleID, err)
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		short := make([]string, len(c.BootIDs))
		for i, b := range c.BootIDs {
			short[i] = b[:8]
		}
		report.Notes = append(report.Notes, fmt.Sprintf(
			"vehicle correction: %d bundle(s) of device %s boot(s) %s filed under %s instead of %s (%s)",
			n, c.DeviceID[:8], strings.Join(short, ","), c.ToVehicleID, c.FromVehicleID, c.Reason))
	}
	return nil
}

func applyOne(ctx context.Context, tx *sql.Tx, c VehicleCorrection) (int64, error) {
	boots := make([]string, len(c.BootIDs))
	for i, b := range c.BootIDs {
		boots[i] = "'" + b + "'" // checked hex above, so safe to inline
	}
	// The bundles to move: this device, these boots, and only those still claiming the
	// vehicle the correction moves them from.
	if _, err := tx.ExecContext(ctx, fmt.Sprintf(`
		CREATE OR REPLACE TEMP TABLE correction_roots AS
		SELECT content_root FROM bundles
		WHERE device_id = '%s' AND vehicle_id = '%s' AND boot_id IN (%s)`,
		c.DeviceID, c.FromVehicleID, strings.Join(boots, ","))); err != nil {
		return 0, err
	}
	var n int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM correction_roots").Scan(&n); err != nil {
		return 0, err
	}
	if n > 0 {
		for _, t := range vehicleTables {
			q := fmt.Sprintf(`UPDATE %s SET vehicle_id = '%s'
				WHERE vehicle_id = '%s' AND content_root IN (SELECT content_root FROM correction_roots)`,
				t, c.ToVehicleID, c.FromVehicleID)
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return 0, fmt.Errorf("%s: %w", t, err)
			}
		}
	}
	_, err := tx.ExecContext(ctx, "DROP TABLE correction_roots")
	return n, err
}
