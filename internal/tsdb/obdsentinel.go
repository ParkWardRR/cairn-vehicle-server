package tsdb

import (
	"context"
	"database/sql"
	"fmt"
)

// A vehicle speed of 255 km/h with the engine at 0 rpm is the DME's "not available"
// (PID 0x0D answered 0xFF), not a reading. Measured 2026-10-24 on the M240i (B58): minutes
// of it after the engine stopped, which every summary read as a 158 mph maximum. Firmware
// after 006c80c records it as unknown; this gives the bundles signed before that the same
// reading. Like the basis repair it runs after the load, so the decoder's output and its
// digests are untouched and a rebuild repeats it.
func clearUnavailableOBDSpeed(ctx context.Context, sdb *sql.DB, report *Report) error {
	res, err := sdb.ExecContext(ctx, `UPDATE obd SET speed_kph = NULL WHERE speed_kph = 255 AND rpm = 0`)
	if err != nil {
		return fmt.Errorf("obd speed sentinel: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		report.Notes = append(report.Notes, fmt.Sprintf(
			"read %d OBD speed(s) of 255 km/h at 0 rpm as unavailable (the DME's 0xFF)", n))
	}
	return nil
}
