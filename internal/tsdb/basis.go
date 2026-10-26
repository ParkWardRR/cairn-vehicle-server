package tsdb

import (
	"context"
	"database/sql"
	"fmt"
)

// Dating the bundles a device signed with no UTC basis, from the bundles of the same
// boot that have one.
//
// A row's observed_at is the manifest's utc_basis_ms plus the frame's monotonic_ms, and
// the basis is UTC at monotonic zero -- a property of the boot, not of the bundle. Until
// firmware 2d262f9 the device dropped it at every seal and re-established it only with
// the next GNSS time observation, two minutes later, so a bundle sealed sooner was signed
// with utc_basis_ms = 0 and decoded to 1970. Measured on the 2026-10-14 evening drive: 12
// of 37 bundles in one boot, interleaved with dated ones, which left 1970 rows out of the
// trip and drew its gaps as straight lines.
//
// The repair is narrow on purpose:
//   - only a bundle with no dated row at all (a basis is per bundle, so a bundle is
//     either dated throughout or not at all);
//   - only from the dated bundles of the same vehicle and boot, and only when at least
//     two of them, and two thirds, agree with the boot's median basis to within
//     basisAgreementMS;
//   - only for an undated bundle bracketed by agreeing bundles in monotonic order (or
//     within basisReachMS before the first or after the last of them), with no
//     disagreeing dated bundle in that interval.
//
// A boot_id is not always one run of the clock. Firmware before 2d262f9 resumed a
// capture left open at power-off and kept writing the next boot's frames into it, under
// the old boot_id -- measured: boot f83d (the 2026-10-13 drive) holds one bundle dated on
// the 2026-10-14 boot's clock, a day out. A disagreeing bundle marks where another clock
// runs, and nothing near it is guessed at. "Where" is the range of its driving samples
// (OBD, IMU, boost, position), not of its status and transition records: those tick
// through a park, and in a bundle that holds two clocks they span both.
//
// It runs after the load and before the views, like the derivations: the decoder's
// output and its reproducibility digest are untouched, and a rebuild repeats it.
const (
	basisAgreementMS = 5000
	basisReachMS     = 10 * 60 * 1000
)

// tablesWithTime are the sample tables and the column holding each one's wall-clock time.
var tablesWithTime = []struct{ table, column string }{
	{"position", "observed_at"},
	{"imu", "observed_at"},
	{"obd", "observed_at"},
	{"boost", "observed_at"},
	{"status", "observed_at"},
	{"transition", "observed_at"},
	{"gap", "started_at"},
	{"wifi_scan", "observed_at"},
	{"wifi_ap_obs", "observed_at"},
}

func repairUndatedBundles(ctx context.Context, sdb *sql.DB, report *Report) error {
	// The basis a bundle implies is observed_at - mono_ms, read from tables that carry
	// no per-row UTC offset (position does: utc_offset_ms). Undated means every row of
	// every table is before 2000.
	setup := fmt.Sprintf(`
		CREATE OR REPLACE TEMP TABLE basis_span AS
		WITH s AS (
			SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, TRUE AS no_offset, TRUE AS sample FROM obd
			UNION ALL SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, TRUE, TRUE FROM imu
			UNION ALL SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, TRUE, TRUE FROM boost
			UNION ALL SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, TRUE, FALSE FROM status
			UNION ALL SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, TRUE, FALSE FROM transition
			UNION ALL SELECT content_root, vehicle_id, boot_id, mono_ms, observed_at, FALSE, TRUE FROM position
		)
		SELECT content_root, vehicle_id, boot_id,
		       CAST(min(mono_ms) AS BIGINT) AS lo, CAST(max(mono_ms) AS BIGINT) AS hi,
		       CAST(min(mono_ms) FILTER (WHERE sample) AS BIGINT) AS s_lo,
		       CAST(max(mono_ms) FILTER (WHERE sample) AS BIGINT) AS s_hi,
		       bool_and(observed_at IS NULL OR observed_at < TIMESTAMP '2000-01-01') AS undated,
		       median(epoch_ms(observed_at) - mono_ms)
		           FILTER (WHERE no_offset AND observed_at >= TIMESTAMP '2000-01-01') AS basis_ms
		FROM s WHERE content_root IS NOT NULL AND boot_id IS NOT NULL
		GROUP BY 1, 2, 3;

		CREATE OR REPLACE TEMP TABLE basis_repair AS
		WITH boot AS (
			SELECT vehicle_id, boot_id, CAST(median(basis_ms) AS BIGINT) AS basis_ms
			FROM basis_span WHERE NOT undated AND basis_ms IS NOT NULL
			GROUP BY 1, 2
		),
		dated AS (
			SELECT s.vehicle_id, s.boot_id, s.lo, s.hi, coalesce(s.s_lo, s.lo) AS s_lo,
			       coalesce(s.s_hi, s.hi) AS s_hi, b.basis_ms AS boot_basis,
			       abs(s.basis_ms - b.basis_ms) <= %[1]d AS agrees
			FROM basis_span s JOIN boot b USING (vehicle_id, boot_id)
			WHERE NOT s.undated AND s.basis_ms IS NOT NULL
		),
		trusted_boot AS (
			SELECT vehicle_id, boot_id, any_value(boot_basis) AS basis_ms,
			       min(lo) FILTER (WHERE agrees) AS first_lo, max(hi) FILTER (WHERE agrees) AS last_hi
			FROM dated GROUP BY 1, 2
			HAVING count(*) FILTER (WHERE agrees) >= 2
			   AND count(*) FILTER (WHERE agrees) * 3 >= count(*) * 2
		),
		cand AS (
			SELECT u.content_root, u.vehicle_id, u.boot_id, u.lo, u.hi, t.basis_ms, t.first_lo, t.last_hi,
			       (SELECT max(a.hi) FROM dated a WHERE a.vehicle_id = u.vehicle_id AND a.boot_id = u.boot_id
			                                         AND a.agrees AND a.hi <= u.lo) AS prev_hi,
			       (SELECT min(a.lo) FROM dated a WHERE a.vehicle_id = u.vehicle_id AND a.boot_id = u.boot_id
			                                         AND a.agrees AND a.lo >= u.hi) AS next_lo
			FROM basis_span u JOIN trusted_boot t USING (vehicle_id, boot_id)
			WHERE u.undated
		)
		SELECT c.content_root, c.basis_ms FROM cand c
		WHERE (c.prev_hi IS NOT NULL OR c.lo + %[2]d >= c.first_lo)
		  AND (c.next_lo IS NOT NULL OR c.hi <= c.last_hi + %[2]d)
		  AND NOT EXISTS (
			SELECT 1 FROM dated d
			WHERE d.vehicle_id = c.vehicle_id AND d.boot_id = c.boot_id AND NOT d.agrees
			  AND d.s_hi >= coalesce(c.prev_hi, c.lo - %[2]d) AND d.s_lo <= coalesce(c.next_lo, c.hi + %[2]d));`,
		basisAgreementMS, basisReachMS)
	if _, err := sdb.ExecContext(ctx, setup); err != nil {
		return fmt.Errorf("basis repair: %w", err)
	}

	var n int64
	if err := sdb.QueryRowContext(ctx, "SELECT count(*) FROM basis_repair").Scan(&n); err != nil {
		return fmt.Errorf("basis repair: %w", err)
	}
	if n > 0 {
		for _, t := range tablesWithTime {
			// The undated rows hold basis 0 + monotonic (+ offset), so adding the boot's
			// basis gives exactly what a correctly signed bundle would have decoded to.
			q := fmt.Sprintf(`UPDATE %[1]s SET %[2]s = %[2]s + to_milliseconds(r.basis_ms)
				FROM basis_repair r WHERE %[1]s.content_root = r.content_root AND %[1]s.%[2]s IS NOT NULL`,
				t.table, t.column)
			if _, err := sdb.ExecContext(ctx, q); err != nil {
				return fmt.Errorf("basis repair %s: %w", t.table, err)
			}
		}
		report.Notes = append(report.Notes, fmt.Sprintf(
			"dated %d bundle(s) signed with no UTC basis from the agreeing basis of their boot's other bundles", n))
	}
	_, err := sdb.ExecContext(ctx, "DROP TABLE basis_span; DROP TABLE basis_repair")
	return err
}
