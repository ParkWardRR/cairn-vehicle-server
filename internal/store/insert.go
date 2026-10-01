package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ParkWardRR/Cairn/server/internal/decode"
)

// Bulk inserts for decode output.
//
// Each uses pgx's CopyFrom where the volume justifies it. The sample tables are
// the high-frequency ones, and a row-at-a-time insert there would make decode
// latency scale badly with trip length — the same mistake v2 removed from the
// ingest path.

// partitionMonths returns the distinct months the result's observations fall in,
// so the partitions can be provisioned before inserting.
func resultMonths(res *decode.Result) []time.Time {
	seen := map[time.Time]struct{}{}
	add := func(t time.Time) {
		m := time.Date(t.UTC().Year(), t.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
		seen[m] = struct{}{}
	}

	for i := range res.Positions {
		add(res.Positions[i].ObservedAt)
	}
	for i := range res.IMU {
		add(res.IMU[i].ObservedAt)
	}
	for i := range res.OBD {
		add(res.OBD[i].ObservedAt)
	}

	out := make([]time.Time, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	return out
}

func insertPositions(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	if len(res.Positions) == 0 {
		return nil
	}

	rows := make([][]any, 0, len(res.Positions))
	for i := range res.Positions {
		p := &res.Positions[i]

		// A sample without a fix carries no position. It is still recorded —
		// the absence is data — but the geometry is the zero point and the
		// fix_type is what a consumer must check.
		rows = append(rows, []any{
			p.ObservedAt, res.ContentRoot[:], int64(p.Seq),
			res.DeviceID[:], res.BootID[:], int64(p.MonotonicMS), p.UTCAccMS,
			p.Latitude, p.Longitude,
			p.AltitudeM, p.SpeedMPS, p.HeadingDeg,
			int16(p.FixType), p.SatsUsed, p.SatsVisible,
			p.HDOP, p.HAccM, p.VAccM,
			int16(p.SourceFlags), int16(p.FrameFlags),
		})
	}

	return copyInto(ctx, tx, "norm", "position_samples", []string{
		"observed_at", "content_root", "seq", "device_id", "boot_id",
		// geom is a generated column: it is derived from latitude and longitude
		// by the database, so it is never inserted and can never disagree.
		"monotonic_ms", "utc_acc_ms", "latitude", "longitude",
		"altitude_m", "speed_mps", "heading_deg", "fix_type",
		"sats_used", "sats_visible", "hdop", "h_acc_m", "v_acc_m",
		"source_flags", "frame_flags",
	}, rows)
}

func insertIMU(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	if len(res.IMU) == 0 {
		return nil
	}

	rows := make([][]any, 0, len(res.IMU))
	for i := range res.IMU {
		s := &res.IMU[i]
		rows = append(rows, []any{
			s.ObservedAt, res.ContentRoot[:], int64(s.Seq),
			res.DeviceID[:], res.BootID[:], int64(s.MonotonicMS),
			int32(s.WindowMS), int32(s.AccelRMSmg),
			int32(s.AccelPeakXmg), int32(s.AccelPeakYmg), int32(s.AccelPeakZmg),
			s.GyroPeakDPS, int32(s.Variance), int32(s.SampleCount),
			int16(s.EventFlags), int16(s.FrameFlags),
		})
	}

	return copyInto(ctx, tx, "norm", "imu_samples", []string{
		"observed_at", "content_root", "seq", "device_id", "boot_id",
		"monotonic_ms", "window_ms", "accel_rms_mg",
		"accel_peak_x_mg", "accel_peak_y_mg", "accel_peak_z_mg",
		"gyro_peak_dps", "variance", "sample_count",
		"event_flags", "frame_flags",
	}, rows)
}

func insertOBD(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	if len(res.OBD) == 0 {
		return nil
	}

	rows := make([][]any, 0, len(res.OBD))
	for i := range res.OBD {
		s := &res.OBD[i]
		rows = append(rows, []any{
			s.ObservedAt, res.ContentRoot[:], int64(s.Seq),
			res.DeviceID[:], res.BootID[:], int64(s.MonotonicMS),
			s.SpeedKPH, s.RPM, s.ThrottlePct, s.EngineLoadPct,
			s.CoolantTempC, s.IntakeTempC, s.FuelPressureKPa, s.TimingAdvanceDeg,
			int16(s.PIDErrorCount), int64(s.PIDsRequested), int64(s.PIDsAnswered),
			s.PollCadenceMS, int16(s.FrameFlags),
		})
	}

	return copyInto(ctx, tx, "norm", "obd_samples", []string{
		"observed_at", "content_root", "seq", "device_id", "boot_id",
		"monotonic_ms", "speed_kph", "rpm", "throttle_pct", "engine_load_pct",
		"coolant_temp_c", "intake_temp_c", "fuel_pressure_kpa", "timing_advance_deg",
		"pid_error_count", "pids_requested", "pids_answered",
		"poll_cadence_ms", "frame_flags",
	}, rows)
}

func insertStatus(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	for i := range res.Status {
		s := &res.Status[i]
		if _, err := tx.Exec(ctx, `
			INSERT INTO norm.device_status (
				observed_at, content_root, seq, device_id, boot_id, monotonic_ms,
				battery_mv, sd_write_errors, sd_free_mib, device_temp_c, rssi_dbm,
				ext_sensor_1, ext_sensor_2, health_state, reboot_count
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		`,
			s.ObservedAt, res.ContentRoot[:], int64(s.Seq),
			res.DeviceID[:], res.BootID[:], int64(s.MonotonicMS),
			s.BatteryMV, s.SDWriteErrors, s.SDFreeMiB, s.DeviceTempC, s.RSSIdBm,
			s.ExtSensor1, s.ExtSensor2, int16(s.HealthState), int16(s.RebootCount),
		); err != nil {
			return fmt.Errorf("insert device_status seq %d: %w", s.Seq, err)
		}
	}
	return nil
}

func insertTransitions(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	for i := range res.Transitions {
		t := &res.Transitions[i]
		if _, err := tx.Exec(ctx, `
			INSERT INTO norm.state_transitions (
				observed_at, content_root, seq, device_id, boot_id, monotonic_ms,
				region, from_state, to_state, trigger_event, reason_code,
				policy_version, start_score, stop_score, wake_cause
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		`,
			t.ObservedAt, res.ContentRoot[:], int64(t.Seq),
			res.DeviceID[:], res.BootID[:], int64(t.MonotonicMS),
			int16(t.Region), int16(t.FromState), int16(t.ToState),
			int16(t.TriggerEvent), int16(t.ReasonCode), int16(t.PolicyVersion),
			t.StartScore, t.StopScore, int64(t.WakeCause),
		); err != nil {
			return fmt.Errorf("insert state_transition seq %d: %w", t.Seq, err)
		}
	}
	return nil
}

func insertTrip(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	t := res.Trip
	if t == nil {
		return nil
	}

	summary, err := json.Marshal(map[string]any{
		"segments":        len(t.Segments),
		"gap_duration_s":  t.GapDurationS,
		"decoder_version": decode.Version,
	})
	if err != nil {
		return fmt.Errorf("encode trip summary: %w", err)
	}

	// The route is built only from fixed positions, and never joined across a
	// gap. A LINESTRING needs two points; a single-fix trip gets none rather
	// than a degenerate geometry.
	var routeWKT *string
	if len(t.Route) >= 2 {
		parts := make([]string, 0, len(t.Route))
		for _, p := range t.Route {
			parts = append(parts, fmt.Sprintf("%.7f %.7f", p.Lon, p.Lat))
		}
		w := fmt.Sprintf("SRID=4326;LINESTRING(%s)", strings.Join(parts, ","))
		routeWKT = &w
	}

	var startWKT, endWKT *string
	if t.StartLat != nil && t.StartLon != nil {
		w := fmt.Sprintf("SRID=4326;POINT(%.7f %.7f)", *t.StartLon, *t.StartLat)
		startWKT = &w
	}
	if t.EndLat != nil && t.EndLon != nil {
		w := fmt.Sprintf("SRID=4326;POINT(%.7f %.7f)", *t.EndLon, *t.EndLat)
		endWKT = &w
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO derived.trips (
			trip_id, content_root, device_id, decoder_version,
			started_at, ended_at, duration_s, distance_m,
			start_geom, end_geom, route_geom,
			max_speed_mps, avg_speed_mps, sample_count,
			gap_count, gap_duration_s, recovery_state, summary
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (trip_id) DO UPDATE SET
			decoder_version = EXCLUDED.decoder_version,
			started_at      = EXCLUDED.started_at,
			ended_at        = EXCLUDED.ended_at,
			duration_s      = EXCLUDED.duration_s,
			distance_m      = EXCLUDED.distance_m,
			start_geom      = EXCLUDED.start_geom,
			end_geom        = EXCLUDED.end_geom,
			route_geom      = EXCLUDED.route_geom,
			max_speed_mps   = EXCLUDED.max_speed_mps,
			avg_speed_mps   = EXCLUDED.avg_speed_mps,
			sample_count    = EXCLUDED.sample_count,
			gap_count       = EXCLUDED.gap_count,
			gap_duration_s  = EXCLUDED.gap_duration_s,
			recovery_state  = EXCLUDED.recovery_state,
			summary         = EXCLUDED.summary
	`,
		t.TripID[:], res.ContentRoot[:], res.DeviceID[:], decode.Version,
		t.StartedAt, t.EndedAt, t.DurationS, t.DistanceM,
		startWKT, endWKT, routeWKT,
		t.MaxSpeedMPS, t.AvgSpeedMPS, t.SampleCount,
		t.GapCount, t.GapDurationS, int16(t.RecoveryState), summary,
	); err != nil {
		return fmt.Errorf("insert trip: %w", err)
	}

	// Segments cascade from the trip, so clearing them explicitly keeps a
	// re-decode from accumulating.
	if _, err := tx.Exec(ctx,
		`DELETE FROM derived.trip_segments WHERE trip_id = $1`, t.TripID[:]); err != nil {
		return fmt.Errorf("clear trip segments: %w", err)
	}

	for _, seg := range t.Segments {
		if _, err := tx.Exec(ctx, `
			INSERT INTO derived.trip_segments
				(trip_id, segment_index, kind, started_at, ended_at, duration_s, distance_m)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
		`, t.TripID[:], seg.Index, seg.Kind,
			seg.StartedAt, seg.EndedAt, seg.DurationS, seg.DistanceM); err != nil {
			return fmt.Errorf("insert trip segment %d: %w", seg.Index, err)
		}
	}

	return nil
}

func insertGaps(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	var tripID []byte
	if res.Trip != nil {
		tripID = res.Trip.TripID[:]
	}

	for i := range res.Gaps {
		g := &res.Gaps[i]
		if _, err := tx.Exec(ctx, `
			INSERT INTO derived.gaps (
				content_root, seq, device_id, trip_id,
				started_at, duration_ms, expected_samples, cause
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`,
			res.ContentRoot[:], int64(g.Seq), res.DeviceID[:], tripID,
			g.StartedAt, int64(g.DurationMS), int32(g.ExpectedSamples), int16(g.Cause),
		); err != nil {
			return fmt.Errorf("insert gap seq %d: %w", g.Seq, err)
		}
	}
	return nil
}

func insertEvents(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	var tripID []byte
	if res.Trip != nil {
		tripID = res.Trip.TripID[:]
	}

	for i := range res.Events {
		e := &res.Events[i]

		detail, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("encode event detail: %w", err)
		}

		var geomWKT *string
		if e.Lat != nil && e.Lon != nil {
			w := fmt.Sprintf("SRID=4326;POINT(%.7f %.7f)", *e.Lon, *e.Lat)
			geomWKT = &w
		}

		// The event identity is deterministic, so a re-decode updates rather
		// than duplicating — and published_at is preserved, because an event
		// already announced must not be announced again.
		if _, err := tx.Exec(ctx, `
			INSERT INTO derived.events (
				event_id, content_root, device_id, trip_id,
				kind, occurred_at, seq, geom, detail
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (event_id) DO UPDATE SET
				trip_id     = EXCLUDED.trip_id,
				occurred_at = EXCLUDED.occurred_at,
				geom        = EXCLUDED.geom,
				detail      = EXCLUDED.detail
		`,
			e.EventID[:], res.ContentRoot[:], res.DeviceID[:], tripID,
			e.Kind, e.OccurredAt, int64(e.Seq), geomWKT, detail,
		); err != nil {
			return fmt.Errorf("insert event %s: %w", e.Kind, err)
		}
	}
	return nil
}

// refreshRollup recomputes the affected day's rollup from the derived trips.
//
// Dashboard cards read rollups rather than scanning raw telemetry, which the
// reviews identified as the right shape. Recomputing from trips keeps the
// rollup a derived value rather than an incrementally maintained one that could
// drift.
func refreshRollup(ctx context.Context, tx pgx.Tx, res *decode.Result) error {
	if res.Trip == nil {
		return nil
	}

	day := res.Trip.StartedAt.UTC().Format("2006-01-02")

	_, err := tx.Exec(ctx, `
		INSERT INTO derived.daily_rollups (
			device_id, day, trip_count, distance_m, duration_s,
			max_speed_mps, event_count, gap_duration_s, computed_at
		)
		SELECT
			$1::bytea,
			$2::date,
			count(*),
			COALESCE(sum(t.distance_m), 0),
			COALESCE(sum(t.duration_s), 0),
			max(t.max_speed_mps),
			COALESCE((
				SELECT count(*) FROM derived.events e
				WHERE e.device_id = $1::bytea
				  AND e.occurred_at >= $2::date
				  AND e.occurred_at <  $2::date + INTERVAL '1 day'
			), 0),
			COALESCE(sum(t.gap_duration_s), 0),
			now()
		FROM derived.trips t
		WHERE t.device_id = $1::bytea
		  AND t.started_at >= $2::date
		  AND t.started_at <  $2::date + INTERVAL '1 day'
		ON CONFLICT (device_id, day) DO UPDATE SET
			trip_count     = EXCLUDED.trip_count,
			distance_m     = EXCLUDED.distance_m,
			duration_s     = EXCLUDED.duration_s,
			max_speed_mps  = EXCLUDED.max_speed_mps,
			event_count    = EXCLUDED.event_count,
			gap_duration_s = EXCLUDED.gap_duration_s,
			computed_at    = now()
	`, res.DeviceID[:], day)

	if err != nil {
		return fmt.Errorf("refresh daily rollup: %w", err)
	}
	return nil
}

// copyInto bulk-loads rows with CopyFrom.
func copyInto(ctx context.Context, tx pgx.Tx, schema, table string, cols []string, rows [][]any) error {
	_, err := tx.CopyFrom(ctx, pgx.Identifier{schema, table}, cols, pgx.CopyFromRows(rows))
	if err != nil {
		return fmt.Errorf("copy into %s.%s: %w", schema, table, err)
	}
	return nil
}
