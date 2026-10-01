-- Cairn v2 schema, layer 2 of 3: normalized.
--
-- Decoded per-sample observations. Everything here is derivable from the raw
-- layer plus a decoder version, so it can be dropped and rebuilt at any time.
--
-- The high-frequency tables are range-partitioned by event time. Native
-- partitioning first: it makes retention, query pruning and bulk ingestion
-- manageable without another extension to operate. TimescaleDB is worth
-- evaluating only if measured volume justifies it, which at a single vehicle's
-- sample rates it does not yet.
--
-- Partition note: PostgreSQL requires the partition key in any unique
-- constraint, so the primary keys lead with observed_at. The natural identity
-- of a sample is (content_root, seq) — observed_at is along for partitioning.

BEGIN;

-- ── position samples ────────────────────────────────────────────────────────
--
-- Every quality field the receiver reported is stored, and none are
-- synthesized. Where the receiver supplied no accuracy estimate the column is
-- NULL, never a plausible guess: a decoder must not invent a precision the
-- hardware did not claim.
CREATE TABLE norm.position_samples (
    observed_at     TIMESTAMPTZ NOT NULL,
    content_root    BYTEA       NOT NULL,
    seq             BIGINT      NOT NULL,

    device_id       BYTEA       NOT NULL,
    boot_id         BYTEA       NOT NULL,

    -- Ordering truth. UTC above is an estimate derived from these plus the
    -- bundle's basis, and carries its own uncertainty.
    monotonic_ms    BIGINT      NOT NULL,
    utc_acc_ms      INTEGER,

    latitude        DOUBLE PRECISION NOT NULL,
    longitude       DOUBLE PRECISION NOT NULL,

    -- Generated, not inserted. A stored generated column means the geometry
    -- cannot drift from the coordinates it is supposed to represent — there is
    -- no code path that could write one without the other.
    geom            GEOGRAPHY(POINT, 4326)
                    GENERATED ALWAYS AS
                        (ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)::geography)
                    STORED,

    altitude_m      REAL,
    speed_mps       REAL,
    heading_deg     REAL,

    -- 0 none, 1 2D, 2 3D, 3 DGPS, 4 RTK-float, 5 RTK-fixed.
    fix_type        SMALLINT    NOT NULL,
    sats_used       SMALLINT,
    sats_visible    SMALLINT,
    hdop            REAL,
    h_acc_m         REAL,
    v_acc_m         REAL,
    source_flags    SMALLINT    NOT NULL DEFAULT 0,

    -- From the frame envelope: pre-roll, degraded, estimated UTC, post-recovery.
    frame_flags     SMALLINT    NOT NULL DEFAULT 0,

    PRIMARY KEY (observed_at, content_root, seq)
) PARTITION BY RANGE (observed_at);

-- The review's query shape: samples for one vehicle in time order.
CREATE INDEX position_samples_device_time_seq_idx
    ON norm.position_samples (device_id, observed_at, seq);

-- Map viewport queries.
CREATE INDEX position_samples_geom_idx
    ON norm.position_samples USING GIST (geom);

-- Re-deriving one bundle deletes and reinserts by content root.
CREATE INDEX position_samples_content_root_idx
    ON norm.position_samples (content_root);

COMMENT ON COLUMN norm.position_samples.fix_type IS
    'A sample with fix_type 0 carries no valid position and must not be plotted. '
    'Prefer an explicit gap row in derived.gaps over a run of fix-less samples.';

-- ── IMU summaries ───────────────────────────────────────────────────────────
CREATE TABLE norm.imu_samples (
    observed_at     TIMESTAMPTZ NOT NULL,
    content_root    BYTEA       NOT NULL,
    seq             BIGINT      NOT NULL,

    device_id       BYTEA       NOT NULL,
    boot_id         BYTEA       NOT NULL,
    monotonic_ms    BIGINT      NOT NULL,

    window_ms       INTEGER     NOT NULL,
    accel_rms_mg    INTEGER     NOT NULL,
    accel_peak_x_mg INTEGER     NOT NULL,
    accel_peak_y_mg INTEGER     NOT NULL,
    accel_peak_z_mg INTEGER     NOT NULL,
    gyro_peak_dps   REAL        NOT NULL,
    variance        INTEGER     NOT NULL,
    sample_count    INTEGER     NOT NULL,

    -- bit 0 impact, 1 hard brake, 2 sharp turn, 3 pothole
    event_flags     SMALLINT    NOT NULL DEFAULT 0,
    frame_flags     SMALLINT    NOT NULL DEFAULT 0,

    PRIMARY KEY (observed_at, content_root, seq)
) PARTITION BY RANGE (observed_at);

CREATE INDEX imu_samples_device_time_seq_idx
    ON norm.imu_samples (device_id, observed_at, seq);
CREATE INDEX imu_samples_content_root_idx
    ON norm.imu_samples (content_root);

-- Only the flagged windows, which is what an event detector scans.
CREATE INDEX imu_samples_events_idx
    ON norm.imu_samples (device_id, observed_at)
    WHERE event_flags <> 0;

-- ── OBD snapshots ───────────────────────────────────────────────────────────
--
-- Every value is nullable and NULL means the ECU did not answer. That
-- distinction matters: "the ECU reported 0 kph" and "the ECU said nothing" are
-- different facts, and collapsing them would fabricate data.
CREATE TABLE norm.obd_samples (
    observed_at     TIMESTAMPTZ NOT NULL,
    content_root    BYTEA       NOT NULL,
    seq             BIGINT      NOT NULL,

    device_id       BYTEA       NOT NULL,
    boot_id         BYTEA       NOT NULL,
    monotonic_ms    BIGINT      NOT NULL,

    speed_kph           SMALLINT,
    rpm                 INTEGER,
    throttle_pct        SMALLINT,
    engine_load_pct     SMALLINT,
    coolant_temp_c      SMALLINT,
    intake_temp_c       SMALLINT,
    fuel_pressure_kpa   INTEGER,
    timing_advance_deg  SMALLINT,

    -- PID availability, so a gap can be attributed to the ECU rather than to us.
    pid_error_count     SMALLINT NOT NULL DEFAULT 0,
    pids_requested      BIGINT   NOT NULL DEFAULT 0,
    pids_answered       BIGINT   NOT NULL DEFAULT 0,

    -- The measured cadence, not the target.
    poll_cadence_ms     INTEGER,

    frame_flags         SMALLINT NOT NULL DEFAULT 0,

    PRIMARY KEY (observed_at, content_root, seq)
) PARTITION BY RANGE (observed_at);

CREATE INDEX obd_samples_device_time_seq_idx
    ON norm.obd_samples (device_id, observed_at, seq);
CREATE INDEX obd_samples_content_root_idx
    ON norm.obd_samples (content_root);

-- ── device status ───────────────────────────────────────────────────────────
--
-- Health telemetry. Lower volume than the sample tables, so unpartitioned.
CREATE TABLE norm.device_status (
    observed_at     TIMESTAMPTZ NOT NULL,
    content_root    BYTEA       NOT NULL,
    seq             BIGINT      NOT NULL,

    device_id       BYTEA       NOT NULL,
    boot_id         BYTEA       NOT NULL,
    monotonic_ms    BIGINT      NOT NULL,

    battery_mv      INTEGER,
    sd_write_errors INTEGER,
    sd_free_mib     INTEGER,
    device_temp_c   SMALLINT,
    rssi_dbm        SMALLINT,
    ext_sensor_1    INTEGER,
    ext_sensor_2    INTEGER,

    -- Bitmap of active degraded states, so a drive can be read alongside the
    -- conditions it was captured under.
    health_state    SMALLINT    NOT NULL DEFAULT 0,
    reboot_count    SMALLINT    NOT NULL DEFAULT 0,

    PRIMARY KEY (content_root, seq)
);

CREATE INDEX device_status_device_time_idx
    ON norm.device_status (device_id, observed_at DESC);

-- ── state transitions ───────────────────────────────────────────────────────
--
-- The device's lifecycle journal, decoded. This is what makes it possible to
-- answer *why* a trip started, continued, split, finalized, retried or was
-- retained — which the reviews rated more useful than any amount of
-- "upload succeeded" logging.
CREATE TABLE norm.state_transitions (
    observed_at     TIMESTAMPTZ NOT NULL,
    content_root    BYTEA       NOT NULL,
    seq             BIGINT      NOT NULL,

    device_id       BYTEA       NOT NULL,
    boot_id         BYTEA       NOT NULL,
    monotonic_ms    BIGINT      NOT NULL,

    region          SMALLINT    NOT NULL,
    from_state      SMALLINT    NOT NULL,
    to_state        SMALLINT    NOT NULL,
    trigger_event   SMALLINT    NOT NULL,
    reason_code     SMALLINT    NOT NULL,
    policy_version  SMALLINT    NOT NULL,

    -- The evidence scores at decision time. Recording them is what makes a
    -- threshold retune attributable after the fact.
    start_score     REAL,
    stop_score      REAL,
    wake_cause      BIGINT,

    PRIMARY KEY (content_root, seq)
);

CREATE INDEX state_transitions_device_time_idx
    ON norm.state_transitions (device_id, observed_at DESC);

-- ── partition management ────────────────────────────────────────────────────
--
-- Monthly partitions, created on demand. A default partition catches anything
-- outside the provisioned range so a decode can never fail for want of a
-- partition — losing derived rows to a missing partition would be a silly way
-- to lose a drive, even a recoverable one.
CREATE TABLE norm.position_samples_default
    PARTITION OF norm.position_samples DEFAULT;
CREATE TABLE norm.imu_samples_default
    PARTITION OF norm.imu_samples DEFAULT;
CREATE TABLE norm.obd_samples_default
    PARTITION OF norm.obd_samples DEFAULT;

-- Create the monthly partition covering a given timestamp, if absent.
CREATE OR REPLACE FUNCTION norm.ensure_month_partition(
    parent regclass,
    at TIMESTAMPTZ
) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    start_ts  TIMESTAMPTZ := date_trunc('month', at);
    end_ts    TIMESTAMPTZ := start_ts + INTERVAL '1 month';
    parent_name TEXT := parent::text;
    short     TEXT := split_part(parent_name, '.', 2);
    part_name TEXT := format('%s_%s', short, to_char(start_ts, 'YYYYMM'));
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'norm' AND c.relname = part_name
    ) THEN
        RETURN;
    END IF;

    EXECUTE format(
        'CREATE TABLE norm.%I PARTITION OF %s FOR VALUES FROM (%L) TO (%L)',
        part_name, parent_name, start_ts, end_ts
    );
END;
$$;

COMMENT ON FUNCTION norm.ensure_month_partition IS
    'Idempotent. Called by the decode worker before inserting, so a bundle from '
    'an unprovisioned month lands in its own partition rather than the default.';

COMMIT;
