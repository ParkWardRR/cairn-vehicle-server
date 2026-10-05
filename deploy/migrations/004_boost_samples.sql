-- Cairn v2 schema, amendment: boost (OBD-extended) samples.
--
-- The ingest decoder has always produced boost data, but the PostgreSQL pipeline
-- silently dropped it — only DuckDB received it. This migration adds the table
-- and the decode_runs counter so the parity test can confirm both stores agree.

BEGIN;

CREATE TABLE norm.boost_samples (
    observed_at         TIMESTAMPTZ NOT NULL,
    content_root        BYTEA       NOT NULL,
    seq                 BIGINT      NOT NULL,

    device_id           BYTEA       NOT NULL,
    boot_id             BYTEA       NOT NULL,
    monotonic_ms        BIGINT      NOT NULL,

    -- MAP and barometric pressure. MAP sensor ceiling is 255 kPa on the N20;
    -- values at that ceiling are saturation, not measurement.
    map_kpa             INTEGER,
    baro_kpa            SMALLINT,

    -- Mass airflow in centgrams per second, lambda × 10000, calculated load.
    maf_cgps            INTEGER,
    lambda_e4           INTEGER,
    abs_load_raw        INTEGER,

    ambient_temp_c      SMALLINT,
    stft_pct            SMALLINT,
    ltft_pct            SMALLINT,

    -- Derived: gauge pressure and equivalence ratio. NULL when the underlying
    -- PIDs are absent.
    boost_psi           DOUBLE PRECISION,
    lambda_ratio        DOUBLE PRECISION,

    pids_requested      BIGINT   NOT NULL DEFAULT 0,
    pids_answered       BIGINT   NOT NULL DEFAULT 0,
    poll_cadence_ms     INTEGER,

    PRIMARY KEY (observed_at, content_root, seq)
) PARTITION BY RANGE (observed_at);

CREATE INDEX boost_samples_device_time_seq_idx
    ON norm.boost_samples (device_id, observed_at, seq);
CREATE INDEX boost_samples_content_root_idx
    ON norm.boost_samples (content_root);

CREATE TABLE norm.boost_samples_default
    PARTITION OF norm.boost_samples DEFAULT;

ALTER TABLE derived.decode_runs
    ADD COLUMN IF NOT EXISTS boost_samples INTEGER NOT NULL DEFAULT 0;

COMMIT;
