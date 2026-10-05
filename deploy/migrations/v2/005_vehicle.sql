-- 005 — every row belongs to a vehicle (Cairn v3).
--
-- v3 bundles bind a vehicle, an assignment and a monotonic device counter into
-- the signed manifest. Until now the derived layer could not say which car a
-- row came from, so a fuel-trim map or a boost curve from the N20 428i could have
-- been averaged with the B58 M240i's. From here every normalized and derived row
-- carries vehicle_id and every analysis keys on it.
--
-- NON-DESTRUCTIVE. Rows that already exist (written by v2, which had no vehicle)
-- are labelled with the all-zero vehicle id — an honest "unassigned" rather than a
-- guess, and not a deletion. The default exists only to let the ALTER succeed on a
-- populated table and is dropped straight away, so every new insert must name its
-- vehicle or fail.
--
-- Apply once, in order, after 004. Safe to run on an empty database.

BEGIN;

-- ── raw ─────────────────────────────────────────────────────────────────────

ALTER TABLE raw.bundles
    ADD COLUMN vehicle_id          BYTEA    NOT NULL DEFAULT '\x00000000000000000000000000000000'
        CHECK (length(vehicle_id) = 16),
    ADD COLUMN assignment_id       BYTEA    NOT NULL DEFAULT '\x00000000000000000000000000000000'
        CHECK (length(assignment_id) = 16),
    -- The device's monotonic bundle counter. Zero only on rows written before v3.
    ADD COLUMN device_counter      BIGINT   NOT NULL DEFAULT 0,
    ADD COLUMN storage_key_version INTEGER  NOT NULL DEFAULT 0;

ALTER TABLE raw.bundles
    ALTER COLUMN vehicle_id          DROP DEFAULT,
    ALTER COLUMN assignment_id       DROP DEFAULT,
    ALTER COLUMN device_counter      DROP DEFAULT,
    ALTER COLUMN storage_key_version DROP DEFAULT;

CREATE INDEX bundles_vehicle_idx ON raw.bundles (vehicle_id, committed_at DESC);

-- ── normalized samples ──────────────────────────────────────────────────────
--
-- Adding a column to a partitioned parent adds it to every partition, including
-- the default one, so a monthly partition created later inherits it too.

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'position_samples', 'imu_samples', 'obd_samples', 'boost_samples',
        'device_status', 'state_transitions'
    ] LOOP
        EXECUTE format(
            'ALTER TABLE norm.%I ADD COLUMN vehicle_id BYTEA NOT NULL '
            'DEFAULT ''\x00000000000000000000000000000000'' CHECK (length(vehicle_id) = 16)', t);
        EXECUTE format('ALTER TABLE norm.%I ALTER COLUMN vehicle_id DROP DEFAULT', t);
        EXECUTE format('CREATE INDEX %I ON norm.%I (vehicle_id, observed_at)', t || '_vehicle_idx', t);
    END LOOP;
END $$;

-- ── derived ─────────────────────────────────────────────────────────────────

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['trips', 'gaps', 'events', 'daily_rollups'] LOOP
        EXECUTE format(
            'ALTER TABLE derived.%I ADD COLUMN vehicle_id BYTEA NOT NULL '
            'DEFAULT ''\x00000000000000000000000000000000'' CHECK (length(vehicle_id) = 16)', t);
        EXECUTE format('ALTER TABLE derived.%I ALTER COLUMN vehicle_id DROP DEFAULT', t);
    END LOOP;
END $$;

CREATE INDEX trips_vehicle_started_idx ON derived.trips (vehicle_id, started_at DESC);
CREATE INDEX gaps_vehicle_idx          ON derived.gaps (vehicle_id, started_at);
CREATE INDEX events_vehicle_idx        ON derived.events (vehicle_id, occurred_at DESC);

-- A rollup is a vehicle's day. The device stays in the key because a dongle moved
-- between cars mid-day must produce two rollups, not one blended row.
ALTER TABLE derived.daily_rollups DROP CONSTRAINT daily_rollups_pkey;
ALTER TABLE derived.daily_rollups ADD PRIMARY KEY (vehicle_id, device_id, day);

COMMIT;
