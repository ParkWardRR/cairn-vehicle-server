-- Cairn v2 schema, layer 3 of 3: derived.
--
-- Recomputable application concepts. Everything here is a pure function of the
-- raw layer plus a decoder version, which is what lets a decoder bug be fixed
-- and every affected trip re-derived with no re-upload.
--
-- Because it is recomputable, nothing here is precious. The decode worker is
-- free to delete and rebuild a bundle's derived rows, and that is exactly how
-- reprocessing works.

BEGIN;

-- ── decode runs ─────────────────────────────────────────────────────────────
--
-- One row per (content_root, decoder_version). This is the table that makes
-- reproducibility checkable rather than merely claimed: output_digest is a hash
-- over the derived output, so re-decoding the same raw bundle at the same
-- decoder version must produce the same digest. A changed digest at an
-- unchanged version means the decoder is not deterministic, which is a bug.
CREATE TABLE derived.decode_runs (
    content_root    BYTEA   NOT NULL,
    decoder_version INTEGER NOT NULL,

    decoded_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms     INTEGER     NOT NULL,

    position_samples INTEGER NOT NULL DEFAULT 0,
    imu_samples      INTEGER NOT NULL DEFAULT 0,
    obd_samples      INTEGER NOT NULL DEFAULT 0,
    status_samples   INTEGER NOT NULL DEFAULT 0,
    transitions      INTEGER NOT NULL DEFAULT 0,
    gaps             INTEGER NOT NULL DEFAULT 0,
    events           INTEGER NOT NULL DEFAULT 0,
    unknown_records  INTEGER NOT NULL DEFAULT 0,

    -- Non-fatal problems found while decoding. A decode that hits trouble still
    -- records what it managed; it never rejects the raw bundle, which is already
    -- committed and receipted.
    warnings        JSONB   NOT NULL DEFAULT '[]'::jsonb,

    output_digest   BYTEA   NOT NULL CHECK (length(output_digest) = 32),

    PRIMARY KEY (content_root, decoder_version)
);

COMMENT ON TABLE derived.decode_runs IS
    'A decoder upgrade is visible as a second row at a higher version. Comparing '
    'output_digest across versions shows exactly which bundles a decoder change '
    'altered, and which it left alone.';

-- ── trips ───────────────────────────────────────────────────────────────────
--
-- Derived, not captured. A trip is an interpretation of samples, so it carries
-- the decoder version that produced it.
CREATE TABLE derived.trips (
    trip_id         BYTEA PRIMARY KEY CHECK (length(trip_id) = 16),

    content_root    BYTEA       NOT NULL,
    device_id       BYTEA       NOT NULL,
    decoder_version INTEGER     NOT NULL,

    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ NOT NULL,
    duration_s      INTEGER     NOT NULL,

    distance_m      DOUBLE PRECISION NOT NULL,

    start_geom      GEOGRAPHY(POINT, 4326),
    end_geom        GEOGRAPHY(POINT, 4326),

    -- The route as captured. Null when no sample carried a valid fix.
    route_geom      GEOGRAPHY(LINESTRING, 4326),

    max_speed_mps   REAL,
    avg_speed_mps   REAL,

    sample_count    INTEGER     NOT NULL DEFAULT 0,

    -- How much of the trip had no valid position. Surfaced rather than hidden:
    -- a trip with a marked gap is useful, a route interpolated across one is not.
    gap_count       INTEGER     NOT NULL DEFAULT 0,
    gap_duration_s  INTEGER     NOT NULL DEFAULT 0,

    -- Mirrors the bundle, so a recovered-tail trip is identifiable without a join.
    recovery_state  SMALLINT    NOT NULL DEFAULT 0,

    summary         JSONB       NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT trips_time_ordered CHECK (ended_at >= started_at)
);

CREATE INDEX trips_device_started_idx
    ON derived.trips (device_id, started_at DESC);
CREATE INDEX trips_content_root_idx
    ON derived.trips (content_root);
CREATE INDEX trips_route_geom_idx
    ON derived.trips USING GIST (route_geom);

-- ── trip segments ───────────────────────────────────────────────────────────
--
-- A trip split into drive and stop phases. A traffic stop is a segment within
-- one trip, not a trip boundary — which is the distinction the reviews said v1
-- got wrong by finalizing on a single stop timer.
CREATE TABLE derived.trip_segments (
    trip_id       BYTEA    NOT NULL REFERENCES derived.trips (trip_id) ON DELETE CASCADE,
    segment_index INTEGER  NOT NULL,

    kind          TEXT     NOT NULL CHECK (kind IN ('drive', 'stop', 'gap')),
    started_at    TIMESTAMPTZ NOT NULL,
    ended_at      TIMESTAMPTZ NOT NULL,
    duration_s    INTEGER  NOT NULL,
    distance_m    DOUBLE PRECISION NOT NULL DEFAULT 0,

    PRIMARY KEY (trip_id, segment_index)
);

-- ── events ──────────────────────────────────────────────────────────────────
--
-- Semantic occurrences, derived. event_id is deterministic — a hash over
-- (content_root, kind, seq) — so re-deriving produces the same identity and a
-- downstream consumer can deduplicate without coordination.
CREATE TABLE derived.events (
    event_id      BYTEA PRIMARY KEY CHECK (length(event_id) = 16),

    content_root  BYTEA       NOT NULL,
    device_id     BYTEA       NOT NULL,
    trip_id       BYTEA       REFERENCES derived.trips (trip_id) ON DELETE SET NULL,

    kind          TEXT        NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    seq           BIGINT      NOT NULL,

    geom          GEOGRAPHY(POINT, 4326),
    detail        JSONB       NOT NULL DEFAULT '{}'::jsonb,

    -- Set once the event has been published to MQTT, so publishing is
    -- at-least-once with a visible record rather than fire-and-forget.
    published_at  TIMESTAMPTZ
);

CREATE INDEX events_device_time_idx
    ON derived.events (device_id, occurred_at DESC);
CREATE INDEX events_content_root_idx
    ON derived.events (content_root);
CREATE INDEX events_kind_time_idx
    ON derived.events (kind, occurred_at DESC);

-- The publisher's work queue: unpublished events, oldest first.
CREATE INDEX events_unpublished_idx
    ON derived.events (occurred_at)
    WHERE published_at IS NULL;

-- ── GNSS gaps ───────────────────────────────────────────────────────────────
--
-- Recorded absence. The device writes an explicit gap record rather than
-- leaving a silent hole, and it survives into the derived layer so a map can
-- render a discontinuity instead of joining across it.
CREATE TABLE derived.gaps (
    content_root  BYTEA       NOT NULL,
    seq           BIGINT      NOT NULL,

    device_id     BYTEA       NOT NULL,
    trip_id       BYTEA       REFERENCES derived.trips (trip_id) ON DELETE SET NULL,

    started_at    TIMESTAMPTZ NOT NULL,
    duration_ms   BIGINT      NOT NULL,
    expected_samples INTEGER  NOT NULL,

    -- 1 no fix, 2 receiver reset, 3 powered down, 4 tunnel/obstruction,
    -- 5 time jump
    cause         SMALLINT    NOT NULL,

    PRIMARY KEY (content_root, seq)
);

CREATE INDEX gaps_device_time_idx
    ON derived.gaps (device_id, started_at DESC);

-- ── daily rollups ───────────────────────────────────────────────────────────
--
-- Dashboard cards read these rather than scanning raw telemetry. The reviews
-- were explicit that repeated full scans for a summary card is the wrong shape.
CREATE TABLE derived.daily_rollups (
    device_id   BYTEA NOT NULL,
    day         DATE  NOT NULL,

    trip_count      INTEGER NOT NULL DEFAULT 0,
    distance_m      DOUBLE PRECISION NOT NULL DEFAULT 0,
    duration_s      BIGINT  NOT NULL DEFAULT 0,
    max_speed_mps   REAL,
    event_count     INTEGER NOT NULL DEFAULT 0,
    gap_duration_s  INTEGER NOT NULL DEFAULT 0,

    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (device_id, day)
);

-- ── retention ───────────────────────────────────────────────────────────────
--
-- An explicit policy, as the reviews asked. Raw high-resolution location is the
-- most sensitive data here, so how long it is kept is a recorded decision
-- rather than an accident of whatever nobody deleted.
CREATE TABLE derived.retention_policy (
    id                      INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),

    -- How long full-resolution position samples are kept before compaction.
    position_full_days      INTEGER NOT NULL DEFAULT 400,

    -- How long the content-addressed raw objects are kept. Longer than the
    -- normalized layer, because raw is what makes re-derivation possible.
    raw_objects_days        INTEGER NOT NULL DEFAULT 1095,

    -- Receipts outlive everything: they are the proof of delivery.
    receipts_days           INTEGER NOT NULL DEFAULT 3650,

    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO derived.retention_policy (id) VALUES (1)
    ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE derived.retention_policy IS
    'Defaults are deliberately generous. Shortening them is a decision to make '
    'knowingly, since raw is the only thing that makes a decoder fix recoverable.';

COMMIT;
