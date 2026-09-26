-- 001_init.sql
-- Core schema for Cairn: devices, uploads, trips, samples, events, places, tags, derivations.

BEGIN;

-- PostGIS
CREATE EXTENSION IF NOT EXISTS postgis;

-- ─── devices ────────────────────────────────────────────────────────────────

CREATE TABLE devices (
    id              TEXT        PRIMARY KEY,
    public_key      TEXT        NOT NULL,
    device_metadata JSONB,
    last_seen_at    TIMESTAMPTZ,
    firmware_version TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── uploads ────────────────────────────────────────────────────────────────

CREATE TABLE uploads (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     TEXT        NOT NULL REFERENCES devices(id),
    content_hash  TEXT        NOT NULL UNIQUE,
    upload_state  TEXT        NOT NULL DEFAULT 'initiated'
        CHECK (upload_state IN ('initiated', 'uploading', 'completed', 'failed')),
    receipt_id    UUID,
    storage_path  TEXT,
    file_size     BIGINT,
    resume_offset BIGINT      NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_uploads_device_id   ON uploads(device_id);
CREATE INDEX idx_uploads_upload_state ON uploads(upload_state);
CREATE INDEX idx_uploads_created_at  ON uploads(created_at);

-- ─── trips ──────────────────────────────────────────────────────────────────

CREATE TABLE trips (
    id              TEXT             PRIMARY KEY, -- ULID
    device_id       TEXT             NOT NULL REFERENCES devices(id),
    started_at      TIMESTAMPTZ      NOT NULL,
    ended_at        TIMESTAMPTZ,
    upload_id       UUID             REFERENCES uploads(id),
    distance_m      DOUBLE PRECISION,
    duration_s      INTEGER,
    start_location  GEOGRAPHY(POINT, 4326),
    end_location    GEOGRAPHY(POINT, 4326),
    summary         JSONB,
    bundle_hash     TEXT             NOT NULL,
    created_at      TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE INDEX idx_trips_device_id  ON trips(device_id);
CREATE INDEX idx_trips_started_at ON trips(started_at);
CREATE INDEX idx_trips_ended_at   ON trips(ended_at);
CREATE INDEX idx_trips_upload_id  ON trips(upload_id);

-- ─── location_samples ───────────────────────────────────────────────────────

CREATE TABLE location_samples (
    id            BIGSERIAL        PRIMARY KEY,
    trip_id       TEXT             NOT NULL REFERENCES trips(id),
    timestamp_ms  BIGINT           NOT NULL,
    latitude      DOUBLE PRECISION NOT NULL,
    longitude     DOUBLE PRECISION NOT NULL,
    altitude_m    DOUBLE PRECISION,
    speed_mps     DOUBLE PRECISION,
    heading_deg   DOUBLE PRECISION,
    fix_quality   SMALLINT,
    satellites    SMALLINT,
    hdop          DOUBLE PRECISION,
    accuracy_m    DOUBLE PRECISION,
    location      GEOGRAPHY(POINT, 4326)
);

CREATE INDEX idx_location_samples_trip_id      ON location_samples(trip_id);
CREATE INDEX idx_location_samples_timestamp_ms ON location_samples(trip_id, timestamp_ms);
CREATE INDEX idx_location_samples_location     ON location_samples USING GIST (location);

-- ─── motion_samples ─────────────────────────────────────────────────────────

CREATE TABLE motion_samples (
    id                BIGSERIAL PRIMARY KEY,
    trip_id           TEXT      NOT NULL REFERENCES trips(id),
    window_start_ms   BIGINT,
    window_duration_ms INTEGER,
    accel_peak_x_mg   SMALLINT,
    accel_peak_y_mg   SMALLINT,
    accel_peak_z_mg   SMALLINT,
    accel_rms_mg      SMALLINT,
    gyro_peak_dps     SMALLINT,
    variance          SMALLINT,
    flags             SMALLINT
);

CREATE INDEX idx_motion_samples_trip_id ON motion_samples(trip_id);

-- ─── trip_events ────────────────────────────────────────────────────────────

CREATE TABLE trip_events (
    id            BIGSERIAL   PRIMARY KEY,
    trip_id       TEXT        NOT NULL REFERENCES trips(id),
    event_type    TEXT        NOT NULL,
    timestamp_at  TIMESTAMPTZ NOT NULL,
    location      GEOGRAPHY(POINT, 4326),
    metadata      JSONB
);

CREATE INDEX idx_trip_events_trip_id      ON trip_events(trip_id);
CREATE INDEX idx_trip_events_event_type   ON trip_events(event_type);
CREATE INDEX idx_trip_events_timestamp_at ON trip_events(timestamp_at);

-- ─── places ─────────────────────────────────────────────────────────────────

CREATE TABLE places (
    id         UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT             NOT NULL,
    location   GEOGRAPHY(POINT, 4326) NOT NULL,
    radius_m   DOUBLE PRECISION NOT NULL DEFAULT 100,
    created_at TIMESTAMPTZ      NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ      NOT NULL DEFAULT now()
);

CREATE INDEX idx_places_location ON places USING GIST (location);

-- ─── trip_tags ──────────────────────────────────────────────────────────────

CREATE TABLE trip_tags (
    trip_id TEXT NOT NULL REFERENCES trips(id),
    tag     TEXT NOT NULL,
    PRIMARY KEY (trip_id, tag)
);

-- ─── derivations ────────────────────────────────────────────────────────────

CREATE TABLE derivations (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    trip_id           TEXT        NOT NULL REFERENCES trips(id),
    algorithm         TEXT,
    algorithm_version TEXT,
    output_hash       TEXT,
    metadata          JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_derivations_trip_id ON derivations(trip_id);

COMMIT;
