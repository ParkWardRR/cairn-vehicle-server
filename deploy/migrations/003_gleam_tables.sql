-- 003_gleam_tables.sql
-- Tables for the Gleam trip-orchestrator: lifecycle projection, quality flags,
-- reprocess queue, notifications, and automation rules.

BEGIN;

-- ─── trip_lifecycle ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS trip_lifecycle (
    id              BIGSERIAL    PRIMARY KEY,
    trip_id         TEXT         NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    state           TEXT         NOT NULL,
    transitioned_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    metadata        JSONB,
    UNIQUE(trip_id, state)
);

CREATE INDEX IF NOT EXISTS idx_trip_lifecycle_trip ON trip_lifecycle(trip_id);

-- ─── trip_quality_flags ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS trip_quality_flags (
    id          BIGSERIAL    PRIMARY KEY,
    trip_id     TEXT         NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    flag_type   TEXT         NOT NULL,
    severity    TEXT         NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    details     JSONB,
    flagged_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    UNIQUE(trip_id, flag_type)
);

CREATE INDEX IF NOT EXISTS idx_quality_flags_trip ON trip_quality_flags(trip_id);

-- ─── reprocess_queue ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS reprocess_queue (
    id            BIGSERIAL    PRIMARY KEY,
    trip_id       TEXT         NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    reason        TEXT         NOT NULL,
    priority      INT          NOT NULL DEFAULT 0,
    queued_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_reprocess_queue_pending
    ON reprocess_queue(queued_at) WHERE completed_at IS NULL;

-- ─── notifications ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS notifications (
    id         BIGSERIAL    PRIMARY KEY,
    severity   TEXT         NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    category   TEXT         NOT NULL,
    title      TEXT         NOT NULL,
    body       TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    read_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_notifications_unread
    ON notifications(created_at) WHERE read_at IS NULL;

-- ─── automation_rules ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS automation_rules (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL,
    trigger_type TEXT        NOT NULL,
    condition    JSONB       NOT NULL DEFAULT '{}',
    action       JSONB       NOT NULL,
    enabled      BOOLEAN     NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
