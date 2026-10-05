-- Cairn v2 schema, layer 1 of 3: raw.
--
-- Raw data is authoritative. Everything in the normalized and derived layers is
-- a pure function of what is recorded here plus a decoder version, so a decoder
-- bug can be fixed and every affected trip re-derived without re-uploading a
-- byte. That property is the whole reason the layers are separate.
--
-- Nothing in this layer is ever updated in place. A bundle row is written once,
-- at commit, and never mutated.
--
-- Fresh migrations: these do not ALTER the v1 schema in deploy/migrations/.
-- v1 and v2 can coexist in one database while v2 proves out.

BEGIN;

CREATE SCHEMA IF NOT EXISTS raw;
CREATE SCHEMA IF NOT EXISTS norm;
CREATE SCHEMA IF NOT EXISTS derived;

CREATE EXTENSION IF NOT EXISTS postgis;

-- ── devices ─────────────────────────────────────────────────────────────────
--
-- The enrolment registry's durable form. Ingest reads its own JSON copy so that
-- a database outage cannot stop a device from being receipted; this table is
-- what the UI and the workers query.
CREATE TABLE raw.devices (
    device_id       BYTEA PRIMARY KEY CHECK (length(device_id) = 16),
    name            TEXT        NOT NULL,
    public_key      BYTEA       NOT NULL CHECK (length(public_key) = 32),
    key_id          BYTEA       NOT NULL CHECK (length(key_id) = 8),
    enrolled_at     TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  TEXT,
    quota_bytes     BIGINT      NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),

    -- Rare or evolving per-device metadata. A jsonb escape hatch, deliberately
    -- not a generic EAV table: everything queried often has its own column.
    metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb
);

COMMENT ON COLUMN raw.devices.revoked_at IS
    'Revocation lives here and in the ingest registry. A certificate may remain '
    'cryptographically valid, so revocation is a separate check, not a TLS concern.';

-- ── bundles ─────────────────────────────────────────────────────────────────
--
-- One row per committed bundle. Written once at commit; never updated.
CREATE TABLE raw.bundles (
    -- The operational handle: a ULID assigned by the device at bundle open.
    bundle_id       BYTEA PRIMARY KEY CHECK (length(bundle_id) = 16),

    device_id       BYTEA       NOT NULL REFERENCES raw.devices (device_id),

    -- Identity of the data. Deduplication and idempotency both key on this.
    content_root    BYTEA       NOT NULL CHECK (length(content_root) = 32),

    boot_id         BYTEA       NOT NULL CHECK (length(boot_id) = 16),
    firmware_version TEXT       NOT NULL,
    schema_version  SMALLINT    NOT NULL,
    manifest_digest BYTEA       NOT NULL CHECK (length(manifest_digest) = 32),

    -- Ordering truth. Monotonic microseconds, never wall-clock.
    capture_started_monotonic_us BIGINT NOT NULL,
    capture_ended_monotonic_us   BIGINT NOT NULL,

    -- UTC is an annotation carrying its own uncertainty, not an index.
    utc_basis_ms     BIGINT     NOT NULL,
    utc_basis_acc_ms INTEGER    NOT NULL,

    first_seq       BIGINT      NOT NULL,
    last_seq        BIGINT      NOT NULL,

    -- 0 clean, 1 recovered tail, 2 salvaged. A recovered tail is the normal
    -- outcome of a power cut and not a defect; salvaged means the offline tool
    -- resynchronised past damage.
    recovery_state  SMALLINT    NOT NULL CHECK (recovery_state BETWEEN 0 AND 2),
    discarded_tail_bytes BIGINT NOT NULL DEFAULT 0,

    -- Which detection policy produced this bundle, so a retune is attributable.
    policy_version  SMALLINT    NOT NULL,

    bytes_stored    BIGINT      NOT NULL,
    committed_at    TIMESTAMPTZ NOT NULL,

    record_counts   JSONB       NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT bundles_capture_ordered
        CHECK (capture_ended_monotonic_us >= capture_started_monotonic_us),
    CONSTRAINT bundles_seq_ordered
        CHECK (last_seq >= first_seq),

    -- The reviews asked for both. bundle_id is unique as the primary key; this
    -- is the second: one device cannot hold two bundles of identical content.
    CONSTRAINT bundles_device_content_unique UNIQUE (device_id, content_root)
);

CREATE INDEX bundles_device_committed_idx
    ON raw.bundles (device_id, committed_at DESC);
CREATE INDEX bundles_content_root_idx
    ON raw.bundles (content_root);

-- ── bundle members ──────────────────────────────────────────────────────────
--
-- The files a bundle is made of, keyed by content root rather than bundle_id:
-- identical content is one set of members however many times it is offered.
CREATE TABLE raw.bundle_members (
    content_root BYTEA  NOT NULL,
    name         TEXT   NOT NULL,
    length       BIGINT NOT NULL CHECK (length >= 0),
    sha256       BYTEA  NOT NULL CHECK (length(sha256) = 32),

    PRIMARY KEY (content_root, name)
);

COMMENT ON TABLE raw.bundle_members IS
    'sha256 is the object id in the content-addressed store. The raw bytes live '
    'there, not in Postgres: the database is a query system, not a file transport.';

-- ── bundle chunks ───────────────────────────────────────────────────────────
--
-- The transfer partition, recorded for audit. Chunks and members are
-- independent partitions of the same byte stream (spec section 6.1), so a
-- member may span chunks and vice versa.
CREATE TABLE raw.bundle_chunks (
    content_root BYTEA   NOT NULL,
    chunk_index  INTEGER NOT NULL CHECK (chunk_index >= 0),
    byte_length  INTEGER NOT NULL CHECK (byte_length > 0),
    sha256       BYTEA   NOT NULL CHECK (length(sha256) = 32),

    PRIMARY KEY (content_root, chunk_index)
);

-- ── receipts ────────────────────────────────────────────────────────────────
--
-- The server's own copy of what it promised a device. Retained longer than the
-- raw payload: it is the proof of delivery, and the device's right to prune
-- rests on it.
CREATE TABLE raw.ingest_receipts (
    receipt_id     BYTEA PRIMARY KEY CHECK (length(receipt_id) = 16),

    -- Unique: idempotency is keyed on content root, so one content root earns
    -- exactly one receipt, forever.
    content_root   BYTEA       NOT NULL UNIQUE CHECK (length(content_root) = 32),

    device_id      BYTEA       NOT NULL,
    bundle_id      BYTEA       NOT NULL,
    server_key_id  BYTEA       NOT NULL CHECK (length(server_key_id) = 8),
    ingest_schema_version SMALLINT NOT NULL,
    server_ingest_utc_ms  BIGINT   NOT NULL,

    -- The exact signed bytes. Stored verbatim so the receipt can be re-served
    -- or re-verified without re-encoding, which is where a canonical-encoding
    -- bug would otherwise hide.
    receipt_cbor   BYTEA       NOT NULL,

    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ingest_receipts_device_idx
    ON raw.ingest_receipts (device_id, server_ingest_utc_ms DESC);

-- ── audit ───────────────────────────────────────────────────────────────────
--
-- Receipt verification failures, certificate changes, exports and
-- administrative access. The reviews asked for these to be auditable; a table
-- makes them queryable rather than merely logged.
CREATE TABLE raw.audit_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind        TEXT        NOT NULL,
    device_id   BYTEA,
    actor       TEXT,
    detail      JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_events_kind_time_idx
    ON raw.audit_events (kind, occurred_at DESC);

COMMIT;
