// Package store persists raw bundle metadata and decode output to PostgreSQL.
//
// Idempotency lives here, and it is structural rather than careful: every write
// path either upserts on a deterministic key or deletes the bundle's rows before
// reinserting them, all inside one transaction. A worker that crashes partway
// and gets its job redelivered therefore costs a repeat, never a duplicate.
//
// Nothing in this package is on the ingest path. Ingest has no database
// dependency at all, so a Postgres outage cannot stop a device from being told
// its data is safe; it only delays the decode that follows.
package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/decode"
)

// Store is a PostgreSQL-backed store.
type Store struct {
	pool *pgxpool.Pool
}

// ErrNotFound means the requested row does not exist.
var ErrNotFound = errors.New("not found")

// Open connects to PostgreSQL.
func Open(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}

	// A homelab workload: a handful of connections is plenty, and a small pool
	// keeps a worker from monopolising a modest database.
	cfg.MaxConns = 8
	cfg.MinConns = 1
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// Pool exposes the connection pool for callers that need direct access.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// ─── devices ────────────────────────────────────────────────────────────────

// Device is the durable form of an enrolment.
type Device struct {
	DeviceID      [16]byte
	Name          string
	PublicKey     [32]byte
	KeyID         [8]byte
	EnrolledAt    time.Time
	RevokedAt     *time.Time
	RevokedReason *string
	QuotaBytes    int64
}

// UpsertDevice records or updates an enrolment.
//
// The ingest service keeps its own JSON registry so it can work without a
// database; this mirrors it for the UI and the workers to query.
func (s *Store) UpsertDevice(ctx context.Context, d Device) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO raw.devices
			(device_id, name, public_key, key_id, enrolled_at,
			 revoked_at, revoked_reason, quota_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (device_id) DO UPDATE SET
			name           = EXCLUDED.name,
			public_key     = EXCLUDED.public_key,
			key_id         = EXCLUDED.key_id,
			revoked_at     = EXCLUDED.revoked_at,
			revoked_reason = EXCLUDED.revoked_reason,
			quota_bytes    = EXCLUDED.quota_bytes
	`, d.DeviceID[:], d.Name, d.PublicKey[:], d.KeyID[:], d.EnrolledAt,
		d.RevokedAt, d.RevokedReason, d.QuotaBytes)

	if err != nil {
		return fmt.Errorf("upsert device: %w", err)
	}
	return nil
}

// ─── bundles ────────────────────────────────────────────────────────────────

// BundleCommit is everything recorded when a bundle is committed.
type BundleCommit struct {
	Manifest       *format.Manifest
	ManifestDigest [32]byte
	BytesStored    int64
	CommittedAt    time.Time

	Receipt      *format.Receipt
	ReceiptBytes []byte
}

// ErrBundleIDConflict means a bundle_id is already recorded against different
// content.
//
// bundle_id is a device-assigned ULID, so this should be impossible. If it
// happens it means a device is reusing identifiers or a ULID collided, and
// either is worth surfacing: silently discarding the record would hide a real
// anomaly and leave the bundle permanently unqueryable.
var ErrBundleIDConflict = errors.New("bundle_id already recorded against different content")

// RecordBundle writes a committed bundle's raw metadata.
//
// Idempotent on bundle_id, so a redelivered job or a reconciliation sweep
// converges rather than conflicting. The raw bytes themselves live in the
// content-addressed store; Postgres holds only what is queried.
func (s *Store) RecordBundle(ctx context.Context, c BundleCommit) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	m := c.Manifest

	counts := make(map[string]int, len(m.RecordCounts))
	for rt, n := range m.RecordCounts {
		counts[rt.String()] = int(n)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO raw.bundles (
			bundle_id, device_id, content_root, boot_id, firmware_version,
			schema_version, manifest_digest,
			capture_started_monotonic_us, capture_ended_monotonic_us,
			utc_basis_ms, utc_basis_acc_ms, first_seq, last_seq,
			recovery_state, discarded_tail_bytes, policy_version,
			bytes_stored, committed_at, record_counts,
			vehicle_id, assignment_id, device_counter, storage_key_version
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23
		)
		ON CONFLICT (bundle_id) DO NOTHING
	`,
		m.BundleID[:], m.DeviceID[:], m.ContentRoot[:], m.BootID[:], m.FirmwareVersion,
		m.SchemaVersion, c.ManifestDigest[:],
		int64(m.CaptureStartedMonotonicUS), int64(m.CaptureEndedMonotonicUS),
		int64(m.UTCBasisMS), int64(m.UTCBasisAccMS), int64(m.FirstSeq), int64(m.LastSeq),
		int16(m.RecoveryState), int64(m.DiscardedTailBytes), int16(m.PolicyVersion),
		c.BytesStored, c.CommittedAt, counts,
		m.VehicleID[:], m.AssignmentID[:], int64(m.DeviceCounter), int32(m.StorageKeyVersion),
	); err != nil {
		return fmt.Errorf("insert bundle: %w", err)
	}

	// DO NOTHING is right for a genuine retry, but it also silently swallows a
	// bundle_id reused for different content. Confirm the row that is actually
	// there is the one we meant to write.
	var storedRoot []byte
	if err := tx.QueryRow(ctx,
		`SELECT content_root FROM raw.bundles WHERE bundle_id = $1`,
		m.BundleID[:]).Scan(&storedRoot); err != nil {
		return fmt.Errorf("confirm recorded bundle: %w", err)
	}
	if !bytes.Equal(storedRoot, m.ContentRoot[:]) {
		return fmt.Errorf("%w: bundle %x is recorded with content root %x, not %x",
			ErrBundleIDConflict, m.BundleID, storedRoot, m.ContentRoot)
	}

	for _, mem := range m.Members {
		if _, err := tx.Exec(ctx, `
			INSERT INTO raw.bundle_members (content_root, name, length, sha256)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (content_root, name) DO NOTHING
		`, m.ContentRoot[:], mem.Name, int64(mem.Length), mem.SHA256[:]); err != nil {
			return fmt.Errorf("insert member %q: %w", mem.Name, err)
		}
	}

	for _, ch := range m.ChunkDescriptors {
		if _, err := tx.Exec(ctx, `
			INSERT INTO raw.bundle_chunks (content_root, chunk_index, byte_length, sha256)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT (content_root, chunk_index) DO NOTHING
		`, m.ContentRoot[:], int32(ch.Index), int32(ch.ByteLength), ch.SHA256[:]); err != nil {
			return fmt.Errorf("insert chunk %d: %w", ch.Index, err)
		}
	}

	if c.Receipt != nil {
		r := c.Receipt
		if _, err := tx.Exec(ctx, `
			INSERT INTO raw.ingest_receipts (
				receipt_id, content_root, device_id, bundle_id,
				server_key_id, ingest_schema_version, server_ingest_utc_ms, receipt_cbor
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (content_root) DO NOTHING
		`,
			r.ReceiptID[:], r.ContentRoot[:], r.DeviceID[:], r.BundleID[:],
			r.ServerKeyID[:], int16(r.IngestSchemaVersion),
			int64(r.ServerIngestUTCMS), c.ReceiptBytes,
		); err != nil {
			return fmt.Errorf("insert receipt: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// BundleForDecode is what a worker needs to decode a bundle.
type BundleForDecode struct {
	ContentRoot    [32]byte
	ManifestDigest [32]byte
	DeviceID       [16]byte
	BundleID       [16]byte
	RecoveryState  uint8
}

// LookupBundle finds a bundle by content root.
func (s *Store) LookupBundle(ctx context.Context, contentRoot [32]byte) (*BundleForDecode, error) {
	var (
		root, digest, device, bundle []byte
		recovery                     int16
	)

	err := s.pool.QueryRow(ctx, `
		SELECT content_root, manifest_digest, device_id, bundle_id, recovery_state
		FROM raw.bundles WHERE content_root = $1
	`, contentRoot[:]).Scan(&root, &digest, &device, &bundle, &recovery)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: bundle %x", ErrNotFound, contentRoot)
	}
	if err != nil {
		return nil, err
	}

	out := &BundleForDecode{RecoveryState: uint8(recovery)}
	copy(out.ContentRoot[:], root)
	copy(out.ManifestDigest[:], digest)
	copy(out.DeviceID[:], device)
	copy(out.BundleID[:], bundle)
	return out, nil
}

// ─── decode output ──────────────────────────────────────────────────────────

// SaveDecode persists a decode result, replacing any previous output for the
// same bundle.
//
// The whole thing is one transaction that deletes before it inserts. That is
// what makes a redelivered job safe and what makes reprocessing a simple
// re-run: there is no partial state a crash can leave behind, and no
// accumulation across repeats.
func (s *Store) SaveDecode(ctx context.Context, res *decode.Result) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	root := res.ContentRoot[:]

	// Provision partitions before inserting, so a bundle from an
	// unprovisioned month lands in its own partition rather than the default.
	for _, t := range resultMonths(res) {
		for _, parent := range []string{
			"norm.position_samples", "norm.imu_samples", "norm.obd_samples", "norm.boost_samples",
		} {
			if _, err := tx.Exec(ctx,
				`SELECT norm.ensure_month_partition($1::regclass, $2)`, parent, t); err != nil {
				return fmt.Errorf("ensure partition %s for %s: %w", parent, t, err)
			}
		}
	}

	// Delete, then insert. Order matters only for the foreign keys.
	for _, stmt := range []string{
		`DELETE FROM derived.gaps WHERE content_root = $1`,
		`DELETE FROM derived.events WHERE content_root = $1`,
		`DELETE FROM derived.trips WHERE content_root = $1`,
		`DELETE FROM norm.position_samples WHERE content_root = $1`,
		`DELETE FROM norm.imu_samples WHERE content_root = $1`,
		`DELETE FROM norm.obd_samples WHERE content_root = $1`,
		`DELETE FROM norm.boost_samples WHERE content_root = $1`,
		`DELETE FROM norm.device_status WHERE content_root = $1`,
		`DELETE FROM norm.state_transitions WHERE content_root = $1`,
	} {
		if _, err := tx.Exec(ctx, stmt, root); err != nil {
			return fmt.Errorf("clear previous output: %w", err)
		}
	}

	if err := insertPositions(ctx, tx, res); err != nil {
		return err
	}
	if err := insertIMU(ctx, tx, res); err != nil {
		return err
	}
	if err := insertOBD(ctx, tx, res); err != nil {
		return err
	}
	if err := insertBoost(ctx, tx, res); err != nil {
		return err
	}
	if err := insertStatus(ctx, tx, res); err != nil {
		return err
	}
	if err := insertTransitions(ctx, tx, res); err != nil {
		return err
	}

	// The trip must exist before gaps and events reference it.
	if err := insertTrip(ctx, tx, res); err != nil {
		return err
	}
	if err := insertGaps(ctx, tx, res); err != nil {
		return err
	}
	if err := insertEvents(ctx, tx, res); err != nil {
		return err
	}

	digest := res.OutputDigest()
	warnings := res.Warnings
	if warnings == nil {
		warnings = []string{}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO derived.decode_runs (
			content_root, decoder_version, decoded_at, duration_ms,
			position_samples, imu_samples, obd_samples, boost_samples, status_samples,
			transitions, gaps, events, unknown_records, warnings, output_digest
		) VALUES ($1,$2,now(),$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (content_root, decoder_version) DO UPDATE SET
			decoded_at       = now(),
			duration_ms      = EXCLUDED.duration_ms,
			position_samples = EXCLUDED.position_samples,
			imu_samples      = EXCLUDED.imu_samples,
			obd_samples      = EXCLUDED.obd_samples,
			boost_samples    = EXCLUDED.boost_samples,
			status_samples   = EXCLUDED.status_samples,
			transitions      = EXCLUDED.transitions,
			gaps             = EXCLUDED.gaps,
			events           = EXCLUDED.events,
			unknown_records  = EXCLUDED.unknown_records,
			warnings         = EXCLUDED.warnings,
			output_digest    = EXCLUDED.output_digest
	`,
		root, decode.Version, res.DurationMS,
		len(res.Positions), len(res.IMU), len(res.OBD), len(res.Boost), len(res.Status),
		len(res.Transitions), len(res.Gaps), len(res.Events),
		res.UnknownRecords, warnings, digest[:],
	); err != nil {
		return fmt.Errorf("record decode run: %w", err)
	}

	if err := refreshRollup(ctx, tx, res); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// DecodeRun is a recorded decode.
type DecodeRun struct {
	ContentRoot     [32]byte
	DecoderVersion  int
	DecodedAt       time.Time
	OutputDigest    [32]byte
	PositionSamples int
	Events          int
	Warnings        []string
}

// LookupDecodeRun finds a recorded run.
//
// Comparing output digests across runs is how a decoder change is audited: the
// same bundle at the same version must give the same digest, and a different
// version showing a different digest tells you exactly which bundles the change
// affected.
func (s *Store) LookupDecodeRun(ctx context.Context, contentRoot [32]byte, version int) (*DecodeRun, error) {
	var (
		root, digest []byte
		run          DecodeRun
	)

	err := s.pool.QueryRow(ctx, `
		SELECT content_root, decoder_version, decoded_at, output_digest,
		       position_samples, events, warnings
		FROM derived.decode_runs
		WHERE content_root = $1 AND decoder_version = $2
	`, contentRoot[:], version).Scan(
		&root, &run.DecoderVersion, &run.DecodedAt, &digest,
		&run.PositionSamples, &run.Events, &run.Warnings)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("%w: decode run %x v%d", ErrNotFound, contentRoot, version)
	}
	if err != nil {
		return nil, err
	}

	copy(run.ContentRoot[:], root)
	copy(run.OutputDigest[:], digest)
	return &run, nil
}

// CountRows returns the row count for a table, for assertions and diagnostics.
func (s *Store) CountRows(ctx context.Context, table string, contentRoot [32]byte) (int, error) {
	var n int
	q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE content_root = $1`, table)
	if err := s.pool.QueryRow(ctx, q, contentRoot[:]).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
