// Package worker drains the ingest outbox, decoding committed bundles into the
// normalized and derived layers.
//
// It runs as a separate process from ingest, which is the point: a worker crash
// loop, a decoder bug or a Postgres outage must not stop a device from being
// receipted. The device's data is already safe by the time a job reaches here.
//
// Failure handling follows from that. A decode failure is recorded and retried
// with backoff; after enough attempts it is parked as failed and the worker
// moves on. Nothing about it rejects the raw bundle, because by then the device
// may well have pruned its copy on the strength of a receipt it legitimately
// holds.
package worker

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/decode"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/outbox"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/store"
)

// Publisher announces derived events. Optional: a publisher failure must never
// fail a decode, because the samples are the valuable part and an unannounced
// event can be announced later.
type Publisher interface {
	Publish(ctx context.Context, ev PublishableEvent) error
}

// PublishableEvent is the semantic state a consumer cares about.
type PublishableEvent struct {
	EventID    string
	DeviceID   string
	Kind       string
	OccurredAt time.Time
	TripID     string
	Lat, Lon   *float64
	Detail     map[string]any
}

// Config configures a Worker.
type Config struct {
	Outbox  *outbox.Queue
	Store   *store.Store
	Decoder *decode.Decoder
	Publish Publisher
	Log     *slog.Logger

	// CAS, Registry and Receipts are the durable artifacts ingest already
	// wrote. The worker reads them to mirror raw metadata into Postgres, which
	// is how ingest stays free of any database dependency.
	CAS      *cas.Store
	Registry *devices.Registry
	Receipts *receipts.Store

	// Ledger records decode outcomes. Optional: a nil ledger means no record,
	// never a failed decode — the same rule ingest follows, because an audit
	// trail that can fail the work it audits is the wrong shape.
	Ledger *ledger.Ledger

	// PollInterval is how often an idle worker checks for work.
	PollInterval time.Duration

	// MaxAttempts bounds retries before a job is parked as failed.
	MaxAttempts int
}

// Worker drains the outbox.
type Worker struct {
	cfg Config
	log *slog.Logger

	// attempts counts failures per outbox sequence, in memory. A restart resets
	// the counts, which is deliberate: a worker restarted after a fix should try
	// again rather than inherit an earlier verdict.
	mu       sync.Mutex
	attempts map[uint64]int
}

func New(cfg Config) *Worker {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	return &Worker{cfg: cfg, log: cfg.Log, attempts: make(map[uint64]int)}
}

// Run drains the outbox until the context is cancelled.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("decode worker starting",
		"decoder_version", decode.Version,
		"poll_interval", w.cfg.PollInterval,
		"max_attempts", w.cfg.MaxAttempts)

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	for {
		// Drain whatever is pending before waiting again, so a backlog clears
		// at full speed rather than one job per tick.
		if n, err := w.DrainOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			w.log.Error("drain failed", "error", err)
		} else if n > 0 {
			w.log.Info("drained outbox", "jobs", n)
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// DrainOnce processes every currently pending job, returning how many
// succeeded.
func (w *Worker) DrainOnce(ctx context.Context) (int, error) {
	pending, err := w.cfg.Outbox.Pending()
	if err != nil {
		return 0, fmt.Errorf("read outbox: %w", err)
	}

	done := 0
	for i := range pending {
		if err := ctx.Err(); err != nil {
			return done, err
		}

		entry := pending[i]
		if w.shouldSkip(entry.Seq) {
			continue
		}

		if err := w.process(ctx, entry); err != nil {
			w.recordFailure(entry, err)
			continue
		}

		// Acknowledge only after the decode is committed. An unacknowledged
		// entry is simply redelivered, so a crash between decode and ack costs
		// a repeat — which is safe, because the decode is idempotent.
		if err := w.cfg.Outbox.Ack(entry.Seq); err != nil {
			w.log.Error("decode committed but acknowledging the job failed",
				"seq", entry.Seq, "bundle", entry.BundleID, "error", err)
			continue
		}

		w.clearFailure(entry.Seq)

		// After the ack, so the entry means "decoded and acknowledged" rather
		// than "decoded, possibly to be redelivered".
		w.record(ledger.Entry{
			Event:       ledger.EventDecodeOK,
			BundleID:    entry.BundleID,
			DeviceID:    entry.DeviceID,
			ContentRoot: entry.ContentRoot,
		})

		done++
	}

	return done, nil
}

// process records a bundle's raw metadata, decodes it, and persists the result.
//
// The raw metadata is written here rather than by ingest, which is what keeps
// ingest free of any database dependency. The authoritative copy of the bundle
// is already in the content-addressed store and the receipt is already issued;
// this is the database catching up, and it can lag without anything being lost.
func (w *Worker) process(ctx context.Context, entry outbox.Entry) error {
	contentRoot, err := parse32(entry.ContentRoot)
	if err != nil {
		return fmt.Errorf("content root %q: %w", entry.ContentRoot, err)
	}
	manifestDigest, err := parse32(entry.ManifestDigest)
	if err != nil {
		return fmt.Errorf("manifest digest %q: %w", entry.ManifestDigest, err)
	}

	started := time.Now()

	if err := w.recordRaw(ctx, entry, contentRoot, manifestDigest); err != nil {
		return fmt.Errorf("record raw metadata: %w", err)
	}

	res, err := w.cfg.Decoder.Decode(ctx, decode.Input{
		ContentRoot:    contentRoot,
		ManifestDigest: manifestDigest,
	})
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if err := w.cfg.Store.SaveDecode(ctx, res); err != nil {
		return fmt.Errorf("persist decode: %w", err)
	}

	digest := res.OutputDigest()
	w.log.Info("decoded bundle",
		"bundle", entry.BundleID,
		"device", entry.DeviceID,
		"positions", len(res.Positions),
		"imu", len(res.IMU),
		"obd", len(res.OBD),
		"gaps", len(res.Gaps),
		"events", len(res.Events),
		"warnings", len(res.Warnings),
		"output_digest", hex.EncodeToString(digest[:8]),
		"took_ms", time.Since(started).Milliseconds())

	for _, warning := range res.Warnings {
		w.log.Warn("decode warning", "bundle", entry.BundleID, "detail", warning)
	}

	// Publishing comes last and its failure is tolerated: the samples are the
	// valuable output, and an event not yet announced can be announced later.
	if w.cfg.Publish != nil {
		w.publishEvents(ctx, res)
	}

	return nil
}

// recordRaw mirrors the committed bundle into the raw layer.
//
// Idempotent, so a redelivered job converges. The device and receipt rows come
// from the same durable artifacts ingest already wrote, so this cannot invent
// anything ingest did not record.
func (w *Worker) recordRaw(
	ctx context.Context,
	entry outbox.Entry,
	contentRoot, manifestDigest [32]byte,
) error {
	// Already recorded: a retry or a reprocess job, nothing to mirror.
	if _, err := w.cfg.Store.LookupBundle(ctx, contentRoot); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}

	if w.cfg.Registry == nil || w.cfg.Receipts == nil {
		return errors.New("cannot record raw metadata without the device registry and receipt store")
	}

	manifestBytes, err := w.cfg.CAS.GetVerified(manifestDigest)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	// The device must exist before the bundle's foreign key will accept it.
	dev, err := w.cfg.Registry.Lookup(manifest.DeviceID)
	if err != nil {
		// A revoked device's past bundles are still valid data, so fall back to
		// the full list rather than refusing to record history.
		dev = nil
		for _, candidate := range w.cfg.Registry.List() {
			if id, idErr := candidate.ID(); idErr == nil && id == manifest.DeviceID {
				dev = candidate
				break
			}
		}
		if dev == nil {
			return fmt.Errorf("device %x is not enrolled", manifest.DeviceID)
		}
	}

	pub, err := dev.PublicKey()
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}

	d := store.Device{
		Name:       dev.Name,
		EnrolledAt: dev.EnrolledAt,
		QuotaBytes: dev.QuotaBytes,
	}
	copy(d.DeviceID[:], manifest.DeviceID[:])
	copy(d.PublicKey[:], pub)
	d.KeyID = format.DeviceKeyID(pub)
	if dev.Revoked {
		revokedAt := dev.RevokedAt
		reason := dev.RevokedReason
		d.RevokedAt = &revokedAt
		d.RevokedReason = &reason
	}

	if err := w.cfg.Store.UpsertDevice(ctx, d); err != nil {
		return err
	}

	receipt, receiptBytes, err := w.cfg.Receipts.Lookup(contentRoot)
	if err != nil {
		// A committed bundle always has a receipt; its absence means something
		// is wrong worth reporting rather than papering over.
		return fmt.Errorf("no receipt on file for a committed bundle: %w", err)
	}

	return w.cfg.Store.RecordBundle(ctx, store.BundleCommit{
		Manifest:       manifest,
		ManifestDigest: manifestDigest,
		BytesStored:    entry.BytesStored,
		CommittedAt:    entry.EnqueuedAt,
		Receipt:        receipt,
		ReceiptBytes:   receiptBytes,
	})
}

func (w *Worker) publishEvents(ctx context.Context, res *decode.Result) {
	tripID := ""
	if res.Trip != nil {
		tripID = hex.EncodeToString(res.Trip.TripID[:])
	}

	for i := range res.Events {
		e := &res.Events[i]

		err := w.cfg.Publish.Publish(ctx, PublishableEvent{
			EventID:    hex.EncodeToString(e.EventID[:]),
			DeviceID:   hex.EncodeToString(res.DeviceID[:]),
			Kind:       e.Kind,
			OccurredAt: e.OccurredAt,
			TripID:     tripID,
			Lat:        e.Lat,
			Lon:        e.Lon,
			Detail:     e.Detail,
		})
		if err != nil {
			w.log.Warn("publishing an event failed; the decode stands",
				"kind", e.Kind, "error", err)
		}
	}
}

// ─── retry accounting ───────────────────────────────────────────────────────

func (w *Worker) shouldSkip(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.attempts[seq] >= w.cfg.MaxAttempts
}

// record appends to the ledger, swallowing failures deliberately.
func (w *Worker) record(e ledger.Entry) {
	if w.cfg.Ledger == nil {
		return
	}
	_ = w.cfg.Ledger.Append(e)
}

func (w *Worker) recordFailure(entry outbox.Entry, err error) {
	w.mu.Lock()
	w.attempts[entry.Seq]++
	n := w.attempts[entry.Seq]
	w.mu.Unlock()

	// A parked job is left unacknowledged on purpose: the raw bundle is intact,
	// so a later worker with a fixed decoder can pick it up. Dropping it would
	// be the one genuinely destructive option.
	if n >= w.cfg.MaxAttempts {
		w.log.Error("parking job after repeated failures; the raw bundle is unaffected "+
			"and can be reprocessed once the cause is fixed",
			"seq", entry.Seq, "bundle", entry.BundleID, "attempts", n, "error", err)

		// Only a parked job gets a ledger entry. A retry is not an outcome —
		// recording every attempt would bury the one entry that matters under
		// transient noise, and the job may still succeed.
		w.record(ledger.Entry{
			Event:       ledger.EventDecodeFailed,
			BundleID:    entry.BundleID,
			DeviceID:    entry.DeviceID,
			ContentRoot: entry.ContentRoot,
			Reason: fmt.Sprintf("parked after %d attempts: %v; the raw bundle "+
				"is intact and can be reprocessed", n, err),
		})
		return
	}

	w.log.Warn("decode failed; will retry",
		"seq", entry.Seq, "bundle", entry.BundleID, "attempt", n, "error", err)
}

func (w *Worker) clearFailure(seq uint64) {
	w.mu.Lock()
	delete(w.attempts, seq)
	w.mu.Unlock()
}

// Parked returns the outbox sequences currently parked as failed, for
// diagnostics and for an operator deciding what to reprocess.
func (w *Worker) Parked() []uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()

	var out []uint64
	for seq, n := range w.attempts {
		if n >= w.cfg.MaxAttempts {
			out = append(out, seq)
		}
	}
	return out
}

// ─── reprocessing ───────────────────────────────────────────────────────────

var ErrUnknownBundle = errors.New("no committed bundle with that content root")

// Reprocess enqueues a bundle for decoding again.
//
// A queued job, not a synchronous endpoint. That matters for two reasons: a
// re-derive of a long trip must not block a request, and reprocessing every
// bundle after a decoder fix is a bulk operation that belongs in a queue the
// worker drains at its own pace.
func Reprocess(ctx context.Context, q *outbox.Queue, s *store.Store, contentRoot [32]byte) error {
	bundle, err := s.LookupBundle(ctx, contentRoot)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("%w: %x", ErrUnknownBundle, contentRoot)
		}
		return err
	}

	return q.Append(outbox.Entry{
		BundleID:       hex.EncodeToString(bundle.BundleID[:]),
		DeviceID:       hex.EncodeToString(bundle.DeviceID[:]),
		ContentRoot:    hex.EncodeToString(bundle.ContentRoot[:]),
		ManifestDigest: hex.EncodeToString(bundle.ManifestDigest[:]),
	})
}

func parse32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("%d bytes, want 32", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
