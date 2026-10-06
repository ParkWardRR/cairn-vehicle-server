// Command cairn-worker drains the ingest outbox, decoding committed bundles
// into the normalized and derived layers.
//
// A separate process from cairn-server on purpose. Ingest validates, stores,
// receipts and returns with no database dependency at all; this is where the
// expensive, fallible work happens. A crash loop here, a decoder bug or a
// Postgres outage therefore cannot stop a device from being told its data is
// safe — it only delays the derived view.
//
//	cairn-worker -data /var/lib/cairn -dsn postgres://cairn@localhost/cairn
//
// Reprocessing after a decoder fix is a queued bulk operation, not a request:
//
//	cairn-worker -data ... -dsn ... -reprocess-all
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/decode"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/mqtt"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/outbox"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/store"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/worker"
)

func main() {
	var (
		dataDir = flag.String("data", "/var/lib/cairn", "root directory shared with cairn-server")
		dsn     = flag.String("dsn", "", "PostgreSQL connection string (required)")

		mqttAddr   = flag.String("mqtt", "", "MQTT broker host:port (optional)")
		mqttPrefix = flag.String("mqtt-prefix", "cairn", "MQTT topic prefix")

		pollInterval = flag.Duration("poll", 5*time.Second, "how often an idle worker checks for work")
		maxAttempts  = flag.Int("max-attempts", 5, "retries before a job is parked as failed")

		once         = flag.Bool("once", false, "drain the outbox once and exit")
		reprocess    = flag.String("reprocess", "", "enqueue one bundle by hex content root")
		reprocessAll = flag.Bool("reprocess-all", false, "enqueue every committed bundle for re-decoding")

		receiptKey = flag.String("receipt-key", "",
			"Ed25519 seed file for receipts; defaults to <data>/keys/receipt.seed")
		keystoreMaster = flag.String("keystore-master", "",
			"keystore master key file (required: bundles are encrypted); keep it outside the backed-up data directory")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(runConfig{
		dataDir:        *dataDir,
		dsn:            *dsn,
		mqttAddr:       *mqttAddr,
		mqttPrefix:     *mqttPrefix,
		pollInterval:   *pollInterval,
		maxAttempts:    *maxAttempts,
		once:           *once,
		reprocess:      *reprocess,
		reprocessAll:   *reprocessAll,
		receiptKey:     *receiptKey,
		keystoreMaster: *keystoreMaster,
		log:            log,
	}); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

type runConfig struct {
	dataDir        string
	dsn            string
	mqttAddr       string
	mqttPrefix     string
	pollInterval   time.Duration
	maxAttempts    int
	once           bool
	reprocess      string
	reprocessAll   bool
	receiptKey     string
	keystoreMaster string
	log            *slog.Logger
}

func run(cfg runConfig) error {
	if cfg.dsn == "" {
		return errors.New("-dsn is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	casStore, err := cas.Open(filepath.Join(cfg.dataDir, "cas"))
	if err != nil {
		return fmt.Errorf("open raw store: %w", err)
	}

	if cfg.keystoreMaster == "" {
		return errors.New("-keystore-master is required: bundles are encrypted and the worker decrypts them")
	}
	ks, err := keystore.Open(filepath.Join(cfg.dataDir, "keystore.json"), cfg.keystoreMaster)
	if err != nil {
		return fmt.Errorf("open keystore: %w", err)
	}

	queue, err := outbox.Open(filepath.Join(cfg.dataDir, "outbox"))
	if err != nil {
		return fmt.Errorf("open outbox: %w", err)
	}

	// The same ledger directory the server writes to. Two processes appending
	// to the same daily file is safe: every entry is a single write of a
	// complete line, and O_APPEND makes that atomic for the sizes involved.
	book, err := ledger.Open(filepath.Join(cfg.dataDir, "ledger"))
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer book.Close()

	db, err := store.Open(ctx, cfg.dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// The registry and receipt store are read-only here: they are ingest's
	// durable artifacts, and the worker only mirrors them into Postgres.
	registry, err := devices.Open(filepath.Join(cfg.dataDir, "devices.json"))
	if err != nil {
		return fmt.Errorf("open device registry: %w", err)
	}

	receiptKeyPath := filepath.Join(cfg.dataDir, "keys", "receipt.seed")
	if cfg.receiptKey != "" {
		receiptKeyPath = cfg.receiptKey
	}
	receiptStore, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(cfg.dataDir, "receipts"),
		KeyPath: receiptKeyPath,
	})
	if err != nil {
		return fmt.Errorf("open receipt store: %w", err)
	}

	// Administrative modes enqueue and exit, so a bulk re-derive does not need
	// the worker stopped.
	switch {
	case cfg.reprocess != "":
		return enqueueOne(ctx, queue, db, cfg)
	case cfg.reprocessAll:
		return enqueueAll(ctx, queue, db, cfg)
	}

	publisher := mqtt.New(mqtt.Config{
		Addr:        cfg.mqttAddr,
		ClientID:    "cairn-worker",
		TopicPrefix: cfg.mqttPrefix,
	})
	defer publisher.Close()

	var pub worker.Publisher
	if publisher.Enabled() {
		pub = publisher
		if err := publisher.PublishAvailability(ctx, true); err != nil {
			// Not fatal. MQTT is an optional edge; a drive must not depend on a
			// broker being reachable.
			cfg.log.Warn("announcing availability failed", "error", err)
		}
	}

	w := worker.New(worker.Config{
		Outbox:       queue,
		Store:        db,
		Decoder:      decode.New(casStore, ks.Provider()),
		Ledger:       book,
		Publish:      pub,
		Log:          cfg.log,
		PollInterval: cfg.pollInterval,
		MaxAttempts:  cfg.maxAttempts,
		CAS:          casStore,
		Registry:     registry,
		Receipts:     receiptStore,
	})

	if cfg.once {
		n, err := w.DrainOnce(ctx)
		if err != nil {
			return err
		}
		cfg.log.Info("drained outbox once", "jobs", n, "parked", len(w.Parked()))
		if parked := w.Parked(); len(parked) > 0 {
			return fmt.Errorf("%d job(s) parked after repeated failures", len(parked))
		}
		return nil
	}

	// Keep the backlog figure current for the dashboard.
	if publisher.Enabled() {
		go publishBacklog(ctx, queue, publisher, cfg.log)
	}

	return w.Run(ctx)
}

func publishBacklog(ctx context.Context, q *outbox.Queue, p *mqtt.Publisher, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	last := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := q.PendingCount()
			if err != nil {
				log.Warn("reading the backlog failed", "error", err)
				continue
			}
			// Only publish on change: a retained value that never changes needs
			// no repetition, and a quiet topic is easier to reason about.
			if n == last {
				continue
			}
			if err := p.PublishBacklog(ctx, n); err != nil {
				log.Warn("publishing the backlog failed", "error", err)
				continue
			}
			last = n
		}
	}
}

func enqueueOne(ctx context.Context, q *outbox.Queue, db *store.Store, cfg runConfig) error {
	raw, err := hex.DecodeString(cfg.reprocess)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("content root must be 64 hex characters, got %q", cfg.reprocess)
	}
	var root [32]byte
	copy(root[:], raw)

	if err := worker.Reprocess(ctx, q, db, root); err != nil {
		return err
	}

	fmt.Printf("enqueued %s for re-decoding\n", cfg.reprocess)
	return nil
}

// enqueueAll queues every committed bundle for re-decoding.
//
// This is the operation that makes a decoder fix tractable: raw stays
// authoritative, so correcting the decoder and re-deriving everything costs
// nothing but time, and no device has to re-upload a byte.
func enqueueAll(ctx context.Context, q *outbox.Queue, db *store.Store, cfg runConfig) error {
	rows, err := db.Pool().Query(ctx, `
		SELECT content_root FROM raw.bundles ORDER BY committed_at
	`)
	if err != nil {
		return fmt.Errorf("list bundles: %w", err)
	}
	defer rows.Close()

	var roots [][32]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var root [32]byte
		copy(root[:], raw)
		roots = append(roots, root)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, root := range roots {
		if err := worker.Reprocess(ctx, q, db, root); err != nil {
			return fmt.Errorf("enqueue %x: %w", root, err)
		}
	}

	fmt.Printf("enqueued %d bundle(s) for re-decoding at decoder version %d\n",
		len(roots), decode.Version)
	return nil
}
