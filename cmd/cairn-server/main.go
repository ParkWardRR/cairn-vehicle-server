// Command cairn-server is the v2 raw-first ingest service.
//
// It validates a manifest-first, content-addressed upload, stores the raw
// bundle durably, issues a signed receipt and enqueues decode work. That is
// the whole job. Decoding, trip building, event detection and MQTT publishing
// happen later, driven by the outbox, so request latency never scales with
// trip length and a decoder bug can never fail an upload.
//
// Everything it needs to receipt a bundle lives on the filesystem. There is
// deliberately no database dependency on the intake path: a Postgres outage
// must not stop a device from being told its data is safe.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/httpapi"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/mtls"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
)

func main() {
	var (
		dataDir = flag.String("data", "/var/lib/cairn", "root directory for raw storage, receipts and queues")
		addr    = flag.String("addr", ":8443", "listen address")

		certFile     = flag.String("tls-cert", "", "server certificate (PEM)")
		keyFile      = flag.String("tls-key", "", "server private key (PEM)")
		clientCAFile = flag.String("tls-client-ca", "", "private CA that device certificates must chain to")

		receiptKey = flag.String("receipt-key", "", "Ed25519 seed file for signing receipts (created if absent)")

		dev = flag.Bool("dev", false,
			"development mode: permit plaintext HTTP and an ephemeral receipt key. Never use in production.")

		enroll     = flag.String("enroll", "", "enrol a device: hex device ID (requires -enroll-key)")
		enrollKey  = flag.String("enroll-key", "", "hex Ed25519 public key for -enroll")
		enrollName = flag.String("enroll-name", "", "friendly name for -enroll")
		revoke     = flag.String("revoke", "", "revoke a device: hex device ID")
		revokeWhy  = flag.String("revoke-reason", "revoked by operator", "reason recorded with -revoke")
		list       = flag.Bool("list-devices", false, "list enrolled devices and exit")

		printReceiptKey = flag.Bool("print-receipt-key", false,
			"print the receipt-signing public key and exit (this is the value a device pins)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(runConfig{
		dataDir:         *dataDir,
		addr:            *addr,
		certFile:        *certFile,
		keyFile:         *keyFile,
		clientCAFile:    *clientCAFile,
		receiptKey:      *receiptKey,
		dev:             *dev,
		enroll:          *enroll,
		enrollKey:       *enrollKey,
		enrollName:      *enrollName,
		revoke:          *revoke,
		revokeWhy:       *revokeWhy,
		list:            *list,
		printReceiptKey: *printReceiptKey,
		log:             log,
	}); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

type runConfig struct {
	dataDir      string
	addr         string
	certFile     string
	keyFile      string
	clientCAFile string
	receiptKey   string
	dev          bool

	enroll     string
	enrollKey  string
	enrollName string
	revoke     string
	revokeWhy  string
	list       bool

	printReceiptKey bool

	log *slog.Logger
}

func run(cfg runConfig) error {
	registryPath := filepath.Join(cfg.dataDir, "devices.json")

	registry, err := devices.Open(registryPath)
	if err != nil {
		return fmt.Errorf("open device registry: %w", err)
	}

	// Administrative modes run and exit, so enrolment never needs the service
	// to be stopped.
	switch {
	case cfg.list:
		return listDevices(registry)
	case cfg.enroll != "":
		return enrollDevice(registry, cfg)
	case cfg.revoke != "":
		return revokeDevice(registry, cfg)
	}

	// Printing the receipt key is also administrative, but it needs the key
	// store rather than the device registry, so it runs after that is opened.

	store, err := cas.Open(filepath.Join(cfg.dataDir, "cas"))
	if err != nil {
		return fmt.Errorf("open raw store: %w", err)
	}

	receiptKeyPath := cfg.receiptKey
	if receiptKeyPath == "" && !cfg.dev {
		receiptKeyPath = filepath.Join(cfg.dataDir, "keys", "receipt.seed")
	}

	receiptStore, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(cfg.dataDir, "receipts"),
		KeyPath: receiptKeyPath,
		Dev:     cfg.dev,
	})
	if err != nil {
		return fmt.Errorf("open receipt store: %w", err)
	}

	// A device pins this value and refuses to delete anything that is not
	// signed by it, so an operator needs a way to read it that does not involve
	// the server already running and reachable.
	if cfg.printReceiptKey {
		keyID := receiptStore.KeyID()
		fmt.Println(receiptStore.PublicKeyHex())
		fmt.Fprintf(os.Stderr, "key ID %s\n", hex.EncodeToString(keyID[:]))
		fmt.Fprintf(os.Stderr,
			"pin this in firmware/cairn-v2/include/secrets.h as "+
				"CAIRN_SERVER_RECEIPT_KEY_HEX\n")
		return nil
	}

	queue, err := outbox.Open(filepath.Join(cfg.dataDir, "outbox"))
	if err != nil {
		return fmt.Errorf("open outbox: %w", err)
	}

	svc, err := intake.New(intake.Config{
		CAS:      store,
		Receipts: receiptStore,
		Registry: registry,
		Outbox:   queue,
		OfferDir: filepath.Join(cfg.dataDir, "offers"),
	})
	if err != nil {
		return fmt.Errorf("create intake service: %w", err)
	}

	tlsConfigured := cfg.certFile != "" && cfg.keyFile != ""
	if !tlsConfigured && !cfg.dev {
		return errors.New("TLS is required: pass -tls-cert and -tls-key, or -dev for plaintext")
	}

	mtlsCfg := mtls.Config{
		CertFile:     cfg.certFile,
		KeyFile:      cfg.keyFile,
		ClientCAFile: cfg.clientCAFile,
	}
	requireClientCert := mtls.RequiresClientAuth(mtlsCfg)

	if tlsConfigured && !requireClientCert {
		cfg.log.Warn("TLS is enabled without client authentication; " +
			"pass -tls-client-ca so devices must present a certificate")
	}

	// A device returning home with a week of backlog is legitimate traffic, so
	// the burst allowance is generous; the limit exists to contain a device
	// stuck in a retry loop, not to shape normal syncs.
	limiter := httpapi.NewLimiter(120, 2)

	api := httpapi.New(httpapi.Config{
		Intake:            svc,
		Receipts:          receiptStore,
		Registry:          registry,
		Outbox:            queue,
		Limiter:           limiter,
		Log:               cfg.log,
		RequireClientCert: requireClientCert,
	})

	srv := &http.Server{
		Addr:    cfg.addr,
		Handler: api.Routes(),

		// A parked car on weak Wi-Fi is slow, not malicious, so the read
		// timeout is forgiving. There is still a cap, because an abandoned
		// connection must not hold resources indefinitely.
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	if tlsConfigured {
		tlsCfg, err := mtls.ServerConfig(mtlsCfg)
		if err != nil {
			return fmt.Errorf("build TLS config: %w", err)
		}
		srv.TLSConfig = tlsCfg
	}

	keyID := receiptStore.KeyID()
	cfg.log.Info("cairn ingest starting",
		"addr", cfg.addr,
		"data", cfg.dataDir,
		"tls", tlsConfigured,
		"client_auth", requireClientCert,
		"receipt_key_id", hex.EncodeToString(keyID[:]),
		"receipt_public_key", receiptStore.PublicKeyHex(),
		"devices", len(registry.List()))

	if cfg.dev {
		cfg.log.Warn("development mode: do not use for real vehicle data")
	}

	// Housekeeping: reclaim committed offer records and idle rate-limit
	// buckets. Neither is required for correctness, which is why both are
	// background sweeps rather than work done on the request path.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go housekeep(ctx, svc, limiter, cfg.log)

	errCh := make(chan error, 1)
	go func() {
		var err error
		if tlsConfigured {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		cfg.log.Info("shutting down")

		// Give an in-flight upload a chance to finish and be receipted. Cutting
		// one off mid-commit is safe — the device simply retries — but letting
		// it complete saves the retry.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func housekeep(ctx context.Context, svc *intake.Service, limiter *httpapi.Limiter, log *slog.Logger) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Only offers whose content root is already receipted are swept, so
			// an interrupted transfer is never discarded.
			if swept, err := svc.SweepOffers(24 * time.Hour); err != nil {
				log.Warn("sweeping offer records failed", "error", err)
			} else if swept > 0 {
				log.Info("reclaimed committed offer records", "count", swept)
			}

			limiter.Sweep(6 * time.Hour)
		}
	}
}

// ─── administrative modes ───────────────────────────────────────────────────

func listDevices(registry *devices.Registry) error {
	list := registry.List()
	if len(list) == 0 {
		fmt.Println("no devices enrolled")
		return nil
	}

	for _, d := range list {
		status := "active"
		if d.Revoked {
			status = "REVOKED: " + d.RevokedReason
		}
		quota := "unlimited"
		if d.QuotaBytes > 0 {
			quota = fmt.Sprintf("%d bytes", d.QuotaBytes)
		}
		fmt.Printf("%s  %-20s key=%s quota=%s  %s\n",
			d.DeviceID, d.Name, d.KeyIDHex, quota, status)
	}
	return nil
}

func enrollDevice(registry *devices.Registry, cfg runConfig) error {
	if cfg.enrollKey == "" {
		return errors.New("-enroll requires -enroll-key (hex Ed25519 public key)")
	}

	idRaw, err := hex.DecodeString(cfg.enroll)
	if err != nil || len(idRaw) != 16 {
		return fmt.Errorf("device ID must be 32 hex characters (16 bytes), got %q", cfg.enroll)
	}
	var deviceID [16]byte
	copy(deviceID[:], idRaw)

	keyRaw, err := hex.DecodeString(cfg.enrollKey)
	if err != nil || len(keyRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d hex characters (%d bytes)",
			ed25519.PublicKeySize*2, ed25519.PublicKeySize)
	}

	name := cfg.enrollName
	if name == "" {
		name = "device-" + cfg.enroll[:8]
	}

	d, err := registry.Enroll(deviceID, name, ed25519.PublicKey(keyRaw), 0)
	if err != nil {
		return fmt.Errorf("enrol device: %w", err)
	}

	fmt.Printf("enrolled %s (%s) with key ID %s\n", d.DeviceID, d.Name, d.KeyIDHex)
	return nil
}

func revokeDevice(registry *devices.Registry, cfg runConfig) error {
	idRaw, err := hex.DecodeString(cfg.revoke)
	if err != nil || len(idRaw) != 16 {
		return fmt.Errorf("device ID must be 32 hex characters (16 bytes), got %q", cfg.revoke)
	}
	var deviceID [16]byte
	copy(deviceID[:], idRaw)

	if err := registry.Revoke(deviceID, cfg.revokeWhy); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}

	fmt.Printf("revoked %s: %s\n", cfg.revoke, cfg.revokeWhy)
	fmt.Println("note: the device's certificate may still be valid; revocation is enforced at the registry")
	return nil
}
