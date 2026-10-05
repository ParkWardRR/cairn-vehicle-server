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
	"github.com/ParkWardRR/Cairn/server/internal/counters"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/enroll"
	"github.com/ParkWardRR/Cairn/server/internal/httpapi"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/keystore"
	"github.com/ParkWardRR/Cairn/server/internal/ledger"
	"github.com/ParkWardRR/Cairn/server/internal/mtls"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

func main() {
	var (
		dataDir = flag.String("data", "/var/lib/cairn", "root directory for raw storage, receipts and queues")
		addr    = flag.String("addr", ":8443", "listen address")

		certFile     = flag.String("tls-cert", "", "server certificate (PEM)")
		keyFile      = flag.String("tls-key", "", "server private key (PEM)")
		clientCAFile = flag.String("tls-client-ca", "", "private CA that device certificates must chain to")

		receiptKey = flag.String("receipt-key", "", "Ed25519 seed file for signing receipts (created if absent)")

		firmwareDir = flag.String("firmware-dir", "",
			"directory of signed update descriptors and images; empty disables "+
				"the OTA endpoints entirely")

		dev = flag.Bool("dev", false,
			"development mode: permit plaintext HTTP. Never use in production.")

		enroll     = flag.String("enroll", "", "enrol a device: hex device ID (requires -enroll-key)")
		enrollKey  = flag.String("enroll-key", "", "hex Ed25519 public key for -enroll")
		enrollName = flag.String("enroll-name", "", "friendly name for -enroll")
		enrollRoot = flag.String("enroll-root", "",
			"hex 32-byte device storage root to escrow with -enroll (required: bundles are encrypted)")
		enrollKeyVersion = flag.Uint("enroll-key-version", 1, "storage_key_version of -enroll-root")
		keystoreMaster   = flag.String("keystore-master", "",
			"keystore master key file; keep it OUTSIDE the backed-up data directory. "+
				"Defaults to <data>/keys/keystore.master, which defeats that separation and is only acceptable for development")
		revoke    = flag.String("revoke", "", "revoke a device: hex device ID")
		revokeWhy = flag.String("revoke-reason", "revoked by operator", "reason recorded with -revoke")
		list      = flag.Bool("list-devices", false, "list enrolled devices and exit")

		printEnrollKey = flag.Bool("print-enroll-key", false,
			"print the server's device-enrolment public key (creating it on first use) and exit; "+
				"pin the value in firmware as CAIRN_SERVER_ENROLL_PUBKEY_HEX")
		printReceiptKey = flag.Bool("print-receipt-key", false,
			"print the receipt-signing public key and exit (this is the value a device pins)")
	)
	var app appFlags
	registerAppFlags(&app)
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
		enrollRoot:      *enrollRoot,
		enrollKeyVer:    uint32(*enrollKeyVersion),
		keystoreMaster:  *keystoreMaster,
		app:             app,
		revoke:          *revoke,
		revokeWhy:       *revokeWhy,
		list:            *list,
		firmwareDir:     *firmwareDir,
		printReceiptKey: *printReceiptKey,
		printEnrollKey:  *printEnrollKey,
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

	enroll       string
	enrollKey    string
	enrollName   string
	enrollRoot   string
	enrollKeyVer uint32

	keystoreMaster string

	app         appFlags
	revoke      string
	revokeWhy   string
	list        bool
	firmwareDir string

	printReceiptKey bool
	printEnrollKey  bool

	log *slog.Logger
}

// resolveReceiptKeyPath decides which Ed25519 seed signs receipts.
//
// Deliberately independent of dev mode. An earlier version skipped the data
// directory default under -dev, so a directory holding a perfectly good
// receipt.seed was ignored and receipts.Open minted an ephemeral key instead.
// The resulting failure is remote from its cause: -print-receipt-key reports the
// persistent key, an operator pins it in firmware, and then every receipt the
// running server issues carries a different key, so the device rejects all of
// them and never prunes — with both sides behaving exactly as written.
//
// Dev mode's job is to relax the transport, not to rotate the trust anchor. An
// ephemeral key remains reachable by pointing -receipt-key somewhere under
// /tmp, which at least states the intent.
func resolveReceiptKeyPath(explicit, dataDir string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(dataDir, "keys", "receipt.seed")
}

func run(cfg runConfig) error {
	registryPath := filepath.Join(cfg.dataDir, "devices.json")

	registry, err := devices.Open(registryPath)
	if err != nil {
		return fmt.Errorf("open device registry: %w", err)
	}

	// The v3 binding state. All three are required by intake; none is optional,
	// because a nil here would silently switch off a security check.
	vehicleReg, err := vehicles.Open(
		filepath.Join(cfg.dataDir, "vehicles.json"),
		filepath.Join(cfg.dataDir, "keys", "vehicles.key"))
	if err != nil {
		return fmt.Errorf("open vehicle registry: %w", err)
	}
	counterGuard, err := counters.Open(filepath.Join(cfg.dataDir, "counters.json"))
	if err != nil {
		return fmt.Errorf("open counter guard: %w", err)
	}
	masterPath := cfg.keystoreMaster
	if masterPath == "" {
		masterPath = filepath.Join(cfg.dataDir, "keys", "keystore.master")
		cfg.log.Warn("keystore master key is inside the data directory; a backup of that directory " +
			"would carry the key to every escrowed storage root — pass -keystore-master pointing elsewhere")
	}
	keyStore, err := keystore.Open(filepath.Join(cfg.dataDir, "keystore.json"), masterPath)
	if err != nil {
		return fmt.Errorf("open keystore: %w", err)
	}

	// Administrative modes run and exit, so enrolment never needs the service
	// to be stopped.
	switch {
	case cfg.printEnrollKey:
		// Created on first use: a device can only seal to a key someone has
		// pinned, so the key has to exist before the first enrolment attempt.
		key, created, err := enroll.LoadOrCreateServerKey(enroll.ServerKeyPath(cfg.dataDir), keyStore)
		if err != nil {
			return fmt.Errorf("enrolment key: %w", err)
		}
		fmt.Println(hex.EncodeToString(key.PublicKey().Bytes()))
		if created {
			fmt.Fprintln(os.Stderr, "created a new enrolment key (private half wrapped under the keystore master key)")
		}
		fmt.Fprintln(os.Stderr, "pin this in firmware/cairn-v2/include/secrets.h as CAIRN_SERVER_ENROLL_PUBKEY_HEX")
		return nil
	case cfg.list:
		return listDevices(registry)
	case cfg.enroll != "":
		return enrollDevice(registry, keyStore, counterGuard, cfg)
	case cfg.revoke != "":
		return revokeDevice(registry, cfg)
	}

	// Printing the receipt key is also administrative, but it needs the key
	// store rather than the device registry, so it runs after that is opened.

	store, err := cas.Open(filepath.Join(cfg.dataDir, "cas"))
	if err != nil {
		return fmt.Errorf("open raw store: %w", err)
	}

	receiptKeyPath := resolveReceiptKeyPath(cfg.receiptKey, cfg.dataDir)

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

	// The lifecycle ledger. On disk rather than in PostgreSQL on purpose:
	// ingest has no database dependency, and making the audit trail a database
	// write would quietly give it one.
	book, err := ledger.Open(filepath.Join(cfg.dataDir, "ledger"))
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer book.Close()

	svc, err := intake.New(intake.Config{
		CAS:      store,
		Receipts: receiptStore,
		Registry: registry,
		Outbox:   queue,
		Ledger:   book,
		OfferDir: filepath.Join(cfg.dataDir, "offers"),
		Vehicles: vehicleReg,
		Counters: counterGuard,
		Keys:     keyStore,
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
		FirmwareDir:       cfg.firmwareDir,
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

	// The app API, when enabled, runs beside the device listener on its own
	// port. It has its own limiter: a phone retrying must never spend a
	// dongle's allowance.
	var stopApp func(context.Context) error
	if cfg.app.addr != "" || cfg.app.serveAddr != "" {
		stopApp, err = startApp(cfg.app, cfg, registry, vehicleReg, httpapi.NewLimiter(240, 4), cfg.log)
		if err != nil {
			return fmt.Errorf("start app API: %w", err)
		}
	}

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
		if stopApp != nil {
			_ = stopApp(shutdownCtx)
		}
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

func enrollDevice(registry *devices.Registry, keys *keystore.Store, guard *counters.Guard, cfg runConfig) error {
	if cfg.enrollRoot == "" {
		return errors.New("-enroll requires -enroll-root (hex 32-byte storage root): " +
			"v3 bundles are encrypted and the server cannot decode a device it holds no root for")
	}
	rootRaw, err := hex.DecodeString(cfg.enrollRoot)
	if err != nil || len(rootRaw) != 32 {
		return fmt.Errorf("storage root must be 64 hex characters (32 bytes)")
	}
	var root [32]byte
	copy(root[:], rootRaw)

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

	if err := keys.Put(d.DeviceID, cfg.enrollKeyVer, root); err != nil {
		return fmt.Errorf("escrow storage root: %w", err)
	}

	// A re-enrolled device must resume above the counters it already spent.
	floor, err := guard.Resume(d.DeviceID)
	if err != nil {
		return fmt.Errorf("counter floor: %w", err)
	}

	fmt.Printf("enrolled %s (%s) with key ID %s\n", d.DeviceID, d.Name, d.KeyIDHex)
	fmt.Printf("storage root escrowed as key version %d\n", cfg.enrollKeyVer)
	fmt.Printf("counter floor: the device must start its bundle counter above %d\n", floor)
	fmt.Println("next: assign it to a vehicle (cairn-admin assign) — bundles from an unassigned device are refused")
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
