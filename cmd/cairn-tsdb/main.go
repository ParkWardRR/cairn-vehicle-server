// Command cairn-tsdb serves Cairn's captures from an in-memory columnar store.
//
//	cairn-tsdb -data /var/lib/cairn -sd /Volumes/CAIRN/cairn
//
// It is a derived view. On start (and on POST /reload) it copies the committed
// bundles from the server's data directory and any sealed v2 bundles from the SD
// card into a scratch CAS, decodes them twice through the production decoder,
// loads the result into an in-memory DuckDB, and checks that the decode
// reproduced and the database holds exactly what the decoder produced. Nothing
// is persisted; the raw bundles stay authoritative.
//
// One-shot modes for the terminal:
//
//	cairn-tsdb -sd /Volumes/CAIRN/cairn -verify
//	cairn-tsdb -sd /Volumes/CAIRN/cairn -query 'SELECT max(boost_psi) FROM boost'
//
// v1 trips are not read. v1 is dead.
//
// The read-only query contract is per vehicle. Every table and every v_* view
// carries vehicle_id (32 lowercase hex, the bundle manifest's binding) and is
// computed per vehicle, so a caller selects one car with
//
//	SELECT … FROM v_trim_map WHERE vehicle_id = '<hex>'
//
// and gets exactly that car's bins. A caller writing its own join must join on
// vehicle_id as well as boot_id; v_vehicles lists the cars the store holds.
// GET /snapshot?vehicle=<hex> narrows every exported table the same way.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/mtls"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

type config struct {
	dataDir, sdRoot, scratch, memory string

	// keys decrypts bundles. Built from -keystore and -keystore-master.
	keys format.KeyProvider
}

func main() {
	var (
		cfg      config
		addr     = flag.String("addr", "127.0.0.1:8480", "listen address; loopback by default because the data includes GNSS positions")
		verify   = flag.Bool("verify", false, "build, print the reproducibility report and exit non-zero on any problem")
		query    = flag.String("query", "", "run one read-only statement against the built store, print JSON and exit")
		snapshot = flag.String("snapshot", "", "build, write the snapshot archive to the given path (or - for stdout) and exit")
		serve    = flag.Bool("serve-unreproduced", false, "serve even when the build did not reproduce cleanly")
		watch    = flag.Duration("watch", 0, "poll the sources this often and rebuild when a receipt or card bundle appears (0 disables)")

		certFile     = flag.String("tls-cert", "", "server certificate (PEM)")
		keyFile      = flag.String("tls-key", "", "server private key (PEM)")
		clientCAFile = flag.String("tls-client-ca", "", "private CA that clients must chain to")
	)
	flag.StringVar(&cfg.dataDir, "data", "", "cairn-server data directory (committed bundles); optional")
	flag.StringVar(&cfg.sdRoot, "sd", "", "SD card cairn/ directory (sealed v2 bundles); optional")
	flag.StringVar(&cfg.scratch, "scratch", "", "parent directory for the throwaway CAS (default: system temp)")
	flag.StringVar(&cfg.memory, "memory", "2GB", "DuckDB memory ceiling")
	keystorePath := flag.String("keystore", "", "escrowed storage-root file (required: bundles are encrypted)")
	keystoreMaster := flag.String("keystore-master", "", "keystore master key file (required with -keystore)")
	flag.Parse()

	if *keystorePath == "" || *keystoreMaster == "" {
		fmt.Fprintln(os.Stderr, "cairn-tsdb: -keystore and -keystore-master are required; v3 bundles are encrypted")
		os.Exit(2)
	}
	ks, err := keystore.Open(*keystorePath, *keystoreMaster)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cairn-tsdb: open keystore: %v\n", err)
		os.Exit(1)
	}
	cfg.keys = ks.Provider()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if cfg.dataDir == "" && cfg.sdRoot == "" {
		fmt.Fprintln(os.Stderr, "cairn-tsdb: give at least one of -data and -sd")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := build(ctx, cfg)
	if err != nil {
		log.Error("build failed", "error", err)
		os.Exit(1)
	}

	switch {
	case *verify:
		printJSON(os.Stdout, db.Report)
		if !db.Report.OK() {
			os.Exit(1)
		}
		return

	case *query != "":
		res, err := db.Query(ctx, *query, 100000)
		if err != nil {
			log.Error("query failed", "error", err)
			os.Exit(1)
		}
		printJSON(os.Stdout, res)
		return

	case *snapshot != "":
		data, meta := db.Snapshot()
		if data == nil {
			log.Error("no snapshot available (zero bundles loaded)")
			os.Exit(1)
		}
		if *snapshot == "-" {
			os.Stdout.Write(data)
		} else {
			if err := os.WriteFile(*snapshot, data, 0o644); err != nil {
				log.Error("write snapshot", "error", err)
				os.Exit(1)
			}
			log.Info("snapshot written", "path", *snapshot, "size", len(data),
				"bundles", meta.BundleCount, "digest", meta.ContentDigest)
		}
		return
	}

	if !db.Report.OK() && !*serve {
		printJSON(os.Stderr, db.Report.Problems)
		log.Error("refusing to serve a build that did not reproduce; fix the cause or pass -serve-unreproduced")
		os.Exit(1)
	}

	tlsConfigured := *certFile != "" && *keyFile != ""
	if !tlsConfigured && !isLoopback(*addr) {
		fmt.Fprintln(os.Stderr, "cairn-tsdb: a non-loopback address requires TLS (pass -tls-cert and -tls-key)")
		os.Exit(2)
	}

	s := &server{cfg: cfg, log: log, allowUnreproduced: *serve}
	s.cur.Store(db)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("POST /query", s.query)
	mux.HandleFunc("POST /reload", s.reload)
	mux.HandleFunc("GET /snapshot", s.snapshotHandler)
	mux.HandleFunc("GET /metrics", s.metrics)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if tlsConfigured {
		mtlsCfg := mtls.Config{
			CertFile:     *certFile,
			KeyFile:      *keyFile,
			ClientCAFile: *clientCAFile,
		}
		tlsCfg, err := mtls.ServerConfig(mtlsCfg)
		if err != nil {
			log.Error("TLS setup failed", "error", err)
			os.Exit(1)
		}
		srv.TLSConfig = tlsCfg

		if !mtls.RequiresClientAuth(mtlsCfg) {
			log.Warn("TLS is enabled without client authentication; " +
				"pass -tls-client-ca so clients must present a certificate")
		}
	}

	if *watch > 0 {
		go s.watch(ctx, *watch)
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()

	log.Info("serving", "addr", *addr, "tls", tlsConfigured,
		"client_auth", mtls.RequiresClientAuth(mtls.Config{ClientCAFile: *clientCAFile}),
		"bundles", len(db.Report.Bundles), "build_ms", db.Report.BuildMS)

	if tlsConfigured {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "error", err)
		os.Exit(1)
	}
}

func build(ctx context.Context, cfg config) (*tsdb.DB, error) {
	snap, notes, err := tsdb.SnapshotSources(cfg.scratch, cfg.dataDir, cfg.sdRoot)
	if err != nil {
		return nil, err
	}
	// The decoder has read everything it needs by the time Build returns, and
	// the database holds its own copy, so the scratch CAS can go.
	defer snap.Close()

	return tsdb.Build(ctx, snap, notes, tsdb.Options{MemoryLimit: cfg.memory, Keys: cfg.keys})
}

type server struct {
	cfg               config
	log               *slog.Logger
	allowUnreproduced bool

	cur atomic.Pointer[tsdb.DB]

	// reloading serialises rebuilds. Two at once would each hold a full copy of
	// the data, which is exactly the memory spike the ceiling is there to stop.
	reloading sync.Mutex
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	db := s.cur.Load()
	if db == nil || !db.Report.OK() && !s.allowUnreproduced {
		http.Error(w, "not reproducible", http.StatusServiceUnavailable)
		return
	}
	io.WriteString(w, "ok\n")
}

func (s *server) status(w http.ResponseWriter, _ *http.Request) {
	printJSON(w, s.cur.Load().Report)
}

// query runs the request body as SQL. A body rather than a query string keeps
// long statements out of access logs and proxies.
func (s *server) query(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	res, err := s.cur.Load().Query(ctx, string(body), 100000)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, tsdb.ErrNotReadOnly) {
			code = http.StatusForbidden
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	printJSON(w, res)
}

// errUnreproduced means a rebuild finished but did not reproduce cleanly, so the
// store being served was left in place.
var errUnreproduced = errors.New("rebuild did not reproduce")

// rebuild builds a fresh store from the sources and swaps it in atomically. A
// query in flight finishes against the store it started on.
func (s *server) rebuild(ctx context.Context) (*tsdb.DB, error) {
	s.reloading.Lock()
	defer s.reloading.Unlock()

	next, err := build(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	if !next.Report.OK() && !s.allowUnreproduced {
		// Keep serving the last good store: numbers that did not reproduce are
		// worse than slightly old numbers that did.
		problems := strings.Join(next.Report.Problems, "; ")
		next.Close()
		return nil, fmt.Errorf("%w: %s", errUnreproduced, problems)
	}

	// Swap first, close later. A handler may still be mid-query on the old store;
	// DuckDB memory is native, so the garbage collector will not reclaim it and it
	// has to be closed explicitly once the longest permitted query has had time to
	// finish.
	old := s.cur.Swap(next)
	if old != nil {
		time.AfterFunc(35*time.Second, func() { old.Close() })
	}
	return next, nil
}

// snapshotHandler serves the Parquet archive. ?vehicle=<32 hex> narrows every
// table to one car; without it the archive holds every vehicle. A vehicle the
// store has no rows for is a 404 rather than an empty archive, so a caller can
// tell "no data for that car" from "that car has no trips in this table".
func (s *server) snapshotHandler(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "zstd"
	}
	vehicle := strings.ToLower(r.URL.Query().Get("vehicle"))
	if vehicle != "" && !tsdb.VehicleIDPattern.MatchString(vehicle) {
		http.Error(w, "vehicle must be 32 hex characters", http.StatusBadRequest)
		return
	}

	db := s.cur.Load()
	data, contentType, digest, meta := db.SnapshotFormat(format, vehicle)
	if data == nil {
		if vehicle != "" && len(db.Report.Bundles) > 0 {
			http.Error(w, "no data for that vehicle", http.StatusNotFound)
			return
		}
		http.Error(w, "no snapshot available", http.StatusServiceUnavailable)
		return
	}

	etag := `"` + digest + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", meta.BuiltAt.UTC().Format(http.TimeFormat))
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(data)
}

func (s *server) reload(w http.ResponseWriter, r *http.Request) {
	next, err := s.rebuild(r.Context())
	switch {
	case errors.Is(err, errUnreproduced):
		http.Error(w, err.Error(), http.StatusConflict)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		printJSON(w, next.Report)
	}
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
