package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/audit"
	"github.com/ParkWardRR/Cairn/server/internal/clients"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/httpapi"
	"github.com/ParkWardRR/Cairn/server/internal/syncapi"
	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

// The app API is a second listener, never a second route on the device's.
//
// The device listener demands a client certificate during the TLS handshake. An
// iPhone has none, and — more to the point — over Tailscale it could not present
// one anyway, because `tailscale serve` terminates TLS on the host. So the app
// authenticates with per-request signatures (internal/syncapi) on a listener
// that asks the TLS layer for nothing, and the two audiences can never reach
// each other's handlers.

// stringList is a repeatable flag.
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// appFlags are the app-listener flags.
type appFlags struct {
	addr            string
	serveAddr       string
	localAddr       string
	certFile        string
	keyFile         string
	lan             stringList
	tailnet         stringList
	allowLogins     stringList
	trustServe      bool
	requireIdentity bool
	denyOther       bool
	snapshotURL     string
}

func registerAppFlags(f *appFlags) {
	flag.StringVar(&f.addr, "app-addr", "",
		"listen address for the iOS app API on the LAN, over TLS (needs -app-tls-cert/-app-tls-key or -tls-cert/-tls-key). "+
			"Plain HTTP is accepted here only on a loopback address")
	flag.StringVar(&f.serveAddr, "app-serve-addr", "",
		"loopback-only plain-HTTP listener for `tailscale serve` to front, e.g. 127.0.0.1:8445. "+
			"Served by the SAME app API instance as -app-addr, so LAN and tailnet share one log, one cursor and one set of clients")
	flag.StringVar(&f.localAddr, "app-local-addr", "",
		"loopback-only listener for same-host processes (the web UI asks it what to call each vehicle). "+
			"Never point tailscale serve or a proxy at it")
	flag.StringVar(&f.certFile, "app-tls-cert", "", "app listener certificate (default: -tls-cert)")
	flag.StringVar(&f.keyFile, "app-tls-key", "", "app listener key (default: -tls-key)")
	flag.Var(&f.lan, "lan-cidr", "CIDR counted as the LAN for the audit log (repeatable; default: private ranges)")
	flag.Var(&f.tailnet, "tailnet-cidr", "CIDR counted as the tailnet (repeatable; default: Tailscale's ranges)")
	flag.Var(&f.allowLogins, "tailnet-allow-login", "Tailscale login allowed when -require-tailnet-identity is set (repeatable)")
	flag.BoolVar(&f.trustServe, "trust-tailscale-serve", false,
		"honour Tailscale-User-* headers from a loopback peer. Only turn this on if `tailscale serve` is what connects")
	flag.BoolVar(&f.requireIdentity, "require-tailnet-identity", false,
		"tailnet-class requests must carry an allowed Tailscale identity as well as a valid app signature")
	flag.StringVar(&f.snapshotURL, "app-snapshot-url", "",
		"loopback cairn-tsdb base URL for the app's authenticated /v1/snapshot (empty disables)")
	flag.BoolVar(&f.denyOther, "app-deny-other-networks", false,
		"refuse requests from peers in neither the LAN nor the tailnet ranges")
}

// startApp opens the app API's state and starts its listener. It returns a
// shutdown function.
func startApp(f appFlags, cfg runConfig, deviceReg *devices.Registry, vehicleReg *vehicles.Registry,
	limiter *httpapi.Limiter, log *slog.Logger) (func(context.Context) error, error) {

	if f.serveAddr != "" && !syncapi.IsLoopbackAddr(f.serveAddr) {
		return nil, errors.New("-app-serve-addr must be a loopback address: it is plain HTTP, " +
			"and only tailscale serve on this host should be able to reach it")
	}

	if f.localAddr != "" && !syncapi.IsLoopbackAddr(f.localAddr) {
		return nil, errors.New("-app-local-addr must be a loopback address: it has no authentication of its own")
	}

	paths := syncapi.DataPaths(cfg.dataDir)

	clientReg, err := clients.Open(paths.Clients)
	if err != nil {
		return nil, fmt.Errorf("open client registry: %w", err)
	}
	store, err := syncapi.OpenStore(paths.SyncDir)
	if err != nil {
		return nil, fmt.Errorf("open sync log: %w", err)
	}
	auditLog, err := audit.Open(paths.AuditDir)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	instance, err := syncapi.LoadOrCreateInstanceID(paths.InstanceID)
	if err != nil {
		return nil, fmt.Errorf("instance id: %w", err)
	}

	lan, tailnet := syncapi.DefaultLAN(), syncapi.DefaultTailnet()
	if len(f.lan) > 0 {
		if lan, err = syncapi.ParsePrefixes(f.lan); err != nil {
			return nil, err
		}
	}
	if len(f.tailnet) > 0 {
		if tailnet, err = syncapi.ParsePrefixes(f.tailnet); err != nil {
			return nil, err
		}
	}

	certFile, keyFile := f.certFile, f.keyFile
	if certFile == "" {
		certFile, keyFile = cfg.certFile, cfg.keyFile
	}
	useTLS := certFile != "" && keyFile != ""
	if f.addr != "" && !useTLS && !syncapi.IsLoopbackAddr(f.addr) {
		return nil, errors.New("the app API is plain HTTP only on a loopback address " +
			"(for tailscale serve); a reachable address needs -app-tls-cert and -app-tls-key")
	}
	if f.requireIdentity && !f.trustServe {
		return nil, errors.New("-require-tailnet-identity needs -trust-tailscale-serve: " +
			"without it no request can present a trustworthy identity")
	}

	var tlsCfg *tls.Config
	spki := ""
	if useTLS {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load app TLS key pair: %w", err)
		}
		// No client certificate is requested: see the comment at the top.
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if leaf := cert.Leaf; leaf != nil {
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			spki = hex.EncodeToString(sum[:])
		} else if len(cert.Certificate) > 0 {
			if x, perr := parseLeaf(cert.Certificate[0]); perr == nil {
				sum := sha256.Sum256(x)
				spki = hex.EncodeToString(sum[:])
			}
		}
	}

	api, err := syncapi.New(syncapi.Config{
		Clients: clientReg, Vehicles: vehicleReg, Devices: deviceReg, Store: store, Audit: auditLog,
		Classifier: &syncapi.Classifier{
			LAN: lan, Tailnet: tailnet, TrustServe: f.trustServe,
			RequireIdentity: f.requireIdentity, AllowLogins: f.allowLogins, DenyOther: f.denyOther,
		},
		InstanceID:  instance,
		SPKIPin:     spki,
		AckPath:     paths.SyncDir + "/acks.json",
		SnapshotURL: f.snapshotURL,
		Limiter:     limiter,
		Log:         log,
	})
	if err != nil {
		return nil, err
	}

	// One API instance, up to two listeners. Two processes would each open the
	// sync log and corrupt it; two listeners on one instance cannot.
	newServer := func(addr string, tlsCfg *tls.Config) *http.Server {
		return &http.Server{
			Addr:              addr,
			Handler:           api.Routes(),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 20 * time.Second,
			ReadTimeout:       2 * time.Minute,
			WriteTimeout:      2 * time.Minute,
			IdleTimeout:       2 * time.Minute,
		}
	}
	serve := func(srv *http.Server, tlsOn bool) {
		go func() {
			var err error
			if tlsOn {
				err = srv.ListenAndServeTLS("", "")
			} else {
				err = srv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("app listener failed", "addr", srv.Addr, "error", err)
			}
		}()
	}

	var servers []*http.Server
	if f.localAddr != "" {
		srv := &http.Server{Addr: f.localAddr, Handler: syncapi.LocalHandler(vehicleReg),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
		serve(srv, false)
		servers = append(servers, srv)
	}
	if f.addr != "" {
		srv := newServer(f.addr, tlsCfg)
		serve(srv, useTLS)
		servers = append(servers, srv)
	}
	if f.serveAddr != "" {
		srv := newServer(f.serveAddr, nil)
		serve(srv, false)
		servers = append(servers, srv)
	}

	// Trips reach the app as trip_summary entities. They are read from the
	// analytical store (the one definition of a trip) by a publisher living in
	// this process, because the sync log is single-writer and the decode worker
	// is a different process.
	pubCtx, stopPublisher := context.WithCancel(context.Background())
	if f.snapshotURL != "" {
		go (&syncapi.TripPublisher{URL: f.snapshotURL, Store: store, Log: log}).Run(pubCtx)
	}

	log.Info("app API listening",
		"lan_addr", f.addr, "lan_tls", useTLS, "serve_addr", f.serveAddr,
		"trust_tailscale_serve", f.trustServe,
		"require_tailnet_identity", f.requireIdentity, "instance", instance)

	return func(ctx context.Context) error {
		stopPublisher()
		var first error
		for _, srv := range servers {
			if err := srv.Shutdown(ctx); err != nil && first == nil {
				first = err
			}
		}
		_ = store.Close()
		_ = auditLog.Close()
		return first
	}, nil
}

// parseLeaf returns a certificate's SubjectPublicKeyInfo.
func parseLeaf(der []byte) ([]byte, error) {
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return x.RawSubjectPublicKeyInfo, nil
}
