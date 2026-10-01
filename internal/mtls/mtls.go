// Package mtls builds the TLS configuration for the ingest listener.
//
// The listener requires and verifies a client certificate issued by the private
// CA. That is what makes the transport an authenticated channel rather than
// merely an encrypted one.
//
// What mTLS does not do is worth stating, because the v1 design conflated it:
// a valid certificate proves who opened the connection, and nothing more. It
// does not establish that the identity is still trusted — revocation lives in
// the device registry — nor that the uploaded bundle belongs to that identity,
// which is why the handlers separately bind the certificate's subject to the
// manifest's declared device.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// Config describes the server's TLS material.
type Config struct {
	// CertFile and KeyFile are the server's own certificate and private key.
	CertFile string
	KeyFile  string

	// ClientCAFile is the private CA that device certificates must chain to.
	// When empty, client authentication is disabled — only acceptable in dev.
	ClientCAFile string
}

// ErrNoServerCert means TLS was requested without a certificate.
var ErrNoServerCert = errors.New("TLS requires both a certificate and a key")

// ServerConfig builds a *tls.Config for the listener.
//
// TLS 1.2 is the floor because mbedTLS on the ESP32 supports 1.2 reliably and
// 1.3 support varies with the IDF version; requiring 1.3 would risk a device
// that cannot connect at all. The cipher list is restricted to forward-secret
// AEAD suites, which both ends support.
func ServerConfig(cfg Config) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, ErrNoServerCert
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		},
	}

	if cfg.ClientCAFile == "" {
		return tlsCfg, nil
	}

	pool, err := loadCAPool(cfg.ClientCAFile)
	if err != nil {
		return nil, err
	}

	// RequireAndVerifyClientCert, not VerifyClientCertIfGiven: an unauthenticated
	// connection must fail the handshake rather than reach a handler that might
	// forget to check.
	tlsCfg.ClientCAs = pool
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert

	return tlsCfg, nil
}

// RequiresClientAuth reports whether this configuration authenticates clients.
func RequiresClientAuth(cfg Config) bool { return cfg.ClientCAFile != "" }

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("client CA file %s contains no usable certificates", path)
	}
	return pool, nil
}
