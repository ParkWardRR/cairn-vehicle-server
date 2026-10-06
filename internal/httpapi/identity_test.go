package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/intake"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/outbox"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// The guarantee: with client authentication configured, a valid signature is
// not enough. The certificate must name the same device the manifest claims.
//
// Without this binding, a signature from any enrolled device would be accepted
// over any connection — so a device that recorded a bundle could be
// impersonated by anything holding a certificate from the same CA. The check is
// cheap and the failure is silent, which is exactly the combination that makes
// it worth a test.
//
// Runs over real TLS rather than by calling the handler directly, because the
// thing being tested is that r.TLS.PeerCertificates is consulted at all.
func TestClientIdentityBinding(t *testing.T) {
	ca, caKey := newTestCA(t)

	deviceID := testbundle.DeviceID()
	matching := hex.EncodeToString(deviceID[:])

	cases := []struct {
		name     string
		cn       string
		wantCode int
		why      string
	}{
		{
			name:     "matching common name is accepted",
			cn:       matching,
			wantCode: http.StatusOK,
			why:      "a certificate naming the manifest's device should be accepted",
		},
		{
			name:     "different device is refused",
			cn:       "ffffffffffffffffffffffffffffffff",
			wantCode: http.StatusForbidden,
			why: "a certificate from a different device was accepted — a valid " +
				"signature over any connection is exactly what this binding exists " +
				"to prevent",
		},
		{
			name:     "non-hex common name is refused",
			cn:       "not-a-device-id",
			wantCode: http.StatusForbidden,
			why:      "a certificate with a nonsense common name was accepted",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, client := newTLSEnv(t, ca, caKey, tc.cn)

			b, err := testbundle.Build(testbundle.Default())
			if err != nil {
				t.Fatalf("build bundle: %v", err)
			}

			req, err := http.NewRequest(http.MethodPost,
				ts.URL+"/api/v2/bundles/offer", bytes.NewReader(b.ManifestBytes))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(SignatureHeader, hex.EncodeToString(b.Signature))

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tc.wantCode {
				t.Errorf("status %d, want %d: %s\n  body: %s",
					resp.StatusCode, tc.wantCode, tc.why, body)
			}
		})
	}
}

// A connection with no client certificate at all must be refused when client
// authentication is required, rather than falling back to trusting the manifest.
func TestNoClientCertificateIsRefused(t *testing.T) {
	ca, caKey := newTestCA(t)
	ts, _ := newTLSEnv(t, ca, caKey, hex.EncodeToString(func() []byte {
		id := testbundle.DeviceID()
		return id[:]
	}()))

	// A client that trusts the CA but presents nothing.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}

	resp, err := client.Get(ts.URL + "/api/v2/health")
	if err == nil {
		resp.Body.Close()
		t.Fatal("a connection with no client certificate succeeded; client " +
			"authentication is not being enforced")
	}
}

// ── harness ─────────────────────────────────────────────────────────────────

func newTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cairn Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	cn string, server bool) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		// An IP SAN, not a DNS name: Go validates 127.0.0.1 against
		// IPAddresses and ignores DNSNames for a literal address. The same
		// trap deploy/make-certs.sh documents for the device.
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTLSEnv starts a server with client authentication required and returns a
// client presenting a certificate with the given common name.
func newTLSEnv(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey,
	clientCN string) (*httptest.Server, *http.Client) {
	t.Helper()
	root := t.TempDir()

	store, err := cas.Open(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(root, "receipts"),
		KeyPath: filepath.Join(root, "keys", "receipt.seed"),
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := devices.Open(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	regs, err := testbundle.OpenRegistries(root)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := intake.New(intake.Config{
		CAS: store, Receipts: rec, Registry: reg, Outbox: ob,
		OfferDir: filepath.Join(root, "offers"),
		Vehicles: regs.Vehicles, Counters: regs.Counters, Keys: regs.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := testbundle.DeviceKey()
	if _, err := reg.Enroll(testbundle.DeviceID(), "test-recorder", pub, 0); err != nil {
		t.Fatal(err)
	}

	api := New(Config{
		Intake: svc, Receipts: rec, Registry: reg, Outbox: ob,
		Log:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		RequireClientCert: true,
	})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	ts := httptest.NewUnstartedServer(api.Routes())
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{issue(t, ca, caKey, "127.0.0.1", true)},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{issue(t, ca, caKey, clientCN, false)},
			},
		},
	}

	return ts, client
}
