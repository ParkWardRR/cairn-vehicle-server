package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T, isCA bool) (der []byte, pemBytes []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Cairn Private CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConfigureLinkCarriesEverythingThePhoneNeeds(t *testing.T) {
	der, pemBytes := testCert(t, true)
	link, err := configureLink("https://cairn.example.lan:8444", "https://cairn.ts.net", "a9e6-2d47", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "cairn" || u.Host != "configure" {
		t.Fatalf("got %s://%s, want cairn://configure", u.Scheme, u.Host)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"v": "1", "url": "https://cairn.example.lan:8444", "tailnet": "https://cairn.ts.net", "code": "a9e6-2d47",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	got, err := base64.RawURLEncoding.DecodeString(q.Get("ca"))
	if err != nil || string(got) != string(der) {
		t.Fatalf("ca does not round-trip to the certificate DER: %v", err)
	}
}

func TestConfigureLinkOmitsOptionalParts(t *testing.T) {
	link, err := configureLink("https://cairn.example.lan:8444", "", "c", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(link, "tailnet=") || strings.Contains(link, "ca=") {
		t.Fatalf("optional parts leaked into %s", link)
	}
}

func TestConfigureLinkRefusesWhatThePhoneWouldRefuse(t *testing.T) {
	_, leafPEM := testCert(t, false)
	for name, c := range map[string]struct {
		url, tailnet string
		ca           []byte
	}{
		"http server url":    {"http://cairn.example.lan:8444", "", nil},
		"no host":            {"https://", "", nil},
		"bare host":          {"cairn.alpina.casa", "", nil},
		"http tailnet url":   {"https://a.lan", "http://b.ts.net", nil},
		"not a certificate":  {"https://a.lan", "", []byte("nope")},
		"certificate not CA": {"https://a.lan", "", leafPEM},
	} {
		if _, err := configureLink(c.url, c.tailnet, "c", c.ca); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestQRRenders(t *testing.T) {
	_, pemBytes := testCert(t, true)
	link, err := configureLink("https://cairn.example.lan:8444", "", "a9e6-2d47-954d-49c0-7a8b-2069-bbd6-8c28", pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	text, err := qrText(link)
	if err != nil || !strings.Contains(text, "█") {
		t.Fatalf("qrText: %v", err)
	}
	png, err := qrPNG(link)
	if err != nil || len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Fatalf("qrPNG: %v", err)
	}
}
