package offloadclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/syncapi"
)

// RelayError is a refusal from the server's relay.
type RelayError struct {
	Status  int
	Code    string
	Message string
}

func (e *RelayError) Error() string {
	return fmt.Sprintf("server said %d %s: %s", e.Status, e.Code, e.Message)
}

// Permanent reports whether retrying the same request can never succeed: the
// bundle is refused (scope, assignment, quarantine, a forged manifest) and stays on
// the dongle. 409 (re-read the chunk) and 429/5xx (back off) are retryable.
func (e *RelayError) Permanent() bool {
	switch e.Status {
	case 409, 429:
		return false
	}
	return e.Status >= 400 && e.Status < 500
}

// HTTPRelay talks to the server's app API, signing every request.
type HTTPRelay struct {
	BaseURL  string
	ClientID string
	Key      *ecdsa.PrivateKey
	// SPKIPin is the SHA-256 of the server leaf's SubjectPublicKeyInfo, hex, from
	// enrolment. Empty means the system trust store (a publicly trusted
	// certificate, e.g. behind tailscale serve).
	SPKIPin string
	HTTP    *http.Client
}

func (r *HTTPRelay) client() *http.Client {
	if r.HTTP != nil {
		return r.HTTP
	}
	tr := &http.Transport{}
	if r.SPKIPin != "" {
		// The server's certificate is from a private CA, so the platform store would
		// reject it. Pin the key instead: accept exactly the key enrolment reported.
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // the pin below is the verification
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return fmt.Errorf("no server certificate")
				}
				cert, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if !strings.EqualFold(hex.EncodeToString(sum[:]), r.SPKIPin) {
					return fmt.Errorf("the server's key does not match the one pinned at enrolment")
				}
				return nil
			},
		}
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute}
}

func (r *HTTPRelay) do(ctx context.Context, method, uri string, body []byte, hdr map[string]string) ([]byte, http.Header, error) {
	nonce, err := syncapi.NewNonce()
	if err != nil {
		return nil, nil, err
	}
	auth, err := syncapi.AuthorizationHeader(r.Key, r.ClientID, method, uri, body, time.Now(), nonce)
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(r.BaseURL, "/")+uri, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", auth)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		return nil, nil, &RelayError{Status: resp.StatusCode, Code: e.Error, Message: e.Message}
	}
	return data, resp.Header, nil
}

// Offer implements Relay.
func (r *HTTPRelay) Offer(ctx context.Context, manifest, sig []byte) (*OfferResult, error) {
	data, _, err := r.do(ctx, "POST", "/v1/relay/bundles/offer", manifest,
		map[string]string{"X-Cairn-Signature": hex.EncodeToString(sig), "Content-Type": "application/cbor"})
	if err != nil {
		return nil, err
	}
	var out OfferResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("offer response: %w", err)
	}
	return &out, nil
}

// PutChunk implements Relay.
func (r *HTTPRelay) PutChunk(ctx context.Context, bundleID, sha256Hex string, data []byte) error {
	_, _, err := r.do(ctx, "PUT", "/v1/relay/bundles/"+bundleID+"/chunks/"+sha256Hex, data,
		map[string]string{"Content-Type": "application/octet-stream"})
	return err
}

// Commit implements Relay. The receipt is returned verbatim: the dongle verifies
// a signature over exactly these bytes.
func (r *HTTPRelay) Commit(ctx context.Context, bundleID string) ([]byte, error) {
	data, _, err := r.do(ctx, "POST", "/v1/relay/bundles/"+bundleID+"/commit", nil, nil)
	return data, err
}
