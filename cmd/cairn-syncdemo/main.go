// Command cairn-syncdemo performs a complete v2 sync against a running server
// using a synthetic bundle.
//
// It exists to exercise the real wire protocol over real TLS, which is where
// the in-process handler tests cannot reach: certificate identity binding,
// header encoding, status-code handling and receipt verification over an
// actual socket. It also serves as the reference for what the firmware's sync
// task has to do, in the order it has to do it.
//
// This is a development and verification tool. The device's own implementation
// lives in the firmware; the emulator in a later phase subsumes this with fault
// injection.
//
//	cairn-syncdemo -server https://127.0.0.1:8443 \
//	  -ca ca.crt -cert device.crt -key device.key
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/httpapi"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

func main() {
	var (
		server    = flag.String("server", "https://127.0.0.1:8443", "base URL of the ingest server")
		caFile    = flag.String("ca", "", "CA certificate to pin the server against (PEM)")
		certFile  = flag.String("cert", "", "device client certificate (PEM)")
		keyFile   = flag.String("key", "", "device client private key (PEM)")
		insecure  = flag.Bool("insecure", false, "skip server certificate verification (development only)")
		chunkSize = flag.Int("chunk-size", 256, "chunk size in bytes")

		printIdentity = flag.Bool("print-identity", false,
			"print the synthetic device ID and public key, then exit — use these to enrol it")
	)
	flag.Parse()

	// Enrolment needs the device's identity before a sync can succeed, and the
	// identity is derived from a fixed seed rather than configured, so the tool
	// reports it rather than making the operator derive it.
	if *printIdentity {
		pub, _ := testbundle.DeviceKey()
		id := testbundle.DeviceID()
		root, vehicle, assignment := testbundle.RootKey(), testbundle.VehicleID(), testbundle.AssignmentID()
		fmt.Printf("device_id  %s\npublic_key %s\n", hex.EncodeToString(id[:]), hex.EncodeToString(pub))
		// The v3 binding a server needs before it will accept this device's
		// bundles. These are the PUBLIC test values the synthetic bundles carry.
		fmt.Printf("storage_root %s\nkey_version %d\nvehicle_id %s\nassignment_id %s\n\n",
			hex.EncodeToString(root[:]), testbundle.DefaultKeyVersion,
			hex.EncodeToString(vehicle[:]), hex.EncodeToString(assignment[:]))
		fmt.Printf("enrol with:\n  cairn-server -data <dir> -enroll %s -enroll-key %s\n",
			hex.EncodeToString(id[:]), hex.EncodeToString(pub))
		return
	}

	if err := run(*server, *caFile, *certFile, *keyFile, *insecure, *chunkSize); err != nil {
		fmt.Fprintf(os.Stderr, "sync failed: %v\n", err)
		os.Exit(1)
	}
}

func run(server, caFile, certFile, keyFile string, insecure bool, chunkSize int) error {
	client, err := buildClient(caFile, certFile, keyFile, insecure)
	if err != nil {
		return err
	}

	opts := testbundle.Default()
	opts.ChunkSize = chunkSize
	b, err := testbundle.Build(opts)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}

	bundleHex := hex.EncodeToString(b.Manifest.BundleID[:])
	fmt.Printf("bundle    %s\n", bundleHex)
	fmt.Printf("device    %s\n", hex.EncodeToString(b.Manifest.DeviceID[:]))
	fmt.Printf("root      %s\n", hex.EncodeToString(b.Manifest.ContentRoot[:]))
	fmt.Printf("stream    %d bytes in %d chunks across %d members\n\n",
		len(b.Stream), len(b.Chunks), len(b.Manifest.Members))

	// The device must pin the receipt key before it can act on any receipt.
	// Fetching it here is provisioning, not part of a sync.
	receiptKey, err := fetchReceiptKey(client, server)
	if err != nil {
		return err
	}
	fmt.Printf("step 0   pinned receipt key %s\n", hex.EncodeToString(receiptKey)[:16]+"…")

	// Step 1: offer the manifest. The server replies with what it still needs.
	offer, err := doOffer(client, server, b)
	if err != nil {
		return err
	}
	if offer.ReceiptAvailable {
		fmt.Println("step 1   server already holds this content; fetching the existing receipt")
	} else {
		fmt.Printf("step 1   offered; server wants %d of %d chunks (%d bytes)\n",
			len(offer.MissingChunks), offer.TotalChunks, offer.BytesOutstanding)
	}

	// Step 2: transfer only what was asked for, addressed by content hash.
	sent := 0
	for _, idx := range offer.MissingChunks {
		if int(idx) >= len(b.Chunks) {
			return fmt.Errorf("server asked for chunk %d but the bundle has %d", idx, len(b.Chunks))
		}
		d := b.Manifest.ChunkDescriptors[idx]
		if err := doChunk(client, server, bundleHex, d.SHA256, b.Chunks[idx]); err != nil {
			return fmt.Errorf("chunk %d: %w", idx, err)
		}
		sent++
	}
	if sent > 0 {
		fmt.Printf("step 2   transferred %d chunks\n", sent)
	}

	// Step 3: commit. The response body is the receipt, verbatim.
	receiptBytes, alreadyCommitted, err := doCommit(client, server, bundleHex)
	if err != nil {
		return err
	}
	note := ""
	if alreadyCommitted {
		note = " (already committed)"
	}
	fmt.Printf("step 3   committed%s; receipt is %d bytes\n", note, len(receiptBytes))

	// Step 4: verify locally before the bundle would become prunable. Both
	// conditions matter — a valid signature over someone else's bundle is not
	// an acknowledgement of this one.
	receipt, err := format.ParseReceipt(receiptBytes)
	if err != nil {
		return fmt.Errorf("parse receipt: %w", err)
	}
	if err := receipt.VerifyAcknowledges(ed25519.PublicKey(receiptKey), b.Manifest.ContentRoot); err != nil {
		return fmt.Errorf("receipt verification failed — the bundle must NOT be pruned: %w", err)
	}

	fmt.Printf("step 4   receipt verified\n")
	fmt.Printf("\n  receipt_id   %s\n", hex.EncodeToString(receipt.ReceiptID[:]))
	fmt.Printf("  server_key   %s\n", hex.EncodeToString(receipt.ServerKeyID[:]))
	fmt.Printf("  ingested_at  %s\n", time.UnixMilli(int64(receipt.ServerIngestUTCMS)).UTC().Format(time.RFC3339))
	fmt.Printf("  objects      %d\n", len(receipt.StoredObjectIDs))
	fmt.Printf("\nthis bundle is now receipt-confirmed and eligible for retention policy\n")
	return nil
}

func buildClient(caFile, certFile, keyFile string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificates", caFile)
		}
		tlsCfg.RootCAs = pool
	}

	if insecure {
		// Mirrors what the firmware must never do: without pinning, anything
		// answering on the LAN can impersonate the server.
		tlsCfg.InsecureSkipVerify = true
	}

	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both -cert and -key are required for client authentication")
		}
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client key pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}

	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

func fetchReceiptKey(client *http.Client, server string) ([]byte, error) {
	resp, err := client.Get(server + "/api/v2/server/receipt-key")
	if err != nil {
		return nil, fmt.Errorf("fetch receipt key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch receipt key: status %d", resp.StatusCode)
	}

	var payload struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode receipt key: %w", err)
	}
	return hex.DecodeString(payload.PublicKey)
}

type offerResult struct {
	MissingChunks    []uint32 `json:"missing_chunks"`
	TotalChunks      int      `json:"total_chunks"`
	BytesOutstanding int64    `json:"bytes_outstanding"`
	ReceiptAvailable bool     `json:"receipt_available"`
}

func doOffer(client *http.Client, server string, b *testbundle.Bundle) (*offerResult, error) {
	req, err := http.NewRequest(http.MethodPost, server+"/api/v2/bundles/offer",
		bytes.NewReader(b.ManifestBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set(httpapi.SignatureHeader, hex.EncodeToString(b.Signature))
	req.Header.Set("Content-Type", httpapi.ContentTypeCBOR)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("offer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("offer rejected: %s", describe(resp))
	}

	var out offerResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode offer response: %w", err)
	}
	return &out, nil
}

func doChunk(client *http.Client, server, bundleHex string, digest [32]byte, data []byte) error {
	url := fmt.Sprintf("%s/api/v2/bundles/%s/chunks/%s", server, bundleHex, hex.EncodeToString(digest[:]))

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rejected: %s", describe(resp))
	}
	return nil
}

func doCommit(client *http.Client, server, bundleHex string) ([]byte, bool, error) {
	url := fmt.Sprintf("%s/api/v2/bundles/%s/commit", server, bundleHex)

	resp, err := client.Post(url, "", nil)
	if err != nil {
		return nil, false, fmt.Errorf("commit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("commit rejected: %s", describe(resp))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read receipt: %w", err)
	}
	return body, resp.Header.Get("X-Cairn-Already-Committed") == "1", nil
}

// describe renders a rejection so the operator can tell a permanent refusal
// from something worth retrying.
func describe(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var payload struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
		if payload.Detail != "" {
			return fmt.Sprintf("status %d: %s (%s)", resp.StatusCode, payload.Error, payload.Detail)
		}
		return fmt.Sprintf("status %d: %s", resp.StatusCode, payload.Error)
	}
	return fmt.Sprintf("status %d: %s", resp.StatusCode, bytes.TrimSpace(body))
}
