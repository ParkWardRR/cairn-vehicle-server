// Command cairn-push uploads sealed bundles from an SD card to the ingest
// server over mTLS. It drives the same offer/transfer/commit protocol the
// firmware uses, but reads from local files instead of SPI flash.
//
//	cairn-push -server https://cairn.example.lan:8443 \
//	  -ca ca.pem -cert client.crt -key client.key \
//	  /Volumes/cairn/cairn/bundles/0000000000PJVAS77RR2JSJDY9
package main

import (
	"bytes"
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
	"path/filepath"
	"sort"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/httpapi"
)

func main() {
	var (
		server   = flag.String("server", "https://127.0.0.1:8443", "base URL of the ingest server")
		caFile   = flag.String("ca", "", "CA certificate (PEM)")
		certFile = flag.String("cert", "", "device client certificate (PEM)")
		keyFile  = flag.String("key", "", "device client private key (PEM)")
		insecure = flag.Bool("insecure", false, "skip server certificate verification")
	)
	flag.Parse()

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: cairn-push [flags] <bundle-dir> [bundle-dir ...]")
		os.Exit(2)
	}

	client, err := buildClient(*caFile, *certFile, *keyFile, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tls: %v\n", err)
		os.Exit(1)
	}

	failed := 0
	for _, dir := range flag.Args() {
		if err := push(client, *server, dir); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", filepath.Base(dir), err)
			failed++
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func push(client *http.Client, server, bundleDir string) error {
	manifestBytes, err := os.ReadFile(filepath.Join(bundleDir, "manifest.cbor"))
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	sigBytes, err := os.ReadFile(filepath.Join(bundleDir, "manifest.sig"))
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}

	m, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	bundleHex := hex.EncodeToString(m.BundleID[:])
	fmt.Printf("%s  bundle %s  root %s\n", filepath.Base(bundleDir),
		bundleHex[:16]+"…", hex.EncodeToString(m.ContentRoot[:])[:16]+"…")
	fmt.Printf("  %d members, %d chunks, %d bytes\n",
		len(m.Members), len(m.ChunkDescriptors), totalBytes(m))

	// Build the byte stream by concatenating members in canonical order.
	stream, err := buildStream(bundleDir, m)
	if err != nil {
		return err
	}

	// Slice into chunks per the manifest's descriptors.
	chunks, err := sliceChunks(stream, m.ChunkDescriptors)
	if err != nil {
		return err
	}

	// Step 1: offer.
	offer, err := doOffer(client, server, manifestBytes, sigBytes)
	if err != nil {
		return err
	}
	if offer.ReceiptAvailable {
		fmt.Printf("  already committed; fetching existing receipt\n")
	} else {
		fmt.Printf("  server wants %d of %d chunks (%d bytes)\n",
			len(offer.MissingChunks), offer.TotalChunks, offer.BytesOutstanding)
	}

	// Step 2: transfer missing chunks.
	for _, idx := range offer.MissingChunks {
		if int(idx) >= len(chunks) {
			return fmt.Errorf("server asked for chunk %d but bundle has %d", idx, len(chunks))
		}
		d := m.ChunkDescriptors[idx]
		if err := doChunk(client, server, bundleHex, d.SHA256, chunks[idx]); err != nil {
			return fmt.Errorf("chunk %d: %w", idx, err)
		}
	}
	if len(offer.MissingChunks) > 0 {
		fmt.Printf("  transferred %d chunks\n", len(offer.MissingChunks))
	}

	// Step 3: commit.
	receiptBytes, already, err := doCommit(client, server, bundleHex)
	if err != nil {
		return err
	}

	receipt, err := format.ParseReceipt(receiptBytes)
	if err != nil {
		return fmt.Errorf("parse receipt: %w", err)
	}

	tag := ""
	if already {
		tag = " (already committed)"
	}
	fmt.Printf("  committed%s  receipt %s  at %s\n", tag,
		hex.EncodeToString(receipt.ReceiptID[:])[:16]+"…",
		time.UnixMilli(int64(receipt.ServerIngestUTCMS)).UTC().Format(time.RFC3339))
	return nil
}

func totalBytes(m *format.Manifest) int64 {
	var n int64
	for _, c := range m.ChunkDescriptors {
		n += int64(c.ByteLength)
	}
	return n
}

func buildStream(bundleDir string, m *format.Manifest) ([]byte, error) {
	sorted := make([]format.Member, len(m.Members))
	copy(sorted, m.Members)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	var stream []byte
	for _, mem := range sorted {
		data, err := os.ReadFile(filepath.Join(bundleDir, mem.Name))
		if err != nil {
			return nil, fmt.Errorf("read member %q: %w", mem.Name, err)
		}
		stream = append(stream, data...)
	}
	return stream, nil
}

func sliceChunks(stream []byte, descs []format.ChunkDescriptor) ([][]byte, error) {
	chunks := make([][]byte, len(descs))
	off := 0
	for i, d := range descs {
		end := off + int(d.ByteLength)
		if end > len(stream) {
			return nil, fmt.Errorf("chunk %d overruns stream (offset %d + %d > %d)",
				i, off, d.ByteLength, len(stream))
		}
		chunks[i] = stream[off:end]
		off = end
	}
	return chunks, nil
}

// --- HTTP helpers (same protocol as cairn-syncdemo) ---

type offerResult struct {
	MissingChunks    []uint32 `json:"missing_chunks"`
	TotalChunks      int      `json:"total_chunks"`
	BytesOutstanding int64    `json:"bytes_outstanding"`
	ReceiptAvailable bool     `json:"receipt_available"`
}

func doOffer(client *http.Client, server string, manifest, sig []byte) (*offerResult, error) {
	req, err := http.NewRequest(http.MethodPost, server+"/api/v2/bundles/offer",
		bytes.NewReader(manifest))
	if err != nil {
		return nil, err
	}
	req.Header.Set(httpapi.SignatureHeader, hex.EncodeToString(sig))
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
	url := fmt.Sprintf("%s/api/v2/bundles/%s/chunks/%s",
		server, bundleHex, hex.EncodeToString(digest[:]))

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
	resp, err := client.Post(server+"/api/v2/bundles/"+bundleHex+"/commit", "", nil)
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
		tlsCfg.InsecureSkipVerify = true
	}

	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return nil, errors.New("both -cert and -key are required")
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
