package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"os"
	"path/filepath"

	"github.com/klauspost/compress/zstd"

	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
	"github.com/ParkWardRR/Cairn/server/internal/tsdb"
)

// writeSD lays out a synthetic bundle on a temp SD path, same as the tsdb
// package's test helper.
func writeSD(t *testing.T, root string, b *testbundle.Bundle, dirName string) {
	t.Helper()
	dir := filepath.Join(root, "bundles", dirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.cbor", b.ManifestBytes)
	write("manifest.sig", b.Signature)

	off := 0
	for _, m := range b.Manifest.Members {
		write(m.Name, b.Stream[off:off+int(m.Length)])
		off += int(m.Length)
	}
}

// buildTestServer creates a server with a single synthetic bundle loaded.
func buildTestServer(t *testing.T) *server {
	t.Helper()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}

	sd := t.TempDir()
	writeSD(t, sd, b, "b1")

	scratch := t.TempDir()
	snap, notes, err := tsdb.SnapshotSources(scratch, "", sd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snap.Close() })

	db, err := tsdb.Build(context.Background(), snap, notes, tsdb.Options{MemoryLimit: "512MB", Threads: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	s := &server{
		cfg: config{sdRoot: sd, scratch: scratch},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s.cur.Store(db)
	return s
}

func TestSnapshotHandler(t *testing.T) {
	s := buildTestServer(t)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /snapshot", s.snapshotHandler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Run("200_with_headers", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/snapshot")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		ct := resp.Header.Get("Content-Type")
		if ct != "application/x-tar+zstd" {
			t.Errorf("Content-Type = %q, want %q", ct, "application/x-tar+zstd")
		}

		etag := resp.Header.Get("ETag")
		if etag == "" {
			t.Fatal("ETag header missing")
		}
		if !strings.HasPrefix(etag, `"sha256:`) || !strings.HasSuffix(etag, `"`) {
			t.Errorf("ETag = %q, want quoted sha256:... digest", etag)
		}

		cl := resp.Header.Get("Content-Length")
		if cl == "" {
			t.Fatal("Content-Length header missing")
		}
		clInt, err := strconv.Atoi(cl)
		if err != nil {
			t.Fatalf("Content-Length %q is not an integer: %v", cl, err)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) != clInt {
			t.Errorf("body length = %d, Content-Length = %d", len(body), clInt)
		}
	})

	t.Run("304_if_none_match", func(t *testing.T) {
		// First request to grab the ETag.
		resp1, err := http.Get(srv.URL + "/snapshot")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp1.Body)
		resp1.Body.Close()

		etag := resp1.Header.Get("ETag")
		if etag == "" {
			t.Fatal("no ETag on first request")
		}

		// Second request with If-None-Match.
		req, err := http.NewRequest("GET", srv.URL+"/snapshot", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("If-None-Match", etag)

		resp2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp2.Body.Close()

		if resp2.StatusCode != http.StatusNotModified {
			t.Fatalf("status = %d, want 304", resp2.StatusCode)
		}
	})

	t.Run("body_decompresses_with_parquet", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/snapshot")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		zr, err := zstd.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("zstd decompress failed: %v", err)
		}
		defer zr.Close()

		tr := tar.NewReader(zr)
		files := map[string]int64{}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("tar read: %v", err)
			}
			name := strings.TrimPrefix(hdr.Name, "snapshot/")
			files[name] = hdr.Size
		}

		if _, ok := files["manifest.json"]; !ok {
			t.Error("manifest.json missing from archive")
		}

		// The snapshot must contain at least position.parquet and obd.parquet
		// from the default testbundle.
		for _, table := range []string{"position", "obd", "transition"} {
			key := table + ".parquet"
			size, ok := files[key]
			if !ok {
				t.Errorf("%s missing from archive", key)
			} else if size == 0 {
				t.Errorf("%s is empty", key)
			}
		}

		// Parquet files start with PAR1 magic.
		// Re-read the archive to check content.
		zr2, _ := zstd.NewReader(bytes.NewReader(body))
		defer zr2.Close()
		tr2 := tar.NewReader(zr2)
		for {
			hdr, err := tr2.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			name := strings.TrimPrefix(hdr.Name, "snapshot/")
			if !strings.HasSuffix(name, ".parquet") {
				continue
			}
			content, err := io.ReadAll(tr2)
			if err != nil {
				t.Fatal(err)
			}
			if len(content) < 4 || string(content[:4]) != "PAR1" {
				t.Errorf("%s does not start with PAR1 magic (got %x)", name, content[:min(4, len(content))])
			}
		}
	})
}
