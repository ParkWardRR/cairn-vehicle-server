package tsdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"
	"github.com/klauspost/compress/zstd"

	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

func TestSnapshotRoundTrip(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	writeSD(t, sd, b, "b1")

	db := buildFromSD(t, sd)

	data, meta := db.Snapshot()
	if data == nil {
		t.Fatal("snapshot is nil")
	}
	if meta == nil {
		t.Fatal("snapshot meta is nil")
	}

	if meta.SchemaVersion != SnapshotSchemaVersion {
		t.Errorf("schema_version = %d, want %d", meta.SchemaVersion, SnapshotSchemaVersion)
	}
	if meta.BundleCount != 1 {
		t.Errorf("bundle_count = %d, want 1", meta.BundleCount)
	}
	if meta.CompressedSize != len(data) {
		t.Errorf("compressed_size = %d, actual = %d", meta.CompressedSize, len(data))
	}
	if !strings.HasPrefix(meta.ContentDigest, "sha256:") {
		t.Errorf("content_digest = %q, want sha256:... prefix", meta.ContentDigest)
	}

	files := extractArchive(t, data)

	manifestBytes, ok := files["manifest.json"]
	if !ok {
		t.Fatal("manifest.json missing from archive")
	}
	var manifest SnapshotMeta
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}

	expectedTables := append([]string{}, snapshotTables...)
	expectedTables = append(expectedTables, "drive_summary")
	for _, table := range expectedTables {
		if _, ok := files[table+".parquet"]; !ok {
			t.Errorf("%s.parquet missing from archive", table)
		}
	}

	bundleRows := db.Report.Bundles[0].Rows
	if got := manifest.RowCounts["position"]; got != int(bundleRows.Position) {
		t.Errorf("position row count: manifest=%d, report=%d", got, bundleRows.Position)
	}
	if got := manifest.RowCounts["obd"]; got != int(bundleRows.OBD) {
		t.Errorf("obd row count: manifest=%d, report=%d", got, bundleRows.OBD)
	}

	verifyParquetImport(t, files, &manifest)
}

func extractArchive(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	files := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		name := strings.TrimPrefix(hdr.Name, "snapshot/")
		files[name] = content
	}
	return files
}

func verifyParquetImport(t *testing.T, files map[string][]byte, meta *SnapshotMeta) {
	t.Helper()
	ctx := context.Background()

	dir := t.TempDir()
	for name, data := range files {
		if !strings.HasSuffix(name, ".parquet") {
			continue
		}
		if err := os.WriteFile(dir+"/"+name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	c, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Fatal(err)
	}
	sdb := sql.OpenDB(c)
	t.Cleanup(func() { sdb.Close() })

	for _, table := range meta.Tables {
		path := dir + "/" + table + ".parquet"
		q := "CREATE TABLE " + table + " AS SELECT * FROM read_parquet('" + path + "')"
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			t.Fatalf("import %s: %v", table, err)
		}

		var got int
		row := sdb.QueryRowContext(ctx, "SELECT count(*) FROM "+table)
		if err := row.Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}

		want := meta.RowCounts[table]
		if got != want {
			t.Errorf("table %s: imported %d rows, manifest says %d", table, got, want)
		}
	}
}

func TestSnapshotEmptyDB(t *testing.T) {
	sd := t.TempDir()
	if err := os.MkdirAll(sd+"/bundles", 0o755); err != nil {
		t.Fatal(err)
	}

	snap, notes, err := SnapshotSources(t.TempDir(), "", sd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { snap.Close() })

	db, err := Build(context.Background(), snap, notes, Options{MemoryLimit: "512MB", Threads: 2, Keys: testbundle.Keys()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	data, meta := db.Snapshot()
	if data != nil {
		t.Error("expected nil snapshot for empty DB")
	}
	if meta != nil {
		t.Error("expected nil meta for empty DB")
	}
}

func TestSnapshotMetadataConsistent(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}

	sd := t.TempDir()
	writeSD(t, sd, b, "b1")

	db1 := buildFromSD(t, sd)
	db2 := buildFromSD(t, sd)

	_, meta1 := db1.Snapshot()
	_, meta2 := db2.Snapshot()
	if meta1 == nil || meta2 == nil {
		t.Fatal("snapshot(s) nil")
	}

	if meta1.SchemaVersion != meta2.SchemaVersion {
		t.Errorf("schema version: %d vs %d", meta1.SchemaVersion, meta2.SchemaVersion)
	}
	if meta1.BundleCount != meta2.BundleCount {
		t.Errorf("bundle count: %d vs %d", meta1.BundleCount, meta2.BundleCount)
	}
	for table, count1 := range meta1.RowCounts {
		if count2 := meta2.RowCounts[table]; count1 != count2 {
			t.Errorf("row count %s: %d vs %d", table, count1, count2)
		}
	}
}

func TestSnapshotFormats(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	writeSD(t, sd, b, "b1")
	db := buildFromSD(t, sd)

	// All three formats should produce valid archives with the same manifest.
	for _, tc := range []struct {
		format      string
		contentType string
	}{
		{"zstd", "application/x-tar+zstd"},
		{"gzip", "application/x-tar+gzip"},
		{"tar", "application/x-tar"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			data, ct, digest, meta := db.SnapshotFormat(tc.format)
			if data == nil {
				t.Fatal("data nil")
			}
			if ct != tc.contentType {
				t.Errorf("content type = %q, want %q", ct, tc.contentType)
			}
			if !strings.HasPrefix(digest, "sha256:") {
				t.Errorf("digest = %q, want sha256:... prefix", digest)
			}
			if meta == nil {
				t.Fatal("meta nil")
			}

			var tarReader *tar.Reader
			switch tc.format {
			case "zstd":
				zr, err := zstd.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer zr.Close()
				tarReader = tar.NewReader(zr)
			case "gzip":
				gr, err := gzip.NewReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer gr.Close()
				tarReader = tar.NewReader(gr)
			case "tar":
				tarReader = tar.NewReader(bytes.NewReader(data))
			}

			var hasManifest bool
			tables := map[string]bool{}
			for {
				hdr, err := tarReader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("tar read: %v", err)
				}
				name := strings.TrimPrefix(hdr.Name, "snapshot/")
				if name == "manifest.json" {
					hasManifest = true
				}
				if strings.HasSuffix(name, ".parquet") {
					tables[strings.TrimSuffix(name, ".parquet")] = true
				}
			}
			if !hasManifest {
				t.Error("manifest.json missing")
			}
			for _, tbl := range meta.Tables {
				if !tables[tbl] {
					t.Errorf("%s.parquet missing", tbl)
				}
			}
		})
	}

	// Digests must differ across formats.
	_, _, dZstd, _ := db.SnapshotFormat("zstd")
	_, _, dGzip, _ := db.SnapshotFormat("gzip")
	_, _, dTar, _ := db.SnapshotFormat("tar")
	if dZstd == dGzip {
		t.Error("zstd and gzip digests should differ")
	}
	if dZstd == dTar {
		t.Error("zstd and tar digests should differ")
	}
}
