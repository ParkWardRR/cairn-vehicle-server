package tsdb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/klauspost/compress/zstd"
)

// SnapshotSchemaVersion is bumped when the set of exported tables or their
// columns change. Clients check it before loading and refuse an unrecognised
// version rather than crashing on a missing column.
const SnapshotSchemaVersion = 1

// SnapshotMeta is the manifest embedded in every snapshot archive.
type SnapshotMeta struct {
	SchemaVersion     int            `json:"schema_version"`
	BuiltAt           time.Time      `json:"built_at"`
	BuildMS           int64          `json:"build_ms"`
	DecoderVersion    int            `json:"decoder_version"`
	BundleCount       int            `json:"bundle_count"`
	RowCounts         map[string]int `json:"row_counts"`
	Tables            []string       `json:"tables"`
	CompressedSize    int            `json:"compressed_size_bytes"`
	ContentDigest     string         `json:"content_digest"`
}

// snapshotTables are exported as individual Parquet files.
var snapshotTables = []string{
	"bundles", "position", "imu", "obd", "boost",
	"status", "transition", "gap",
}

// SnapshotFormats holds the snapshot archive in multiple compression formats,
// cached in memory and atomically swapped on rebuild.
type SnapshotFormats struct {
	Zstd    []byte
	Gzip    []byte
	Tar     []byte
	Meta    *SnapshotMeta
	Digests map[string]string // format key → "sha256:..."
}

// Snapshot returns the default (zstd) format for backward compatibility.
func (d *DB) Snapshot() ([]byte, *SnapshotMeta) {
	if d.snapshotFormats == nil {
		return nil, nil
	}
	return d.snapshotFormats.Zstd, d.snapshotFormats.Meta
}

// SnapshotFormat returns the snapshot in the requested format.
// Returns nil data when no snapshot exists or the format is unknown.
func (d *DB) SnapshotFormat(format string) (data []byte, contentType string, digest string, meta *SnapshotMeta) {
	sf := d.snapshotFormats
	if sf == nil {
		return nil, "", "", nil
	}
	switch format {
	case "gzip", "gz":
		return sf.Gzip, "application/x-tar+gzip", sf.Digests["gzip"], sf.Meta
	case "tar":
		return sf.Tar, "application/x-tar", sf.Digests["tar"], sf.Meta
	default:
		return sf.Zstd, "application/x-tar+zstd", sf.Digests["zstd"], sf.Meta
	}
}

// SnapshotFormatNames returns the supported format keys.
func SnapshotFormatNames() []string { return []string{"zstd", "gzip", "tar"} }

// exportSnapshot writes every table to Parquet in a temp directory,
// materialises v_drive_summary, builds the archive in multiple compression
// formats and returns them with shared metadata. Called during Build() before
// the DuckDB lockdown.
func exportSnapshot(ctx context.Context, sdb *sql.DB, report *Report) (*SnapshotFormats, error) {
	dir, err := os.MkdirTemp("", "cairn-snapshot-")
	if err != nil {
		return nil, fmt.Errorf("snapshot tmpdir: %w", err)
	}
	defer os.RemoveAll(dir)

	tables := make([]string, 0, len(snapshotTables)+1)
	tables = append(tables, snapshotTables...)
	tables = append(tables, "drive_summary")

	// Materialise v_drive_summary as a real table for export, then drop it
	// afterwards so the view definition can be created normally.
	if _, err := sdb.ExecContext(ctx, "CREATE TABLE drive_summary AS SELECT * FROM v_drive_summary"); err != nil {
		return nil, fmt.Errorf("materialise drive_summary: %w", err)
	}
	defer sdb.ExecContext(ctx, "DROP TABLE IF EXISTS drive_summary")

	rowCounts := make(map[string]int, len(tables))
	for _, t := range tables {
		path := filepath.Join(dir, t+".parquet")
		q := fmt.Sprintf("COPY %s TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD)", t, path)
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("export %s: %w", t, err)
		}

		var n int
		row := sdb.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s", t))
		if err := row.Scan(&n); err != nil {
			return nil, fmt.Errorf("count %s: %w", t, err)
		}
		rowCounts[t] = n
	}

	meta := &SnapshotMeta{
		SchemaVersion:  SnapshotSchemaVersion,
		BuiltAt:        report.BuiltAt,
		BuildMS:        report.BuildMS,
		DecoderVersion: report.DecoderVer,
		BundleCount:    len(report.Bundles),
		RowCounts:      rowCounts,
		Tables:         tables,
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}

	tarBytes, err := buildTar(dir, tables, metaJSON)
	if err != nil {
		return nil, err
	}

	zstdBytes, err := compressZstd(tarBytes)
	if err != nil {
		return nil, fmt.Errorf("zstd compress: %w", err)
	}

	gzipBytes, err := compressGzip(tarBytes)
	if err != nil {
		return nil, fmt.Errorf("gzip compress: %w", err)
	}

	digests := map[string]string{
		"zstd": sha256hex(zstdBytes),
		"gzip": sha256hex(gzipBytes),
		"tar":  sha256hex(tarBytes),
	}

	meta.CompressedSize = len(zstdBytes)
	meta.ContentDigest = digests["zstd"]

	return &SnapshotFormats{
		Zstd:    zstdBytes,
		Gzip:    gzipBytes,
		Tar:     tarBytes,
		Meta:    meta,
		Digests: digests,
	}, nil
}

func buildTar(dir string, tables []string, manifestJSON []byte) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	addFile := func(name string, data []byte) error {
		hdr := &tar.Header{
			Name:    "snapshot/" + name,
			Size:    int64(len(data)),
			Mode:    0o644,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", name, err)
		}
		_, err := tw.Write(data)
		return err
	}

	if err := addFile("manifest.json", manifestJSON); err != nil {
		return nil, err
	}
	for _, t := range tables {
		data, err := os.ReadFile(filepath.Join(dir, t+".parquet"))
		if err != nil {
			return nil, fmt.Errorf("read %s.parquet: %w", t, err)
		}
		if err := addFile(t+".parquet", data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf.Bytes(), nil
}

func compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sha256hex(data []byte) string {
	d := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(d[:])
}
