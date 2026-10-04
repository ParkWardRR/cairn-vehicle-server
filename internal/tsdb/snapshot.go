package tsdb

import (
	"archive/tar"
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

// Snapshot returns the cached snapshot archive bytes and metadata. Both are
// nil when the build produced no snapshot (e.g. zero bundles, or the export
// was skipped).
func (d *DB) Snapshot() ([]byte, *SnapshotMeta) {
	return d.snapshot, d.snapshotMeta
}

// exportSnapshot writes every table to Parquet in a temp directory,
// materialises v_drive_summary, builds a tar.zst archive and returns it with
// its metadata. Called during Build() before the DuckDB lockdown.
func exportSnapshot(ctx context.Context, sdb *sql.DB, report *Report) ([]byte, *SnapshotMeta, error) {
	dir, err := os.MkdirTemp("", "cairn-snapshot-")
	if err != nil {
		return nil, nil, fmt.Errorf("snapshot tmpdir: %w", err)
	}
	defer os.RemoveAll(dir)

	tables := make([]string, 0, len(snapshotTables)+1)
	tables = append(tables, snapshotTables...)
	tables = append(tables, "drive_summary")

	// Materialise v_drive_summary as a real table for export, then drop it
	// afterwards so the view definition can be created normally.
	if _, err := sdb.ExecContext(ctx, "CREATE TABLE drive_summary AS SELECT * FROM v_drive_summary"); err != nil {
		return nil, nil, fmt.Errorf("materialise drive_summary: %w", err)
	}
	defer sdb.ExecContext(ctx, "DROP TABLE IF EXISTS drive_summary")

	rowCounts := make(map[string]int, len(tables))
	for _, t := range tables {
		path := filepath.Join(dir, t+".parquet")
		q := fmt.Sprintf("COPY %s TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD)", t, path)
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return nil, nil, fmt.Errorf("export %s: %w", t, err)
		}

		var n int
		row := sdb.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s", t))
		if err := row.Scan(&n); err != nil {
			return nil, nil, fmt.Errorf("count %s: %w", t, err)
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
		return nil, nil, fmt.Errorf("encode manifest: %w", err)
	}
	metaPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		return nil, nil, fmt.Errorf("write manifest: %w", err)
	}

	archive, err := buildTarZstd(dir, tables, metaJSON)
	if err != nil {
		return nil, nil, err
	}

	digest := sha256.Sum256(archive)
	meta.CompressedSize = len(archive)
	meta.ContentDigest = "sha256:" + hex.EncodeToString(digest[:])

	return archive, meta, nil
}

// buildTarZstd creates a tar.zst archive from the Parquet files and manifest.
func buildTarZstd(dir string, tables []string, manifestJSON []byte) ([]byte, error) {
	// Write the tar.zst to a temp file to avoid holding everything in memory
	// during compression, then read it back. At current data volumes this is
	// negligible either way.
	f, err := os.CreateTemp("", "cairn-snapshot-*.tar.zst")
	if err != nil {
		return nil, fmt.Errorf("snapshot temp file: %w", err)
	}
	tmpPath := f.Name()
	defer os.Remove(tmpPath)

	zw, err := zstd.NewWriter(f, zstd.WithEncoderLevel(zstd.SpeedDefault))
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("zstd writer: %w", err)
	}
	tw := tar.NewWriter(zw)

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
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("tar write %s: %w", name, err)
		}
		return nil
	}

	if err := addFile("manifest.json", manifestJSON); err != nil {
		tw.Close()
		zw.Close()
		f.Close()
		return nil, err
	}

	for _, t := range tables {
		data, err := os.ReadFile(filepath.Join(dir, t+".parquet"))
		if err != nil {
			tw.Close()
			zw.Close()
			f.Close()
			return nil, fmt.Errorf("read %s.parquet: %w", t, err)
		}
		if err := addFile(t+".parquet", data); err != nil {
			tw.Close()
			zw.Close()
			f.Close()
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		zw.Close()
		f.Close()
		return nil, fmt.Errorf("tar close: %w", err)
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return nil, fmt.Errorf("zstd close: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("snapshot file close: %w", err)
	}

	return os.ReadFile(tmpPath)
}
