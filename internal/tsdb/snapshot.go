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
	"regexp"
	"time"

	"github.com/klauspost/compress/zstd"
)

// SnapshotSchemaVersion is bumped when the set of exported tables or their
// columns change. Clients check it before loading and refuse an unrecognised
// version rather than crashing on a missing column.
//
// Version 2 adds vehicle_id to every table (and to drive_summary), and the
// manifest's vehicle/vehicles fields. A version-1 reader would load the tables
// and blend every car's trims into one map, so it must refuse rather than
// guess.
const SnapshotSchemaVersion = 2

// SnapshotMeta is the manifest embedded in every snapshot archive.
type SnapshotMeta struct {
	SchemaVersion  int       `json:"schema_version"`
	BuiltAt        time.Time `json:"built_at"`
	BuildMS        int64     `json:"build_ms"`
	DecoderVersion int       `json:"decoder_version"`
	BundleCount    int       `json:"bundle_count"`

	// Vehicle is the filter this archive was cut with: one vehicle id, or empty
	// for every vehicle. Vehicles lists the vehicles whose rows it holds.
	Vehicle  string   `json:"vehicle,omitempty"`
	Vehicles []string `json:"vehicles"`

	RowCounts      map[string]int `json:"row_counts"`
	Tables         []string       `json:"tables"`
	CompressedSize int            `json:"compressed_size_bytes"`
	ContentDigest  string         `json:"content_digest"`
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

// snapshotSet is every archive one build produced: the unfiltered one under the
// empty key and one per vehicle under its id.
//
// They are all cut at build time because COPY TO needs external access, which
// is switched off for good before the store serves a single query. A handful of
// cars makes that a handful of small archives, and it means a filtered
// snapshot is the same kind of immutable, digest-addressed object as the full
// one rather than something assembled per request.
type snapshotSet map[string]*SnapshotFormats

// VehicleIDPattern is the shape of a vehicle id everywhere in the store: the
// 16-byte identifier as 32 lowercase hex characters.
var VehicleIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Snapshot returns the unfiltered snapshot in the default (zstd) format.
func (d *DB) Snapshot() ([]byte, *SnapshotMeta) {
	sf := d.snapshots[""]
	if sf == nil {
		return nil, nil
	}
	return sf.Zstd, sf.Meta
}

// SnapshotFormat returns the snapshot in the requested format, filtered to one
// vehicle when vehicle is non-empty. It returns nil data when no snapshot
// exists, which for a vehicle means the store holds no rows for it.
func (d *DB) SnapshotFormat(format, vehicle string) (data []byte, contentType string, digest string, meta *SnapshotMeta) {
	sf := d.snapshots[vehicle]
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

// SnapshotVehicles returns the vehicles a filtered snapshot exists for.
func (d *DB) SnapshotVehicles() []string {
	sf := d.snapshots[""]
	if sf == nil {
		return nil
	}
	return append([]string(nil), sf.Meta.Vehicles...)
}

// SnapshotFormatNames returns the supported format keys.
func SnapshotFormatNames() []string { return []string{"zstd", "gzip", "tar"} }

// exportSnapshots materialises v_drive_summary and cuts the unfiltered archive
// plus one per vehicle. Called during Build() before the DuckDB lockdown.
func exportSnapshots(ctx context.Context, sdb *sql.DB, report *Report) (snapshotSet, error) {
	// Materialise v_drive_summary as a real table for export, then drop it
	// afterwards so the view definition can be created normally.
	if _, err := sdb.ExecContext(ctx, "CREATE TABLE drive_summary AS SELECT * FROM v_drive_summary"); err != nil {
		return nil, fmt.Errorf("materialise drive_summary: %w", err)
	}
	defer sdb.ExecContext(ctx, "DROP TABLE IF EXISTS drive_summary")

	rows, err := sdb.QueryContext(ctx, "SELECT DISTINCT vehicle_id FROM bundles ORDER BY vehicle_id")
	if err != nil {
		return nil, fmt.Errorf("list vehicles: %w", err)
	}
	var vehicles []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		// The id is spliced into SQL below, so it is checked rather than
		// trusted, even though this process wrote it.
		if !VehicleIDPattern.MatchString(v) {
			rows.Close()
			return nil, fmt.Errorf("vehicle id %q is not 32 lowercase hex", v)
		}
		vehicles = append(vehicles, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	set := snapshotSet{}
	all, err := exportSnapshot(ctx, sdb, report, "", vehicles)
	if err != nil {
		return nil, err
	}
	set[""] = all
	for _, v := range vehicles {
		sf, err := exportSnapshot(ctx, sdb, report, v, []string{v})
		if err != nil {
			return nil, fmt.Errorf("vehicle %s: %w", v, err)
		}
		set[v] = sf
	}
	return set, nil
}

// exportSnapshot writes every table to Parquet in a temp directory — only
// vehicle's rows when vehicle is set — builds the archive in multiple
// compression formats and returns them with shared metadata.
func exportSnapshot(ctx context.Context, sdb *sql.DB, report *Report, vehicle string, vehicles []string) (*SnapshotFormats, error) {
	dir, err := os.MkdirTemp("", "cairn-snapshot-")
	if err != nil {
		return nil, fmt.Errorf("snapshot tmpdir: %w", err)
	}
	defer os.RemoveAll(dir)

	tables := make([]string, 0, len(snapshotTables)+1)
	tables = append(tables, snapshotTables...)
	tables = append(tables, "drive_summary")

	where := ""
	if vehicle != "" {
		where = fmt.Sprintf(" WHERE vehicle_id = '%s'", vehicle)
	}

	rowCounts := make(map[string]int, len(tables))
	for _, t := range tables {
		path := filepath.Join(dir, t+".parquet")
		q := fmt.Sprintf("COPY (SELECT * FROM %s%s) TO '%s' (FORMAT PARQUET, COMPRESSION ZSTD)", t, where, path)
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return nil, fmt.Errorf("export %s: %w", t, err)
		}

		var n int
		row := sdb.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s%s", t, where))
		if err := row.Scan(&n); err != nil {
			return nil, fmt.Errorf("count %s: %w", t, err)
		}
		rowCounts[t] = n
	}

	if vehicles == nil {
		vehicles = []string{}
	}
	meta := &SnapshotMeta{
		SchemaVersion:  SnapshotSchemaVersion,
		BuiltAt:        report.BuiltAt,
		BuildMS:        report.BuildMS,
		DecoderVersion: report.DecoderVer,
		BundleCount:    rowCounts["bundles"],
		Vehicle:        vehicle,
		Vehicles:       vehicles,
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
