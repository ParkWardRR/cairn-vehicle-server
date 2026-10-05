// Command cairn-fsq extracts a regional slice of Foursquare OS Places into a
// small NDJSON file that the web UI loads to name the places you stop at.
//
//	HF_TOKEN=hf_... cairn-fsq -bbox -119.0,33.6,-117.6,34.4 -out fsq-pois.ndjson
//
// FSQ OS Places is Apache-2.0, but it is gated: the Hugging Face dataset needs
// an account that has accepted its terms (https://huggingface.co/datasets/
// foursquare/fsq-os-places), or a token from the Foursquare Places Portal. The
// public S3 copy has been retired. The full dataset is hundreds of gigabytes,
// so only the rows inside -bbox are kept, and only five fields of each.
//
// -src accepts any DuckDB-readable parquet path, which is also how the tests
// run without network access.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

const defaultRelease = "2026-09-15"

type options struct {
	Src   string
	Out   string
	BBox  [4]float64 // minLon, minLat, maxLon, maxLat
	Token string
}

func main() {
	var (
		src     = flag.String("src", "", "parquet path or glob (default: the Hugging Face release)")
		release = flag.String("release", defaultRelease, "release date partition used with the default -src")
		out     = flag.String("out", "fsq-pois.ndjson", "output NDJSON file")
		bbox    = flag.String("bbox", "", "minLon,minLat,maxLon,maxLat of the area to keep (required)")
	)
	flag.Parse()

	box, err := parseBBox(*bbox)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cairn-fsq:", err)
		os.Exit(2)
	}
	o := options{Src: *src, Out: *out, BBox: box, Token: os.Getenv("HF_TOKEN")}
	if o.Src == "" {
		o.Src = fmt.Sprintf("hf://datasets/foursquare/fsq-os-places/release/dt=%s/places/parquet/*.parquet", *release)
		if o.Token == "" {
			fmt.Fprintln(os.Stderr, "cairn-fsq: HF_TOKEN is not set. The dataset is gated: accept its terms on Hugging Face and create a read token.")
			os.Exit(2)
		}
	}

	n, err := extract(context.Background(), o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cairn-fsq:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d places to %s\n", n, o.Out)
}

func parseBBox(s string) ([4]float64, error) {
	var b [4]float64
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return b, fmt.Errorf("-bbox must be minLon,minLat,maxLon,maxLat")
	}
	for i, p := range parts {
		v, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			return b, fmt.Errorf("-bbox: %q is not a number", p)
		}
		b[i] = v
	}
	if b[0] >= b[2] || b[1] >= b[3] {
		return b, fmt.Errorf("-bbox: min must be below max")
	}
	return b, nil
}

func sqlQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// extract copies the places inside the box, skipping closed ones, to o.Out.
func extract(ctx context.Context, o options) (int64, error) {
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		return 0, fmt.Errorf("open duckdb: %w", err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	// One connection: secrets and loaded extensions are per-connection state.
	db.SetMaxOpenConns(1)

	if strings.Contains(o.Src, "://") {
		for _, stmt := range []string{"INSTALL httpfs", "LOAD httpfs"} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				return 0, fmt.Errorf("%s: %w (the host needs internet access to fetch the httpfs extension)", stmt, err)
			}
		}
		if o.Token != "" {
			if _, err := db.ExecContext(ctx, "CREATE SECRET (TYPE HUGGINGFACE, TOKEN "+sqlQuote(o.Token)+")"); err != nil {
				return 0, fmt.Errorf("configure token: %w", err)
			}
		}
	}

	src := "read_parquet(" + sqlQuote(o.Src) + ")"
	if err := checkSchema(ctx, db, src); err != nil {
		return 0, err
	}

	// The first category label is the most specific path, e.g.
	// "Dining and Drinking > Restaurant > Pizzeria".
	q := fmt.Sprintf(`COPY (
		SELECT name, latitude AS lat, longitude AS lon, fsq_category_labels[1] AS category
		FROM %s
		WHERE latitude BETWEEN %v AND %v AND longitude BETWEEN %v AND %v
		  AND date_closed IS NULL AND name IS NOT NULL AND name <> ''
	) TO %s (FORMAT JSON)`, src, o.BBox[1], o.BBox[3], o.BBox[0], o.BBox[2], sqlQuote(o.Out))
	if _, err := db.ExecContext(ctx, q); err != nil {
		return 0, fmt.Errorf("extract: %w", err)
	}

	var n int64
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM read_json("+sqlQuote(o.Out)+", format='newline_delimited')").Scan(&n); err != nil {
		return 0, fmt.Errorf("count output: %w", err)
	}
	return n, nil
}

// checkSchema fails early, with the names that are missing, if the release has
// changed shape, rather than failing deep inside a long remote scan.
func checkSchema(ctx context.Context, db *sql.DB, src string) error {
	rows, err := db.QueryContext(ctx, "SELECT column_name FROM (DESCRIBE SELECT * FROM "+src+")")
	if err != nil {
		return fmt.Errorf("read source: %w", err)
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return err
		}
		have[c] = true
	}
	var missing []string
	for _, want := range []string{"name", "latitude", "longitude", "fsq_category_labels", "date_closed"} {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("source is missing columns %v: the release schema may have changed", missing)
	}
	return nil
}
