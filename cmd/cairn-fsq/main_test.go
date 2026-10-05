package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// fixture writes a parquet file shaped like an FSQ OS Places release.
func fixture(t *testing.T, dir string) string {
	t.Helper()
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Fatal(err)
	}
	db := sql.OpenDB(connector)
	defer db.Close()

	path := filepath.Join(dir, "places.parquet")
	q := `COPY (SELECT * FROM (VALUES
		('Ralphs',     34.0001, -118.4,  ['Retail > Grocery Store'],        NULL::DATE),
		('Pizza Spot', 34.0002, -118.4,  ['Dining and Drinking > Restaurant > Pizzeria', 'Retail'], NULL::DATE),
		('Closed Cafe',34.0003, -118.4,  ['Dining and Drinking > Cafe'],    DATE '2024-01-01'),
		('Far Away',   40.0,    -100.0,  ['Retail'],                        NULL::DATE),
		('',           34.0004, -118.4,  ['Retail'],                        NULL::DATE)
	) AS t(name, latitude, longitude, fsq_category_labels, date_closed)) TO '` + path + `' (FORMAT PARQUET)`
	if _, err := db.Exec(q); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtractKeepsOpenPlacesInsideTheBox(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.ndjson")
	n, err := extract(context.Background(), options{
		Src: fixture(t, dir), Out: out, BBox: [4]float64{-119, 33.5, -117.5, 34.5},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("wrote %d places, want 2 (open, named, inside the box)", n)
	}

	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r struct {
			Name     string  `json:"name"`
			Lat      float64 `json:"lat"`
			Lon      float64 `json:"lon"`
			Category string  `json:"category"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		got[r.Name] = r.Category
	}
	if got["Pizza Spot"] != "Dining and Drinking > Restaurant > Pizzeria" {
		t.Errorf("category = %q, want the first label", got["Pizza Spot"])
	}
	if _, ok := got["Closed Cafe"]; ok {
		t.Error("a closed place was kept")
	}
}

func TestExtractNamesMissingColumns(t *testing.T) {
	dir := t.TempDir()
	connector, _ := duckdb.NewConnector("", nil)
	db := sql.OpenDB(connector)
	defer db.Close()
	path := filepath.Join(dir, "bad.parquet")
	if _, err := db.Exec(`COPY (SELECT 'x' AS name, 1.0 AS latitude) TO '` + path + `' (FORMAT PARQUET)`); err != nil {
		t.Fatal(err)
	}
	_, err := extract(context.Background(), options{Src: path, Out: filepath.Join(dir, "o"), BBox: [4]float64{-1, -1, 1, 1}})
	if err == nil {
		t.Fatal("expected a schema error")
	}
	t.Log(err)
}

func TestParseBBox(t *testing.T) {
	if _, err := parseBBox("-119,33.6,-117.6,34.4"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", "1,2,3", "a,b,c,d", "5,0,1,1"} {
		if _, err := parseBBox(bad); err == nil {
			t.Errorf("parseBBox(%q) accepted", bad)
		}
	}
}
