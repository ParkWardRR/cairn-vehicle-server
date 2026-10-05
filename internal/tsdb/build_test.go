package tsdb

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

// writeSD lays a synthetic bundle out the way the device writes a sealed one:
// bundles/<id>/{manifest.cbor,manifest.sig,<members>}. The bundle stream is the
// members concatenated in canonical order, so slicing it by the manifest's own
// lengths recovers each file.
func writeSD(t *testing.T, root string, b *testbundle.Bundle, dirName string) string {
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
	return dir
}

func buildFromSD(t *testing.T, sd string) *DB {
	t.Helper()
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
	return db
}

// The pinned digests are the decoder's output at Version 2 for these exact
// synthetic bundles. If one changes, the decoder changed what it produces: that
// is either a bug, or a deliberate change, in which case bump decode.Version and
// update the pins in the same commit so the shift is visible in review rather
// than discovered later in every chart.
func TestGoldenDigests(t *testing.T) {
	cases := []struct {
		name   string
		opts   testbundle.Options
		digest string
		rows   Counts
	}{
		{
			name:   "default",
			opts:   testbundle.Default(),
			digest: "37b4f1bc9adc96bd15ffa5b7fb0475aaf45d55b9c0ce97674c9b977811084260",
			rows:   Counts{Position: 12, OBD: 7, Transition: 4},
		},
		{
			name:   "gap-and-fixless",
			opts:   testbundle.Options{ChunkSize: 256, GNSSSamples: 20, OBDSamples: 5, JournalEntries: 2, GapAfter: 8, FixlessFrom: 15},
			digest: "7760c135d8316d8e97d8c669cddc3d8354ea653bb7c187d10ca78a19e39e9d86",
			rows:   Counts{Position: 15, OBD: 5, Transition: 2, Gap: 1},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := testbundle.Build(c.opts)
			if err != nil {
				t.Fatal(err)
			}
			sd := t.TempDir()
			writeSD(t, sd, b, "b1")

			db := buildFromSD(t, sd)
			r := db.Report

			if !r.OK() {
				t.Fatalf("did not reproduce: %v", r.Problems)
			}
			if len(r.Bundles) != 1 {
				t.Fatalf("loaded %d bundles, want 1", len(r.Bundles))
			}
			got := r.Bundles[0]
			t.Logf("digest=%s rows=%+v warnings=%v", got.OutputDigest, got.Rows, got.Warnings)

			if !got.Reproduced {
				t.Error("second decode did not match the first")
			}
			if got.OutputDigest != c.digest {
				t.Errorf("output digest = %s, want %s — the decoder's output changed", got.OutputDigest, c.digest)
			}
			if got.Rows != c.rows {
				t.Errorf("rows = %+v, want %+v", got.Rows, c.rows)
			}
		})
	}
}

// v1 is dead: a trips/ directory beside bundles/ must be ignored, not parsed and
// not an error.
func TestV1TripsIgnored(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	writeSD(t, sd, b, "b1")

	trip := filepath.Join(sd, "trips", "000001E9A8858FD0AC5CE73802")
	if err := os.MkdirAll(trip, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"samples.bin", "obd.bin", "health.bin", "imu_summary.bin"} {
		if err := os.WriteFile(filepath.Join(trip, f), []byte("not a v2 bundle"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	db := buildFromSD(t, sd)
	if !db.Report.OK() || len(db.Report.Bundles) != 1 {
		t.Fatalf("report = %+v", db.Report)
	}
	for _, n := range db.Report.Notes {
		if strings.Contains(n, "trips") {
			t.Errorf("v1 trips were looked at: %s", n)
		}
	}
}

// A member that does not hash to its manifest digest must be refused, never
// quietly decoded.
func TestCorruptMemberRefused(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	dir := writeSD(t, sd, b, "b1")

	victim := filepath.Join(dir, b.Manifest.Members[0].Name)
	data, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(victim, data, 0o644); err != nil {
		t.Fatal(err)
	}

	db := buildFromSD(t, sd)
	if n := len(db.Report.Bundles); n != 0 {
		t.Fatalf("loaded %d bundles from a corrupt card, want 0", n)
	}
	var said bool
	for _, n := range db.Report.Notes {
		if strings.Contains(n, "fails its manifest digest") {
			said = true
		}
	}
	if !said {
		t.Errorf("no note explaining the refusal: %v", db.Report.Notes)
	}
}

// The same bundle on the card twice (two directory names, one content root)
// loads once.
func TestDedupOnContentRoot(t *testing.T) {
	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	writeSD(t, sd, b, "copy-a")
	writeSD(t, sd, b, "copy-b")

	db := buildFromSD(t, sd)
	if n := len(db.Report.Bundles); n != 1 {
		t.Fatalf("loaded %d bundles, want 1: %+v", n, db.Report.Notes)
	}
}
