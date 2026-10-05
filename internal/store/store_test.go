package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/decode"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
	"github.com/ParkWardRR/Cairn/server/internal/store"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
	"github.com/ParkWardRR/Cairn/server/internal/tsdb"
	"github.com/ParkWardRR/Cairn/server/internal/worker"
)

// These tests need a real PostgreSQL with PostGIS. Partitioning, geography
// columns and ON CONFLICT behaviour are exactly the things a fake would get
// wrong while reporting success, so there is no mock here.
//
//	CAIRN_TEST_DSN=postgres://postgres:test@127.0.0.1:55432/cairn go test ./internal/store/
func dsn(t *testing.T) string {
	t.Helper()
	d := os.Getenv("CAIRN_TEST_DSN")
	if d == "" {
		t.Skip("set CAIRN_TEST_DSN to run the database integration tests")
	}
	return d
}

// env is a full pipeline: ingest, outbox, decoder, worker and database.
type env struct {
	root     string
	cas      *cas.Store
	receipts *receipts.Store
	registry *devices.Registry
	outbox   *outbox.Queue
	intake   *intake.Service
	db       *store.Store
	worker   *worker.Worker
}

// testLogger discards by default and writes to stderr under
// CAIRN_TEST_VERBOSE, so a failing drain can be diagnosed.
func testLogger() *slog.Logger {
	if os.Getenv("CAIRN_TEST_VERBOSE") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()

	root := t.TempDir()

	casStore, err := cas.Open(filepath.Join(root, "cas"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipts.Open(receipts.Config{
		Dir:     filepath.Join(root, "receipts"),
		KeyPath: filepath.Join(root, "keys", "receipt.seed"),
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := devices.Open(filepath.Join(root, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	regs, err := testbundle.OpenRegistries(root)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := intake.New(intake.Config{
		CAS: casStore, Receipts: rec, Registry: reg, Outbox: ob,
		OfferDir: filepath.Join(root, "offers"),
		Vehicles: regs.Vehicles, Counters: regs.Counters, Keys: regs.Keys,
	})
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := testbundle.DeviceKey()
	if _, err := reg.Enroll(testbundle.DeviceID(), "decode-test", pub, 0); err != nil {
		t.Fatal(err)
	}

	db, err := store.Open(ctx, dsn(t))
	if err != nil {
		t.Fatalf("connect to the test database: %v", err)
	}
	t.Cleanup(db.Close)

	w := worker.New(worker.Config{
		Outbox:   ob,
		Store:    db,
		Decoder:  decode.New(casStore, testbundle.Keys()),
		Log:      testLogger(),
		CAS:      casStore,
		Registry: reg,
		Receipts: rec,
	})

	return &env{
		root: root, cas: casStore, receipts: rec, registry: reg,
		outbox: ob, intake: svc, db: db, worker: w,
	}
}

// syncBundle runs a full offer/transfer/commit, leaving a job in the outbox.
func (e *env) syncBundle(t *testing.T, b *testbundle.Bundle) {
	t.Helper()

	offer, err := e.intake.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	for _, idx := range offer.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		if _, err := e.intake.AcceptChunk(b.Manifest.BundleID, d.SHA256, b.Chunks[idx]); err != nil {
			t.Fatalf("chunk %d: %v", idx, err)
		}
	}
	if _, err := e.intake.Commit(b.Manifest.BundleID); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// cleanup removes this bundle's rows, so repeated runs against a shared
// database do not interfere.
func (e *env) cleanup(t *testing.T, contentRoot [32]byte) {
	t.Helper()
	ctx := context.Background()

	for _, q := range []string{
		`DELETE FROM derived.gaps WHERE content_root = $1`,
		`DELETE FROM derived.events WHERE content_root = $1`,
		`DELETE FROM derived.trip_segments WHERE trip_id IN
			(SELECT trip_id FROM derived.trips WHERE content_root = $1)`,
		`DELETE FROM derived.trips WHERE content_root = $1`,
		`DELETE FROM derived.decode_runs WHERE content_root = $1`,
		`DELETE FROM norm.position_samples WHERE content_root = $1`,
		`DELETE FROM norm.imu_samples WHERE content_root = $1`,
		`DELETE FROM norm.obd_samples WHERE content_root = $1`,
		`DELETE FROM norm.boost_samples WHERE content_root = $1`,
		`DELETE FROM norm.device_status WHERE content_root = $1`,
		`DELETE FROM norm.state_transitions WHERE content_root = $1`,
		`DELETE FROM raw.bundle_chunks WHERE content_root = $1`,
		`DELETE FROM raw.bundle_members WHERE content_root = $1`,
		`DELETE FROM raw.ingest_receipts WHERE content_root = $1`,
		`DELETE FROM raw.bundles WHERE content_root = $1`,
	} {
		if _, err := e.db.Pool().Exec(ctx, q, contentRoot[:]); err != nil {
			t.Logf("cleanup %q: %v", q, err)
		}
	}
}

// ─── the full pipeline ──────────────────────────────────────────────────────

// A bundle synced through ingest must come out the other side as normalized
// samples and a derived trip, with nothing done on the request path.
func TestDecodePipelineEndToEnd(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)

	// Ingest queued the work rather than doing it.
	pending, err := e.outbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d pending jobs, want 1", len(pending))
	}

	n, err := e.worker.DrainOnce(ctx)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("drained %d jobs, want 1", n)
	}

	// The job is acknowledged, so it is not redelivered.
	if after, err := e.outbox.PendingCount(); err != nil {
		t.Fatal(err)
	} else if after != 0 {
		t.Errorf("%d jobs still pending after a successful drain", after)
	}

	root := b.Manifest.ContentRoot

	// Raw metadata mirrored.
	bundle, err := e.db.LookupBundle(ctx, root)
	if err != nil {
		t.Fatalf("bundle not recorded: %v", err)
	}
	if bundle.DeviceID != testbundle.DeviceID() {
		t.Error("bundle recorded against the wrong device")
	}

	// Normalized samples, matching the bundle's record counts.
	positions, err := e.db.CountRows(ctx, "norm.position_samples", root)
	if err != nil {
		t.Fatal(err)
	}
	wantPositions := int(b.Manifest.RecordCounts[format.RecordGNSSSample])
	if positions != wantPositions {
		t.Errorf("%d position samples, want %d", positions, wantPositions)
	}

	obd, err := e.db.CountRows(ctx, "norm.obd_samples", root)
	if err != nil {
		t.Fatal(err)
	}
	wantOBD := int(b.Manifest.RecordCounts[format.RecordOBDSnapshot])
	if obd != wantOBD {
		t.Errorf("%d OBD samples, want %d", obd, wantOBD)
	}

	transitions, err := e.db.CountRows(ctx, "norm.state_transitions", root)
	if err != nil {
		t.Fatal(err)
	}
	wantTransitions := int(b.Manifest.RecordCounts[format.RecordStateTransition])
	if transitions != wantTransitions {
		t.Errorf("%d state transitions, want %d", transitions, wantTransitions)
	}

	// A derived trip with a route.
	var (
		tripCount   int
		distanceM   float64
		sampleCount int
		hasRoute    bool
	)
	err = e.db.Pool().QueryRow(ctx, `
		SELECT count(*), COALESCE(max(distance_m),0), COALESCE(max(sample_count),0),
		       bool_or(route_geom IS NOT NULL)
		FROM derived.trips WHERE content_root = $1
	`, root[:]).Scan(&tripCount, &distanceM, &sampleCount, &hasRoute)
	if err != nil {
		t.Fatal(err)
	}

	if tripCount != 1 {
		t.Fatalf("%d trips, want 1", tripCount)
	}
	if distanceM <= 0 {
		t.Errorf("trip distance is %f, want a positive distance", distanceM)
	}
	if sampleCount != wantPositions {
		t.Errorf("trip sample_count = %d, want %d", sampleCount, wantPositions)
	}
	if !hasRoute {
		t.Error("the trip has no route geometry despite having fixed positions")
	}

	// A decode run was recorded with a digest.
	run, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatalf("decode run not recorded: %v", err)
	}
	if run.OutputDigest == [32]byte{} {
		t.Error("the decode run has a zero output digest")
	}
	if run.PositionSamples != wantPositions {
		t.Errorf("run records %d positions, want %d", run.PositionSamples, wantPositions)
	}
}

// ─── reproducibility ────────────────────────────────────────────────────────

// Property: the decoder is a pure function of the raw bytes and its version, so
// re-decoding the same bundle produces the same output digest.
//
// This is the matrix row the architecture has been claiming since Phase 2 and
// could not demonstrate until the decoder existed.
func TestDecodeIsReproducible(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)

	decoder := decode.New(e.cas, testbundle.Keys())
	manifestDigest := sha256.Sum256(b.ManifestBytes)

	in := decode.Input{ContentRoot: b.Manifest.ContentRoot, ManifestDigest: manifestDigest}

	first, err := decoder.Decode(ctx, in)
	if err != nil {
		t.Fatalf("first decode: %v", err)
	}
	firstDigest := first.OutputDigest()

	// Decode repeatedly. A digest that varies would mean map iteration order,
	// a timestamp or a float difference leaking into the output.
	for i := 0; i < 20; i++ {
		again, err := decoder.Decode(ctx, in)
		if err != nil {
			t.Fatalf("decode %d: %v", i, err)
		}
		if again.OutputDigest() != firstDigest {
			t.Fatalf("decode %d produced a different digest: %x then %x",
				i, firstDigest, again.OutputDigest())
		}
	}

	// And the derived identities must be stable, not merely the digest.
	again, err := decoder.Decode(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if again.Trip.TripID != first.Trip.TripID {
		t.Error("the trip ID is not deterministic")
	}
	if len(again.Events) != len(first.Events) {
		t.Fatalf("event count changed: %d then %d", len(first.Events), len(again.Events))
	}
	for i := range first.Events {
		if again.Events[i].EventID != first.Events[i].EventID {
			t.Errorf("event %d (%s) has a non-deterministic ID", i, first.Events[i].Kind)
		}
	}
}

// Property: re-decoding converges on the same database state. A redelivered job
// costs a repeat, never a duplicate.
func TestReDecodeIsIdempotent(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot
	snapshot := func() map[string]int {
		t.Helper()
		out := map[string]int{}
		for _, table := range []string{
			"norm.position_samples", "norm.imu_samples", "norm.obd_samples",
			"norm.boost_samples", "norm.device_status", "norm.state_transitions",
			"derived.trips", "derived.events", "derived.gaps",
		} {
			n, err := e.db.CountRows(ctx, table, root)
			if err != nil {
				t.Fatalf("count %s: %v", table, err)
			}
			out[table] = n
		}
		return out
	}

	before := snapshot()
	runBefore, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatal(err)
	}

	// Re-enqueue and drain three more times, as a redelivered job would.
	for i := 0; i < 3; i++ {
		if err := worker.Reprocess(ctx, e.outbox, e.db, root); err != nil {
			t.Fatalf("reprocess %d: %v", i, err)
		}
		if n, err := e.worker.DrainOnce(ctx); err != nil {
			t.Fatalf("drain %d: %v", i, err)
		} else if n != 1 {
			t.Fatalf("drain %d handled %d jobs, want 1", i, n)
		}
	}

	after := snapshot()
	for table, want := range before {
		if after[table] != want {
			t.Errorf("%s has %d rows after re-decoding, want %d — re-decoding must converge",
				table, after[table], want)
		}
	}

	runAfter, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatal(err)
	}
	if runAfter.OutputDigest != runBefore.OutputDigest {
		t.Errorf("output digest changed across re-decodes: %x then %x",
			runBefore.OutputDigest, runAfter.OutputDigest)
	}

	// Exactly one decode-run row, not one per attempt.
	var runs int
	if err := e.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM derived.decode_runs WHERE content_root = $1`,
		root[:]).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Errorf("%d decode_runs rows, want 1", runs)
	}
}

// ─── honest incompleteness ──────────────────────────────────────────────────

// Property: a recorded gap survives into the derived layer, and the route is
// not joined across it.
//
// This is invariant 4 made checkable: a trip with a marked gap is useful, a
// route interpolated across one is a fabrication.
func TestGapsAreRecordedAndNotBridged(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// A bundle with a gap record between two distant fixes.
	opts := testbundle.Default()
	opts.GapAfter = 5
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot

	gaps, err := e.db.CountRows(ctx, "derived.gaps", root)
	if err != nil {
		t.Fatal(err)
	}
	if gaps != 1 {
		t.Fatalf("%d gap rows, want 1 — a recorded absence must survive decoding", gaps)
	}

	var gapCount, gapDurationS int
	if err := e.db.Pool().QueryRow(ctx, `
		SELECT gap_count, gap_duration_s FROM derived.trips WHERE content_root = $1
	`, root[:]).Scan(&gapCount, &gapDurationS); err != nil {
		t.Fatal(err)
	}
	if gapCount != 1 {
		t.Errorf("trip gap_count = %d, want 1", gapCount)
	}
	if gapDurationS <= 0 {
		t.Errorf("trip gap_duration_s = %d, want a positive duration", gapDurationS)
	}

	// The gap must appear as its own segment, so a map can render a break.
	var gapSegments int
	if err := e.db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM derived.trip_segments s
		JOIN derived.trips t ON t.trip_id = s.trip_id
		WHERE t.content_root = $1 AND s.kind = 'gap'
	`, root[:]).Scan(&gapSegments); err != nil {
		t.Fatal(err)
	}
	if gapSegments != 1 {
		t.Errorf("%d gap segments, want 1", gapSegments)
	}
}

// Property: a sample without a fix is recorded but is not a plottable position.
func TestFixlessSamplesAreRecordedNotPlotted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	opts := testbundle.Default()
	opts.FixlessFrom = 10
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot

	var total, fixless int
	if err := e.db.Pool().QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE fix_type = 0)
		FROM norm.position_samples WHERE content_root = $1
	`, root[:]).Scan(&total, &fixless); err != nil {
		t.Fatal(err)
	}

	if fixless == 0 {
		t.Fatal("no fix-less samples were recorded; the absence is data and must be kept")
	}

	// The trip's sample_count covers every sample, but the route must contain
	// only the fixed ones.
	var routePoints int
	if err := e.db.Pool().QueryRow(ctx, `
		SELECT COALESCE(ST_NPoints(route_geom::geometry), 0)
		FROM derived.trips WHERE content_root = $1
	`, root[:]).Scan(&routePoints); err != nil {
		t.Fatal(err)
	}

	if routePoints != total-fixless {
		t.Errorf("the route has %d points but %d samples carried a fix — a fix-less "+
			"sample must never be plotted", routePoints, total-fixless)
	}
}

// ─── partitioning ───────────────────────────────────────────────────────────

// Samples must land in the monthly partition for their observation time, not
// the default, so retention and query pruning work as designed.
func TestSamplesLandInMonthlyPartitions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot

	var inDefault int
	if err := e.db.Pool().QueryRow(ctx, `
		SELECT count(*) FROM norm.position_samples_default WHERE content_root = $1
	`, root[:]).Scan(&inDefault); err != nil {
		t.Fatal(err)
	}
	if inDefault != 0 {
		t.Errorf("%d samples landed in the default partition; the worker should have "+
			"provisioned the monthly one", inDefault)
	}

	// The expected monthly partition should exist and hold them.
	observedAt := time.UnixMilli(int64(b.Manifest.UTCBasisMS)).UTC()
	partition := fmt.Sprintf("norm.position_samples_%s", observedAt.Format("200601"))

	var inMonth int
	if err := e.db.Pool().QueryRow(ctx,
		fmt.Sprintf(`SELECT count(*) FROM %s WHERE content_root = $1`, partition),
		root[:]).Scan(&inMonth); err != nil {
		t.Fatalf("query %s: %v", partition, err)
	}
	if inMonth == 0 {
		t.Errorf("no samples in %s", partition)
	}
}

// ─── rollups ────────────────────────────────────────────────────────────────

// Dashboard cards read rollups rather than scanning telemetry, so the rollup
// must agree with the trips it summarises.
func TestDailyRollupMatchesTrips(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	device := testbundle.DeviceID()

	var (
		rollupTrips    int
		rollupDistance float64
		tripCount      int
		tripDistance   float64
	)

	if err := e.db.Pool().QueryRow(ctx, `
		SELECT r.trip_count, r.distance_m,
		       (SELECT count(*) FROM derived.trips t
		        WHERE t.device_id = r.device_id AND t.started_at::date = r.day),
		       (SELECT COALESCE(sum(t.distance_m),0) FROM derived.trips t
		        WHERE t.device_id = r.device_id AND t.started_at::date = r.day)
		FROM derived.daily_rollups r
		WHERE r.device_id = $1
		ORDER BY r.day DESC LIMIT 1
	`, device[:]).Scan(&rollupTrips, &rollupDistance, &tripCount, &tripDistance); err != nil {
		t.Fatalf("no rollup recorded: %v", err)
	}

	if rollupTrips != tripCount {
		t.Errorf("rollup trip_count = %d, trips table has %d", rollupTrips, tripCount)
	}
	if diff := rollupDistance - tripDistance; diff > 0.01 || diff < -0.01 {
		t.Errorf("rollup distance %f does not match the trips' %f", rollupDistance, tripDistance)
	}
}

// ─── failure isolation ──────────────────────────────────────────────────────

// Property: a worker that cannot decode must not lose the job, and must not
// affect the raw bundle or its receipt.
//
// By the time a job reaches the worker the device may already have pruned its
// copy on the strength of a receipt it legitimately holds, so discarding the
// job would be the one genuinely destructive option.
func TestDecodeFailureLeavesRawAndReceiptIntact(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	root := b.Manifest.ContentRoot

	// Enqueue a job whose manifest digest points at nothing, so the decode
	// cannot succeed.
	bogus := sha256.Sum256([]byte("not a manifest"))
	if err := e.outbox.Append(outbox.Entry{
		BundleID:       hex.EncodeToString(b.Manifest.BundleID[:]),
		DeviceID:       hex.EncodeToString(b.Manifest.DeviceID[:]),
		ContentRoot:    hex.EncodeToString(root[:]),
		ManifestDigest: hex.EncodeToString(bogus[:]),
	}); err != nil {
		t.Fatal(err)
	}

	// The good job succeeds; the bad one fails and stays pending.
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	pending, err := e.outbox.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("%d jobs pending, want 1 — a failed job must not be acknowledged", len(pending))
	}

	// The receipt is untouched: the device's proof of delivery does not depend
	// on anything the worker does.
	if _, _, err := e.receipts.Lookup(root); err != nil {
		t.Errorf("the receipt was affected by a decode failure: %v", err)
	}

	// And the raw members are all still retrievable.
	for _, m := range b.Manifest.Members {
		if _, err := e.cas.GetVerified(m.SHA256); err != nil {
			t.Errorf("raw member %q affected by a decode failure: %v", m.Name, err)
		}
	}
}

// ─── decoder upgrade ────────────────────────────────────────────────────────

// Fault matrix row: "parser upgrade — the same raw bundle yields versioned,
// reproducible derived output."
//
// This is the property that makes a decoder bug fixable. A new decoder version
// re-derives from raw, records its own run alongside the old one, and the two
// digests show exactly which bundles the change altered. Raw is never touched,
// so no device re-uploads anything.
func TestDecoderUpgradeReDerivesFromRaw(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot

	v1, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatalf("the original decode run is missing: %v", err)
	}

	// Simulate the next decoder version recording a run over the same raw
	// bundle. A real upgrade bumps decode.Version; here the row is written
	// directly, because the point under test is that versions coexist and stay
	// comparable rather than overwrite each other.
	nextVersion := decode.Version + 1
	alteredDigest := sha256.Sum256([]byte("output from a corrected decoder"))

	if _, err := e.db.Pool().Exec(ctx, `
		INSERT INTO derived.decode_runs (
			content_root, decoder_version, duration_ms,
			position_samples, events, output_digest
		) VALUES ($1, $2, 1, $3, $4, $5)
	`, root[:], nextVersion, v1.PositionSamples, v1.Events, alteredDigest[:]); err != nil {
		t.Fatalf("record the upgraded run: %v", err)
	}

	// Both runs must survive: the old one is the record of what was previously
	// derived, which is what makes the change auditable.
	v1Again, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatalf("the original run was lost when a newer version was recorded: %v", err)
	}
	if v1Again.OutputDigest != v1.OutputDigest {
		t.Error("recording a newer decoder version altered the older run's digest")
	}

	v2, err := e.db.LookupDecodeRun(ctx, root, nextVersion)
	if err != nil {
		t.Fatalf("the upgraded run was not recorded: %v", err)
	}

	// The digests differ, which is precisely the signal an operator needs:
	// this bundle's derived output changed under the new decoder.
	if v2.OutputDigest == v1.OutputDigest {
		t.Error("the two versions have identical digests, so the comparison proves nothing")
	}

	// And the raw layer is untouched by any of it.
	for _, m := range b.Manifest.Members {
		if _, err := e.cas.GetVerified(m.SHA256); err != nil {
			t.Errorf("raw member %q was affected by a decoder upgrade: %v", m.Name, err)
		}
	}

	var rawBundles int
	if err := e.db.Pool().QueryRow(ctx,
		`SELECT count(*) FROM raw.bundles WHERE content_root = $1`, root[:]).Scan(&rawBundles); err != nil {
		t.Fatal(err)
	}
	if rawBundles != 1 {
		t.Errorf("%d raw bundle rows after an upgrade, want 1", rawBundles)
	}

	// Re-deriving at the current version must still converge, so an upgrade
	// does not leave the pipeline unable to re-run.
	if err := worker.Reprocess(ctx, e.outbox, e.db, root); err != nil {
		t.Fatal(err)
	}
	if n, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatalf("re-decode after an upgrade: %v", err)
	} else if n != 1 {
		t.Fatalf("re-decode handled %d jobs, want 1", n)
	}

	final, err := e.db.LookupDecodeRun(ctx, root, decode.Version)
	if err != nil {
		t.Fatal(err)
	}
	if final.OutputDigest != v1.OutputDigest {
		t.Error("re-decoding at the original version produced a different digest")
	}
}

// Property: a worker crash loop does not prevent a device from syncing and
// being receipted.
//
// Stated in the plan's acceptance criteria for this phase, and worth asserting
// rather than assuming: ingest has no database dependency, so a worker that
// cannot reach Postgres at all must not affect the sync path.
func TestSyncSucceedsWithNoWorkerOrDatabase(t *testing.T) {
	e := newEnv(t)

	// Close the database the worker would use, modelling a Postgres outage.
	e.db.Close()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}

	// The full sync must still complete and produce a verifiable receipt.
	offer, err := e.intake.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("offer failed during a database outage: %v", err)
	}
	for _, idx := range offer.MissingChunks {
		d := b.Manifest.ChunkDescriptors[idx]
		if _, err := e.intake.AcceptChunk(b.Manifest.BundleID, d.SHA256, b.Chunks[idx]); err != nil {
			t.Fatalf("chunk %d failed during a database outage: %v", idx, err)
		}
	}

	result, err := e.intake.Commit(b.Manifest.BundleID)
	if err != nil {
		t.Fatalf("commit failed during a database outage: %v", err)
	}

	if err := result.Receipt.VerifyAcknowledges(
		e.receipts.PublicKey(), b.Manifest.ContentRoot); err != nil {
		t.Errorf("the receipt issued during a database outage does not verify: %v", err)
	}

	// The work is queued, waiting for a worker that can reach the database.
	if n, err := e.outbox.PendingCount(); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("%d jobs queued, want 1 — the decode should be waiting, not lost", n)
	}
}

// A bundle_id recorded against different content must be reported, not
// silently discarded.
//
// bundle_id is a device-assigned ULID, so this should be impossible. If it ever
// happens it means a device is reusing identifiers or a ULID collided, and
// swallowing it would leave the second bundle permanently unqueryable while
// everything appeared to succeed.
func TestBundleIDConflictIsReported(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	first, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, first.Manifest.ContentRoot) })

	e.syncBundle(t, first)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// A second bundle with different content but the first one's bundle_id.
	opts := testbundle.Default()
	opts.GNSSSamples = 20
	opts.Mutate = func(m *format.Manifest) {
		m.BundleID = first.Manifest.BundleID
	}
	second, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, second.Manifest.ContentRoot) })

	if second.Manifest.ContentRoot == first.Manifest.ContentRoot {
		t.Fatal("the two bundles must differ in content for this test to mean anything")
	}

	pub, _ := testbundle.DeviceKey()
	manifestDigest := sha256.Sum256(second.ManifestBytes)

	err = e.db.RecordBundle(ctx, store.BundleCommit{
		Manifest:       second.Manifest,
		ManifestDigest: manifestDigest,
		CommittedAt:    time.Now().UTC(),
	})
	_ = pub

	if err == nil {
		t.Fatal("recording a conflicting bundle_id succeeded; the anomaly would be invisible")
	}
	if !errors.Is(err, store.ErrBundleIDConflict) {
		t.Fatalf("error = %v, want store.ErrBundleIDConflict", err)
	}
}

// ─── parity ────────────────────────────────────────────────────────────────

// Property: decoding the same bundle into PostgreSQL and DuckDB produces
// identical row counts per table. This is the parity assertion the roadmap
// calls for — one bundle set, two stores, same numbers.
func TestParityWithDuckDB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	b, err := testbundle.Build(testbundle.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.cleanup(t, b.Manifest.ContentRoot) })

	e.syncBundle(t, b)
	if _, err := e.worker.DrainOnce(ctx); err != nil {
		t.Fatal(err)
	}

	root := b.Manifest.ContentRoot

	// Build the same bundle into DuckDB via the analytical store path.
	snap, _, err := tsdb.SnapshotSources("", e.root, "")
	if err != nil {
		t.Fatalf("snapshot sources: %v", err)
	}
	defer snap.Close()

	db, err := tsdb.Build(ctx, snap, nil, tsdb.Options{MemoryLimit: "256MB"})
	if err != nil {
		t.Fatalf("duckdb build: %v", err)
	}
	defer db.Close()

	if len(db.Report.Bundles) != 1 {
		t.Fatalf("duckdb loaded %d bundles, want 1", len(db.Report.Bundles))
	}
	if !db.Report.OK() {
		t.Fatalf("duckdb build did not reproduce: %v", db.Report.Problems)
	}

	duck := db.Report.Bundles[0].Rows

	type pair struct {
		table string
		duck  uint32
	}
	tables := []pair{
		{"norm.position_samples", duck.Position},
		{"norm.imu_samples", duck.IMU},
		{"norm.obd_samples", duck.OBD},
		{"norm.boost_samples", duck.Boost},
		{"norm.device_status", duck.Status},
		{"norm.state_transitions", duck.Transition},
		{"derived.gaps", duck.Gap},
	}

	for _, p := range tables {
		pg, err := e.db.CountRows(ctx, p.table, root)
		if err != nil {
			t.Fatalf("count %s: %v", p.table, err)
		}
		if uint32(pg) != p.duck {
			t.Errorf("%s: PostgreSQL has %d rows, DuckDB has %d — the two stores disagree",
				p.table, pg, p.duck)
		}
	}
}
