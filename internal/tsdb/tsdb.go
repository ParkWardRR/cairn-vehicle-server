// Package tsdb is Cairn's in-memory analytical store.
//
// It is a derived view and nothing more. Raw bundles in the CAS stay
// authoritative; this package decodes them through the same pure, versioned
// decoder the worker uses and holds the result in an in-memory DuckDB, so speed,
// boost and fuel-trim questions run as columnar scans and ASOF joins instead of
// round trips to PostgreSQL.
//
// Volatility is the design, not a limitation. Nothing here is written to disk,
// so there is nothing to back up, migrate or repair: a restart rebuilds the
// whole store from the CAS and the SD card in well under a second at today's
// volume. What stops that from being a leap of faith is the reproducibility
// check — each bundle is decoded twice and the two output digests must match,
// and every table's per-bundle row count is re-read from the database and
// compared with what the decoder produced. A build that cannot reproduce itself
// reports it rather than serving numbers.
package tsdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"github.com/ParkWardRR/Cairn/server/internal/decode"
)

// Options tunes a build.
type Options struct {
	// MemoryLimit is DuckDB's memory ceiling, e.g. "2GB". The VM is shared with
	// the runner and the ingest stack, so an unbounded analytical engine is a
	// way to take the rest of Cairn down.
	MemoryLimit string

	// Threads defaults to GOMAXPROCS.
	Threads int
}

// DB is a built, locked, queryable store.
type DB struct {
	db     *sql.DB
	Report Report
}

// BundleReport is the reproducibility record for one loaded bundle.
type BundleReport struct {
	ContentRoot  string   `json:"content_root"`
	Origin       string   `json:"origin"`
	OutputDigest string   `json:"output_digest"`
	Reproduced   bool     `json:"reproduced"`
	Rows         Counts   `json:"rows"`
	Warnings     []string `json:"warnings,omitempty"`
}

// Counts are per-table row counts.
type Counts struct {
	Position   uint32 `json:"position"`
	IMU        uint32 `json:"imu"`
	OBD        uint32 `json:"obd"`
	Boost      uint32 `json:"boost"`
	Status     uint32 `json:"status"`
	Transition uint32 `json:"transition"`
	Gap        uint32 `json:"gap"`
}

// Report summarises a build.
type Report struct {
	BuiltAt    time.Time      `json:"built_at"`
	BuildMS    int64          `json:"build_ms"`
	DecoderVer int            `json:"decoder_version"`
	Bundles    []BundleReport `json:"bundles"`
	Notes      []string       `json:"notes,omitempty"`

	// Problems are the reproducibility failures. A build with any is not served
	// by default: numbers that did not reproduce are worse than no numbers.
	Problems []string `json:"problems,omitempty"`
}

// OK reports whether the build reproduced cleanly.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

// Build decodes every bundle in the snapshot into a fresh in-memory database.
func Build(ctx context.Context, snap *Snapshot, notes []string, opts Options) (*DB, error) {
	started := time.Now()

	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}
	sdb := sql.OpenDB(connector)

	fail := func(err error) (*DB, error) {
		sdb.Close()
		return nil, err
	}

	threads := opts.Threads
	if threads <= 0 {
		threads = runtime.GOMAXPROCS(0)
	}
	pragmas := []string{
		fmt.Sprintf("SET threads = %d", threads),
		// Row order inside a table is imposed explicitly below. Letting the
		// engine drop insertion order frees it to parallelise the scans.
		"SET preserve_insertion_order = false",
	}
	if opts.MemoryLimit != "" {
		pragmas = append(pragmas, fmt.Sprintf("SET memory_limit = '%s'", opts.MemoryLimit))
	}
	for _, p := range pragmas {
		if _, err := sdb.ExecContext(ctx, p); err != nil {
			return fail(fmt.Errorf("%s: %w", p, err))
		}
	}
	if _, err := sdb.ExecContext(ctx, schemaSQL); err != nil {
		return fail(fmt.Errorf("schema: %w", err))
	}

	report := Report{BuiltAt: started.UTC(), DecoderVer: decode.Version, Notes: notes}

	loaded, err := loadAll(ctx, sdb, snap, &report)
	if err != nil {
		return fail(err)
	}
	if err := reconcile(ctx, sdb, loaded, &report); err != nil {
		return fail(err)
	}

	for _, t := range sampleTables {
		q := fmt.Sprintf("CREATE OR REPLACE TABLE %[1]s AS SELECT * FROM %[1]s ORDER BY boot_id, mono_ms, seq", t)
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return fail(fmt.Errorf("sort %s: %w", t, err))
		}
	}
	if _, err := sdb.ExecContext(ctx, viewsSQL); err != nil {
		return fail(fmt.Errorf("views: %w", err))
	}

	// Lock the engine down before anything can query it. The HTTP surface runs
	// caller-supplied SQL, and DuckDB's SQL can read files, fetch URLs and write
	// them back out; with external access off and the configuration frozen, a
	// query can read the tables and nothing else.
	for _, p := range []string{"SET enable_external_access = false", "SET lock_configuration = true"} {
		if _, err := sdb.ExecContext(ctx, p); err != nil {
			return fail(fmt.Errorf("%s: %w", p, err))
		}
	}

	report.BuildMS = time.Since(started).Milliseconds()
	return &DB{db: sdb, Report: report}, nil
}

// Close releases the database.
func (d *DB) Close() error { return d.db.Close() }

// expected is what the decoder produced for one bundle, kept to compare with
// what the database reports back.
type expected struct {
	root   string
	counts Counts
}

func loadAll(ctx context.Context, sdb *sql.DB, snap *Snapshot, report *Report) ([]expected, error) {
	conn, err := sdb.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	var out []expected
	err = conn.Raw(func(dc any) error {
		dconn, ok := dc.(driver.Conn)
		if !ok {
			return fmt.Errorf("unexpected driver connection %T", dc)
		}

		apps := map[string]*duckdb.Appender{}
		for _, t := range []string{"bundles", "position", "imu", "obd", "boost", "status", "transition", "gap"} {
			a, err := duckdb.NewAppenderFromConn(dconn, "", t)
			if err != nil {
				return fmt.Errorf("appender %s: %w", t, err)
			}
			apps[t] = a
		}

		dec := decode.New(snap.Store)
		for _, ref := range snap.Refs {
			in := decode.Input{ContentRoot: ref.ContentRoot, ManifestDigest: ref.ManifestDigest}

			res, err := dec.Decode(ctx, in)
			if err != nil {
				report.Problems = append(report.Problems,
					fmt.Sprintf("bundle %x (%s): decode failed: %v", ref.ContentRoot[:6], ref.Origin, err))
				continue
			}
			// The decoder is documented as a pure function of the raw bytes.
			// Decoding again and comparing digests is how that is checked rather
			// than assumed.
			again, err := dec.Decode(ctx, in)
			digest := res.OutputDigest()
			reproduced := err == nil && again.OutputDigest() == digest
			if !reproduced {
				report.Problems = append(report.Problems, fmt.Sprintf(
					"bundle %x (%s): second decode did not reproduce the first", ref.ContentRoot[:6], ref.Origin))
			}

			exp, err := appendResult(apps, ref, res, hex.EncodeToString(digest[:]), reproduced)
			if err != nil {
				return fmt.Errorf("bundle %x: %w", ref.ContentRoot[:6], err)
			}
			out = append(out, exp)

			report.Bundles = append(report.Bundles, BundleReport{
				ContentRoot:  exp.root,
				Origin:       ref.Origin,
				OutputDigest: hex.EncodeToString(digest[:]),
				Reproduced:   reproduced,
				Rows:         exp.counts,
				Warnings:     res.Warnings,
			})
		}

		for t, a := range apps {
			if err := a.Close(); err != nil {
				return fmt.Errorf("flush %s: %w", t, err)
			}
		}
		return nil
	})
	return out, err
}

// opt dereferences a decoder's optional value. A nil pointer is the decoder
// saying the device reported "unavailable", which must reach the database as
// NULL and never as a zero that looks like a reading.
func opt[T any](p *T) driver.Value {
	if p == nil {
		return nil
	}
	return *p
}

func appendResult(apps map[string]*duckdb.Appender, ref Ref, res *decode.Result, digest string, reproduced bool) (expected, error) {
	root := hex.EncodeToString(res.ContentRoot[:])
	boot := hex.EncodeToString(res.BootID[:])

	c := Counts{
		Position:   uint32(len(res.Positions)),
		IMU:        uint32(len(res.IMU)),
		OBD:        uint32(len(res.OBD)),
		Boost:      uint32(len(res.Boost)),
		Status:     uint32(len(res.Status)),
		Transition: uint32(len(res.Transitions)),
		Gap:        uint32(len(res.Gaps)),
	}

	row := func(table string, args ...driver.Value) error {
		if err := apps[table].AppendRow(args...); err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
		return nil
	}

	if err := row("bundles", root, hex.EncodeToString(res.BundleID[:]), hex.EncodeToString(res.DeviceID[:]),
		boot, ref.Origin, int32(decode.Version), digest, reproduced, int32(res.DurationMS),
		c.Position, c.IMU, c.OBD, c.Boost, c.Status, c.Transition, c.Gap,
		int32(res.UnknownRecords), strings.Join(res.Warnings, "; ")); err != nil {
		return expected{}, err
	}

	for i := range res.Positions {
		p := &res.Positions[i]
		if err := row("position", root, boot, p.MonotonicMS, p.Seq, p.ObservedAt,
			p.Latitude, p.Longitude, opt(p.AltitudeM), opt(p.SpeedMPS), opt(p.HeadingDeg),
			p.FixType, opt(p.SatsUsed), opt(p.SatsVisible),
			opt(p.HDOP), opt(p.HAccM), opt(p.VAccM), opt(p.UTCAccMS),
			p.SourceFlags, p.FrameFlags); err != nil {
			return expected{}, err
		}
	}
	for i := range res.IMU {
		m := &res.IMU[i]
		if err := row("imu", root, boot, m.MonotonicMS, m.Seq, m.ObservedAt,
			m.WindowMS, m.AccelRMSmg, m.AccelPeakXmg, m.AccelPeakYmg, m.AccelPeakZmg,
			m.GyroPeakDPS, m.Variance, m.SampleCount, m.EventFlags, m.FrameFlags); err != nil {
			return expected{}, err
		}
	}
	for i := range res.OBD {
		o := &res.OBD[i]
		if err := row("obd", root, boot, o.MonotonicMS, o.Seq, o.ObservedAt,
			opt(o.SpeedKPH), opt(o.RPM), opt(o.ThrottlePct), opt(o.EngineLoadPct),
			opt(o.CoolantTempC), opt(o.IntakeTempC),
			opt(o.FuelPressureKPa), opt(o.TimingAdvanceDeg),
			o.PIDErrorCount, o.PIDsRequested, o.PIDsAnswered, opt(o.PollCadenceMS), o.FrameFlags); err != nil {
			return expected{}, err
		}
	}
	for i := range res.Boost {
		b := &res.Boost[i]
		if err := row("boost", root, boot, b.MonotonicMS, b.Seq, b.ObservedAt,
			opt(b.MAPkPa), opt(b.BaroKPa), opt(b.MAFcgps), opt(b.LambdaE4), opt(b.AbsLoadRaw),
			opt(b.AmbientTempC), opt(b.FuelTrimShortPct), opt(b.FuelTrimLongPct),
			opt(b.BoostPSI), opt(b.Lambda),
			b.PIDsRequested, b.PIDsAnswered, b.PollCadenceMS); err != nil {
			return expected{}, err
		}
	}
	for i := range res.Status {
		s := &res.Status[i]
		if err := row("status", root, boot, s.MonotonicMS, s.Seq, s.ObservedAt,
			opt(s.BatteryMV), opt(s.SDWriteErrors), opt(s.SDFreeMiB),
			opt(s.DeviceTempC), opt(s.RSSIdBm), opt(s.ExtSensor1), opt(s.ExtSensor2),
			s.HealthState, s.RebootCount); err != nil {
			return expected{}, err
		}
	}
	for i := range res.Transitions {
		t := &res.Transitions[i]
		if err := row("transition", root, boot, t.MonotonicMS, t.Seq, t.ObservedAt,
			t.Region, t.FromState, t.ToState, t.TriggerEvent, t.ReasonCode, t.PolicyVersion,
			t.StartScore, t.StopScore, t.WakeCause); err != nil {
			return expected{}, err
		}
	}
	for i := range res.Gaps {
		g := &res.Gaps[i]
		if err := row("gap", root, boot, g.Seq, g.StartedAt, g.DurationMS, g.ExpectedSamples, g.Cause); err != nil {
			return expected{}, err
		}
	}

	return expected{root: root, counts: c}, nil
}

// reconcile re-reads per-bundle row counts from the database and compares them
// with what the decoder produced. The appender can succeed and still leave the
// database short — a type coercion that silently dropped a row, say — and this
// is the check that catches it.
func reconcile(ctx context.Context, sdb *sql.DB, loaded []expected, report *Report) error {
	want := map[string]Counts{}
	for _, e := range loaded {
		want[e.root] = e.counts
	}

	got := map[string]*Counts{}
	fields := func(c *Counts, table string) *uint32 {
		switch table {
		case "position":
			return &c.Position
		case "imu":
			return &c.IMU
		case "obd":
			return &c.OBD
		case "boost":
			return &c.Boost
		case "status":
			return &c.Status
		case "transition":
			return &c.Transition
		default:
			return &c.Gap
		}
	}

	for _, t := range []string{"position", "imu", "obd", "boost", "status", "transition", "gap"} {
		rows, err := sdb.QueryContext(ctx, fmt.Sprintf("SELECT content_root, count(*) FROM %s GROUP BY 1", t))
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", t, err)
		}
		for rows.Next() {
			var root string
			var n int64
			if err := rows.Scan(&root, &n); err != nil {
				rows.Close()
				return err
			}
			c := got[root]
			if c == nil {
				c = &Counts{}
				got[root] = c
			}
			*fields(c, t) = uint32(n)
		}
		rows.Close()
	}

	roots := make([]string, 0, len(want))
	for r := range want {
		roots = append(roots, r)
	}
	sort.Strings(roots)
	for _, r := range roots {
		g := Counts{}
		if p := got[r]; p != nil {
			g = *p
		}
		if g != want[r] {
			report.Problems = append(report.Problems, fmt.Sprintf(
				"bundle %s: database holds %+v but the decoder produced %+v", r[:12], g, want[r]))
		}
	}
	return nil
}
