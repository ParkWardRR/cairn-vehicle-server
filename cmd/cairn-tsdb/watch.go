package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/tsdb"
)

// fingerprint summarises what the sources currently hold, cheaply enough to
// poll: the number of entries and the newest modification time in each watched
// directory.
//
// A receipt is the commit point. An offer is a promise the device made and a
// chunk is a half-finished upload, so neither is watched; a rebuild triggered by
// them would load nothing new. The card mirror is watched through its bundles/
// directory, since a bundle there is complete by construction (sealed bundles
// are never mutated).
func (c config) fingerprint() string {
	var dirs []string
	if c.dataDir != "" {
		dirs = append(dirs, filepath.Join(c.dataDir, "receipts"))
	}
	if c.sdRoot != "" {
		dirs = append(dirs, filepath.Join(c.sdRoot, "bundles"))
	}

	var b strings.Builder
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			fmt.Fprintf(&b, "%s:err;", d)
			continue
		}
		var newest time.Time
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
		fmt.Fprintf(&b, "%s:%d:%d;", d, len(entries), newest.UnixNano())
	}
	return b.String()
}

// watch rebuilds when the sources change.
//
// A change must hold still for one full interval before the rebuild starts. A
// card being copied in, or a burst of receipts, would otherwise trigger a
// rebuild per file, each holding a full copy of the data in memory.
func (s *server) watch(ctx context.Context, every time.Duration) {
	seen := s.cfg.fingerprint()
	pending := ""

	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		now := s.cfg.fingerprint()
		switch {
		case now == seen:
			pending = ""
		case now != pending:
			pending = now // changed; wait one more tick to see if it settles
		default:
			s.log.Info("sources changed; rebuilding")
			_, err := s.rebuild(ctx)
			switch {
			case errors.Is(err, errUnreproduced):
				s.log.Error("rebuild did not reproduce; still serving the previous store")
			case err != nil:
				s.log.Error("rebuild failed; still serving the previous store", "error", err)
			default:
				s.log.Info("rebuilt", "bundles", len(s.cur.Load().Report.Bundles))
			}
			// Record the fingerprint either way. Retrying a failing rebuild every
			// tick would hold a full copy of the data in memory each time.
			seen, pending = now, ""
		}
	}
}

// metrics writes Prometheus text exposition by hand: a handful of gauges does
// not justify a client library in a binary that already links a database
// engine.
func (s *server) metrics(w http.ResponseWriter, _ *http.Request) {
	r := s.cur.Load().Report

	var rows totals
	reproduced := 0
	for _, b := range r.Bundles {
		if b.Reproduced {
			reproduced++
		}
		rows.add(b.Rows)
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	g := func(name, help string, v any) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, v)
	}
	g("cairn_tsdb_build_seconds", "Wall time of the build serving now.", float64(r.BuildMS)/1000)
	g("cairn_tsdb_built_timestamp_seconds", "When the serving build finished.", r.BuiltAt.Unix())
	g("cairn_tsdb_bundles", "Bundles loaded.", len(r.Bundles))
	g("cairn_tsdb_bundles_reproduced", "Bundles whose second decode matched the first.", reproduced)
	g("cairn_tsdb_problems", "Reproducibility problems in the serving build.", len(r.Problems))
	g("cairn_tsdb_decoder_version", "Decoder version the build used.", r.DecoderVer)

	fmt.Fprintf(w, "# HELP cairn_tsdb_rows Rows loaded, by table.\n# TYPE cairn_tsdb_rows gauge\n")
	for _, t := range []struct {
		name string
		n    uint64
	}{
		{"position", rows.Position}, {"imu", rows.IMU}, {"obd", rows.OBD}, {"boost", rows.Boost},
		{"status", rows.Status}, {"transition", rows.Transition}, {"gap", rows.Gap},
	} {
		fmt.Fprintf(w, "cairn_tsdb_rows{table=%q} %d\n", t.name, t.n)
	}

	g("cairn_tsdb_go_heap_bytes", "Go heap in use. DuckDB's own memory is native and is bounded by -memory and the unit's MemoryMax.", ms.HeapAlloc)

	snapData, snapMeta := s.cur.Load().Snapshot()
	snapSize := 0
	if snapData != nil {
		snapSize = len(snapData)
	}
	g("cairn_tsdb_snapshot_bytes", "Compressed snapshot archive size (zstd).", snapSize)
	if snapMeta != nil {
		g("cairn_tsdb_snapshot_tables", "Number of tables in the snapshot.", len(snapMeta.Tables))
	}

	fmt.Fprintf(w, "# HELP cairn_tsdb_snapshot_format_bytes Snapshot archive size by format.\n# TYPE cairn_tsdb_snapshot_format_bytes gauge\n")
	for _, f := range tsdb.SnapshotFormatNames() {
		data, _, _, _ := s.cur.Load().SnapshotFormat(f)
		sz := 0
		if data != nil {
			sz = len(data)
		}
		fmt.Fprintf(w, "cairn_tsdb_snapshot_format_bytes{format=%q} %d\n", f, sz)
	}
}

// totals sums per-table rows across bundles.
type totals struct {
	Position, IMU, OBD, Boost, Status, Transition, Gap uint64
}

func (c *totals) add(o tsdb.Counts) {
	c.Position += uint64(o.Position)
	c.IMU += uint64(o.IMU)
	c.OBD += uint64(o.OBD)
	c.Boost += uint64(o.Boost)
	c.Status += uint64(o.Status)
	c.Transition += uint64(o.Transition)
	c.Gap += uint64(o.Gap)
}
