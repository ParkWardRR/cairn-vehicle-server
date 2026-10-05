package syncapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// The trip_summary publisher.
//
// The app learns about trips through the same cursor as everything else: as
// trip_summary entities in the sync log. Something has to turn "a bundle was
// decoded" into "an entity was published", and the choice of where that runs is
// forced by a constraint rather than taste: the sync log is single-writer. If it
// were appended to by two processes it would corrupt, so the decode worker (a
// separate process) cannot publish into it directly.
//
// So the publisher lives inside the process that owns the log, and reads from
// the place trips are already derived: cairn-tsdb's v_trip_summary view, over its
// loopback query endpoint. That also means the sync API and the analytical store
// can never disagree about what a trip is — there is one definition, in SQL, with
// its own tests — and the publisher is stateless: every pass re-reads everything
// and Store.Publish is idempotent by content digest, so an unchanged trip costs
// nothing and a trip whose bundles were reprocessed simply publishes its new
// version.

// tripSummarySQL selects one row per (vehicle, boot).
//
// Everything is converted to integers here, because the protocol forbids floats
// in payloads (docs/app-sync-protocol.md §4.1: two languages disagree about how
// to print them, and a hash over a printed float is a hash over a disagreement).
// Timestamps are epoch milliseconds, speeds are cm/s, distance is whole metres.
const tripSummarySQL = `SELECT vehicle_id, boot_id, device_id,
  CAST(epoch_ms(started_at) AS BIGINT) AS started_ms,
  CAST(epoch_ms(ended_at)   AS BIGINT) AS ended_ms,
  CAST(duration_ms AS BIGINT) AS duration_ms,
  CAST(round(coalesce(distance_m, 0)) AS BIGINT) AS distance_m,
  CAST(round(coalesce(max_gnss_speed_mps, 0) * 100) AS BIGINT) AS max_gnss_speed_cmps,
  CAST(round(coalesce(max_obd_speed_kph, 0) * 100 / 3.6) AS BIGINT) AS max_obd_speed_cmps,
  CAST(coalesce(max_rpm, 0) AS BIGINT) AS max_rpm,
  CAST(obd_samples AS BIGINT) AS obd_samples,
  CAST(gnss_samples AS BIGINT) AS gnss_samples,
  CAST(boost_samples AS BIGINT) AS boost_samples,
  CAST(gap_count AS BIGINT) AS gap_count,
  CAST(gap_duration_ms AS BIGINT) AS gap_duration_ms,
  CAST(coalesce(bundle_count, 0) AS BIGINT) AS bundle_count,
  CAST(coalesce(decoder_version, 0) AS BIGINT) AS decoder_version
FROM v_trip_summary ORDER BY vehicle_id, started_ms`

// tripSummary is the entity payload. Field order is fixed by the struct, so the
// same trip always marshals to the same bytes and the content digest is stable.
type tripSummary struct {
	BootID          string `json:"boot_id"`
	DeviceID        string `json:"device_id"`
	StartedMS       int64  `json:"started_ms"`
	EndedMS         int64  `json:"ended_ms"`
	DurationMS      int64  `json:"duration_ms"`
	DistanceM       int64  `json:"distance_m"`
	MaxGNSSSpeedCMS int64  `json:"max_gnss_speed_cmps"`
	MaxOBDSpeedCMS  int64  `json:"max_obd_speed_cmps"`
	MaxRPM          int64  `json:"max_rpm"`
	OBDSamples      int64  `json:"obd_samples"`
	GNSSSamples     int64  `json:"gnss_samples"`
	BoostSamples    int64  `json:"boost_samples"`
	GapCount        int64  `json:"gap_count"`
	GapDurationMS   int64  `json:"gap_duration_ms"`
	BundleCount     int64  `json:"bundle_count"`
	DecoderVersion  int64  `json:"decoder_version"`
}

// TripPublisher publishes trip_summary entities from cairn-tsdb.
type TripPublisher struct {
	// URL is the loopback cairn-tsdb base URL.
	URL      string
	Store    *Store
	Client   *http.Client
	Interval time.Duration
	Log      *slog.Logger
}

// Once runs one pass and returns how many entities actually changed.
func (p *TripPublisher) Once(ctx context.Context) (int, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 45 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(p.URL, "/")+"/query", strings.NewReader(tripSummarySQL))
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("query cairn-tsdb: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		// The upstream message can name tables and columns; it stays in the log.
		return 0, fmt.Errorf("cairn-tsdb answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var res struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // epoch milliseconds are exact integers; do not route them through a float
	if err := dec.Decode(&res); err != nil {
		return 0, fmt.Errorf("decode cairn-tsdb result: %w", err)
	}

	col := map[string]int{}
	for i, c := range res.Columns {
		col[c] = i
	}
	for _, need := range []string{"vehicle_id", "boot_id", "device_id", "started_ms", "ended_ms", "duration_ms",
		"distance_m", "max_gnss_speed_cmps", "max_obd_speed_cmps", "max_rpm", "obd_samples", "gnss_samples",
		"boost_samples", "gap_count", "gap_duration_ms", "bundle_count", "decoder_version"} {
		if _, ok := col[need]; !ok {
			return 0, fmt.Errorf("cairn-tsdb result lacks column %q (schema changed?)", need)
		}
	}

	str := func(r []any, name string) string {
		if v, ok := r[col[name]].(string); ok {
			return v
		}
		return ""
	}
	integer := func(r []any, name string) int64 {
		n, ok := r[col[name]].(json.Number)
		if !ok {
			return 0
		}
		v, err := n.Int64()
		if err != nil {
			f, ferr := n.Float64()
			if ferr != nil {
				return 0
			}
			return int64(f)
		}
		return v
	}

	changed := 0
	for _, r := range res.Rows {
		vehicle, boot := strings.ToLower(str(r, "vehicle_id")), str(r, "boot_id")
		if vehicle == "" || boot == "" {
			continue
		}
		data, err := json.Marshal(tripSummary{
			BootID: boot, DeviceID: str(r, "device_id"),
			StartedMS: integer(r, "started_ms"), EndedMS: integer(r, "ended_ms"), DurationMS: integer(r, "duration_ms"),
			DistanceM:       integer(r, "distance_m"),
			MaxGNSSSpeedCMS: integer(r, "max_gnss_speed_cmps"), MaxOBDSpeedCMS: integer(r, "max_obd_speed_cmps"),
			MaxRPM: integer(r, "max_rpm"), OBDSamples: integer(r, "obd_samples"), GNSSSamples: integer(r, "gnss_samples"),
			BoostSamples: integer(r, "boost_samples"), GapCount: integer(r, "gap_count"),
			GapDurationMS: integer(r, "gap_duration_ms"), BundleCount: integer(r, "bundle_count"),
			DecoderVersion: integer(r, "decoder_version"),
		})
		if err != nil {
			return changed, err
		}
		_, did, err := p.Store.Publish(Entity{Type: EntityTypeTripSummary, ID: vehicle + ":" + boot, VehicleID: vehicle, Data: data})
		if err != nil {
			return changed, fmt.Errorf("publish trip %s:%s: %w", vehicle, boot, err)
		}
		if did {
			changed++
		}
	}
	return changed, nil
}

// Run publishes until ctx is cancelled. A failed pass is logged and retried at
// the next tick: the analytical store is rebuilt on every restart and may simply
// not be up yet.
func (p *TripPublisher) Run(ctx context.Context) {
	log := p.Log
	if log == nil {
		log = slog.Default()
	}
	interval := p.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}

	pass := func() {
		n, err := p.Once(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("trip_summary publish failed; will retry", "error", err)
		case n > 0:
			log.Info("published trip summaries", "changed", n)
		}
	}

	// Soon after start, so a restart does not leave the app waiting a whole interval.
	select {
	case <-time.After(2 * time.Second):
		pass()
	case <-ctx.Done():
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			pass()
		case <-ctx.Done():
			return
		}
	}
}
