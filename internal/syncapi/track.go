package syncapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The trip track: where the car went, for one trip, as a line a phone can draw.
//
// Why it exists. A trip's numbers reach the phone through the sync log as a
// trip_summary entity, but its *shape* did not: the only route to positions was
// the Parquet snapshot, which is the analytical store's whole output and which
// the phone could only read by carrying DuckDB — a heavy binary dependency for
// one table. The rewrite drops DuckDB from the phone (front door
// docs/ios-rewrite-plan.md, decision D4) and this is what replaces it.
//
// Three things it is careful about:
//
//   - **Only trusted positions.** v_position_trusted is the store's own view of
//     which fixes are worth believing. A phone drawing a route from everything
//     would draw the spurs that view exists to exclude.
//   - **Phone fixes are excluded.** The dongle records the companion's fixes as
//     a second position source (source_flags bit 5). They are a diagnostic and a
//     hint, not the car's track, and a route drawn from them would be a route of
//     wherever the phone was — which during a stop is the owner walking around a
//     shop.
//   - **Runs, not one line.** A dropout is a gap in knowledge, not a straight
//     road. The track comes back as runs with the gaps between them named, so a
//     map never draws a line across eight minutes of no signal.
//
// The encoding is Google's encoded-polyline at precision 5 (about 1.1 m), which
// every map library decodes and which is roughly a tenth the size of the same
// points as JSON numbers. A 2-hour drive at 1 Hz is ~7000 points: 100 kB of
// JSON pairs, 10 kB encoded.
//
// Added to contracts/sync/v1 as an additive endpoint.

// trackGapThreshold is how long a silence has to be before it is a gap rather
// than a slow second. The receiver writes at about 1 Hz when it has a fix, so
// anything beyond this is the fix being lost, not the clock drifting.
const trackGapThreshold = 30 * time.Second

// trackMaxPoints caps what one response can carry. A drive long enough to
// exceed it is thinned rather than truncated: losing the end of a route reads
// as a trip that stopped somewhere it did not.
const trackMaxPoints = 20000

type trackRun struct {
	StartedMS int64 `json:"started_ms"`
	EndedMS   int64 `json:"ended_ms"`
	Count     int   `json:"count"`
	// Encoded polyline, precision 5.
	Polyline string `json:"polyline"`
}

type trackGap struct {
	AfterMS    int64 `json:"after_ms"`
	BeforeMS   int64 `json:"before_ms"`
	DurationMS int64 `json:"duration_ms"`
}

type trackBody struct {
	TripID     string `json:"trip_id"`
	VehicleID  string `json:"vehicle_id"`
	StartedMS  int64  `json:"started_ms"`
	EndedMS    int64  `json:"ended_ms"`
	Encoding   string `json:"encoding"`
	PointCount int    `json:"point_count"`
	// Thinned says the track was reduced to fit; the shape is right and the
	// sample rate is not. A client showing speeds per point must notice.
	Thinned bool       `json:"thinned,omitempty"`
	Runs    []trackRun `json:"runs"`
	Gaps    []trackGap `json:"gaps"`
}

// trackSQL reads one trip's trusted, device-sourced positions in time order.
//
// The span comes from the request rather than from a join on v_trip_summary so
// that a trip whose entity has been re-keyed — which sync/v1 §12 says happens
// whenever a bundle covering an earlier part of the outing arrives late — still
// answers for the span the client asked about.
//
// cairn-tsdb's query endpoint takes SQL as the request body and has no bind
// protocol, so the three values are formatted in. All three are validated
// before they get here and cannot carry a quote: the vehicle id against
// vehicleIDRE (32 lowercase hex), and both timestamps through ParseInt.
const trackSQL = `SELECT
  CAST(epoch_ms(observed_at) AS BIGINT) AS at_ms, lat, lon
FROM v_position_trusted
WHERE vehicle_id = '%s'
  AND observed_at >= epoch_ms(CAST(%d AS BIGINT))
  AND observed_at <= epoch_ms(CAST(%d AS BIGINT))
  AND (source_flags & 32) = 0
  AND lat IS NOT NULL AND lon IS NOT NULL
ORDER BY observed_at`

// handleTrack serves GET /v1/trips/{id}/track.
//
// The id is the trip_summary entity id, <vehicle_id>:<started_ms>, so a client
// that has a trip has everything it needs to ask for its shape. The end of the
// span comes from ?ended_ms=, which the client also has from the same entity;
// without it the server would have to find the trip, and a trip is derived, not
// stored.
func (s *Server) handleTrack(q *request) (int, string) {
	if s.cfg.SnapshotURL == "" {
		s.writeError(q.w, http.StatusNotFound, "not_found", "this server has no analytical store")
		return http.StatusNotFound, "no tsdb"
	}

	id := q.r.PathValue("id")
	vehicle, startedMS, ok := parseTripID(id)
	if !ok {
		s.writeError(q.w, http.StatusBadRequest, "bad_request",
			"the trip id must be <vehicle_id>:<started_ms>")
		return http.StatusBadRequest, "bad trip id"
	}
	q.target = vehicle

	// Scope, the same way every other route enforces it, and with the same
	// answer whether or not the trip exists: a 404 for somebody else's car
	// would be a way to ask which cars there are.
	if !q.client.InScope(vehicle) {
		s.writeError(q.w, http.StatusForbidden, "scope", "that vehicle is outside this client's scope")
		return http.StatusForbidden, "vehicle out of scope"
	}

	endedMS := startedMS
	if raw := q.r.URL.Query().Get("ended_ms"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed < startedMS {
			s.writeError(q.w, http.StatusBadRequest, "bad_request",
				"ended_ms must be an integer at or after the trip's start")
			return http.StatusBadRequest, "bad ended_ms"
		}
		endedMS = parsed
	}
	// A span that is open-ended is a scan of the whole table. Refuse it rather
	// than serve it slowly.
	if endedMS == startedMS {
		s.writeError(q.w, http.StatusBadRequest, "bad_request",
			"ended_ms is required: a track needs a span")
		return http.StatusBadRequest, "no span"
	}
	const maxSpan = int64(48 * 60 * 60 * 1000)
	if endedMS-startedMS > maxSpan {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "that span is longer than two days")
		return http.StatusBadRequest, "span too long"
	}

	points, err := s.queryTrack(q.r.Context(), vehicle, startedMS, endedMS)
	if err != nil {
		if s.cfg.Log != nil {
			s.cfg.Log.Warn("track query failed", "error", err)
		}
		s.writeError(q.w, http.StatusBadGateway, "upstream", "the analytical store did not answer")
		return http.StatusBadGateway, "tsdb error"
	}

	body := buildTrack(id, vehicle, startedMS, endedMS, points)
	s.writeJSON(q.w, http.StatusOK, body)
	return http.StatusOK, fmt.Sprintf("%d points", body.PointCount)
}

// parseTripID splits <vehicle_id>:<started_ms>.
func parseTripID(id string) (vehicle string, startedMS int64, ok bool) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	vehicle = strings.ToLower(parts[0])
	if !vehicleIDRE.MatchString(vehicle) {
		return "", 0, false
	}
	startedMS, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || startedMS <= 0 {
		return "", 0, false
	}
	return vehicle, startedMS, true
}

type trackPoint struct {
	atMS int64
	lat  float64
	lon  float64
}

func (s *Server) queryTrack(ctx context.Context, vehicle string, startedMS, endedMS int64) ([]trackPoint, error) {
	statement := fmt.Sprintf(trackSQL, vehicle, startedMS, endedMS)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(s.cfg.SnapshotURL, "/")+"/query", strings.NewReader(statement))
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query cairn-tsdb: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cairn-tsdb answered %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var res struct {
		Columns []string `json:"columns"`
		Rows    [][]any  `json:"rows"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // epoch milliseconds are exact integers
	if err := dec.Decode(&res); err != nil {
		return nil, fmt.Errorf("decode cairn-tsdb result: %w", err)
	}
	col := map[string]int{}
	for i, c := range res.Columns {
		col[c] = i
	}
	for _, need := range []string{"at_ms", "lat", "lon"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("cairn-tsdb result lacks column %q (schema changed?)", need)
		}
	}

	points := make([]trackPoint, 0, len(res.Rows))
	for _, row := range res.Rows {
		at, okAt := jsonInt(row[col["at_ms"]])
		lat, okLat := jsonFloat(row[col["lat"]])
		lon, okLon := jsonFloat(row[col["lon"]])
		if !okAt || !okLat || !okLon {
			continue
		}
		points = append(points, trackPoint{atMS: at, lat: lat, lon: lon})
	}
	return points, nil
}

func jsonInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}

func jsonFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// buildTrack turns ordered points into runs and the gaps between them.
func buildTrack(id, vehicle string, startedMS, endedMS int64, points []trackPoint) trackBody {
	body := trackBody{
		TripID:    id,
		VehicleID: vehicle,
		StartedMS: startedMS,
		EndedMS:   endedMS,
		Encoding:  "polyline5",
		Runs:      []trackRun{},
		Gaps:      []trackGap{},
	}
	if len(points) == 0 {
		return body
	}

	// Thin before splitting, so a run's shape survives and only its sample rate
	// changes. Keeping the first and last of every stride keeps the ends.
	thinned := false
	if len(points) > trackMaxPoints {
		stride := (len(points) + trackMaxPoints - 1) / trackMaxPoints
		kept := make([]trackPoint, 0, trackMaxPoints+1)
		for i, p := range points {
			if i%stride == 0 || i == len(points)-1 {
				kept = append(kept, p)
			}
		}
		points = kept
		thinned = true
	}
	body.Thinned = thinned
	body.PointCount = len(points)

	gapMS := trackGapThreshold.Milliseconds()
	run := []trackPoint{points[0]}
	flush := func() {
		if len(run) == 0 {
			return
		}
		body.Runs = append(body.Runs, trackRun{
			StartedMS: run[0].atMS,
			EndedMS:   run[len(run)-1].atMS,
			Count:     len(run),
			Polyline:  encodePolyline(run),
		})
		run = nil
	}
	for i := 1; i < len(points); i++ {
		if points[i].atMS-points[i-1].atMS > gapMS {
			body.Gaps = append(body.Gaps, trackGap{
				AfterMS:    points[i-1].atMS,
				BeforeMS:   points[i].atMS,
				DurationMS: points[i].atMS - points[i-1].atMS,
			})
			flush()
		}
		run = append(run, points[i])
	}
	flush()
	return body
}

// encodePolyline is Google's encoded-polyline algorithm at precision 5: each
// coordinate as a delta from the last, scaled by 1e5, zig-zag encoded, then
// five bits at a time with a continuation bit, offset by 63 so the result is
// printable ASCII.
func encodePolyline(points []trackPoint) string {
	var out strings.Builder
	out.Grow(len(points) * 8)
	var lastLat, lastLon int64
	for _, p := range points {
		lat := int64(math.Round(p.lat * 1e5))
		lon := int64(math.Round(p.lon * 1e5))
		encodeSigned(&out, lat-lastLat)
		encodeSigned(&out, lon-lastLon)
		lastLat, lastLon = lat, lon
	}
	return out.String()
}

func encodeSigned(out *strings.Builder, value int64) {
	v := value << 1
	if value < 0 {
		v = ^(value << 1)
	}
	for v >= 0x20 {
		out.WriteByte(byte((0x20 | (v & 0x1f)) + 63))
		v >>= 5
	}
	out.WriteByte(byte(v + 63))
}
