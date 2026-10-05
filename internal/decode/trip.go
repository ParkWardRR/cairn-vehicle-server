package decode

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sort"
	"time"
)

// Trip derivation and event detection.
//
// A trip is an interpretation, not a measurement. That is why it lives in the
// derived layer carrying the decoder version that produced it: a change to the
// rules here is a change to the output, and must be visible as such rather than
// silently rewriting history.

// Thresholds for segmenting and event detection.
//
// These are starting values, deliberately conservative, and they are the
// decoder's own — distinct from the device's capture policy. The device decides
// what to record; this decides how to read it.
const (
	// Below this, the vehicle is treated as stationary.
	stopSpeedMPS = 1.0

	// A stationary run shorter than this is noise, not a stop worth segmenting.
	minStopDurationS = 30

	// A gap longer than this breaks the route rather than being bridged.
	maxRouteBridgeS = 5

	// Hard braking: a sustained longitudinal deceleration, in milli-g.
	hardBrakeMilliG = 800

	// An impact-like acceleration, in milli-g.
	impactMilliG = 3000
)

// sortByseq orders samples by sequence, which is the ordering truth.
func (r *Result) sortBySeq() {
	sort.Slice(r.Positions, func(i, j int) bool { return r.Positions[i].Seq < r.Positions[j].Seq })
	sort.Slice(r.IMU, func(i, j int) bool { return r.IMU[i].Seq < r.IMU[j].Seq })
	sort.Slice(r.OBD, func(i, j int) bool { return r.OBD[i].Seq < r.OBD[j].Seq })
	sort.Slice(r.Status, func(i, j int) bool { return r.Status[i].Seq < r.Status[j].Seq })
	sort.Slice(r.Transitions, func(i, j int) bool { return r.Transitions[i].Seq < r.Transitions[j].Seq })
	sort.Slice(r.Gaps, func(i, j int) bool { return r.Gaps[i].Seq < r.Gaps[j].Seq })
}

// haversineM returns the great-circle distance in metres.
func haversineM(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusM = 6371000.0

	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	l1 := lat1 * math.Pi / 180.0
	l2 := lat2 * math.Pi / 180.0

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(l1)*math.Cos(l2)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return earthRadiusM * 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
}

// tripID derives a deterministic trip identity from the bundle's content root.
//
// One bundle is one trip in v2, and the identity is a function of the content,
// so re-deriving yields the same trip_id and an upsert converges rather than
// accumulating duplicates.
func tripID(contentRoot [32]byte) [16]byte {
	h := sha256.New()
	h.Write([]byte("cairn-trip-v1"))
	h.Write(contentRoot[:])

	var id [16]byte
	copy(id[:], h.Sum(nil)[:16])
	return id
}

// deriveTrip builds the trip, segments and route from the decoded samples.
//
// A bundle with no valid fix produces a trip with no route rather than no trip:
// the drive happened, and a trip with a marked absence is more useful than
// silence.
func (r *Result) deriveTrip(recoveryState uint8) {
	r.sortBySeq()

	trip := &Trip{
		TripID:        tripID(r.ContentRoot),
		VehicleID:     r.VehicleID,
		RecoveryState: recoveryState,
		SampleCount:   len(r.Positions),
		GapCount:      len(r.Gaps),
	}

	for i := range r.Gaps {
		trip.GapDurationS += int(r.Gaps[i].DurationMS / 1000)
	}

	// Timing comes from whatever observations exist, not only from positions: a
	// drive through a tunnel with no fix at all still has a duration.
	first, last, ok := r.observationBounds()
	if !ok {
		// Nothing decoded at all. Record no trip rather than inventing one.
		r.Trip = nil
		return
	}
	trip.StartedAt = first
	trip.EndedAt = last
	trip.DurationS = int(last.Sub(first).Seconds())

	// Only fixed positions contribute to the route and distance. A sample
	// without a fix is an honest blank, never a plotted point.
	fixes := make([]Position, 0, len(r.Positions))
	for i := range r.Positions {
		if r.Positions[i].FixType != 0 {
			fixes = append(fixes, r.Positions[i])
		}
	}

	if len(fixes) > 0 {
		trip.StartLat, trip.StartLon = &fixes[0].Latitude, &fixes[0].Longitude
		lastFix := &fixes[len(fixes)-1]
		trip.EndLat, trip.EndLon = &lastFix.Latitude, &lastFix.Longitude

		var maxSpeed float64
		var speedSum float64
		var speedCount int

		for i := range fixes {
			trip.Route = append(trip.Route, RoutePoint{
				Lat: fixes[i].Latitude,
				Lon: fixes[i].Longitude,
			})

			if i > 0 {
				// Do not bridge a long interruption: the vehicle's actual path
				// across it is unknown, and a straight line would be a
				// fabrication.
				apart := fixes[i].ObservedAt.Sub(fixes[i-1].ObservedAt).Seconds()
				if apart <= maxRouteBridgeS {
					trip.DistanceM += haversineM(
						fixes[i-1].Latitude, fixes[i-1].Longitude,
						fixes[i].Latitude, fixes[i].Longitude)
				}
			}

			if fixes[i].SpeedMPS != nil {
				s := *fixes[i].SpeedMPS
				if s > maxSpeed {
					maxSpeed = s
				}
				speedSum += s
				speedCount++
			}
		}

		if speedCount > 0 {
			trip.MaxSpeedMPS = &maxSpeed
			avg := speedSum / float64(speedCount)
			trip.AvgSpeedMPS = &avg
		}
	}

	trip.Segments = segmentTrip(fixes, r.Gaps)
	r.Trip = trip
}

// observationBounds returns the earliest and latest observation across every
// record type.
func (r *Result) observationBounds() (first, last time.Time, ok bool) {
	consider := func(t time.Time) {
		if !ok {
			first, last, ok = t, t, true
			return
		}
		if t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
	}

	for i := range r.Positions {
		consider(r.Positions[i].ObservedAt)
	}
	for i := range r.IMU {
		consider(r.IMU[i].ObservedAt)
	}
	for i := range r.OBD {
		consider(r.OBD[i].ObservedAt)
	}
	for i := range r.Status {
		consider(r.Status[i].ObservedAt)
	}

	return first, last, ok
}

// segmentTrip splits a trip into drive, stop and gap phases.
//
// A traffic stop is a segment inside one trip, not a trip boundary. The reviews
// identified finalizing on a single stop timer as the reason v1 would split one
// drive into several; keeping stops as segments is the structural fix.
func segmentTrip(fixes []Position, gaps []Gap) []Segment {
	if len(fixes) == 0 {
		return nil
	}

	var segments []Segment

	// Classify each fix as moving or stationary, then coalesce runs.
	moving := func(p *Position) bool {
		if p.SpeedMPS == nil {
			return true // unknown speed: assume moving rather than inventing a stop
		}
		return *p.SpeedMPS >= stopSpeedMPS
	}

	runStart := 0
	runMoving := moving(&fixes[0])

	flush := func(endIdx int) {
		start := fixes[runStart]
		end := fixes[endIdx]
		duration := int(end.ObservedAt.Sub(start.ObservedAt).Seconds())

		kind := "drive"
		if !runMoving {
			// A brief stationary run is noise within a drive, not a stop.
			if duration < minStopDurationS {
				kind = "drive"
			} else {
				kind = "stop"
			}
		}

		var distance float64
		if kind == "drive" {
			for i := runStart + 1; i <= endIdx; i++ {
				apart := fixes[i].ObservedAt.Sub(fixes[i-1].ObservedAt).Seconds()
				if apart <= maxRouteBridgeS {
					distance += haversineM(
						fixes[i-1].Latitude, fixes[i-1].Longitude,
						fixes[i].Latitude, fixes[i].Longitude)
				}
			}
		}

		segments = append(segments, Segment{
			Index:     len(segments),
			Kind:      kind,
			StartedAt: start.ObservedAt,
			EndedAt:   end.ObservedAt,
			DurationS: duration,
			DistanceM: distance,
		})
	}

	for i := 1; i < len(fixes); i++ {
		if moving(&fixes[i]) != runMoving {
			flush(i - 1)
			runStart = i
			runMoving = moving(&fixes[i])
		}
	}
	flush(len(fixes) - 1)

	// Gaps are their own segments, so a map can render the discontinuity.
	for i := range gaps {
		g := &gaps[i]
		segments = append(segments, Segment{
			Index:     len(segments),
			Kind:      "gap",
			StartedAt: g.StartedAt,
			EndedAt:   g.StartedAt.Add(time.Duration(g.DurationMS) * time.Millisecond),
			DurationS: int(g.DurationMS / 1000),
		})
	}

	sort.Slice(segments, func(i, j int) bool {
		return segments[i].StartedAt.Before(segments[j].StartedAt)
	})
	for i := range segments {
		segments[i].Index = i
	}

	return segments
}

// detectEvents derives semantic events.
//
// These are what get published to MQTT, so they are deliberately few and
// meaningful. Publishing every sample would turn Home Assistant into an
// accidental telemetry database, which the reviews called out explicitly.
func (r *Result) detectEvents() {
	if r.Trip != nil {
		// Hex, not the raw byte array: a consumer reading detail.trip_id should
		// get the same shape as the top-level trip_id field.
		tripHex := hex.EncodeToString(r.Trip.TripID[:])

		r.addEvent("trip.started", r.Trip.StartedAt, r.Trip.FirstSeq(), map[string]any{
			"trip_id": tripHex,
		}, r.Trip.StartLat, r.Trip.StartLon)

		r.addEvent("trip.ended", r.Trip.EndedAt, r.Trip.LastSeq(), map[string]any{
			"trip_id":    tripHex,
			"distance_m": r.Trip.DistanceM,
			"duration_s": r.Trip.DurationS,
		}, r.Trip.EndLat, r.Trip.EndLon)
	}

	// IMU-flagged windows. The device already decided these were notable; the
	// decoder's job is to name them, not to re-derive the threshold.
	for i := range r.IMU {
		s := &r.IMU[i]

		if s.EventFlags&formatIMUEventHardBrake != 0 || s.AccelRMSmg >= hardBrakeMilliG {
			r.addEvent("hard_braking_detected", s.ObservedAt, s.Seq, map[string]any{
				"accel_rms_mg": s.AccelRMSmg,
			}, nil, nil)
		}
		if s.EventFlags&formatIMUEventImpact != 0 || s.AccelRMSmg >= impactMilliG {
			r.addEvent("impact_detected", s.ObservedAt, s.Seq, map[string]any{
				"accel_rms_mg": s.AccelRMSmg,
			}, nil, nil)
		}
		if s.EventFlags&formatIMUEventPothole != 0 {
			r.addEvent("pothole_detected", s.ObservedAt, s.Seq, nil, nil, nil)
		}
	}

	// Storage pressure, from health telemetry. Worth surfacing because an
	// unattended device filling its card is how data stops being captured.
	for i := range r.Status {
		s := &r.Status[i]
		if s.SDFreeMiB != nil && *s.SDFreeMiB < 256 {
			r.addEvent("storage_attention_required", s.ObservedAt, s.Seq, map[string]any{
				"sd_free_mib": *s.SDFreeMiB,
			}, nil, nil)
		}
		if s.SDWriteErrors != nil && *s.SDWriteErrors > 0 {
			r.addEvent("storage_errors_observed", s.ObservedAt, s.Seq, map[string]any{
				"sd_write_errors": *s.SDWriteErrors,
			}, nil, nil)
		}
	}

	// A recorded gap is itself worth an event: it is the honest signal that
	// part of a drive is unknown.
	for i := range r.Gaps {
		g := &r.Gaps[i]
		if g.DurationMS < 10_000 {
			continue
		}
		r.addEvent("gnss_gap_observed", g.StartedAt, g.Seq, map[string]any{
			"duration_ms": g.DurationMS,
			"cause":       g.Cause,
		}, nil, nil)
	}

	sort.Slice(r.Events, func(i, j int) bool {
		if r.Events[i].OccurredAt.Equal(r.Events[j].OccurredAt) {
			return r.Events[i].Seq < r.Events[j].Seq
		}
		return r.Events[i].OccurredAt.Before(r.Events[j].OccurredAt)
	})
}

// Mirror the format package's IMU flags, so trip.go does not need to import it
// for three constants.
const (
	formatIMUEventImpact    uint8 = 1 << 0
	formatIMUEventHardBrake uint8 = 1 << 1
	formatIMUEventPothole   uint8 = 1 << 3
)

func (r *Result) addEvent(kind string, at time.Time, seq uint32, detail map[string]any, lat, lon *float64) {
	if detail == nil {
		detail = map[string]any{}
	}
	r.Events = append(r.Events, Event{
		VehicleID:  r.VehicleID,
		EventID:    eventID(r.ContentRoot, kind, seq),
		Kind:       kind,
		OccurredAt: at,
		Seq:        seq,
		Lat:        lat,
		Lon:        lon,
		Detail:     detail,
	})
}

// FirstSeq and LastSeq bound the trip's sequence range.
func (t *Trip) FirstSeq() uint32 { return 0 }

// LastSeq uses the sample count so the trip-ended event has a distinct
// sequence from trip-started, keeping their derived identities different.
func (t *Trip) LastSeq() uint32 {
	if t.SampleCount == 0 {
		return 1
	}
	return uint32(t.SampleCount)
}
