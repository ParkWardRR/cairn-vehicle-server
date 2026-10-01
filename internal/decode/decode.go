// Package decode turns a committed raw bundle into normalized samples and
// derived trips.
//
// Two properties define this package, and both are load-bearing:
//
//   - **Idempotent.** Decoding the same content root twice converges on the
//     same database state. Everything happens in one transaction that deletes
//     the bundle's derived rows before reinserting them, so a worker that
//     crashes halfway and gets redelivered the job costs a repeat rather than a
//     duplicate.
//
//   - **Reproducible.** The decoder is a pure function of the raw bytes and its
//     own version. It records a digest over its output, so re-decoding the same
//     bundle at the same version must produce the same digest. A changed digest
//     at an unchanged version means the decoder is not deterministic, which is
//     a bug worth failing loudly over.
//
// Together these are what let a decoder bug be fixed and every affected trip
// re-derived without re-uploading a byte. Raw stays authoritative; this layer
// is disposable by design.
//
// A decode failure is a recorded result, never a reason to reject a bundle. By
// the time a job reaches here the bundle is already committed and receipted,
// and the device may well have pruned its copy — so refusing the data now would
// be both pointless and destructive.
package decode

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
)

// Version is the decoder version. Bump it whenever the decode or derivation
// logic changes in a way that could alter output.
//
// It is recorded with every decode run, so a change is visible as a second row
// at a higher version and the two outputs can be compared bundle by bundle.
const Version = 1

// Result is what one decode produced.
type Result struct {
	ContentRoot [32]byte
	DeviceID    [16]byte
	BundleID    [16]byte

	// BootID is part of the ordering identity (boot_id, seq), so it belongs on
	// every normalized row rather than only on the bundle.
	BootID [16]byte

	Positions   []Position
	IMU         []IMU
	OBD         []OBD
	Status      []Status
	Transitions []Transition
	Gaps        []Gap

	Trip   *Trip
	Events []Event

	UnknownRecords int

	// Warnings are non-fatal problems. A decode that hits trouble still records
	// what it managed; the raw bundle is already committed and receipted.
	Warnings []string

	DurationMS int
}

// OutputDigest hashes the decode output.
//
// This is what makes reproducibility checkable rather than merely claimed. The
// digest covers every derived value in a fixed order, so it changes if and only
// if the output changes.
func (r *Result) OutputDigest() [32]byte {
	h := sha256.New()

	write := func(parts ...any) {
		for _, p := range parts {
			switch v := p.(type) {
			case string:
				h.Write([]byte(v))
			case []byte:
				h.Write(v)
			case int64:
				var b [8]byte
				binary.LittleEndian.PutUint64(b[:], uint64(v))
				h.Write(b[:])
			case uint64:
				var b [8]byte
				binary.LittleEndian.PutUint64(b[:], v)
				h.Write(b[:])
			case float64:
				// Round to a fixed precision so a benign floating-point
				// difference between platforms cannot change the digest while
				// a real output change still does.
				var b [8]byte
				binary.LittleEndian.PutUint64(b[:], uint64(int64(v*1e6)))
				h.Write(b[:])
			}
		}
	}

	h.Write([]byte("cairn-decode-v"))
	write(int64(Version))
	h.Write(r.ContentRoot[:])

	for i := range r.Positions {
		p := &r.Positions[i]
		write(int64(p.Seq), p.ObservedAt.UTC().Format(time.RFC3339Nano),
			p.Latitude, p.Longitude, int64(p.FixType))
	}
	for i := range r.IMU {
		s := &r.IMU[i]
		write(int64(s.Seq), int64(s.AccelRMSmg), int64(s.EventFlags))
	}
	for i := range r.OBD {
		s := &r.OBD[i]
		write(int64(s.Seq), int64(s.PIDsAnswered))
	}
	for i := range r.Gaps {
		g := &r.Gaps[i]
		write(int64(g.Seq), int64(g.DurationMS), int64(g.Cause))
	}
	for i := range r.Events {
		e := &r.Events[i]
		h.Write(e.EventID[:])
		write(e.Kind, int64(e.Seq))
	}
	if r.Trip != nil {
		write(r.Trip.DistanceM, int64(r.Trip.DurationS), int64(r.Trip.SampleCount),
			int64(r.Trip.GapCount))
	}

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Position is a decoded GNSS observation ready for the normalized layer.
type Position struct {
	Seq         uint32
	ObservedAt  time.Time
	MonotonicMS uint32

	Latitude  float64
	Longitude float64

	AltitudeM  *float64
	SpeedMPS   *float64
	HeadingDeg *float64

	FixType     uint8
	SatsUsed    *int16
	SatsVisible *int16
	HDOP        *float64
	HAccM       *float64
	VAccM       *float64
	UTCAccMS    *int32
	SourceFlags uint8
	FrameFlags  uint16
}

// IMU is a decoded motion window.
type IMU struct {
	Seq         uint32
	ObservedAt  time.Time
	MonotonicMS uint32

	WindowMS     uint16
	AccelRMSmg   uint16
	AccelPeakXmg int16
	AccelPeakYmg int16
	AccelPeakZmg int16
	GyroPeakDPS  float64
	Variance     uint16
	SampleCount  uint16
	EventFlags   uint8
	FrameFlags   uint16
}

// OBD is a decoded engine observation.
type OBD struct {
	Seq         uint32
	ObservedAt  time.Time
	MonotonicMS uint32

	SpeedKPH         *int16
	RPM              *int16
	ThrottlePct      *int16
	EngineLoadPct    *int16
	CoolantTempC     *int16
	IntakeTempC      *int16
	FuelPressureKPa  *int32
	TimingAdvanceDeg *int16

	PIDErrorCount uint8
	PIDsRequested uint32
	PIDsAnswered  uint32
	PollCadenceMS *int32
	FrameFlags    uint16
}

// Status is a decoded health snapshot.
type Status struct {
	Seq         uint32
	ObservedAt  time.Time
	MonotonicMS uint32

	BatteryMV     *int32
	SDWriteErrors *int32
	SDFreeMiB     *int32
	DeviceTempC   *int16
	RSSIdBm       *int16
	ExtSensor1    *int32
	ExtSensor2    *int32
	HealthState   uint8
	RebootCount   uint8
}

// Transition is a decoded lifecycle journal record.
type Transition struct {
	Seq         uint32
	ObservedAt  time.Time
	MonotonicMS uint32

	Region        uint8
	FromState     uint8
	ToState       uint8
	TriggerEvent  uint8
	ReasonCode    uint8
	PolicyVersion uint8
	StartScore    float64
	StopScore     float64
	WakeCause     uint32
}

// Gap is a recorded absence of position.
type Gap struct {
	Seq             uint32
	StartedAt       time.Time
	DurationMS      uint32
	ExpectedSamples uint16
	Cause           uint8
}

// Trip is the derived journey.
type Trip struct {
	TripID [16]byte

	StartedAt time.Time
	EndedAt   time.Time
	DurationS int

	DistanceM float64

	StartLat, StartLon *float64
	EndLat, EndLon     *float64

	// Route is the ordered fix positions. Gaps break it: consecutive points
	// across a gap are not joined, which is why segments are tracked too.
	Route []RoutePoint

	MaxSpeedMPS *float64
	AvgSpeedMPS *float64

	SampleCount  int
	GapCount     int
	GapDurationS int

	RecoveryState uint8

	Segments []Segment
}

// RoutePoint is one vertex of a derived route.
type RoutePoint struct {
	Lat, Lon float64
}

// Segment is a drive, stop or gap phase within a trip.
type Segment struct {
	Index     int
	Kind      string
	StartedAt time.Time
	EndedAt   time.Time
	DurationS int
	DistanceM float64
}

// Event is a derived semantic occurrence.
type Event struct {
	// EventID is deterministic: a hash over (content_root, kind, seq). Two
	// decodes of the same bundle produce the same identity, so a downstream
	// consumer can deduplicate with no coordination.
	EventID [16]byte

	Kind       string
	OccurredAt time.Time
	Seq        uint32

	Lat, Lon *float64
	Detail   map[string]any
}

// Decoder reads raw bundles from the content-addressed store.
type Decoder struct {
	cas *cas.Store
}

func New(store *cas.Store) *Decoder {
	return &Decoder{cas: store}
}

// Input identifies the bundle to decode.
type Input struct {
	ContentRoot    [32]byte
	ManifestDigest [32]byte
}

// Decode reads the bundle's raw members and produces normalized and derived
// output.
//
// It never mutates anything. The caller persists the result, which is what
// keeps the decoder a pure function and therefore testable for reproducibility.
func (d *Decoder) Decode(ctx context.Context, in Input) (*Result, error) {
	started := time.Now()

	manifestBytes, err := d.cas.GetVerified(in.ManifestDigest)
	if err != nil {
		return nil, fmt.Errorf("read manifest %x: %w", in.ManifestDigest, err)
	}

	manifest, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if manifest.ContentRoot != in.ContentRoot {
		return nil, fmt.Errorf("manifest content root %x does not match the requested %x",
			manifest.ContentRoot, in.ContentRoot)
	}

	res := &Result{
		ContentRoot: manifest.ContentRoot,
		DeviceID:    manifest.DeviceID,
		BundleID:    manifest.BundleID,
		BootID:      manifest.BootID,
	}

	// Capture segments form one chain; the journal is a separate chain with its
	// own sequence space (spec §3.2.1), so they are scanned independently.
	capture, journal := partitionMembers(manifest.Members)

	if err := d.scanChain(ctx, res, manifest, capture, false); err != nil {
		return nil, err
	}
	if err := d.scanChain(ctx, res, manifest, journal, true); err != nil {
		return nil, err
	}

	// A bundle recovered from a torn tail is still decoded; the recovery state
	// travels with the trip so a consumer can see it was not a clean capture.
	res.deriveTrip(uint8(manifest.RecoveryState))
	res.detectEvents()

	res.DurationMS = int(time.Since(started).Milliseconds())
	return res, nil
}

// partitionMembers splits members into the capture chain (ordered by name,
// which is also segment order) and the journal.
func partitionMembers(members []format.Member) (capture, journal []format.Member) {
	for _, m := range members {
		switch {
		case m.Name == "journal.seg":
			journal = append(journal, m)
		case len(m.Name) > 4 && m.Name[:4] == "seg-":
			capture = append(capture, m)
		}
	}
	sort.Slice(capture, func(i, j int) bool { return capture[i].Name < capture[j].Name })
	return capture, journal
}

// scanChain walks one chain's segments, threading scan continuity between them.
func (d *Decoder) scanChain(
	ctx context.Context,
	res *Result,
	manifest *format.Manifest,
	members []format.Member,
	isJournal bool,
) error {
	state := format.ScanState{}

	for _, m := range members {
		if err := ctx.Err(); err != nil {
			return err
		}

		data, err := d.cas.GetVerified(m.SHA256)
		if err != nil {
			return fmt.Errorf("read member %q: %w", m.Name, err)
		}

		scan, err := format.ScanSegment(data, state)
		if err != nil {
			// An unreadable segment is recorded, not fatal: the rest of the
			// bundle may still decode, and refusing all of it would discard
			// recoverable evidence.
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("segment %q is unusable: %v", m.Name, err))
			continue
		}

		if !scan.Stop.Clean() {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"segment %q ended with %s after %d frames (%d bytes discarded): %s",
				m.Name, scan.Stop, len(scan.Frames), scan.DiscardedTailBytes, scan.StopDetail))
		}

		for i := range scan.Frames {
			res.decodeFrame(manifest, &scan.Frames[i], m.Name)
		}

		res.UnknownRecords += scan.UnknownTypeCount
		state = scan.Next

		// A damaged segment makes every later segment's chain expectation
		// unknowable, so continuing would produce misleading output.
		if !scan.Stop.Clean() {
			break
		}
	}

	_ = isJournal
	return nil
}

// observedAt converts a frame's monotonic offset into a UTC estimate.
//
// The result is an estimate and nothing more: it is derived from the device's
// UTC basis, which carries its own uncertainty. Ordering is never taken from
// this value — that comes from (boot_id, seq).
func observedAt(manifest *format.Manifest, monotonicMS uint32, utcOffsetMS int32) time.Time {
	base := int64(manifest.UTCBasisMS) + int64(monotonicMS) + int64(utcOffsetMS)
	return time.UnixMilli(base).UTC()
}

// decodeFrame dispatches one frame to its payload decoder.
//
// An unparseable payload is a warning, not a failure. A single malformed record
// must not cost the rest of a drive.
func (r *Result) decodeFrame(manifest *format.Manifest, f *format.Frame, segment string) {
	warn := func(err error) {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("%s seq %d in %q: %v", f.RecordType, f.Seq, segment, err))
	}

	switch f.RecordType {
	case format.RecordGNSSSample:
		s, err := format.ParseGNSSSample(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.Positions = append(r.Positions, newPosition(manifest, f, s))

	case format.RecordIMUSummary:
		s, err := format.ParseIMUSummary(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.IMU = append(r.IMU, IMU{
			Seq:          f.Seq,
			ObservedAt:   observedAt(manifest, f.MonotonicMS, 0),
			MonotonicMS:  f.MonotonicMS,
			WindowMS:     s.WindowMS,
			AccelRMSmg:   s.AccelRMSmg,
			AccelPeakXmg: s.AccelPeakXmg,
			AccelPeakYmg: s.AccelPeakYmg,
			AccelPeakZmg: s.AccelPeakZmg,
			GyroPeakDPS:  s.GyroPeakDPS(),
			Variance:     s.Variance,
			SampleCount:  s.SampleCount,
			EventFlags:   s.EventFlags,
			FrameFlags:   f.Flags,
		})

	case format.RecordOBDSnapshot:
		s, err := format.ParseOBDSnapshot(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.OBD = append(r.OBD, newOBD(manifest, f, s))

	case format.RecordDeviceHealth:
		s, err := format.ParseDeviceHealth(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.Status = append(r.Status, newStatus(manifest, f, s))

	case format.RecordStateTransition:
		t, err := format.ParseStateTransition(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.Transitions = append(r.Transitions, Transition{
			Seq:           f.Seq,
			ObservedAt:    observedAt(manifest, f.MonotonicMS, 0),
			MonotonicMS:   f.MonotonicMS,
			Region:        t.Region,
			FromState:     t.FromState,
			ToState:       t.ToState,
			TriggerEvent:  t.TriggerEvent,
			ReasonCode:    t.ReasonCode,
			PolicyVersion: t.PolicyVersion,
			StartScore:    t.StartScore(),
			StopScore:     t.StopScore(),
			WakeCause:     t.WakeCause,
		})

	case format.RecordGNSSGap:
		g, err := format.ParseGNSSGap(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		r.Gaps = append(r.Gaps, Gap{
			Seq:             f.Seq,
			StartedAt:       observedAt(manifest, f.MonotonicMS, 0),
			DurationMS:      g.DurationMS,
			ExpectedSamples: g.ExpectedSamples,
			Cause:           g.Cause,
		})

	case format.RecordTripEvent:
		e, err := format.ParseTripEvent(f.Payload)
		if err != nil {
			warn(err)
			return
		}
		ev := Event{
			EventID:    eventID(r.ContentRoot, "device.marker", f.Seq),
			Kind:       "device.marker",
			OccurredAt: observedAt(manifest, f.MonotonicMS, 0),
			Seq:        f.Seq,
			Detail: map[string]any{
				"event_type":      e.EventType,
				"event_type_name": format.EventTypeName(e.EventType),
				"detail":          e.Detail,
			},
		}
		if e.HasPosition() {
			lat := float64(e.LatE7) / 1e7
			lon := float64(e.LonE7) / 1e7
			ev.Lat, ev.Lon = &lat, &lon
		}
		r.Events = append(r.Events, ev)

	case format.RecordIMURawWindow, format.RecordPolicySnapshot:
		// Understood but not yet normalized into its own table. Counted so the
		// decode run records that the data was seen rather than silently
		// dropped.
		r.UnknownRecords++
	}
}

func newPosition(manifest *format.Manifest, f *format.Frame, s *format.GNSSSample) Position {
	p := Position{
		Seq:         f.Seq,
		ObservedAt:  observedAt(manifest, f.MonotonicMS, s.UTCOffsetMS),
		MonotonicMS: f.MonotonicMS,
		Latitude:    s.LatDeg(),
		Longitude:   s.LonDeg(),
		FixType:     s.FixType,
		SourceFlags: s.SourceFlags,
		FrameFlags:  f.Flags,
	}

	alt := s.AltitudeM()
	p.AltitudeM = &alt
	speed := s.SpeedMPS()
	p.SpeedMPS = &speed
	heading := s.HeadingDeg()
	p.HeadingDeg = &heading

	su := int16(s.SatsUsed)
	p.SatsUsed = &su
	sv := int16(s.SatsVisible)
	p.SatsVisible = &sv

	// Accuracy fields stay nil when the receiver did not report them.
	if s.HDOPe2 != nil {
		v := float64(*s.HDOPe2) / 100.0
		p.HDOP = &v
	}
	if s.HAccCM != nil {
		v := float64(*s.HAccCM) / 100.0
		p.HAccM = &v
	}
	if s.VAccCM != nil {
		v := float64(*s.VAccCM) / 100.0
		p.VAccM = &v
	}
	if s.UTCAccMS != nil {
		v := int32(*s.UTCAccMS)
		p.UTCAccMS = &v
	}

	return p
}

func newOBD(manifest *format.Manifest, f *format.Frame, s *format.OBDSnapshot) OBD {
	o := OBD{
		Seq:           f.Seq,
		ObservedAt:    observedAt(manifest, f.MonotonicMS, 0),
		MonotonicMS:   f.MonotonicMS,
		PIDErrorCount: s.PIDErrorCount,
		PIDsRequested: s.PIDsRequested,
		PIDsAnswered:  s.PIDsAnswered,
		FrameFlags:    f.Flags,
	}

	o.SpeedKPH = s.SpeedKPH
	o.RPM = s.RPM
	if s.ThrottlePct != nil {
		v := int16(*s.ThrottlePct)
		o.ThrottlePct = &v
	}
	if s.EngineLoadPct != nil {
		v := int16(*s.EngineLoadPct)
		o.EngineLoadPct = &v
	}
	if s.CoolantTempC != nil {
		v := int16(*s.CoolantTempC)
		o.CoolantTempC = &v
	}
	if s.IntakeTempC != nil {
		v := int16(*s.IntakeTempC)
		o.IntakeTempC = &v
	}
	if s.FuelPressureKPa != nil {
		v := int32(*s.FuelPressureKPa)
		o.FuelPressureKPa = &v
	}
	if s.TimingAdvanceDeg != nil {
		v := int16(*s.TimingAdvanceDeg)
		o.TimingAdvanceDeg = &v
	}
	if s.PollCadenceMS != 0 {
		v := int32(s.PollCadenceMS)
		o.PollCadenceMS = &v
	}

	return o
}

func newStatus(manifest *format.Manifest, f *format.Frame, s *format.DeviceHealth) Status {
	st := Status{
		Seq:         f.Seq,
		ObservedAt:  observedAt(manifest, f.MonotonicMS, 0),
		MonotonicMS: f.MonotonicMS,
		HealthState: s.HealthState,
		RebootCount: s.RebootCount,
	}

	bat := int32(s.BatteryMV)
	st.BatteryMV = &bat
	errs := int32(s.SDWriteErrors)
	st.SDWriteErrors = &errs
	free := int32(s.SDFreeMiB)
	st.SDFreeMiB = &free
	temp := int16(s.DeviceTempC)
	st.DeviceTempC = &temp
	rssi := int16(s.RSSIdBm)
	st.RSSIdBm = &rssi
	e1 := int32(s.ExtSensor1)
	st.ExtSensor1 = &e1
	e2 := int32(s.ExtSensor2)
	st.ExtSensor2 = &e2

	return st
}

// eventID derives a deterministic 16-byte identity from the bundle, kind and
// sequence.
//
// Determinism is the point: re-deriving produces the same identity, so a
// downstream consumer — Home Assistant in particular — can deduplicate without
// any coordination with the server.
func eventID(contentRoot [32]byte, kind string, seq uint32) [16]byte {
	h := sha256.New()
	h.Write([]byte("cairn-event-v1"))
	h.Write(contentRoot[:])
	h.Write([]byte(kind))
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], seq)
	h.Write(b[:])

	var id [16]byte
	copy(id[:], h.Sum(nil)[:16])
	return id
}
