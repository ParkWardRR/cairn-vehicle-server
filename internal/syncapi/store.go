package syncapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The sync log
//
// Everything the app can see or change is one totally ordered sequence of
// records, and the order is the server's own: a counter assigned under a lock at
// the moment a record becomes durable. Not the phone's clock (it can be wrong,
// and the roadmap's third invariant is that wall-clock is never an ordering
// key) and not the order requests happened to arrive in over two different
// network paths. A client that has pulled up to sequence N has seen exactly the
// history up to N, whichever route it used.
//
// # Storage
//
// Append-only JSONL segments, fsynced before a push is acknowledged, with the
// whole thing indexed in memory at open. The volume is small by construction
// (annotations, maintenance events, a few vehicles), the log is the source of
// truth, and every index is rebuilt from it — which is also what makes the
// idempotency guarantee durable: the operation and idempotency-key indexes are
// derived from the same records a client was told "accepted" about, so a crash
// can never leave the index claiming something the log does not hold, nor the
// log holding something a retry would duplicate.
//
// Segments rotate by size. Each starts with a header record carrying the log's
// epoch, so the epoch survives dropping old segments later and, just as
// importantly, is created together with the log: wiping the data directory
// removes the log and the epoch in one act, and the next start mints a new one.
// That is how a client with a cursor from before the wipe finds out it must
// resync rather than quietly missing everything.
//
// # Crash safety
//
// A crash mid-append leaves a final line with no newline. At open, a
// newline-less tail on the last segment is truncated away: it was never
// acknowledged (the fsync that precedes the acknowledgement had not
// completed), so dropping it loses nothing a client was promised. A complete
// line that does not parse, or a gap in the sequence, is different — that is
// corruption, not a torn write — and open fails loudly instead of serving a log
// with a hole in it.

const (
	recHeader = "hdr"
	recOp     = "op"
	recEntity = "ent"

	defaultSegmentBytes = 4 << 20
)

// Operation kinds.
const (
	KindTripAnnotation    = "trip_annotation"
	KindMaintenanceEvent  = "maintenance_event"
	KindOdometerCorrect   = "odometer_correction"
	KindVehicleUpdate     = "vehicle_update"
	KindObservation       = "observation"
	supportedPayloadVer   = 1
	maxPayloadBytes       = 32 << 10
	maxFieldsPerOp        = 32
	maxIdempotencyKeyLen  = 128
	maxTargetLen          = 64
	maxFieldNameLen       = 48
	entityTypeVehicle     = "vehicle"
	entityTypeAssignment  = "assignment"
	EntityTypeTripSummary = "trip_summary"
)

// mutableKinds hold app-owned metadata that more than one client may edit, so
// they carry per-field revisions; the others are immutable events, appended and
// never changed.
var mutableKinds = map[string]bool{
	KindTripAnnotation:  true,
	KindOdometerCorrect: true,
	KindVehicleUpdate:   true,
}

var knownKinds = map[string]bool{
	KindTripAnnotation:   true,
	KindMaintenanceEvent: true,
	KindOdometerCorrect:  true,
	KindVehicleUpdate:    true,
	KindObservation:      true,
}

var (
	fieldNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	targetRE    = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

// Op is one client operation, as sent and as stored.
type Op struct {
	OperationID    string           `json:"operation_id"`
	ClientID       string           `json:"client_id"`
	VehicleID      string           `json:"vehicle_id"`
	Kind           string           `json:"kind"`
	CreatedAt      string           `json:"created_at"`
	PayloadVersion int              `json:"payload_version"`
	Payload        json.RawMessage  `json:"payload"`
	ContentHash    string           `json:"content_hash"`
	IdempotencyKey string           `json:"idempotency_key,omitempty"`
	BaseRevision   map[string]int64 `json:"base_revision,omitempty"`
}

type storedOp struct {
	Op
	// Revisions are the per-field revisions this operation produced. Kept in
	// the record so replaying the log restores field state exactly, and so a
	// duplicate can return the original result.
	Revisions map[string]int64 `json:"revisions,omitempty"`
}

// record is one line of a segment.
type record struct {
	T   string `json:"t"`
	Seq uint64 `json:"seq,omitempty"`
	At  int64  `json:"at,omitempty"` // server time, unix ms

	Epoch   string `json:"epoch,omitempty"`   // header only
	Segment int    `json:"segment,omitempty"` // header only

	Op *storedOp `json:"op,omitempty"`

	EntityType string          `json:"entity_type,omitempty"`
	EntityID   string          `json:"entity_id,omitempty"`
	VehicleID  string          `json:"vehicle_id,omitempty"`
	Digest     string          `json:"digest,omitempty"`
	Data       json.RawMessage `json:"data,omitempty"`

	// Derived at index time, never written.
	normID string
	fields map[string]json.RawMessage
}

// vehicle returns the vehicle a record concerns.
func (r *record) vehicle() string {
	if r.Op != nil {
		return r.Op.VehicleID
	}
	return r.VehicleID
}

// Entity is a server-originated object offered to clients. Vehicles and
// assignments are reconciled from the registry; trip summaries are published by
// whatever derives them.
type Entity struct {
	Type      string
	ID        string
	VehicleID string
	Data      json.RawMessage
}

// Result statuses.
const (
	StatusAccepted  = "accepted"
	StatusDuplicate = "duplicate"
	StatusConflict  = "conflict"
	StatusRejected  = "rejected"
)

// Rejection reasons. Machine-readable and stable: a client branches on them.
const (
	ReasonScope            = "scope"
	ReasonUnknownVehicle   = "unknown_vehicle"
	ReasonArchivedVehicle  = "archived_vehicle"
	ReasonHashMismatch     = "hash_mismatch"
	ReasonPayloadTooLarge  = "payload_too_large"
	ReasonUnsupportedKind  = "unsupported_kind"
	ReasonUnsupportedVer   = "unsupported_payload_version"
	ReasonInvalidPayload   = "invalid_payload"
	ReasonInvalidOperation = "invalid_operation"
	ReasonClientMismatch   = "client_mismatch"
	ReasonOperationIDReuse = "operation_id_conflict"
	ReasonIdempotencyReuse = "idempotency_key_conflict"
)

// Conflict reports a field whose server revision differs from the operation's
// base, with what the server holds now so the client can merge without another
// round trip.
type Conflict struct {
	Field           string          `json:"field"`
	CurrentRevision int64           `json:"current_revision"`
	CurrentValue    json.RawMessage `json:"current_value,omitempty"`
}

// OpResult is the outcome for one operation in a push.
type OpResult struct {
	OperationID    string           `json:"operation_id"`
	Status         string           `json:"status"`
	Reason         string           `json:"reason,omitempty"`
	ServerSequence uint64           `json:"server_sequence,omitempty"`
	Revisions      map[string]int64 `json:"revisions,omitempty"`
	Conflicts      []Conflict       `json:"conflicts,omitempty"`
	// OriginalStatus is set on a duplicate: the status the first submission
	// received. Always "accepted", because only accepted operations are
	// remembered.
	OriginalStatus string `json:"original_status,omitempty"`
}

// Gate answers the questions about a vehicle that depend on the caller and the
// vehicle registry rather than on the log.
type Gate interface {
	// InScope reports whether the authenticated client may use the vehicle.
	InScope(vehicleID string) bool
	// VehicleStatus returns "", ReasonUnknownVehicle or ReasonArchivedVehicle.
	VehicleStatus(vehicleID string) string
}

// index is everything derivable from the log.
type index struct {
	ops    map[string]*record // normalised operation id -> record
	idem   map[string]*record // client + key -> record
	fields map[string]fieldState
	ent    map[string]string // entity type/id -> latest digest
}

type fieldState struct {
	Rev   int64
	Value json.RawMessage
}

func newIndex() *index {
	return &index{
		ops:    map[string]*record{},
		idem:   map[string]*record{},
		fields: map[string]fieldState{},
		ent:    map[string]string{},
	}
}

// Store is the sync log.
type Store struct {
	dir      string
	maxSeg   int64
	now      func() time.Time
	mu       sync.Mutex
	epoch    string
	base     uint64 // sequence of recs[0]
	recs     []*record
	main     *index
	seg      *os.File
	segNo    int
	segSize  int64
	segHdrSz int64
	broken   error
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithSegmentBytes sets the rotation size.
func WithSegmentBytes(n int64) StoreOption { return func(s *Store) { s.maxSeg = n } }

// WithStoreClock replaces the time source.
func WithStoreClock(now func() time.Time) StoreOption { return func(s *Store) { s.now = now } }

// OpenStore opens (creating if needed) the log in dir and rebuilds its indexes.
func OpenStore(dir string, opts ...StoreOption) (*Store, error) {
	s := &Store{
		dir:    dir,
		maxSeg: defaultSegmentBytes,
		now:    func() time.Time { return time.Now().UTC() },
		main:   newIndex(),
		base:   1,
	}
	for _, o := range opts {
		o(s)
	}
	if err := os.MkdirAll(s.logDir(), 0o700); err != nil {
		return nil, fmt.Errorf("sync log: create dir: %w", err)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) logDir() string { return filepath.Join(s.dir, "log") }

func segName(n int) string { return fmt.Sprintf("seg-%08d.jsonl", n) }

func (s *Store) load() error {
	names, err := filepath.Glob(filepath.Join(s.logDir(), "seg-*.jsonl"))
	if err != nil {
		return err
	}
	sort.Strings(names)

	for i, name := range names {
		last := i == len(names)-1
		var n int
		if _, err := fmt.Sscanf(filepath.Base(name), "seg-%08d.jsonl", &n); err != nil {
			return fmt.Errorf("sync log: unexpected file %s", filepath.Base(name))
		}
		size, err := s.loadSegment(name, last)
		if err != nil {
			return err
		}
		if last {
			s.segNo = n
			s.segSize = size
		}
	}

	if len(names) == 0 {
		s.epoch = newEpoch()
		return s.createSegment(1)
	}

	lastPath := filepath.Join(s.logDir(), segName(s.segNo))
	f, err := os.OpenFile(lastPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("sync log: reopen %s: %w", filepath.Base(lastPath), err)
	}
	s.seg = f
	if s.segSize == 0 {
		// The last segment was created but its header never became durable. It
		// holds no records, so it can safely be given one now.
		if s.epoch == "" {
			s.epoch = newEpoch()
		}
		line, _ := json.Marshal(record{T: recHeader, Epoch: s.epoch, Segment: s.segNo})
		line = append(line, '\n')
		if _, err := f.Write(line); err != nil {
			return fmt.Errorf("sync log: rewrite header: %w", err)
		}
		if err := f.Sync(); err != nil {
			return err
		}
		s.segSize = int64(len(line))
	}
	s.segHdrSz = headerSize(s.epoch, s.segNo)
	return nil
}

// loadSegment replays one segment into the indexes and returns its valid
// length. A torn tail on the last segment is truncated; anywhere else it is
// corruption.
func (s *Store) loadSegment(path string, last bool) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("sync log: read %s: %w", filepath.Base(path), err)
	}

	var off int
	sawHeader := false
	for off < len(raw) {
		nl := bytes.IndexByte(raw[off:], '\n')
		if nl < 0 {
			if !last {
				return 0, fmt.Errorf("sync log: %s ends mid-record but is not the last segment", filepath.Base(path))
			}
			break // torn tail, handled below
		}
		line := raw[off : off+nl]
		off += nl + 1

		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			return 0, fmt.Errorf("sync log: %s: corrupt record at byte %d: %w", filepath.Base(path), off-nl-1, err)
		}
		if !sawHeader {
			if rec.T != recHeader || rec.Epoch == "" {
				return 0, fmt.Errorf("sync log: %s does not start with a header", filepath.Base(path))
			}
			if s.epoch != "" && rec.Epoch != s.epoch {
				return 0, fmt.Errorf("sync log: %s has epoch %s, earlier segments have %s", filepath.Base(path), rec.Epoch, s.epoch)
			}
			s.epoch = rec.Epoch
			sawHeader = true
			continue
		}
		if rec.T == recHeader {
			return 0, fmt.Errorf("sync log: stray header inside %s", filepath.Base(path))
		}
		if err := s.replay(&rec); err != nil {
			return 0, fmt.Errorf("sync log: %s: %w", filepath.Base(path), err)
		}
	}

	if off < len(raw) {
		// Torn tail: bytes after the last newline. Unacknowledged by
		// construction, so dropping them is safe, and keeping them would
		// corrupt the next append.
		if err := os.Truncate(path, int64(off)); err != nil {
			return 0, fmt.Errorf("sync log: truncate torn tail of %s: %w", filepath.Base(path), err)
		}
	}
	return int64(off), nil
}

func (s *Store) replay(rec *record) error {
	if len(s.recs) == 0 {
		s.base = rec.Seq
		if s.base == 0 {
			return errors.New("record without a sequence number")
		}
	}
	if want := s.base + uint64(len(s.recs)); rec.Seq != want {
		return fmt.Errorf("sequence gap: expected %d, found %d", want, rec.Seq)
	}
	if err := indexRecord(s.main, rec); err != nil {
		return err
	}
	s.recs = append(s.recs, rec)
	return nil
}

func newEpoch() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func headerSize(epoch string, seg int) int64 {
	line, _ := json.Marshal(record{T: recHeader, Epoch: epoch, Segment: seg})
	return int64(len(line)) + 1
}

// createSegment starts segment n with a header and makes it the active one.
func (s *Store) createSegment(n int) error {
	path := filepath.Join(s.logDir(), segName(n))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("sync log: create segment: %w", err)
	}
	line, _ := json.Marshal(record{T: recHeader, Epoch: s.epoch, Segment: n})
	line = append(line, '\n')
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("sync log: write header: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	// The directory entry must be durable too, or a crash can lose the file
	// whose contents were just synced.
	if d, err := os.Open(s.logDir()); err == nil {
		_ = d.Sync()
		d.Close()
	}
	if s.seg != nil {
		_ = s.seg.Close()
	}
	s.seg, s.segNo, s.segSize, s.segHdrSz = f, n, int64(len(line)), int64(len(line))
	return nil
}

// Close releases the active segment.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seg == nil {
		return nil
	}
	err := s.seg.Close()
	s.seg = nil
	return err
}

// Epoch identifies this incarnation of the log.
func (s *Store) Epoch() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.epoch
}

// Head is the highest assigned sequence (0 when the log is empty).
func (s *Store) Head() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headLocked()
}

func (s *Store) headLocked() uint64 { return s.base + uint64(len(s.recs)) - 1 }

// indexRecord folds one record into an index. Used both to rebuild at open and
// to stage a batch, so the two cannot disagree about what a record means.
func indexRecord(ix *index, rec *record) error {
	switch rec.T {
	case recOp:
		if rec.Op == nil {
			return errors.New("operation record without an operation")
		}
		norm, ok := normalizeUUID(rec.Op.OperationID)
		if !ok {
			return fmt.Errorf("stored operation has a malformed id %q", rec.Op.OperationID)
		}
		rec.normID = norm
		ix.ops[norm] = rec
		if k := rec.Op.IdempotencyKey; k != "" {
			ix.idem[rec.Op.ClientID+"\x00"+k] = rec
		}
		if mutableKinds[rec.Op.Kind] {
			mp, err := parseMutable(rec.Op.Kind, rec.Op.VehicleID, rec.Op.Payload)
			if err != nil {
				return fmt.Errorf("stored operation %s: %w", rec.Op.OperationID, err)
			}
			rec.fields = mp.fields
			for name, val := range mp.fields {
				ix.fields[fieldKey(rec.Op.Kind, rec.Op.VehicleID, mp.target, name)] =
					fieldState{Rev: rec.Op.Revisions[name], Value: val}
			}
		}
	case recEntity:
		ix.ent[rec.EntityType+"/"+rec.EntityID] = rec.Digest
	default:
		return fmt.Errorf("unknown record type %q", rec.T)
	}
	return nil
}

func fieldKey(kind, vehicle, target, field string) string {
	return kind + "\x00" + vehicle + "\x00" + target + "\x00" + field
}

// mutablePayload is the parsed shape of a revisioned operation.
type mutablePayload struct {
	target string
	fields map[string]json.RawMessage
}

// parseMutable validates the payload of a mutable kind:
//
//	{"target": "<id>", "fields": {"<name>": <value>, ...}}
//
// vehicle_update takes no target: the vehicle is the target.
func parseMutable(kind, vehicleID string, canonical []byte) (*mutablePayload, error) {
	var p struct {
		Target *string                    `json:"target"`
		Fields map[string]json.RawMessage `json:"fields"`
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("payload must be {target, fields}: %w", err)
	}
	if len(p.Fields) == 0 || len(p.Fields) > maxFieldsPerOp {
		return nil, fmt.Errorf("fields must hold 1..%d entries", maxFieldsPerOp)
	}
	for name := range p.Fields {
		if len(name) > maxFieldNameLen || !fieldNameRE.MatchString(name) {
			return nil, fmt.Errorf("field name %q is not [a-z][a-z0-9_]* within %d bytes", name, maxFieldNameLen)
		}
	}

	target := ""
	if kind == KindVehicleUpdate {
		if p.Target != nil && *p.Target != vehicleID {
			return nil, errors.New("vehicle_update target, when given, must be the vehicle")
		}
		target = vehicleID
	} else {
		if p.Target == nil || *p.Target == "" || len(*p.Target) > maxTargetLen || !targetRE.MatchString(*p.Target) {
			return nil, fmt.Errorf("target is required, [A-Za-z0-9._:-], up to %d bytes", maxTargetLen)
		}
		target = *p.Target
	}
	return &mutablePayload{target: target, fields: p.Fields}, nil
}

// normalizeUUID accepts a UUID in 32-hex or hyphenated form and returns it as
// lowercase 32 hex. iOS's UUID.uuidString is upper-case and hyphenated; the
// server's own identifiers are bare hex; both must name the same operation.
func normalizeUUID(s string) (string, bool) {
	if len(s) == 36 {
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return "", false
		}
		s = s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	}
	s = strings.ToLower(s)
	if raw, err := hex.DecodeString(s); err != nil || len(raw) != 16 {
		return "", false
	}
	return s, true
}

// ─── pushing operations ─────────────────────────────────────────────────────

// ApplyBatch evaluates a client's operations in order and appends the accepted
// ones in a single durable write.
//
// The batch is evaluated against the log *plus the batch so far*, so an
// operation can depend on one earlier in the same push (an edit to a field the
// previous operation just set) without a spurious conflict. Evaluation changes
// nothing in memory; indexes are updated only after the write is durable, so a
// failed write leaves memory and disk agreeing.
func (s *Store) ApplyBatch(clientID string, ops []Op, gate Gate) ([]OpResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return nil, s.broken
	}

	stage := newIndex()
	next := s.headLocked() + 1
	nowMS := s.now().UnixMilli()

	results := make([]OpResult, len(ops))
	var fresh []*record
	for i := range ops {
		res, rec := s.evaluate(clientID, ops[i], gate, stage, next, nowMS)
		results[i] = res
		if rec != nil {
			fresh = append(fresh, rec)
			next++
		}
	}

	if len(fresh) > 0 {
		if err := s.appendLocked(fresh); err != nil {
			return nil, err
		}
		for _, rec := range fresh {
			// Cannot fail: the same records were just indexed into the stage.
			_ = indexRecord(s.main, rec)
			s.recs = append(s.recs, rec)
		}
	}
	return results, nil
}

func (s *Store) lookupOp(stage *index, norm string) *record {
	if r, ok := stage.ops[norm]; ok {
		return r
	}
	return s.main.ops[norm]
}

func (s *Store) lookupIdem(stage *index, key string) *record {
	if r, ok := stage.idem[key]; ok {
		return r
	}
	return s.main.idem[key]
}

func (s *Store) lookupField(stage *index, key string) fieldState {
	if f, ok := stage.fields[key]; ok {
		return f
	}
	return s.main.fields[key]
}

func reject(op Op, reason string) OpResult {
	return OpResult{OperationID: op.OperationID, Status: StatusRejected, Reason: reason}
}

func duplicateOf(op Op, orig *record) OpResult {
	return OpResult{
		OperationID:    op.OperationID,
		Status:         StatusDuplicate,
		ServerSequence: orig.Seq,
		Revisions:      orig.Op.Revisions,
		OriginalStatus: StatusAccepted,
	}
}

// evaluate decides one operation. The order of the checks is deliberate and
// documented in contracts/sync/v1/spec.md:
//
//  1. cheap structural checks that need no state;
//  2. scope, before anything that would reveal whether a vehicle or an
//     operation exists, so a client cannot probe outside its scope;
//  3. the duplicate lookup, before the vehicle's current state, so a retry of
//     something accepted earlier still gets its original answer after the
//     vehicle has since been archived;
//  4. vehicle state, hash, payload shape, and finally revision conflicts.
func (s *Store) evaluate(clientID string, op Op, gate Gate, stage *index, seq uint64, nowMS int64) (OpResult, *record) {
	if op.ClientID != "" && !strings.EqualFold(op.ClientID, clientID) {
		return reject(op, ReasonClientMismatch), nil
	}
	op.ClientID = clientID
	op.VehicleID = strings.ToLower(op.VehicleID)

	norm, ok := normalizeUUID(op.OperationID)
	if !ok {
		return reject(op, ReasonInvalidOperation), nil
	}
	if !knownKinds[op.Kind] {
		return reject(op, ReasonUnsupportedKind), nil
	}
	if len(op.Payload) > maxPayloadBytes {
		return reject(op, ReasonPayloadTooLarge), nil
	}
	if op.PayloadVersion != supportedPayloadVer {
		return reject(op, ReasonUnsupportedVer), nil
	}
	if len(op.IdempotencyKey) > maxIdempotencyKeyLen || strings.ContainsAny(op.IdempotencyKey, "\x00\n\r") {
		return reject(op, ReasonInvalidOperation), nil
	}
	if _, err := time.Parse(time.RFC3339, op.CreatedAt); err != nil {
		return reject(op, ReasonInvalidOperation), nil
	}

	if !gate.InScope(op.VehicleID) {
		return reject(op, ReasonScope), nil
	}

	if orig := s.lookupOp(stage, norm); orig != nil {
		if !strings.EqualFold(orig.Op.ClientID, clientID) || orig.Op.ContentHash != op.ContentHash {
			// Same id, different content (a client bug), or an id that belongs
			// to someone else. Neither is a retry, and the second must not
			// confirm that the id exists.
			return reject(op, ReasonOperationIDReuse), nil
		}
		return duplicateOf(op, orig), nil
	}
	if op.IdempotencyKey != "" {
		if orig := s.lookupIdem(stage, clientID+"\x00"+op.IdempotencyKey); orig != nil {
			if orig.Op.ContentHash != op.ContentHash {
				return reject(op, ReasonIdempotencyReuse), nil
			}
			return duplicateOf(op, orig), nil
		}
	}

	if reason := gate.VehicleStatus(op.VehicleID); reason != "" {
		return reject(op, reason), nil
	}

	canonical, err := Canonicalize(op.Payload)
	if err != nil {
		return reject(op, ReasonInvalidPayload), nil
	}
	// The hash is checked against what the server computes, never taken on
	// trust: it is the evidence that the payload arrived as it was written.
	if !strings.EqualFold(op.ContentHash, ContentHash(canonical)) {
		return reject(op, ReasonHashMismatch), nil
	}
	op.ContentHash = strings.ToLower(op.ContentHash)
	op.Payload = canonical

	rec := &record{T: recOp, Seq: seq, At: nowMS, normID: norm}
	so := &storedOp{Op: op}
	rec.Op = so

	if mutableKinds[op.Kind] {
		mp, err := parseMutable(op.Kind, op.VehicleID, canonical)
		if err != nil {
			return reject(op, ReasonInvalidPayload), nil
		}
		for name := range op.BaseRevision {
			if _, ok := mp.fields[name]; !ok {
				return reject(op, ReasonInvalidPayload), nil
			}
		}

		names := make([]string, 0, len(mp.fields))
		for n := range mp.fields {
			names = append(names, n)
		}
		sort.Strings(names)

		var conflicts []Conflict
		for _, name := range names {
			cur := s.lookupField(stage, fieldKey(op.Kind, op.VehicleID, mp.target, name))
			if op.BaseRevision[name] != cur.Rev {
				conflicts = append(conflicts, Conflict{Field: name, CurrentRevision: cur.Rev, CurrentValue: cur.Value})
			}
		}
		if len(conflicts) > 0 {
			// All or nothing: applying part of an edit would leave the client
			// believing a state the server never held.
			return OpResult{OperationID: op.OperationID, Status: StatusConflict, Conflicts: conflicts}, nil
		}

		so.Revisions = make(map[string]int64, len(names))
		for _, name := range names {
			cur := s.lookupField(stage, fieldKey(op.Kind, op.VehicleID, mp.target, name))
			so.Revisions[name] = cur.Rev + 1
		}
	} else if len(op.BaseRevision) > 0 {
		return reject(op, ReasonInvalidPayload), nil
	}

	if err := indexRecord(stage, rec); err != nil {
		return reject(op, ReasonInvalidPayload), nil
	}
	return OpResult{
		OperationID:    op.OperationID,
		Status:         StatusAccepted,
		ServerSequence: seq,
		Revisions:      so.Revisions,
	}, rec
}

// ─── server-originated entities ─────────────────────────────────────────────

// Publish offers a server-originated entity to clients. It is how the decode
// worker will publish trip summaries: it calls this once a trip is derived,
// and every in-scope client receives it on its next pull.
//
// Publishing is an upsert by (type, id): identical content is a no-op, changed
// content appends a new record that supersedes the old one in sequence order.
// Only trip_summary is open to callers; vehicles and assignments come from the
// registries and are reconciled by the server itself.
func (s *Store) Publish(e Entity) (seq uint64, changed bool, err error) {
	if e.Type != EntityTypeTripSummary {
		return 0, false, fmt.Errorf("entity type %q cannot be published", e.Type)
	}
	if e.VehicleID == "" || e.ID == "" {
		return 0, false, errors.New("an entity needs an id and a vehicle")
	}
	n, err := s.publishMany([]Entity{e})
	if err != nil {
		return 0, false, err
	}
	if n == 0 {
		return 0, false, nil
	}
	return s.Head(), true, nil
}

// publishMany appends every entity whose content differs from the last
// published version, in one durable write, and returns how many changed.
func (s *Store) publishMany(ents []Entity) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return 0, s.broken
	}

	stage := newIndex()
	next := s.headLocked() + 1
	nowMS := s.now().UnixMilli()

	var fresh []*record
	for _, e := range ents {
		var compact bytes.Buffer
		if err := json.Compact(&compact, e.Data); err != nil {
			return 0, fmt.Errorf("entity %s/%s: data is not JSON: %w", e.Type, e.ID, err)
		}
		sum := sha256.Sum256(compact.Bytes())
		digest := hex.EncodeToString(sum[:])

		key := e.Type + "/" + e.ID
		if prev, ok := stage.ent[key]; ok && prev == digest {
			continue
		}
		if prev, ok := s.main.ent[key]; ok && prev == digest {
			if _, staged := stage.ent[key]; !staged {
				continue
			}
		}
		rec := &record{
			T: recEntity, Seq: next, At: nowMS,
			EntityType: e.Type, EntityID: e.ID, VehicleID: strings.ToLower(e.VehicleID),
			Digest: digest, Data: json.RawMessage(compact.Bytes()),
		}
		_ = indexRecord(stage, rec)
		fresh = append(fresh, rec)
		next++
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	if err := s.appendLocked(fresh); err != nil {
		return 0, err
	}
	for _, rec := range fresh {
		_ = indexRecord(s.main, rec)
		s.recs = append(s.recs, rec)
	}
	return len(fresh), nil
}

// appendLocked writes records durably. On failure it truncates the partial
// write away so the file ends on a record boundary; if even that fails the
// store refuses further writes, because appending after a torn line would
// corrupt the log, and a restart (which repairs the tail) is the safe way back.
func (s *Store) appendLocked(recs []*record) error {
	var buf bytes.Buffer
	for _, r := range recs {
		line, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("sync log: marshal: %w", err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	if s.segSize > s.segHdrSz && s.segSize+int64(buf.Len()) > s.maxSeg {
		if err := s.createSegment(s.segNo + 1); err != nil {
			return err
		}
	}

	n, err := s.seg.Write(buf.Bytes())
	if err == nil {
		err = s.seg.Sync()
	}
	if err != nil {
		if terr := s.seg.Truncate(s.segSize); terr != nil {
			s.broken = fmt.Errorf("sync log is unwritable after a failed append (restart to repair): %w", terr)
		}
		return fmt.Errorf("sync log: append: %w", err)
	}
	s.segSize += int64(n)
	return nil
}

// ─── reading ────────────────────────────────────────────────────────────────

// ErrBehindLog means a cursor points before the oldest retained record.
var ErrBehindLog = errors.New("cursor is older than the retained log")

// scan returns records with sequence greater than after that match, up to
// limit, and the highest sequence examined. The returned records are immutable.
func (s *Store) scan(after uint64, limit int, match func(*record) bool) ([]*record, uint64, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	head := s.headLocked()
	if len(s.recs) == 0 {
		return nil, after, head, nil
	}
	if after+1 < s.base {
		return nil, 0, head, ErrBehindLog
	}
	if after > head {
		return nil, 0, head, fmt.Errorf("cursor %d is ahead of the log (%d)", after, head)
	}

	var out []*record
	last := after
	for seq := after + 1; seq <= head; seq++ {
		rec := s.recs[seq-s.base]
		last = seq
		if match(rec) {
			out = append(out, rec)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, last, head, nil
}

// field returns the current state of a field, for tests and diagnostics.
func (s *Store) field(kind, vehicle, target, name string) fieldState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.main.fields[fieldKey(kind, vehicle, target, name)]
}
