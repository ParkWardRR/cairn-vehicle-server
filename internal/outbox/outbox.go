// Package outbox is the durable hand-off between ingest and the decode
// workers.
//
// It exists so that ingest can return as soon as the raw commit is durable.
// The old design parsed samples, built trips, detected events and published
// MQTT on the upload request while the device held a connection open, which
// made request latency scale with trip length and turned a decoder bug into an
// upload failure. Here, a failed decode job never implies a failed upload.
//
// Entries are append-only JSON lines plus a separate directory of completion
// markers. A worker claims an entry, does its work and acknowledges it; an
// unacknowledged entry is simply redelivered on the next pass, so a worker
// crash costs a repeat rather than a lost job. Decode work must therefore be
// idempotent — which it naturally is, being a pure function of immutable raw
// data.
package outbox

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one unit of decode work: a bundle that has been committed to raw
// storage and receipted.
type Entry struct {
	// Seq is assigned by the queue, ascending.
	Seq uint64 `json:"seq"`

	// EnqueuedAt is when ingest handed the work over.
	EnqueuedAt time.Time `json:"enqueued_at"`

	BundleID       string `json:"bundle_id"`
	DeviceID       string `json:"device_id"`
	ContentRoot    string `json:"content_root"`
	ManifestDigest string `json:"manifest_digest"`
	ReceiptID      string `json:"receipt_id"`
	BytesStored    int64  `json:"bytes_stored"`
}

// Queue is a durable append-only work queue.
type Queue struct {
	dir     string
	logPath string
	ackDir  string

	mu   sync.Mutex
	next uint64
}

// ErrNotFound means no entry with that sequence number exists.
var ErrNotFound = errors.New("outbox entry not found")

// Open prepares a queue, recovering the next sequence number from the log.
func Open(dir string) (*Queue, error) {
	q := &Queue{
		dir:     dir,
		logPath: filepath.Join(dir, "entries.jsonl"),
		ackDir:  filepath.Join(dir, "acked"),
	}

	for _, d := range []string{q.dir, q.ackDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", d, err)
		}
	}

	entries, err := q.readAll()
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Seq >= q.next {
			q.next = e.Seq + 1
		}
	}

	return q, nil
}

// Append adds an entry and fsyncs before returning.
//
// Durability here is what lets ingest answer the device immediately: once this
// returns, the decode work is recorded even if the process dies in the next
// instant.
func (q *Queue) Append(e Entry) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	e.Seq = q.next
	if e.EnqueuedAt.IsZero() {
		e.EnqueuedAt = time.Now().UTC()
	}

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode outbox entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(q.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open outbox log: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("append outbox entry: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync outbox log: %w", err)
	}

	q.next = e.Seq + 1
	return nil
}

// Pending returns entries that have not been acknowledged, in queue order.
//
// Pending is derived by subtracting the acknowledgement markers from the log
// rather than by mutating the log. An append-only log plus derived state means
// a crash can never leave the queue in a half-updated condition.
func (q *Queue) Pending() ([]Entry, error) {
	entries, err := q.readAll()
	if err != nil {
		return nil, err
	}

	pending := make([]Entry, 0, len(entries))
	for _, e := range entries {
		acked, err := q.isAcked(e.Seq)
		if err != nil {
			return nil, err
		}
		if !acked {
			pending = append(pending, e)
		}
	}
	return pending, nil
}

// Ack marks an entry complete. Acking twice is not an error, so a worker that
// crashes after finishing but before acking can safely repeat.
func (q *Queue) Ack(seq uint64) error {
	marker := q.ackPath(seq)

	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create ack marker: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync ack marker: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close ack marker: %w", err)
	}

	d, err := os.Open(q.ackDir)
	if err != nil {
		return fmt.Errorf("open ack dir for sync: %w", err)
	}
	defer d.Close()
	return d.Sync()
}

// Len returns the total number of entries ever enqueued.
func (q *Queue) Len() (int, error) {
	entries, err := q.readAll()
	return len(entries), err
}

// PendingCount returns how many entries are outstanding. This is the
// upload-backlog figure worth surfacing on a dashboard.
func (q *Queue) PendingCount() (int, error) {
	pending, err := q.Pending()
	return len(pending), err
}

func (q *Queue) ackPath(seq uint64) string {
	return filepath.Join(q.ackDir, fmt.Sprintf("%020d", seq))
}

func (q *Queue) isAcked(seq uint64) (bool, error) {
	_, err := os.Stat(q.ackPath(seq))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// readAll parses the log.
//
// A truncated final line is tolerated and dropped: an append that was cut short
// by a crash never completed its fsync, so no caller was ever told the entry
// existed. Refusing to start over a partial tail would be worse than ignoring
// it — and the alternative, treating it as valid, would hand a worker a
// malformed job.
func (q *Queue) readAll() ([]Entry, error) {
	f, err := os.Open(q.logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open outbox log: %w", err)
	}
	defer f.Close()

	var entries []Entry

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			// Only a torn final line is acceptable. A malformed line in the
			// middle means real corruption, which must be reported.
			if scanner.Scan() {
				return nil, fmt.Errorf("corrupt outbox entry at seq position %d: %w", len(entries), err)
			}
			break
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read outbox log: %w", err)
	}

	return entries, nil
}

// Get returns one entry by sequence number.
func (q *Queue) Get(seq uint64) (*Entry, error) {
	entries, err := q.readAll()
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Seq == seq {
			return &entries[i], nil
		}
	}
	return nil, fmt.Errorf("%w: seq %d", ErrNotFound, seq)
}

// HexID is a small helper for callers building entries from raw identifiers.
func HexID(b []byte) string { return hex.EncodeToString(b) }

// BytesStoredFor sums the raw bytes committed for one device.
//
// This is a growth cap derived from the commit log, not an authoritative
// account of current disk usage: it does not shrink when retention prunes
// server-side copies. That is an acceptable approximation for a quota whose
// purpose is to stop one device filling the dataset, and the relational schema
// in a later phase replaces it with a real figure.
func (q *Queue) BytesStoredFor(deviceID string) (int64, error) {
	entries, err := q.readAll()
	if err != nil {
		return 0, err
	}

	var total int64
	for _, e := range entries {
		if e.DeviceID == deviceID {
			total += e.BytesStored
		}
	}
	return total, nil
}
