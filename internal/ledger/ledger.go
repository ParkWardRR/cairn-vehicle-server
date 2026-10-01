// Package ledger records every bundle lifecycle transition, with a reason.
//
// The point is answering "what happened to this bundle, and why" without
// reconstructing it from logs. A log line is prose and is rotated away; a
// ledger entry is a record with a reason code that outlives the bundle it
// describes — which matters most for the entries that explain a *refusal*,
// since those are the cases where the data is gone from the device and the
// server is the only thing that can say what happened to it.
//
// Append-only on disk rather than in PostgreSQL, deliberately. Ingest has no
// database dependency — a Postgres outage delays the derived view and nothing
// more — and making the ledger a database write would quietly give ingest one.
// The worker mirrors entries into the derived layer later, where queries live.
package ledger

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is what happened. String constants rather than integers: a ledger is
// read by people far more often than by code, and an unrecognized integer in a
// file nobody can decode is a poor way to learn what went wrong.
type Event string

const (
	EventOffered       Event = "offered"
	EventOfferRejected Event = "offer_rejected"
	EventChunkAccepted Event = "chunk_accepted"
	EventChunkRejected Event = "chunk_rejected"
	EventCommitted     Event = "committed"
	EventCommitFailed  Event = "commit_failed"
	EventReceiptIssued Event = "receipt_issued"
	EventDecodeQueued  Event = "decode_queued"
	EventDecodeOK      Event = "decode_succeeded"
	EventDecodeFailed  Event = "decode_failed"
	EventReprocessed   Event = "reprocessed"
	EventQuotaRefused  Event = "quota_refused"
	EventDeviceUnknown Event = "device_unknown"
)

// Entry is one transition.
type Entry struct {
	// UTCMS is when the server observed this. Wall-clock is acceptable here in
	// a way it is not inside a bundle: this is the server's own log of its own
	// actions, not an ordering key for device data.
	UTCMS int64 `json:"utc_ms"`

	Event    Event  `json:"event"`
	BundleID string `json:"bundle_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`

	// ContentRoot is the data's identity, and is what survives re-chunking,
	// re-upload and a reused bundle id.
	ContentRoot string `json:"content_root,omitempty"`

	// Reason is why, in a form meant to be read. Required for every rejection:
	// a refusal without a reason is the one entry that cannot be acted on.
	Reason string `json:"reason,omitempty"`

	Bytes int64   `json:"bytes,omitempty"`
	Chunk *uint32 `json:"chunk,omitempty"`
}

// Ledger appends entries to a daily file.
//
// Daily files rather than one growing file so that archiving and pruning are
// ordinary filesystem operations, and so a corrupt tail costs one day rather
// than the whole history.
type Ledger struct {
	dir string

	mu   sync.Mutex
	day  string
	file *os.File
}

// Open prepares the ledger directory.
func Open(dir string) (*Ledger, error) {
	if dir == "" {
		return nil, errors.New("ledger: directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("ledger: create %s: %w", dir, err)
	}
	return &Ledger{dir: dir}, nil
}

// Append writes one entry durably.
//
// Flushed and fsynced before returning. The ledger exists to explain what
// happened to data, and an entry lost to a crash is most likely to be the entry
// explaining that crash.
func (l *Ledger) Append(e Entry) error {
	if e.Event == "" {
		return errors.New("ledger: entry has no event")
	}
	if e.UTCMS == 0 {
		e.UTCMS = time.Now().UnixMilli()
	}

	// Every rejection must say why. Enforced here rather than trusted to call
	// sites, because the entries that need a reason are exactly the ones
	// written on an error path where it is easiest to forget.
	switch e.Event {
	case EventOfferRejected, EventChunkRejected, EventCommitFailed,
		EventDecodeFailed, EventQuotaRefused, EventDeviceUnknown:
		if e.Reason == "" {
			return fmt.Errorf("ledger: %s requires a reason", e.Event)
		}
	}

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("ledger: marshal: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateLocked(e.UTCMS); err != nil {
		return err
	}
	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("ledger: write: %w", err)
	}
	return l.file.Sync()
}

func (l *Ledger) rotateLocked(utcMS int64) error {
	day := time.UnixMilli(utcMS).UTC().Format("2006-01-02")
	if l.file != nil && l.day == day {
		return nil
	}

	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}

	path := filepath.Join(l.dir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("ledger: open %s: %w", path, err)
	}

	l.file = f
	l.day = day
	return nil
}

// Close releases the current file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Read returns every entry, oldest first.
//
// A malformed line is reported rather than skipped. Silently dropping one would
// make the ledger quietly incomplete, which is worse than a ledger that admits
// it is damaged.
func (l *Ledger) Read() ([]Entry, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}

	var days []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".jsonl" {
			days = append(days, e.Name())
		}
	}
	// Names are ISO dates, so lexicographic order is chronological.
	sortStrings(days)

	var out []Entry
	for _, name := range days {
		raw, err := os.ReadFile(filepath.Join(l.dir, name))
		if err != nil {
			return nil, err
		}

		for i, line := range splitLines(raw) {
			if len(line) == 0 {
				continue
			}
			var e Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return out, fmt.Errorf("ledger: %s line %d is malformed: %w",
					name, i+1, err)
			}
			out = append(out, e)
		}
	}

	return out, nil
}

// HexID renders an id for an entry.
func HexID(b []byte) string { return hex.EncodeToString(b) }

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}
