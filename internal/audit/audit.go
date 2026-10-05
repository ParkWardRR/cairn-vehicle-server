// Package audit is the append-only record of who did what to the app API.
//
// The ledger answers "what happened to this bundle". This answers a different
// question: "which identity, over which path, asked the server to do which
// thing, and what did it say". That is the record an operator needs after a
// phone is lost or a device is revoked, and it has to be trustworthy in a
// narrow sense: it must never become a second place secrets leak to.
//
// # What is deliberately not recordable
//
// Entry is a closed struct. There is no field for a request payload, a
// location, a token, a signature, a certificate, a Wi-Fi name or a VIN, so a
// caller cannot add one by accident; the best it can do is hash a body. The one
// free-text field, Reason, is squeezed through sanitizeReason, which keeps it to
// a short machine code. That matters because the easy way to fill a "reason"
// is err.Error(), and an error message is exactly where a stray credential or
// coordinate would otherwise slip into a file that is kept for years and read by
// people who were never meant to see it.
//
// The Tailscale login (an e-mail address) is recorded because attributing a
// request to a tailnet user is the whole point of recording it; it is trimmed
// to printable ASCII so it cannot be used to forge log lines.
//
// # Shape
//
// One JSON object per line, one file per UTC day, fsynced per entry. Volume is
// a handful of requests per drive, so the fsync is affordable, and an audit
// entry lost to a crash is most likely the one explaining the crash. Daily
// files keep archiving and pruning ordinary filesystem operations.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Actor types.
const (
	ActorApp       = "app"
	ActorDevice    = "device"
	ActorAnonymous = "anonymous"
)

// Entry is one audited request.
type Entry struct {
	Time time.Time `json:"ts"`

	ActorType string `json:"actor_type"`
	ActorID   string `json:"actor_id,omitempty"`

	// Transport is loopback, lan, tailnet or other. It records the path the
	// request arrived by, which is what distinguishes "my phone at home" from
	// "something reached the app listener from somewhere unexpected".
	Transport      string `json:"transport,omitempty"`
	TailscaleLogin string `json:"tailscale_login,omitempty"`

	// ClientID and DeviceID name the app client and OBD device the entry
	// concerns. TargetID is the object of an administrative action, such as the
	// client or device being revoked.
	ClientID string `json:"client_id,omitempty"`
	DeviceID string `json:"device_id,omitempty"`
	TargetID string `json:"target_id,omitempty"`

	Method string `json:"method"`

	// Route is the route pattern ("POST /v1/clients/{id}/revoke"), not the raw
	// path. The pattern groups requests usefully and keeps identifiers that
	// arrived in the path out of the file.
	Route string `json:"route"`

	// BodySHA256 identifies what was sent without keeping it.
	BodySHA256 string `json:"body_sha256,omitempty"`

	Status int    `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Log appends entries to a daily file.
type Log struct {
	dir string
	now func() time.Time

	mu   sync.Mutex
	day  string
	file *os.File
}

// Open prepares the audit directory.
func Open(dir string) (*Log, error) {
	if dir == "" {
		return nil, errors.New("audit: directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create %s: %w", dir, err)
	}
	return &Log{dir: dir, now: func() time.Time { return time.Now().UTC() }}, nil
}

// SetClock replaces the time source. Tests use it to cross a day boundary
// without waiting for one.
func (l *Log) SetClock(now func() time.Time) { l.now = now }

// Append writes one entry durably.
func (l *Log) Append(e Entry) error {
	if e.Time.IsZero() {
		e.Time = l.now()
	}
	e.Time = e.Time.UTC()
	e.Reason = sanitizeReason(e.Reason)
	e.TailscaleLogin = sanitizeLogin(e.TailscaleLogin)
	if e.ActorType == "" {
		e.ActorType = ActorAnonymous
	}

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.rotateLocked(e.Time); err != nil {
		return err
	}
	if _, err := l.file.Write(line); err != nil {
		return fmt.Errorf("audit: write: %w", err)
	}
	return l.file.Sync()
}

func (l *Log) rotateLocked(t time.Time) error {
	day := t.Format("2006-01-02")
	if l.file != nil && l.day == day {
		return nil
	}
	if l.file != nil {
		_ = l.file.Close()
		l.file = nil
	}
	f, err := os.OpenFile(filepath.Join(l.dir, "audit-"+day+".jsonl"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open day file: %w", err)
	}
	l.file, l.day = f, day
	return nil
}

// Close releases the open file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Read returns every entry across all day files, oldest first. It is for tests
// and the admin CLI; a corrupt line is an error rather than being skipped,
// because a silently shortened audit trail is worse than a loud one.
func (l *Log) Read() ([]Entry, error) {
	names, err := filepath.Glob(filepath.Join(l.dir, "audit-*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	var out []Entry
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("audit: read %s: %w", filepath.Base(name), err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if line == "" {
				continue
			}
			var e Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				return nil, fmt.Errorf("audit: %s line %d: %w", filepath.Base(name), i+1, err)
			}
			out = append(out, e)
		}
	}
	return out, nil
}

// sanitizeReason reduces a reason to a short machine code. Anything outside a
// conservative alphabet becomes '_', so an error string passed by mistake
// cannot smuggle structure, whitespace or long secrets into the file.
func sanitizeReason(s string) string {
	const max = 96
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '_', r == '-', r == '.', r == ':', r == '=', r == ',':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// sanitizeLogin keeps a Tailscale login to printable ASCII and a sane length.
func sanitizeLogin(s string) string {
	const max = 128
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		if c := s[i]; c > 0x20 && c < 0x7f {
			b.WriteByte(c)
		}
	}
	return b.String()
}
