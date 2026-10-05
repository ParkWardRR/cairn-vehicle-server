// Package jsonstore is a small durable, externally-editable JSON document.
//
// The registries (devices, vehicles, app clients, sync counters) share one
// shape of need: a file the ingest process reads on every request, that an
// operator edits from the command line while the service runs, and that must
// never be left half-written. Ingest deliberately has no database dependency,
// so these are files — and this package is the one place that knows how to
// write them safely.
//
// The guarantees are the same ones the device registry established:
//
//   - writes are atomic (temp file, fsync, rename, directory fsync), so a crash
//     leaves the previous contents or the new ones, never a mixture;
//   - the file is mode 0600, because several of these hold identifiers an
//     attacker could use to impersonate a client;
//   - a change made by another process is noticed with a stat, so revoking a
//     stolen unit from the CLI takes effect without restarting the server;
//   - a corrupt file mid-edit keeps the last good contents in memory rather
//     than failing the request that happened to look.
package jsonstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store holds one JSON document of type T.
type Store[T any] struct {
	path string

	mu     sync.Mutex
	value  T
	empty  func() T
	modAt  time.Time
	size   int64
	loaded bool
}

// Open loads path, or starts from empty() when the file does not exist yet.
func Open[T any](path string, empty func() T) (*Store[T], error) {
	s := &Store[T]{path: path, empty: empty, value: empty()}
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// reload reads the file into memory. Callers hold no lock.
func (s *Store[T]) reload() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		s.value = s.empty()
		s.modAt, s.size, s.loaded = time.Time{}, 0, true
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(s.path), err)
	}

	v := s.empty()
	if err := json.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(s.path), err)
	}

	var mod time.Time
	var size int64
	if info, err := os.Stat(s.path); err == nil {
		mod, size = info.ModTime(), info.Size()
	}

	s.mu.Lock()
	s.value, s.modAt, s.size, s.loaded = v, mod, size, true
	s.mu.Unlock()
	return nil
}

// Refresh reloads when another process has changed the file. A parse failure is
// swallowed on purpose: see the package comment.
func (s *Store[T]) Refresh() {
	info, err := os.Stat(s.path)
	if err != nil {
		return
	}
	s.mu.Lock()
	unchanged := info.ModTime().Equal(s.modAt) && info.Size() == s.size
	s.mu.Unlock()
	if unchanged {
		return
	}
	_ = s.reload()
}

// View runs fn against the current contents under the lock. fn must not retain
// or mutate the value.
func (s *Store[T]) View(fn func(*T)) {
	s.Refresh()
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.value)
}

// Update applies fn to the current contents and, when fn returns nil, writes
// the result durably. It refreshes first, so an update never silently discards
// a change another process made since this one last loaded.
func (s *Store[T]) Update(fn func(*T) error) error {
	s.Refresh()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Mutate a copy via a JSON round trip so a failing fn leaves memory
	// untouched. Documents here are small, so the cost is irrelevant next to
	// the fsyncs, and it avoids requiring every T to implement a deep copy.
	snapshot, err := json.Marshal(s.value)
	if err != nil {
		return fmt.Errorf("snapshot %s: %w", filepath.Base(s.path), err)
	}
	working := s.empty()
	if err := json.Unmarshal(snapshot, &working); err != nil {
		return fmt.Errorf("snapshot %s: %w", filepath.Base(s.path), err)
	}

	if err := fn(&working); err != nil {
		return err
	}
	if err := writeAtomic(s.path, working); err != nil {
		return err
	}

	s.value = working
	if info, err := os.Stat(s.path); err == nil {
		s.modAt, s.size = info.ModTime(), info.Size()
	}
	return nil
}

func writeAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", filepath.Base(path), err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	f, err := os.CreateTemp(dir, ".jsonstore-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmp := f.Name()

	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	return d.Sync()
}
