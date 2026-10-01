// Package cas is a content-addressed object store for raw bundle data.
//
// Raw data is authoritative: a decoder bug must be fixable without losing
// original evidence, so bundle members land here before any relational
// expansion and are never mutated afterwards. Objects are named by the SHA-256
// of their contents, which makes writes idempotent and deduplication automatic.
//
// The abstraction is deliberately object-like so that swapping the backing
// filesystem for MinIO later is not a protocol change. A directory on a ZFS
// dataset is sufficient on day one.
//
// Durability is the point of this package. A receipt promises the device that a
// recoverable record exists, so every Put returns only once the data is durable
// through an fsync of both the file and its parent directory. Anything weaker
// would make the receipt a lie after a power cut on the server.
package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Store is a content-addressed object store rooted at a directory.
type Store struct {
	root    string
	objects string
	tmp     string
}

// ErrNotFound means no object with that digest is stored.
var ErrNotFound = errors.New("object not found")

// ErrDigestMismatch means the data did not hash to the declared digest. This is
// the integrity gate: the store refuses to accept data under a name that does
// not describe it.
var ErrDigestMismatch = errors.New("data does not match the declared digest")

// Open prepares a store at root, creating its directories if needed.
func Open(root string) (*Store, error) {
	s := &Store{
		root:    root,
		objects: filepath.Join(root, "objects"),
		tmp:     filepath.Join(root, "tmp"),
	}

	for _, dir := range []string{s.root, s.objects, s.tmp} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	// A tmp directory surviving from a previous run holds only partial writes:
	// nothing was ever renamed into place, so nothing is referenced.
	if err := s.clearTmp(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) clearTmp() error {
	entries, err := os.ReadDir(s.tmp)
	if err != nil {
		return fmt.Errorf("read tmp: %w", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(s.tmp, e.Name())); err != nil {
			return fmt.Errorf("remove stale temp %s: %w", e.Name(), err)
		}
	}
	return nil
}

// ObjectID returns the stable identifier for a digest, suitable for a receipt's
// stored_object_ids. It is a path-shaped string rather than a filesystem path,
// so it stays valid if the backing store changes.
func ObjectID(digest [32]byte) string {
	h := hex.EncodeToString(digest[:])
	return "cas/" + h[:2] + "/" + h
}

// path returns the on-disk location for a digest. Objects are sharded by the
// first byte so no single directory accumulates an unbounded entry count.
func (s *Store) path(digest [32]byte) string {
	h := hex.EncodeToString(digest[:])
	return filepath.Join(s.objects, h[:2], h)
}

// Has reports whether the object is stored, and its size.
func (s *Store) Has(digest [32]byte) (bool, int64, error) {
	info, err := os.Stat(s.path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	return true, info.Size(), nil
}

// Put stores data under its digest, verifying that it actually hashes to the
// declared value.
//
// The write is idempotent: storing data that is already present is a no-op that
// succeeds. Because the name is the hash of the contents, an existing object
// with the same digest already holds the same bytes.
func (s *Store) Put(digest [32]byte, data []byte) error {
	if computed := sha256.Sum256(data); computed != digest {
		return fmt.Errorf("%w: computed %x, declared %x", ErrDigestMismatch, computed, digest)
	}

	present, _, err := s.Has(digest)
	if err != nil {
		return err
	}
	if present {
		return nil
	}

	return s.writeDurable(s.path(digest), data)
}

// PutFrom streams from r, hashing as it writes, and stores the result under the
// computed digest. It returns the digest and the byte count.
//
// Use this when the content is large enough that buffering it is wasteful; the
// caller does not need to know the digest in advance.
func (s *Store) PutFrom(r io.Reader) ([32]byte, int64, error) {
	var digest [32]byte

	f, err := os.CreateTemp(s.tmp, "put-*")
	if err != nil {
		return digest, 0, fmt.Errorf("create temp: %w", err)
	}
	tmpName := f.Name()

	// Any early return must not leave a partial file behind.
	committed := false
	defer func() {
		f.Close()
		if !committed {
			os.Remove(tmpName)
		}
	}()

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		return digest, 0, fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return digest, 0, fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return digest, 0, fmt.Errorf("close temp: %w", err)
	}

	copy(digest[:], h.Sum(nil))

	present, _, err := s.Has(digest)
	if err != nil {
		return digest, 0, err
	}
	if present {
		return digest, n, nil
	}

	final := s.path(digest)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return digest, 0, fmt.Errorf("create shard: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return digest, 0, fmt.Errorf("rename into place: %w", err)
	}
	committed = true

	if err := syncDir(filepath.Dir(final)); err != nil {
		return digest, 0, err
	}
	return digest, n, nil
}

// Get returns an object's contents.
func (s *Store) Get(digest [32]byte) ([]byte, error) {
	data, err := os.ReadFile(s.path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %x", ErrNotFound, digest)
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetVerified returns an object's contents and re-verifies its digest.
//
// Content addressing makes silent corruption detectable, so a reader that cares
// about integrity rather than speed should use this. Bit rot on the backing
// store is exactly the failure that a plain Get would pass through unnoticed.
func (s *Store) GetVerified(digest [32]byte) ([]byte, error) {
	data, err := s.Get(digest)
	if err != nil {
		return nil, err
	}
	if computed := sha256.Sum256(data); computed != digest {
		return nil, fmt.Errorf("%w: stored object %x hashes to %x — the store is corrupt",
			ErrDigestMismatch, digest, computed)
	}
	return data, nil
}

// OpenReader opens an object for streaming.
func (s *Store) OpenReader(digest [32]byte) (*os.File, error) {
	f, err := os.Open(s.path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %x", ErrNotFound, digest)
	}
	return f, err
}

// writeDurable writes data to a temporary file, fsyncs it, renames it into
// place and fsyncs the parent directory.
//
// The rename is what makes the write atomic: a reader sees either no object or
// the complete object, never a partial one. The directory fsync is what makes
// the rename itself survive a power cut — without it the file contents are
// durable but the name may not be.
func (s *Store) writeDurable(final string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return fmt.Errorf("create shard: %w", err)
	}

	f, err := os.CreateTemp(s.tmp, "put-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := f.Name()

	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true

	return syncDir(filepath.Dir(final))
}

// syncDir fsyncs a directory so a rename into it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir %s: %w", dir, err)
	}
	return nil
}

// Root returns the store's root directory.
func (s *Store) Root() string { return s.root }
