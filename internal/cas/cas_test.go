package cas

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestPutGetRoundTrip(t *testing.T) {
	s := newStore(t)

	data := []byte("a sealed bundle segment")
	digest := sha256.Sum256(data)

	if err := s.Put(digest, data); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := s.GetVerified(digest)
	if err != nil {
		t.Fatalf("GetVerified: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}

	present, size, err := s.Has(digest)
	if err != nil {
		t.Fatal(err)
	}
	if !present {
		t.Error("HasReports absent after Put")
	}
	if size != int64(len(data)) {
		t.Errorf("size = %d, want %d", size, len(data))
	}
}

// The store must refuse data that does not hash to its declared name.
// Accepting it would mean an object whose identity does not describe its
// contents, which breaks every downstream integrity guarantee.
func TestPutRejectsDigestMismatch(t *testing.T) {
	s := newStore(t)

	data := []byte("the real contents")
	wrong := sha256.Sum256([]byte("something else"))

	err := s.Put(wrong, data)
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("error = %v, want ErrDigestMismatch", err)
	}

	present, _, err := s.Has(wrong)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("a rejected object was stored anyway")
	}
}

// Put must be idempotent: a device retrying an upload, or two devices uploading
// identical data, must not fail or duplicate storage.
func TestPutIsIdempotent(t *testing.T) {
	s := newStore(t)

	data := []byte("identical content")
	digest := sha256.Sum256(data)

	for i := 0; i < 3; i++ {
		if err := s.Put(digest, data); err != nil {
			t.Fatalf("Put attempt %d: %v", i, err)
		}
	}

	// Exactly one object on disk.
	count := 0
	err := filepath.WalkDir(s.objects, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("%d objects on disk, want 1", count)
	}
}

func TestGetMissingObject(t *testing.T) {
	s := newStore(t)

	digest := sha256.Sum256([]byte("never stored"))
	if _, err := s.Get(digest); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}

	present, _, err := s.Has(digest)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("Has reports an object that was never stored")
	}
}

func TestPutFrom(t *testing.T) {
	s := newStore(t)

	data := bytes.Repeat([]byte("segment bytes "), 5000)
	want := sha256.Sum256(data)

	digest, n, err := s.PutFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("PutFrom: %v", err)
	}
	if digest != want {
		t.Errorf("digest = %x, want %x", digest, want)
	}
	if n != int64(len(data)) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}

	got, err := s.GetVerified(digest)
	if err != nil {
		t.Fatalf("GetVerified: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round-tripped content differs")
	}
}

func TestPutFromIsIdempotent(t *testing.T) {
	s := newStore(t)

	data := []byte("streamed twice")
	first, _, err := s.PutFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := s.PutFrom(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("digests differ across identical writes: %x vs %x", first, second)
	}
}

// Corruption of a stored object must be detected rather than passed through.
// Bit rot on the backing store is exactly the failure a plain read would miss.
func TestGetVerifiedDetectsCorruption(t *testing.T) {
	s := newStore(t)

	data := []byte("content that will rot")
	digest := sha256.Sum256(data)
	if err := s.Put(digest, data); err != nil {
		t.Fatal(err)
	}

	// Corrupt the stored bytes behind the store's back.
	path := s.path(digest)
	corrupted := append([]byte(nil), data...)
	corrupted[0] ^= 0xFF
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetVerified(digest); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("error = %v, want ErrDigestMismatch", err)
	}

	// A plain Get deliberately does not verify, so it still returns the bytes.
	if _, err := s.Get(digest); err != nil {
		t.Errorf("plain Get should not verify: %v", err)
	}
}

// A tmp directory left over from a crashed run holds only partial writes that
// were never renamed into place, so nothing references them.
func TestOpenClearsStaleTempFiles(t *testing.T) {
	root := t.TempDir()

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	stale := filepath.Join(s.tmp, "put-interrupted")
	if err := os.WriteFile(stale, []byte("partial write from a crash"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(root); err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Error("stale temp file survived reopen")
	}
}

// Reopening must not disturb committed objects.
func TestReopenPreservesObjects(t *testing.T) {
	root := t.TempDir()

	s, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("committed before restart")
	digest := sha256.Sum256(data)
	if err := s.Put(digest, data); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.GetVerified(digest)
	if err != nil {
		t.Fatalf("object lost across reopen: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("content changed across reopen")
	}
}

func TestObjectIDShape(t *testing.T) {
	data := []byte("x")
	digest := sha256.Sum256(data)

	id := ObjectID(digest)
	if !strings.HasPrefix(id, "cas/") {
		t.Errorf("ObjectID = %q, want a cas/ prefix", id)
	}
	// cas/ + 2 hex + / + 64 hex
	if want := 4 + 2 + 1 + 64; len(id) != want {
		t.Errorf("len(ObjectID) = %d, want %d", len(id), want)
	}
	// Stable across calls — it goes into signed receipts.
	if ObjectID(digest) != id {
		t.Error("ObjectID is not stable")
	}
}

func TestEmptyObject(t *testing.T) {
	s := newStore(t)

	var empty []byte
	digest := sha256.Sum256(empty)

	if err := s.Put(digest, empty); err != nil {
		t.Fatalf("Put empty: %v", err)
	}
	got, err := s.GetVerified(digest)
	if err != nil {
		t.Fatalf("GetVerified empty: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes, want 0", len(got))
	}
}

// Distinct contents must not collide in the sharded layout.
func TestManyObjectsAcrossShards(t *testing.T) {
	s := newStore(t)

	stored := make(map[[32]byte][]byte)
	for i := 0; i < 500; i++ {
		data := []byte(strings.Repeat("o", i%7) + string(rune('a'+i%26)) + string(rune(i)))
		digest := sha256.Sum256(data)
		if err := s.Put(digest, data); err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
		stored[digest] = data
	}

	for digest, want := range stored {
		got, err := s.GetVerified(digest)
		if err != nil {
			t.Fatalf("GetVerified %x: %v", digest, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("object %x round-tripped differently", digest)
		}
	}
}
