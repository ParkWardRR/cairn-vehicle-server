package keystore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dev = "8777228e000000000000000000000001"

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "keys.json"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func root(b byte) (r [32]byte) {
	for i := range r {
		r[i] = b
	}
	return r
}

func TestRoundTripAndNeverStoredInTheClear(t *testing.T) {
	s, dir := open(t)
	r := root(0xAB)
	if err := s.Put(dev, 1, r); err != nil {
		t.Fatal(err)
	}

	got, err := s.Root(dev, 1)
	if err != nil || got != r {
		t.Fatalf("Root = %x, %v", got, err)
	}

	raw, _ := os.ReadFile(filepath.Join(dir, "keys.json"))
	if bytes.Contains(raw, []byte(hex.EncodeToString(r[:]))) {
		t.Fatal("the storage root appears in the key file in the clear")
	}
}

func TestMasterKeyIsPrivate(t *testing.T) {
	_, dir := open(t)
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("master key: %v, %v", info, err)
	}
}

func TestWrongMasterKeyCannotUnwrap(t *testing.T) {
	s, dir := open(t)
	if err := s.Put(dev, 1, root(1)); err != nil {
		t.Fatal(err)
	}
	other, err := Open(filepath.Join(dir, "keys.json"), filepath.Join(dir, "other-master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Root(dev, 1); err == nil {
		t.Fatal("unwrapped under a different master key")
	}
}

// A wrapped root copied onto another device's record must not open: that is
// what binding the device and version as associated data is for.
func TestWrappedRootCannotBeMovedBetweenRecords(t *testing.T) {
	s, dir := open(t)
	if err := s.Put(dev, 1, root(1)); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "keys.json"))
	moved := strings.Replace(string(raw), dev, "8777228e000000000000000000000002", 1)
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), []byte(moved), 0o600); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(filepath.Join(dir, "keys.json"), filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Root("8777228e000000000000000000000002", 1); err == nil {
		t.Fatal("a wrapped root opened under a different device ID")
	}
}

func TestVersionIsWriteOnce(t *testing.T) {
	s, _ := open(t)
	if err := s.Put(dev, 1, root(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(dev, 1, root(2)); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ := s.Root(dev, 1)
	if got != root(1) {
		t.Fatal("the original root was replaced")
	}
}

func TestVersionsAndLatest(t *testing.T) {
	s, _ := open(t)
	if _, ok := s.Latest(dev); ok {
		t.Fatal("Latest on an empty store")
	}
	for _, v := range []uint32{2, 1, 3} {
		if err := s.Put(dev, v, root(byte(v))); err != nil {
			t.Fatal(err)
		}
	}
	if v, ok := s.Latest(dev); !ok || v != 3 {
		t.Fatalf("Latest = %d, %v", v, ok)
	}
	if got := s.Versions(dev); len(got) != 3 || got[0] != 1 || got[2] != 3 {
		t.Fatalf("Versions = %v", got)
	}
}

func TestDestroyShredsTheBytes(t *testing.T) {
	s, dir := open(t)
	if err := s.Put(dev, 1, root(7)); err != nil {
		t.Fatal(err)
	}
	if err := s.Destroy(dev, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Root(dev, 1); !errors.Is(err, ErrDestroyed) {
		t.Fatalf("Root after destroy: %v", err)
	}
	if len(s.Versions(dev)) != 0 {
		t.Fatal("a destroyed version is still listed as live")
	}
	// The wrapped bytes are gone from the file, not just flagged.
	raw, _ := os.ReadFile(filepath.Join(dir, "keys.json"))
	if strings.Contains(string(raw), `"wrapped": "`) {
		t.Fatalf("wrapped bytes survive destruction:\n%s", raw)
	}
	// And a destroyed version cannot be silently re-created.
	if err := s.Put(dev, 1, root(8)); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("re-creating a destroyed version: %v", err)
	}
}

func TestMissingKey(t *testing.T) {
	s, _ := open(t)
	if _, err := s.Root(dev, 9); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Root: %v", err)
	}
	if err := s.Destroy(dev, 9); !errors.Is(err, ErrNoKey) {
		t.Fatalf("Destroy: %v", err)
	}
}
