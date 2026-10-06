package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(Config{
		Dir:     filepath.Join(dir, "receipts"),
		KeyPath: filepath.Join(dir, "keys", "receipt.seed"),
		Now:     func() time.Time { return time.UnixMilli(1_790_000_123_456).UTC() },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func ids(t *testing.T) ([16]byte, [16]byte, [32]byte) {
	t.Helper()
	var device, bundle [16]byte
	for i := range device {
		device[i] = byte(0x10 + i)
		bundle[i] = byte(i)
	}
	return device, bundle, sha256.Sum256([]byte("a bundle"))
}

// Refusing to start without a configured key is the point: an ephemeral key
// would silently invalidate every previously issued receipt on restart,
// stranding already-synced bundles as permanently un-prunable.
func TestOpenRefusesEphemeralKeyByDefault(t *testing.T) {
	_, err := Open(Config{Dir: t.TempDir()})
	if !errors.Is(err, ErrEphemeralKeyRefused) {
		t.Fatalf("error = %v, want ErrEphemeralKeyRefused", err)
	}
}

func TestOpenAllowsEphemeralKeyInDevMode(t *testing.T) {
	s, err := Open(Config{Dir: t.TempDir(), Dev: true})
	if err != nil {
		t.Fatalf("dev mode should permit an ephemeral key: %v", err)
	}
	if len(s.PublicKey()) != ed25519.PublicKeySize {
		t.Error("no usable public key in dev mode")
	}
}

// The signing key must survive a restart, or receipts issued before it become
// unverifiable.
func TestSigningKeyPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:     filepath.Join(dir, "receipts"),
		KeyPath: filepath.Join(dir, "keys", "receipt.seed"),
	}

	first, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := first.PublicKeyHex()

	second, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second.PublicKeyHex() != firstKey {
		t.Errorf("key changed across restart: %s then %s", firstKey, second.PublicKeyHex())
	}
	if second.KeyID() != first.KeyID() {
		t.Error("key ID changed across restart")
	}

	info, err := os.Stat(cfg.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
}

func TestOpenRejectsMalformedKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "receipt.seed")
	if err := os.WriteFile(keyPath, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(Config{Dir: dir, KeyPath: keyPath}); err == nil {
		t.Error("a malformed key file was accepted")
	}
}

func TestIssueAndVerify(t *testing.T) {
	s := newStore(t)
	device, bundle, root := ids(t)

	r, encoded, err := s.Issue(device, bundle, root, []string{"cas/ab/abcd"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := r.Verify(s.PublicKey()); err != nil {
		t.Errorf("issued receipt does not verify: %v", err)
	}
	if err := r.VerifyAcknowledges(s.PublicKey(), root); err != nil {
		t.Errorf("issued receipt does not acknowledge its own root: %v", err)
	}
	if r.ServerKeyID != s.KeyID() {
		t.Error("receipt does not record the signing key ID")
	}
	if r.IngestSchemaVersion != IngestSchemaVersion {
		t.Errorf("IngestSchemaVersion = %d, want %d", r.IngestSchemaVersion, IngestSchemaVersion)
	}
	if r.ServerIngestUTCMS != 1_790_000_123_456 {
		t.Errorf("ServerIngestUTCMS = %d, want the injected time", r.ServerIngestUTCMS)
	}

	// The returned bytes must be exactly what a device would parse.
	parsed, err := format.ParseReceipt(encoded)
	if err != nil {
		t.Fatalf("returned bytes do not parse: %v", err)
	}
	if parsed.ContentRoot != root {
		t.Error("parsed content root differs")
	}
}

// Durable before returned: a receipt handed to a device must already be on
// disk, so a crash immediately afterwards cannot lose the server's record of it.
func TestIssuePersistsBeforeReturning(t *testing.T) {
	s := newStore(t)
	device, bundle, root := ids(t)

	_, encoded, err := s.Issue(device, bundle, root, nil)
	if err != nil {
		t.Fatal(err)
	}

	onDisk, err := os.ReadFile(s.path(root))
	if err != nil {
		t.Fatalf("receipt was not persisted: %v", err)
	}
	if !bytes.Equal(onDisk, encoded) {
		t.Error("persisted bytes differ from the bytes returned to the device")
	}
}

// Idempotency is keyed on content_root. A device retrying with a fresh
// bundle_id must get back the receipt it already earned, not a second one —
// otherwise the receipt it holds could stop matching the server's record.
func TestIssueIsIdempotentOnContentRoot(t *testing.T) {
	s := newStore(t)
	device, bundle, root := ids(t)

	first, firstBytes, err := s.Issue(device, bundle, root, nil)
	if err != nil {
		t.Fatal(err)
	}

	var retryBundle [16]byte
	for i := range retryBundle {
		retryBundle[i] = byte(0xF0 + i)
	}

	second, secondBytes, err := s.Issue(device, retryBundle, root, nil)
	if err != nil {
		t.Fatal(err)
	}

	if second.ReceiptID != first.ReceiptID {
		t.Error("a re-offer of identical data minted a second receipt")
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Error("re-issued receipt bytes differ from the original")
	}
	if second.BundleID != first.BundleID {
		t.Error("the stored receipt's bundle ID was overwritten by the retry")
	}
}

func TestIssueDistinctRootsAreDistinctReceipts(t *testing.T) {
	s := newStore(t)
	device, bundle, rootA := ids(t)
	rootB := sha256.Sum256([]byte("a different bundle"))

	a, _, err := s.Issue(device, bundle, rootA, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.Issue(device, bundle, rootB, nil)
	if err != nil {
		t.Fatal(err)
	}

	if a.ReceiptID == b.ReceiptID {
		t.Error("distinct content roots share a receipt ID")
	}
	if err := b.VerifyAcknowledges(s.PublicKey(), rootA); err == nil {
		t.Error("receipt for root B acknowledged root A")
	}
}

func TestReceiptsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Dir:     filepath.Join(dir, "receipts"),
		KeyPath: filepath.Join(dir, "keys", "receipt.seed"),
	}

	first, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	device, bundle, root := ids(t)
	original, _, err := first.Issue(device, bundle, root, nil)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}

	found, _, err := second.Lookup(root)
	if err != nil {
		t.Fatalf("receipt lost across restart: %v", err)
	}
	if found.ReceiptID != original.ReceiptID {
		t.Error("a different receipt came back after restart")
	}
	if err := found.Verify(second.PublicKey()); err != nil {
		t.Errorf("receipt issued before restart no longer verifies: %v", err)
	}
}

func TestLookupMissing(t *testing.T) {
	s := newStore(t)
	root := sha256.Sum256([]byte("never issued"))

	if _, _, err := s.Lookup(root); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// A receipt signed by one server must not verify against another's key. This is
// what stops a rogue or rotated server from inducing a prune.
func TestReceiptDoesNotVerifyAcrossServers(t *testing.T) {
	a := newStore(t)
	b := newStore(t)
	device, bundle, root := ids(t)

	r, _, err := a.Issue(device, bundle, root, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.Verify(b.PublicKey()); err == nil {
		t.Error("a receipt from server A verified against server B's key")
	}
}

func TestObjectIDsFor(t *testing.T) {
	digests := [][32]byte{
		sha256.Sum256([]byte("member one")),
		sha256.Sum256([]byte("member two")),
	}

	got := ObjectIDsFor(digests)
	if len(got) != 2 {
		t.Fatalf("got %d ids, want 2", len(got))
	}
	if got[0] == got[1] {
		t.Error("distinct members produced identical object IDs")
	}
	// Order must be preserved: receipts record which objects, in order.
	again := ObjectIDsFor(digests)
	if got[0] != again[0] || got[1] != again[1] {
		t.Error("ObjectIDsFor is not stable")
	}
}
