package devices

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/Cairn/server/format"
	"time"
)

func newRegistry(t *testing.T) (*Registry, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "devices.json")
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return r, path
}

func testKey(seed string) (ed25519.PublicKey, ed25519.PrivateKey) {
	padded := make([]byte, ed25519.SeedSize)
	copy(padded, seed)
	priv := ed25519.NewKeyFromSeed(padded)
	return priv.Public().(ed25519.PublicKey), priv
}

func deviceID(b byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = b + byte(i)
	}
	return id
}

func TestEnrollAndLookup(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	d, err := r.Enroll(id, "garage-recorder", pub, 0)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if d.Name != "garage-recorder" {
		t.Errorf("Name = %q", d.Name)
	}

	found, err := r.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	gotPub, err := found.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !gotPub.Equal(pub) {
		t.Error("looked-up public key differs from the enrolled one")
	}

	gotID, err := found.ID()
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id {
		t.Error("looked-up device ID differs")
	}
}

// The key ID is derived from the public key rather than accepted from the
// caller, so the two can never disagree.
func TestEnrollDerivesKeyID(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 0); err != nil {
		t.Fatal(err)
	}

	signer, err := r.SignerFor(id, format.DeviceKeyID(pub))
	if err != nil {
		t.Fatalf("SignerFor with the derived key ID: %v", err)
	}
	if !signer.Equal(pub) {
		t.Error("SignerFor returned a different key")
	}
}

func TestLookupUnknownDevice(t *testing.T) {
	r, _ := newRegistry(t)

	if _, err := r.Lookup(deviceID(0x99)); !errors.Is(err, ErrUnknown) {
		t.Errorf("error = %v, want ErrUnknown", err)
	}
}

// Revocation is what actually stops a lost or stolen unit, since its
// certificate and signing key both stay cryptographically valid.
func TestRevoke(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(id, "unit reported stolen"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err := r.Lookup(id)
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("error = %v, want ErrRevoked", err)
	}

	// A revoked device's manifests must not resolve to a signer either.
	if _, err := r.SignerFor(id, format.DeviceKeyID(pub)); !errors.Is(err, ErrRevoked) {
		t.Errorf("SignerFor error = %v, want ErrRevoked", err)
	}
}

func TestRevokeUnknownDevice(t *testing.T) {
	r, _ := newRegistry(t)

	if err := r.Revoke(deviceID(0x99), "never enrolled"); !errors.Is(err, ErrUnknown) {
		t.Errorf("error = %v, want ErrUnknown", err)
	}
}

// A manifest may not assert a signing key other than the enrolled one, which
// keeps key rotation an administrative act rather than something a device
// claims for itself.
func TestSignerForRejectsKeyIDMismatch(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	other, _ := testKey("some-other-key")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 0); err != nil {
		t.Fatal(err)
	}

	_, err := r.SignerFor(id, format.DeviceKeyID(other))
	if !errors.Is(err, ErrKeyIDMismatch) {
		t.Fatalf("error = %v, want ErrKeyIDMismatch", err)
	}
}

func TestEnrollRejectsMalformedKey(t *testing.T) {
	r, _ := newRegistry(t)

	if _, err := r.Enroll(deviceID(0x10), "recorder", ed25519.PublicKey("too short"), 0); err == nil {
		t.Error("a malformed public key was accepted")
	}
}

// The registry must survive a restart: enrolment is administrative state, not
// cache.
func TestRegistryPersists(t *testing.T) {
	r, path := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 5<<30); err != nil {
		t.Fatal(err)
	}
	if err := r.Revoke(deviceID(0x10), "test"); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	if _, err := reopened.Lookup(id); !errors.Is(err, ErrRevoked) {
		t.Errorf("revocation did not persist: %v", err)
	}

	list := reopened.List()
	if len(list) != 1 {
		t.Fatalf("%d devices after reopen, want 1", len(list))
	}
	if list[0].QuotaBytes != 5<<30 {
		t.Errorf("QuotaBytes = %d, want %d", list[0].QuotaBytes, int64(5)<<30)
	}
	if list[0].RevokedReason != "test" {
		t.Errorf("RevokedReason = %q", list[0].RevokedReason)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("registry file mode = %o, want 600", perm)
	}
}

func TestOpenMissingFileIsEmpty(t *testing.T) {
	r, err := Open(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("Open on a missing file should succeed: %v", err)
	}
	if len(r.List()) != 0 {
		t.Error("a missing registry file produced devices")
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Error("a corrupt registry file was accepted")
	}
}

// A quota protects the server from one misbehaving device filling the dataset
// and starving the others.
func TestCheckQuota(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 1000); err != nil {
		t.Fatal(err)
	}

	if err := r.CheckQuota(id, 400, 500); err != nil {
		t.Errorf("900 of 1000 bytes should be allowed: %v", err)
	}
	if err := r.CheckQuota(id, 600, 500); !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("error = %v, want ErrQuotaExceeded", err)
	}
	// Exactly at the limit is allowed.
	if err := r.CheckQuota(id, 500, 500); err != nil {
		t.Errorf("exactly the quota should be allowed: %v", err)
	}
}

func TestZeroQuotaIsUnlimited(t *testing.T) {
	r, _ := newRegistry(t)
	pub, _ := testKey("device-one")
	id := deviceID(0x10)

	if _, err := r.Enroll(id, "recorder", pub, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.CheckQuota(id, 1<<40, 1<<40); err != nil {
		t.Errorf("a zero quota should mean unlimited: %v", err)
	}
}

func TestListIsOrderedAndCopied(t *testing.T) {
	r, _ := newRegistry(t)

	for i, seed := range []string{"c", "a", "b"} {
		pub, _ := testKey(seed)
		if _, err := r.Enroll(deviceID(byte(0x30+i*0x10)), seed, pub, 0); err != nil {
			t.Fatal(err)
		}
	}

	list := r.List()
	for i := 1; i < len(list); i++ {
		if list[i-1].DeviceID >= list[i].DeviceID {
			t.Errorf("List is not ordered by device ID: %q then %q",
				list[i-1].DeviceID, list[i].DeviceID)
		}
	}

	// Mutating a returned device must not affect the registry.
	list[0].Name = "mutated"
	again := r.List()
	if again[0].Name == "mutated" {
		t.Error("List returned a reference into the registry's own state")
	}
}

// Revoking a device from another process must take effect in a running server
// without a restart.
//
// This is the guarantee that matters when a unit is stolen: the remedy has to
// be immediate, and a maintenance window is not an acceptable price. The
// registry reloads when the file's mtime or size changes, and this exercises
// that path by writing through a second Registry on the same file — which is
// exactly what `cairn-server -revoke` does while the service is up.
func TestRevocationTakesEffectWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")

	serving, err := Open(path)
	if err != nil {
		t.Fatalf("open serving registry: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var id [16]byte
	id[0] = 0x42

	if _, err := serving.Enroll(id, "car", pub, 0); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if _, err := serving.Lookup(id); err != nil {
		t.Fatalf("Lookup after enrol: %v", err)
	}

	// A second process revokes it.
	admin, err := Open(path)
	if err != nil {
		t.Fatalf("open admin registry: %v", err)
	}
	if err := admin.Revoke(id, "stolen"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Some filesystems have coarse mtime granularity, so the size change is
	// what makes this reliable — and a revocation always grows the record.
	// Nudge the mtime anyway so the test does not depend on that.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	if _, err := serving.Lookup(id); err == nil {
		t.Fatal("the serving registry still accepts a revoked device; " +
			"revocation would need a restart to take effect")
	}

	// And the signer must be refused too, which is the path an upload takes.
	keyID := format.DeviceKeyID(pub)
	if _, err := serving.SignerFor(id, keyID); err == nil {
		t.Error("SignerFor still returns a key for a revoked device")
	}
}
