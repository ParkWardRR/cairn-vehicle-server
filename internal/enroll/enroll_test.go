package enroll

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
)

type fixture struct {
	devKey   ed25519.PrivateKey
	deviceID [16]byte
	root     [32]byte
	server   *ecdh.PrivateKey
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{devKey: priv, server: server}
	rand.Read(f.deviceID[:])
	rand.Read(f.root[:])
	return f
}

func (f *fixture) seal(t *testing.T, version uint32) []byte {
	t.Helper()
	var p SealParams
	p.DeviceID, p.DeviceKey, p.KeyVersion, p.Root = f.deviceID, f.devKey, version, f.root
	copy(p.ServerPublic[:], f.server.PublicKey().Bytes())
	rand.Read(p.EphemeralPrivate[:])
	rand.Read(p.Nonce[:])
	blob, err := Seal(p)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func (f *fixture) fingerprint() string {
	return Fingerprint(f.devKey.Public().(ed25519.PublicKey))
}

// resign replaces the signature, so a test can isolate the AEAD's AAD binding
// from the signature check: an attacker who could forge the device signature
// must still fail at the tag.
func resign(blob []byte, key ed25519.PrivateKey) {
	copy(blob[offSignature:], ed25519.Sign(key, blob[:offSignature]))
}

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	blob := f.seal(t, 3)
	if len(blob) != BlobSize {
		t.Fatalf("blob is %d bytes", len(blob))
	}
	o, err := Open(blob, f.server)
	if err != nil {
		t.Fatal(err)
	}
	if o.Root != f.root || o.DeviceID != f.deviceID || o.KeyVersion != 3 || o.Fingerprint() != f.fingerprint() {
		t.Fatal("round trip changed a field")
	}
	text := EncodeText(blob)
	if !strings.HasPrefix(text, "ENROLL-BLOB ") {
		t.Fatalf("text form %q", text)
	}
	back, err := DecodeText("  " + text + "\r\n")
	if err != nil || string(back) != string(blob) {
		t.Fatalf("text round trip: %v", err)
	}
}

func TestWrongServerKeyCannotOpen(t *testing.T) {
	f := newFixture(t)
	blob := f.seal(t, 1)
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := Open(blob, other); !errors.Is(err, ErrUnseal) {
		t.Fatalf("opened with the wrong server key: %v", err)
	}
}

func TestTamperIsRefused(t *testing.T) {
	f := newFixture(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = other

	cases := []struct {
		name   string
		mutate func(b []byte) // after which the blob is re-signed
	}{
		{"device_id", func(b []byte) { b[offDeviceID] ^= 1 }},
		// High byte, not the low one: flipping the low bit of version 1 gives
		// version 0, which is refused as malformed before the signature is even
		// looked at, and that is a different property.
		{"key_version", func(b []byte) { b[offKeyVersion+1] ^= 1 }},
		{"ephemeral key", func(b []byte) { b[offEphemeral+3] ^= 0x40 }},
		{"nonce", func(b []byte) { b[offNonce] ^= 1 }},
		{"ciphertext", func(b []byte) { b[offCiphertext+7] ^= 1 }},
		{"tag", func(b []byte) { b[offTag] ^= 1 }},
	}
	for _, c := range cases {
		t.Run(c.name+" without re-signing", func(t *testing.T) {
			blob := f.seal(t, 1)
			c.mutate(blob)
			if _, err := Open(blob, f.server); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("got %v, want ErrBadSignature", err)
			}
		})
		t.Run(c.name+" re-signed (AEAD must still refuse)", func(t *testing.T) {
			blob := f.seal(t, 1)
			c.mutate(blob)
			resign(blob, f.devKey)
			_, err := Open(blob, f.server)
			if err == nil {
				t.Fatal("a tampered blob opened")
			}
			if !errors.Is(err, ErrUnseal) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("got %v", err)
			}
		})
	}

	t.Run("public key swapped and re-signed by the new key", func(t *testing.T) {
		// Proof of possession passes for the attacker's key, but the key is in
		// the AAD: the root cannot be re-attributed to another signer.
		blob := f.seal(t, 1)
		_, evil, _ := ed25519.GenerateKey(rand.Reader)
		copy(blob[offPublicKey:offKeyVersion], evil.Public().(ed25519.PublicKey))
		resign(blob, evil)
		if _, err := Open(blob, f.server); !errors.Is(err, ErrUnseal) {
			t.Fatalf("got %v, want ErrUnseal", err)
		}
	})
}

func TestBadSignature(t *testing.T) {
	f := newFixture(t)
	blob := f.seal(t, 1)
	blob[offSignature+10] ^= 1
	if _, err := Parse(blob); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v", err)
	}
}

func TestMalformed(t *testing.T) {
	f := newFixture(t)
	good := f.seal(t, 1)

	if _, err := Parse(good[:BlobSize-1]); !errors.Is(err, ErrMalformed) {
		t.Fatal("short blob accepted")
	}
	b := append([]byte(nil), good...)
	b[0] = 'X'
	if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("bad magic accepted")
	}
	b = append([]byte(nil), good...)
	b[offVersion] = 2
	if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("unknown version accepted")
	}
	b = append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(b[offKeyVersion:], 0)
	resign(b, f.devKey)
	if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("key version 0 accepted")
	}
	b = append([]byte(nil), good...)
	clear(b[offDeviceID:offPublicKey])
	resign(b, f.devKey)
	if _, err := Parse(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("all-zero device id accepted")
	}

	// One blob, one text form. 225 bytes is an exact multiple of three, so its
	// base64 has no padding and there are no spare bits to set; what can still
	// vary is padding and whitespace, and neither may be accepted as a second
	// spelling.
	text := base64.StdEncoding.EncodeToString(good)
	if strings.Contains(text, "=") {
		t.Fatalf("a %d-byte blob should need no base64 padding", BlobSize)
	}
	for name, sloppy := range map[string]string{
		"extra padding": text + "=",
		"inner space":   text[:10] + " " + text[10:],
		"truncated":     text[:len(text)-4],
		"url alphabet":  strings.NewReplacer("+", "-", "/", "_").Replace(text + "A"),
	} {
		raw, err := DecodeText(sloppy)
		if err == nil {
			if _, perr := Parse(raw); perr == nil {
				t.Fatalf("%s accepted as a valid blob", name)
			}
		}
	}
}

func TestLowOrderEphemeralRefused(t *testing.T) {
	f := newFixture(t)
	blob := f.seal(t, 1)
	// u = 0 is a low-order point; X25519 with it is all-zero, which ecdh
	// refuses. Re-signed so only the key-agreement check stands in the way.
	clear(blob[offEphemeral:offNonce])
	resign(blob, f.devKey)
	if _, err := Open(blob, f.server); err == nil {
		t.Fatal("a low-order ephemeral key was accepted")
	}
}

func TestSealRefusesPlaceholderServerKey(t *testing.T) {
	f := newFixture(t)
	_, err := Seal(SealParams{DeviceID: f.deviceID, DeviceKey: f.devKey, KeyVersion: 1, Root: f.root})
	if err == nil {
		t.Fatal("sealed to the all-zero placeholder key")
	}
}

// ─── Enroll ─────────────────────────────────────────────────────────────────

type env struct {
	dir  string
	deps Deps
}

func newEnv(t *testing.T, server *ecdh.PrivateKey) *env {
	t.Helper()
	dir := t.TempDir()
	reg, err := devices.Open(filepath.Join(dir, "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keystore.Open(filepath.Join(dir, "keystore.json"), filepath.Join(dir, "master"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := counters.Open(filepath.Join(dir, "counters.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &env{dir: dir, deps: Deps{Registry: reg, Keys: ks, Counters: g, ServerKey: server}}
}

func TestEnrollEscrowsAndReturnsFloor(t *testing.T) {
	f := newFixture(t)
	e := newEnv(t, f.server)
	idHex := hex.EncodeToString(f.deviceID[:])

	// A device that has spent counters 1..5 under an earlier enrolment.
	for c := uint64(1); c <= 5; c++ {
		if err := e.deps.Counters.Record(idHex, c, strings.Repeat("ab", 32)[:62]+hex.EncodeToString([]byte{byte(c)})); err != nil {
			t.Fatal(err)
		}
	}

	res, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: strings.ToUpper(f.fingerprint()), Name: "car"}, e.deps)
	if err != nil {
		t.Fatal(err)
	}
	if res.CounterFloor != 5 {
		t.Fatalf("floor %d, want 5", res.CounterFloor)
	}
	if res.DeviceID != idHex || res.Fingerprint != f.fingerprint() || res.KeyVersion != 1 || res.RootAlreadyEscrowed {
		t.Fatalf("result %+v", res)
	}
	root, err := e.deps.Keys.Root(idHex, 1)
	if err != nil || root != f.root {
		t.Fatalf("root not escrowed: %v", err)
	}
	signer, err := e.deps.Registry.SignerFor(f.deviceID, [8]byte(mustHex(t, res.KeyIDHex)))
	if err != nil || !signer.Equal(f.devKey.Public()) {
		t.Fatalf("registry: %v", err)
	}

	// Repeating the same enrolment converges rather than failing.
	again, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps)
	if err != nil {
		t.Fatalf("repeat enrolment: %v", err)
	}
	if !again.RootAlreadyEscrowed || !again.Reenrolled || again.Name != "car" {
		t.Fatalf("repeat result %+v", again)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEnrollRequiresMatchingFingerprint(t *testing.T) {
	f := newFixture(t)
	e := newEnv(t, f.server)
	blob := f.seal(t, 1)

	for _, fp := range []string{"", "0000000", "zzzzzzzz"} {
		if _, err := Enroll(Request{Blob: blob, ConfirmFingerprint: fp}, e.deps); err == nil {
			t.Fatalf("fingerprint %q accepted", fp)
		}
	}

	wrong := []byte(f.fingerprint())
	wrong[0] ^= 1 // still hex: '0'..'9'/'a'..'f' with the low bit flipped stays in range
	if wrong[0] > 'f' || (wrong[0] > '9' && wrong[0] < 'a') {
		wrong[0] = '0'
	}
	_, err := Enroll(Request{Blob: blob, ConfirmFingerprint: string(wrong)}, e.deps)
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("got %v, want ErrFingerprintMismatch", err)
	}
	if len(e.deps.Registry.List()) != 0 || len(e.deps.Keys.Versions(hex.EncodeToString(f.deviceID[:]))) != 0 {
		t.Fatal("a refused enrolment wrote state")
	}
}

func TestEnrollRefusesADifferentRootAtTheSameVersion(t *testing.T) {
	f := newFixture(t)
	e := newEnv(t, f.server)
	if _, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(e.dir, "devices.json"))

	original := f.root
	rand.Read(f.root[:]) // the unit re-keyed (NVS wiped) or a clone with its key
	_, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("got %v, want ErrRootMismatch", err)
	}
	root, _ := e.deps.Keys.Root(hex.EncodeToString(f.deviceID[:]), 1)
	if root != original {
		t.Fatal("the escrowed root was replaced")
	}
	after, _ := os.ReadFile(filepath.Join(e.dir, "devices.json"))
	if string(before) != string(after) {
		t.Fatal("the registry changed on a refused enrolment")
	}

	// The next key version is a rotation, not a conflict.
	if _, err := Enroll(Request{Blob: f.seal(t, 2), ConfirmFingerprint: f.fingerprint()}, e.deps); err != nil {
		t.Fatalf("rotation to v2: %v", err)
	}
}

func TestEnrollRefusesKeyChangeAndRevokedDevice(t *testing.T) {
	f := newFixture(t)
	e := newEnv(t, f.server)
	if _, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps); err != nil {
		t.Fatal(err)
	}

	g := *f
	_, g.devKey, _ = ed25519.GenerateKey(rand.Reader)
	_, err := Enroll(Request{Blob: g.seal(t, 1), ConfirmFingerprint: g.fingerprint()}, e.deps)
	if !errors.Is(err, ErrKeyChanged) {
		t.Fatalf("got %v, want ErrKeyChanged", err)
	}

	if err := e.deps.Registry.Revoke(f.deviceID, "stolen"); err != nil {
		t.Fatal(err)
	}
	_, err = Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps)
	if !errors.Is(err, ErrRevokedDevice) {
		t.Fatalf("got %v, want ErrRevokedDevice", err)
	}
	if _, err := e.deps.Registry.Lookup(f.deviceID); !errors.Is(err, devices.ErrRevoked) {
		t.Fatal("a refused enrolment un-revoked the device")
	}
	if _, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint(), Reinstate: true}, e.deps); err != nil {
		t.Fatalf("deliberate reinstatement: %v", err)
	}
}

func TestEnrollWithoutServerKey(t *testing.T) {
	f := newFixture(t)
	e := newEnv(t, nil)
	_, err := Enroll(Request{Blob: f.seal(t, 1), ConfirmFingerprint: f.fingerprint()}, e.deps)
	if !errors.Is(err, ErrNoServerKey) {
		t.Fatalf("got %v", err)
	}
}

func TestServerKeyIsWrappedAndStable(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Open(filepath.Join(dir, "keystore.json"), filepath.Join(dir, "master"))
	if err != nil {
		t.Fatal(err)
	}
	path := ServerKeyPath(dir)

	if _, err := LoadServerKey(path, ks); !errors.Is(err, ErrNoServerKey) {
		t.Fatalf("got %v, want ErrNoServerKey", err)
	}
	k1, created, err := LoadOrCreateServerKey(path, ks)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("enrolment key mode %v", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	priv := hex.EncodeToString(k1.Bytes())
	if strings.Contains(string(raw), priv) {
		t.Fatal("the enrolment private key is on disk in the clear")
	}

	k2, created, err := LoadOrCreateServerKey(path, ks)
	if err != nil || created || !k2.Equal(k1) {
		t.Fatalf("reload: created=%v err=%v equal=%v", created, err, k2 != nil && k2.Equal(k1))
	}

	// A data directory restored without its master key cannot open blobs.
	other, err := keystore.Open(filepath.Join(dir, "keystore2.json"), filepath.Join(t.TempDir(), "other-master"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerKey(path, other); err == nil {
		t.Fatal("the enrolment key unwrapped under a different master key")
	}
}
