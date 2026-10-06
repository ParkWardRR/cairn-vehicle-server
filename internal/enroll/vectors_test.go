package enroll

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/ParkWardRR/Cairn/server/internal/contracts"
	"os"
	"path/filepath"
	"testing"
)

// go test ./internal/enroll -run TestVectors -update regenerates the committed
// vectors. CI runs without -update, so a change to Seal that alters a single
// byte fails here rather than silently diverging from the firmware, which is
// checked against the same file.
var update = flag.Bool("update", false, "rewrite contracts/enrolment/v1/vectors/vectors.json")

var vectorPath = contracts.Path("enrolment", "v1", "vectors", "vectors.json")

type vectorFile struct {
	Description string   `json:"description"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name                string `json:"name"`
	DeviceSeed          string `json:"device_seed"`
	DevicePublicKey     string `json:"device_public_key"`
	DeviceID            string `json:"device_id"`
	StorageKeyVersion   uint32 `json:"storage_key_version"`
	StorageRoot         string `json:"storage_root"`
	ServerPrivateKey    string `json:"server_private_key"`
	ServerPublicKey     string `json:"server_public_key"`
	EphemeralPrivateKey string `json:"ephemeral_private_key"`
	EphemeralPublicKey  string `json:"ephemeral_public_key"`
	Nonce               string `json:"nonce"`
	SharedSecret        string `json:"shared_secret"`
	SealKey             string `json:"seal_key"`
	Fingerprint         string `json:"fingerprint"`
	Blob                string `json:"blob"`
	BlobText            string `json:"blob_text"`
}

// label derives a fixed test value from a public string. Every input in the
// vectors is made this way, so anyone can see that none of them is a real key.
func label(s string) [32]byte {
	return sha256.Sum256([]byte("cairn/enroll-v1 PUBLIC TEST VECTOR: " + s))
}

type vectorSpec struct {
	name       string
	tag        string
	deviceID   [16]byte
	keyVersion uint32
}

func buildVector(t *testing.T, s vectorSpec) vector {
	t.Helper()
	seed := label(s.tag + " device seed")
	root := label(s.tag + " storage root")
	serverSeed := label(s.tag + " server enrolment key")
	eph := label(s.tag + " ephemeral key")
	nonceSrc := label(s.tag + " nonce")
	var nonce [24]byte
	copy(nonce[:], nonceSrc[:])

	devKey := ed25519.NewKeyFromSeed(seed[:])
	server, err := ecdh.X25519().NewPrivateKey(serverSeed[:])
	if err != nil {
		t.Fatal(err)
	}
	var serverPub [32]byte
	copy(serverPub[:], server.PublicKey().Bytes())

	blob, err := Seal(SealParams{
		DeviceID: s.deviceID, DeviceKey: devKey, KeyVersion: s.keyVersion, Root: root,
		ServerPublic: serverPub, EphemeralPrivate: eph, Nonce: nonce,
	})
	if err != nil {
		t.Fatal(err)
	}

	ephKey, _ := ecdh.X25519().NewPrivateKey(eph[:])
	shared, err := ephKey.ECDH(server.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sealKey, err := sealKey(ephKey, server.PublicKey(), ephKey.PublicKey().Bytes(), serverPub[:])
	if err != nil {
		t.Fatal(err)
	}

	pub := devKey.Public().(ed25519.PublicKey)
	return vector{
		Name:                s.name,
		DeviceSeed:          hex.EncodeToString(seed[:]),
		DevicePublicKey:     hex.EncodeToString(pub),
		DeviceID:            hex.EncodeToString(s.deviceID[:]),
		StorageKeyVersion:   s.keyVersion,
		StorageRoot:         hex.EncodeToString(root[:]),
		ServerPrivateKey:    hex.EncodeToString(serverSeed[:]),
		ServerPublicKey:     hex.EncodeToString(serverPub[:]),
		EphemeralPrivateKey: hex.EncodeToString(eph[:]),
		EphemeralPublicKey:  hex.EncodeToString(ephKey.PublicKey().Bytes()),
		Nonce:               hex.EncodeToString(nonce[:]),
		SharedSecret:        hex.EncodeToString(shared),
		SealKey:             hex.EncodeToString(sealKey),
		Fingerprint:         Fingerprint(pub),
		Blob:                hex.EncodeToString(blob),
		BlobText:            EncodeText(blob),
	}
}

func specs() []vectorSpec {
	var a, b [16]byte
	for i := range a {
		a[i] = byte(0xa0 + i)
		b[i] = byte(0xc0 + i)
	}
	return []vectorSpec{
		{name: "first enrolment, key version 1", tag: "v1", deviceID: a, keyVersion: 1},
		// A non-trivial version exercises the little-endian field and proves the
		// version is authenticated as well as carried.
		{name: "rotated root, key version 0x01020304", tag: "rot", deviceID: b, keyVersion: 0x01020304},
	}
}

func TestVectors(t *testing.T) {
	want := vectorFile{
		Description: "Cairn device enrolment blob v1 (docs/device-provisioning.md). " +
			"Every key here is a PUBLIC TEST KEY derived from a published label; none protects anything.",
	}
	for _, s := range specs() {
		want.Vectors = append(want.Vectors, buildVector(t, s))
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')

	if *update {
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatal("contracts/enrolment/v1/vectors/vectors.json differs from what Seal produces; " +
			"if the change is intended, regenerate with: go test ./internal/enroll -run TestVectors -update")
	}

	// The committed blobs must also open, with the committed server key, to the
	// committed root — the direction the server actually uses.
	var file vectorFile
	if err := json.Unmarshal(got, &file); err != nil {
		t.Fatal(err)
	}
	for _, v := range file.Vectors {
		blob, _ := hex.DecodeString(v.Blob)
		seed, _ := hex.DecodeString(v.ServerPrivateKey)
		server, err := ecdh.X25519().NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		o, err := Open(blob, server)
		if err != nil {
			t.Fatalf("%s: open: %v", v.Name, err)
		}
		if hex.EncodeToString(o.Root[:]) != v.StorageRoot || o.Fingerprint() != v.Fingerprint ||
			o.KeyVersion != v.StorageKeyVersion || hex.EncodeToString(o.DeviceID[:]) != v.DeviceID {
			t.Fatalf("%s: opened to different values", v.Name)
		}
		if text, err := DecodeText(v.BlobText); err != nil || !bytes.Equal(text, blob) {
			t.Fatalf("%s: blob_text does not decode to blob: %v", v.Name, err)
		}
	}
}

// TestCrossCheckFirmwareBlob opens a blob the C firmware sealed with a fresh
// ephemeral key and nonce (not the vector's), which is the direction that
// matters in production: device seals, server opens. Driven by
// firmware/cairn-v2/test/host `make enroll-crosscheck`, which sets the env var;
// skipped otherwise.
func TestCrossCheckFirmwareBlob(t *testing.T) {
	path := os.Getenv("CAIRN_ENROLL_CROSSCHECK")
	if path == "" {
		t.Skip("set CAIRN_ENROLL_CROSSCHECK (make -C firmware/cairn-v2/test/host enroll-crosscheck)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var in struct {
		ServerPrivateKey string `json:"server_private_key"`
		StorageRoot      string `json:"storage_root"`
		Fingerprint      string `json:"fingerprint"`
		BlobText         string `json:"blob_text"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(in.ServerPrivateKey)
	server, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := DecodeText(in.BlobText)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Open(blob, server)
	if err != nil {
		t.Fatalf("Go cannot open the C-sealed blob: %v", err)
	}
	if hex.EncodeToString(o.Root[:]) != in.StorageRoot {
		t.Fatal("C-sealed blob opened to a different root")
	}
	if o.Fingerprint() != in.Fingerprint {
		t.Fatalf("fingerprint %s, C printed %s", o.Fingerprint(), in.Fingerprint)
	}
	t.Logf("opened a C-sealed blob: device %x, key version %d, fingerprint %s",
		o.DeviceID, o.KeyVersion, o.Fingerprint())
}
