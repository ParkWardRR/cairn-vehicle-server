// Package receipts issues, persists and looks up the signed receipts that
// justify a device deleting its local copy of a bundle.
//
// A receipt is the only thing that authorises deletion, which sets the bar for
// this package: a receipt must be durable before it is returned. If the server
// crashes between signing and responding, the device simply does not get a
// receipt and retries — but a device that *did* receive one must never discover
// later that the server has no record of it.
//
// The signing key is persistent and loaded from disk. An ephemeral key would
// silently invalidate every previously issued receipt on restart, which would
// strand already-synced bundles as permanently un-prunable.
package receipts

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/cas"

	"github.com/ParkWardRR/Cairn/server/format"
)

// IngestSchemaVersion is recorded in every receipt so a consumer can tell which
// server contract produced it.
const IngestSchemaVersion uint8 = 1

var (
	// ErrNotFound means no receipt exists for that lookup.
	ErrNotFound = errors.New("receipt not found")
	// ErrEphemeralKeyRefused means no signing key was configured and dev mode
	// was not explicitly enabled.
	ErrEphemeralKeyRefused = errors.New(
		"no receipt signing key configured; refusing to start with an ephemeral key " +
			"because it would invalidate every previously issued receipt (set -dev to override)")
)

// Store issues and persists receipts.
type Store struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID [8]byte

	dir string // receipts/<content_root hex>.cbor
	now func() time.Time
}

// Config configures a Store.
type Config struct {
	// Dir is where receipts are persisted.
	Dir string

	// KeyPath is the Ed25519 seed file. When empty, Dev must be true.
	KeyPath string

	// Dev permits an ephemeral signing key. Never set this in production: on
	// restart every previously issued receipt becomes unverifiable, so devices
	// holding one can never prune.
	Dev bool

	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

// Open prepares a receipt store, loading or generating the signing key.
func Open(cfg Config) (*Store, error) {
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("create receipt dir: %w", err)
	}

	var priv ed25519.PrivateKey

	switch {
	case cfg.KeyPath != "":
		var err error
		if priv, err = loadOrCreateKey(cfg.KeyPath); err != nil {
			return nil, err
		}
	case cfg.Dev:
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral key: %w", err)
		}
		priv = generated
	default:
		return nil, ErrEphemeralKeyRefused
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	pub := priv.Public().(ed25519.PublicKey)
	return &Store{
		priv:  priv,
		pub:   pub,
		keyID: keyIDFor(pub),
		dir:   cfg.Dir,
		now:   now,
	}, nil
}

// loadOrCreateKey reads a 32-byte Ed25519 seed, creating one if absent.
//
// Creating on first use is safe because there is nothing to invalidate yet. The
// file is written with 0600 and an fsync so a crash cannot leave a key that is
// half-written but then used.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err == nil {
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("signing key %s is %d bytes, want %d",
				path, len(seed), ed25519.SeedSize)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read signing key: %w", err)
	}

	fresh := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create key dir: %w", err)
	}
	if err := writeDurable(path, fresh, 0o600); err != nil {
		return nil, fmt.Errorf("persist signing key: %w", err)
	}
	return ed25519.NewKeyFromSeed(fresh), nil
}

func keyIDFor(pub ed25519.PublicKey) [8]byte {
	return format.DeviceKeyID(pub)
}

// PublicKey returns the receipt verification key. Devices pin this; it is
// served over the API for provisioning.
func (s *Store) PublicKey() ed25519.PublicKey { return s.pub }

// PublicKeyHex returns the hex-encoded verification key.
func (s *Store) PublicKeyHex() string { return hex.EncodeToString(s.pub) }

// KeyID returns the 8-byte key identifier recorded in every receipt.
func (s *Store) KeyID() [8]byte { return s.keyID }

// path returns the persistence path for a receipt.
//
// Receipts are keyed by content_root rather than by bundle_id because
// content_root is what makes the protocol idempotent: a device that re-offers
// identical data must get back the receipt it already earned, even if it
// generated a fresh bundle_id for the retry.
func (s *Store) path(contentRoot [32]byte) string {
	return filepath.Join(s.dir, hex.EncodeToString(contentRoot[:])+".cbor")
}

// Lookup returns an existing receipt for a content root.
func (s *Store) Lookup(contentRoot [32]byte) (*format.Receipt, []byte, error) {
	encoded, err := os.ReadFile(s.path(contentRoot))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("%w for content root %x", ErrNotFound, contentRoot)
	}
	if err != nil {
		return nil, nil, err
	}

	r, err := format.ParseReceipt(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("stored receipt for %x is unparseable: %w", contentRoot, err)
	}
	return r, encoded, nil
}

// Issue signs a receipt and persists it before returning.
//
// The ordering is the contract: nothing is returned to the device until the
// receipt is durable on disk. A crash before the fsync means the device gets an
// error and retries; a crash after it means a retry finds the persisted receipt
// and returns it unchanged.
//
// Issuing is idempotent on content_root. A re-offer of identical data returns
// the original receipt rather than minting a second one, so the receipt a device
// holds stays valid forever.
func (s *Store) Issue(deviceID, bundleID [16]byte, contentRoot [32]byte, objectIDs []string) (*format.Receipt, []byte, error) {
	if existing, encoded, err := s.Lookup(contentRoot); err == nil {
		return existing, encoded, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}

	var receiptID [16]byte
	if _, err := rand.Read(receiptID[:]); err != nil {
		return nil, nil, fmt.Errorf("generate receipt id: %w", err)
	}

	r := &format.Receipt{
		ReceiptVersion:      format.ReceiptVersion,
		ReceiptID:           receiptID,
		DeviceID:            deviceID,
		BundleID:            bundleID,
		ContentRoot:         contentRoot,
		ServerIngestUTCMS:   uint64(s.now().UTC().UnixMilli()),
		ServerKeyID:         s.keyID,
		IngestSchemaVersion: IngestSchemaVersion,
		StoredObjectIDs:     objectIDs,
		SignatureAlgorithm:  format.SignatureAlgorithmEd25519,
	}

	encoded, err := r.Sign(s.priv)
	if err != nil {
		return nil, nil, fmt.Errorf("sign receipt: %w", err)
	}

	// Durable before returned. This is the whole promise of a receipt.
	if err := writeDurable(s.path(contentRoot), encoded, 0o600); err != nil {
		return nil, nil, fmt.Errorf("persist receipt: %w", err)
	}

	return r, encoded, nil
}

// ObjectIDsFor returns the canonical stored-object identifiers for a set of
// member digests, in the order given.
func ObjectIDsFor(digests [][32]byte) []string {
	ids := make([]string, len(digests))
	for i, d := range digests {
		ids[i] = cas.ObjectID(d)
	}
	return ids
}

// writeDurable writes data atomically and durably: temp file, fsync, rename,
// fsync parent directory.
func writeDurable(final string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(final)

	f, err := os.CreateTemp(dir, ".tmp-*")
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
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
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

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
