// Package keystore holds each device's escrowed storage root key.
//
// Bundles are encrypted on the device's SD card (format v3) under keys derived
// from a per-device root. The server needs that root to decode what the device
// uploads, so it is escrowed here at enrolment. What the design buys is not that
// the server cannot read the data — it must — but that *the card alone* cannot:
// someone holding a copied card has ciphertext and no root.
//
// # Why the roots are wrapped on disk
//
// A root in a plaintext file would turn "the server's disk was imaged" into
// "every bundle ever recorded is readable". So each root is sealed with a server
// master key before it is written, with the device ID and key version bound in
// as associated data so a wrapped root cannot be moved between records. The
// master key lives in its own file, mode 0600, and the deployment is expected to
// keep it somewhere other than the data directory that gets backed up (a
// systemd credential, or a separate mount). The backup guidance in
// docs/trust-model-v3.md says the same.
//
// # Crypto-shredding
//
// Destroying a root makes every bundle recorded under it permanently
// unreadable, wherever copies of the ciphertext live — the CAS, a Parquet
// mirror, an old backup. That is the only deletion that reaches backups, which
// is why Destroy exists and why it is separate from revoking a device: a
// revoked device's history is still wanted; a deliberately shredded one is not.
package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/jsonstore"
)

var (
	// ErrNoKey means there is no root for that device and version.
	ErrNoKey = errors.New("no storage root for that device and key version")
	// ErrKeyExists means a root is already recorded for that version. A version
	// is write-once: replacing a root would make every bundle sealed under the
	// old one undecodable without anyone having decided that.
	ErrKeyExists = errors.New("a storage root is already recorded for that device and key version")
	// ErrDestroyed means the root was deliberately shredded.
	ErrDestroyed = errors.New("storage root was destroyed")
)

type entry struct {
	DeviceID    string    `json:"device_id"`
	Version     uint32    `json:"version"`
	Wrapped     string    `json:"wrapped,omitempty"` // hex(nonce || sealed root)
	CreatedAt   time.Time `json:"created_at"`
	DestroyedAt time.Time `json:"destroyed_at,omitzero"`
}

type document struct {
	Entries []*entry `json:"entries"`
}

// Store is the escrow.
type Store struct {
	store  *jsonstore.Store[document]
	master [32]byte
}

// Open loads the store. masterKeyPath is created (0600) on first use.
func Open(path, masterKeyPath string) (*Store, error) {
	js, err := jsonstore.Open(path, func() document { return document{} })
	if err != nil {
		return nil, err
	}
	master, err := loadOrCreateMaster(masterKeyPath)
	if err != nil {
		return nil, err
	}
	return &Store{store: js, master: master}, nil
}

func loadOrCreateMaster(path string) ([32]byte, error) {
	var key [32]byte
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		b, derr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if derr != nil || len(b) != 32 {
			return key, fmt.Errorf("master key %s must hold 64 hex characters", filepath.Base(path))
		}
		copy(key[:], b)
		return key, nil
	case !errors.Is(err, os.ErrNotExist):
		return key, fmt.Errorf("read master key: %w", err)
	}

	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("create key dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadOrCreateMaster(path)
		}
		return key, fmt.Errorf("create master key: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(key[:]) + "\n"); err != nil {
		return key, fmt.Errorf("write master key: %w", err)
	}
	return key, f.Sync()
}

func (s *Store) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(s.master[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad binds a wrapped root to its device and version.
func aad(deviceID string, version uint32) []byte {
	out := []byte("cairn/keystore/v1\x00" + deviceID + "\x00")
	return binary.BigEndian.AppendUint32(out, version)
}

// Put records a device's storage root for a key version.
func (s *Store) Put(deviceID string, version uint32, root [32]byte) error {
	deviceID = strings.ToLower(deviceID)
	gcm, err := s.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("keystore nonce: %w", err)
	}
	wrapped := hex.EncodeToString(gcm.Seal(nonce, nonce, root[:], aad(deviceID, version)))

	return s.store.Update(func(d *document) error {
		for _, e := range d.Entries {
			if e.DeviceID == deviceID && e.Version == version {
				return fmt.Errorf("%w: %s v%d", ErrKeyExists, deviceID, version)
			}
		}
		d.Entries = append(d.Entries, &entry{
			DeviceID:  deviceID,
			Version:   version,
			Wrapped:   wrapped,
			CreatedAt: time.Now().UTC(),
		})
		return nil
	})
}

// Root returns the storage root for a device and key version.
func (s *Store) Root(deviceID string, version uint32) ([32]byte, error) {
	deviceID = strings.ToLower(deviceID)
	var root [32]byte

	var found *entry
	s.store.View(func(d *document) {
		for _, e := range d.Entries {
			if e.DeviceID == deviceID && e.Version == version {
				c := *e
				found = &c
			}
		}
	})
	switch {
	case found == nil:
		return root, fmt.Errorf("%w: %s v%d", ErrNoKey, deviceID, version)
	case !found.DestroyedAt.IsZero():
		return root, fmt.Errorf("%w: %s v%d at %s", ErrDestroyed, deviceID, version, found.DestroyedAt.Format(time.RFC3339))
	}

	raw, err := hex.DecodeString(found.Wrapped)
	if err != nil {
		return root, fmt.Errorf("keystore entry is not hex: %w", err)
	}
	gcm, err := s.aead()
	if err != nil {
		return root, err
	}
	if len(raw) < gcm.NonceSize() {
		return root, errors.New("keystore entry is truncated")
	}
	pt, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], aad(deviceID, version))
	if err != nil {
		// Either the wrong master key or a record moved from elsewhere; the two
		// are deliberately indistinguishable.
		return root, fmt.Errorf("storage root for %s v%d cannot be unwrapped: %w", deviceID, version, err)
	}
	copy(root[:], pt)
	return root, nil
}

// Latest returns the newest live key version for a device.
func (s *Store) Latest(deviceID string) (uint32, bool) {
	var best uint32
	var ok bool
	for _, v := range s.Versions(deviceID) {
		if v >= best {
			best, ok = v, true
		}
	}
	return best, ok
}

// Versions lists a device's live (not destroyed) key versions, ascending.
func (s *Store) Versions(deviceID string) []uint32 {
	deviceID = strings.ToLower(deviceID)
	var out []uint32
	s.store.View(func(d *document) {
		for _, e := range d.Entries {
			if e.DeviceID == deviceID && e.DestroyedAt.IsZero() {
				out = append(out, e.Version)
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Destroy shreds a root. The wrapped bytes are removed, not merely flagged, so
// a later copy of this file cannot bring the key back.
func (s *Store) Destroy(deviceID string, version uint32) error {
	deviceID = strings.ToLower(deviceID)
	return s.store.Update(func(d *document) error {
		for _, e := range d.Entries {
			if e.DeviceID == deviceID && e.Version == version {
				e.Wrapped = ""
				if e.DestroyedAt.IsZero() {
					e.DestroyedAt = time.Now().UTC()
				}
				return nil
			}
		}
		return fmt.Errorf("%w: %s v%d", ErrNoKey, deviceID, version)
	})
}

// RootKey implements format.RootKeyResolver, so the keystore can drive
// decryption of any device's bundles.
func (s *Store) RootKey(deviceID [16]byte, version uint32) ([32]byte, error) {
	root, err := s.Root(hex.EncodeToString(deviceID[:]), version)
	switch {
	case errors.Is(err, ErrNoKey), errors.Is(err, ErrDestroyed):
		// Mapped to the format package's sentinel so a caller scanning a
		// segment sees "no key" rather than a keystore-specific error.
		return root, fmt.Errorf("%w: %w", format.ErrNoKey, err)
	}
	return root, err
}

// Provider returns a format.KeyProvider over every escrowed root.
func (s *Store) Provider() format.KeyProvider {
	return format.ResolverKeyProvider{Resolver: s}
}

// wrapAAD binds a wrapped secret to its purpose, so a blob wrapped for one use
// can never be unwrapped as another — and never as a device root, whose AAD has
// a different prefix.
func wrapAAD(purpose string) []byte {
	return []byte("cairn/keystore-wrap/v1\x00" + purpose)
}

// WrapSecret seals an arbitrary server secret under the keystore master key.
//
// It exists for the device-enrolment private key. That key opens every
// enrolment blob, and a blob is not secret — it is printed on a serial console,
// passed through ssh and possibly logged — so a plaintext enrolment key sitting
// in a backed-up data directory would turn "backup plus an old terminal
// scroll-back" into every device's storage root. Wrapping it under the same
// master key as the roots means it is exactly as protected as what it unlocks.
func (s *Store) WrapSecret(purpose string, plaintext []byte) ([]byte, error) {
	gcm, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("keystore nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, wrapAAD(purpose)), nil
}

// UnwrapSecret reverses WrapSecret. A wrong master key, a different purpose and
// a tampered blob are deliberately indistinguishable.
func (s *Store) UnwrapSecret(purpose string, wrapped []byte) ([]byte, error) {
	gcm, err := s.aead()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < gcm.NonceSize() {
		return nil, errors.New("wrapped secret is truncated")
	}
	pt, err := gcm.Open(nil, wrapped[:gcm.NonceSize()], wrapped[gcm.NonceSize():], wrapAAD(purpose))
	if err != nil {
		return nil, fmt.Errorf("%s cannot be unwrapped (wrong keystore master key?): %w", purpose, err)
	}
	return pt, nil
}
