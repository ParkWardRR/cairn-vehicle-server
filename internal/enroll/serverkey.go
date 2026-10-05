package enroll

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ServerKeyFile is the enrolment key's file name under <data>/keys.
const ServerKeyFile = "enroll.x25519"

// keyPurpose binds the wrapped key to this use inside the keystore's wrapping.
const keyPurpose = "enroll-x25519/v1"

const keyFileHeader = "cairn-enroll-x25519-v1"

// Wrapper seals the private half at rest. keystore.Store implements it.
type Wrapper interface {
	WrapSecret(purpose string, plaintext []byte) ([]byte, error)
	UnwrapSecret(purpose string, wrapped []byte) ([]byte, error)
}

// ErrNoServerKey means no enrolment key has been created yet, so no device can
// have sealed a blob to this server.
var ErrNoServerKey = errors.New("this server has no enrolment key yet: run `cairn-server -print-enroll-key` " +
	"to create it, then pin the printed value in the firmware")

// ServerKeyPath is where the enrolment key lives for a data directory.
func ServerKeyPath(dataDir string) string {
	return filepath.Join(dataDir, "keys", ServerKeyFile)
}

// LoadServerKey reads the enrolment private key. It never creates one: an
// enrolment can only succeed against the key the firmware already pinned, so
// minting a fresh key at that point would just produce a confusing unseal
// failure.
func LoadServerKey(path string, w Wrapper) (*ecdh.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoServerKey
	}
	if err != nil {
		return nil, fmt.Errorf("read enrolment key: %w", err)
	}
	fields := strings.Fields(string(raw))
	if len(fields) != 2 || fields[0] != keyFileHeader {
		return nil, fmt.Errorf("enrolment key %s is not a %s file", filepath.Base(path), keyFileHeader)
	}
	wrapped, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("enrolment key %s: %w", filepath.Base(path), err)
	}
	seed, err := w.UnwrapSecret(keyPurpose, wrapped)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ecdh.X25519().NewPrivateKey(seed)
}

// LoadOrCreateServerKey returns the enrolment key, creating it (mode 0600,
// wrapped under the keystore master key) on first use. created reports whether
// it was just made, so the caller can tell the operator to pin it.
func LoadOrCreateServerKey(path string, w Wrapper) (key *ecdh.PrivateKey, created bool, err error) {
	key, err = LoadServerKey(path, w)
	if !errors.Is(err, ErrNoServerKey) {
		return key, false, err
	}

	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, false, fmt.Errorf("generate enrolment key: %w", err)
	}
	defer clear(seed[:])
	key, err = ecdh.X25519().NewPrivateKey(seed[:])
	if err != nil {
		return nil, false, err
	}
	wrapped, err := w.WrapSecret(keyPurpose, seed[:])
	if err != nil {
		return nil, false, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("create key dir: %w", err)
	}
	// O_EXCL: two processes racing to create the key must not end with each
	// believing its own key is the one on disk — the loser re-reads instead.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		key, err = LoadServerKey(path, w)
		return key, false, err
	}
	if err != nil {
		return nil, false, fmt.Errorf("create enrolment key: %w", err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s\n", keyFileHeader, hex.EncodeToString(wrapped)); err != nil {
		return nil, false, fmt.Errorf("write enrolment key: %w", err)
	}
	if err := f.Sync(); err != nil {
		return nil, false, err
	}
	return key, true, nil
}
