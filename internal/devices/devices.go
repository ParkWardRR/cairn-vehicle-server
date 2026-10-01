// Package devices is the enrolment registry: which devices may upload, which
// key signs their manifests, and which have been revoked.
//
// mTLS proves who opened the connection. It does not say whether that identity
// is still trusted, nor which signing key its manifests should carry — so the
// registry is a separate check, not a side effect of the handshake. A stolen
// device whose certificate is still cryptographically valid must be stoppable,
// which means revocation lives here rather than in the TLS layer.
//
// Backed by a JSON file. The relational schema arrives in a later phase; until
// then ingest deliberately has no database dependency, so a Postgres outage
// cannot stop a device from being receipted.
package devices

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
)

var (
	// ErrUnknown means the device was never enrolled.
	ErrUnknown = errors.New("device not enrolled")
	// ErrRevoked means the device is on the denylist.
	ErrRevoked = errors.New("device revoked")
	// ErrKeyIDMismatch means a manifest claims a signing key that is not the
	// one enrolled for that device.
	ErrKeyIDMismatch = errors.New("manifest key ID does not match the enrolled device key")
	// ErrQuotaExceeded means the device is over its storage allowance.
	ErrQuotaExceeded = errors.New("device storage quota exceeded")
)

// Device is one enrolled recorder.
type Device struct {
	DeviceID      string    `json:"device_id"` // hex of the 16-byte ID
	Name          string    `json:"name"`
	PublicKeyHex  string    `json:"public_key"` // Ed25519 manifest signing key
	KeyIDHex      string    `json:"key_id"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	Revoked       bool      `json:"revoked,omitempty"`
	RevokedAt     time.Time `json:"revoked_at,omitempty"`
	RevokedReason string    `json:"revoked_reason,omitempty"`

	// QuotaBytes caps the raw bytes this device may store. Zero means
	// unlimited. A quota protects the server from one misbehaving device
	// filling the dataset and starving the others.
	QuotaBytes int64 `json:"quota_bytes,omitempty"`
}

// ID returns the parsed 16-byte device identifier.
func (d *Device) ID() ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(d.DeviceID)
	if err != nil {
		return id, fmt.Errorf("decode device id: %w", err)
	}
	if len(raw) != 16 {
		return id, fmt.Errorf("device id is %d bytes, want 16", len(raw))
	}
	copy(id[:], raw)
	return id, nil
}

// PublicKey returns the parsed manifest signing key.
func (d *Device) PublicKey() (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(d.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// Registry holds the enrolled devices.
type Registry struct {
	path string

	mu      sync.RWMutex
	devices map[string]*Device // keyed by hex device ID

	// loadedModTime and loadedSize detect an edit made by another process, so
	// enrolling or revoking from the command line takes effect in a running
	// server without a restart. Requiring a restart to enrol a device would
	// mean an interrupted sync for every other device, and requiring one to
	// revoke a stolen unit would be worse still.
	loadedModTime time.Time
	loadedSize    int64
}

// Open loads a registry, creating an empty one if the file does not exist.
func Open(path string) (*Registry, error) {
	r := &Registry{path: path, devices: make(map[string]*Device)}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

// load reads the registry file, replacing the in-memory contents.
func (r *Registry) load() error {
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		r.mu.Lock()
		r.devices = make(map[string]*Device)
		r.loadedModTime = time.Time{}
		r.loadedSize = 0
		r.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("read device registry: %w", err)
	}

	var list []*Device
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("parse device registry: %w", err)
	}

	loaded := make(map[string]*Device, len(list))
	for _, d := range list {
		if _, err := d.ID(); err != nil {
			return fmt.Errorf("device %q: %w", d.DeviceID, err)
		}
		if _, err := d.PublicKey(); err != nil {
			return fmt.Errorf("device %q: %w", d.DeviceID, err)
		}
		loaded[d.DeviceID] = d
	}

	var modTime time.Time
	var size int64
	if info, err := os.Stat(r.path); err == nil {
		modTime = info.ModTime()
		size = info.Size()
	}

	r.mu.Lock()
	r.devices = loaded
	r.loadedModTime = modTime
	r.loadedSize = size
	r.mu.Unlock()

	return nil
}

// refreshIfChanged reloads the registry when the file has been modified by
// another process.
//
// A stat per lookup is negligible against the handful of lookups a sync makes,
// and it buys the property that administrative changes are effective
// immediately. A corrupt file mid-edit is tolerated by keeping the last good
// contents rather than failing the request: a device in the middle of a sync
// should not be refused because an operator is editing the registry.
func (r *Registry) refreshIfChanged() {
	info, err := os.Stat(r.path)
	if err != nil {
		return
	}

	r.mu.RLock()
	unchanged := info.ModTime().Equal(r.loadedModTime) && info.Size() == r.loadedSize
	r.mu.RUnlock()

	if unchanged {
		return
	}
	_ = r.load()
}

// Enroll adds or replaces a device. The key ID is derived from the public key
// rather than accepted from the caller, so the two can never disagree.
func (r *Registry) Enroll(deviceID [16]byte, name string, pub ed25519.PublicKey, quotaBytes int64) (*Device, error) {
	// Operate on current state, so an enrolment does not silently drop a change
	// another process made since this one loaded.
	r.refreshIfChanged()

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}

	keyID := format.DeviceKeyID(pub)
	d := &Device{
		DeviceID:     hex.EncodeToString(deviceID[:]),
		Name:         name,
		PublicKeyHex: hex.EncodeToString(pub),
		KeyIDHex:     hex.EncodeToString(keyID[:]),
		EnrolledAt:   time.Now().UTC(),
		QuotaBytes:   quotaBytes,
	}

	r.mu.Lock()
	r.devices[d.DeviceID] = d
	r.mu.Unlock()

	if err := r.save(); err != nil {
		return nil, err
	}
	return d, nil
}

// Revoke denylists a device. Its certificate may still be cryptographically
// valid, so this is the control that actually stops a lost or compromised unit.
func (r *Registry) Revoke(deviceID [16]byte, reason string) error {
	r.refreshIfChanged()

	key := hex.EncodeToString(deviceID[:])

	r.mu.Lock()
	d, ok := r.devices[key]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknown, key)
	}
	d.Revoked = true
	d.RevokedAt = time.Now().UTC()
	d.RevokedReason = reason
	r.mu.Unlock()

	return r.save()
}

// Lookup returns an enrolled device, rejecting revoked ones.
func (r *Registry) Lookup(deviceID [16]byte) (*Device, error) {
	r.refreshIfChanged()

	key := hex.EncodeToString(deviceID[:])

	r.mu.RLock()
	d, ok := r.devices[key]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknown, key)
	}
	if d.Revoked {
		return nil, fmt.Errorf("%w: %s (%s)", ErrRevoked, key, d.RevokedReason)
	}
	return d, nil
}

// SignerFor returns the public key that must have signed this device's
// manifests, checking that the manifest's declared key ID matches.
//
// Checking the key ID as well as the signature means a manifest cannot claim to
// come from a different key than the one enrolled, which keeps key rotation an
// explicit administrative act rather than something a device can assert.
func (r *Registry) SignerFor(deviceID [16]byte, manifestKeyID [8]byte) (ed25519.PublicKey, error) {
	d, err := r.Lookup(deviceID)
	if err != nil {
		return nil, err
	}

	pub, err := d.PublicKey()
	if err != nil {
		return nil, err
	}

	if enrolled := format.DeviceKeyID(pub); enrolled != manifestKeyID {
		return nil, fmt.Errorf("%w: manifest claims %x, device %s is enrolled with %x",
			ErrKeyIDMismatch, manifestKeyID, d.DeviceID, enrolled)
	}
	return pub, nil
}

// CheckQuota reports whether storing additionalBytes would exceed the device's
// allowance, given what it already stores.
func (r *Registry) CheckQuota(deviceID [16]byte, currentBytes, additionalBytes int64) error {
	d, err := r.Lookup(deviceID)
	if err != nil {
		return err
	}
	if d.QuotaBytes == 0 {
		return nil
	}
	if currentBytes+additionalBytes > d.QuotaBytes {
		return fmt.Errorf("%w: %s would hold %d bytes, quota is %d",
			ErrQuotaExceeded, d.DeviceID, currentBytes+additionalBytes, d.QuotaBytes)
	}
	return nil
}

// List returns every device, including revoked ones, ordered by ID.
func (r *Registry) List() []*Device {
	r.refreshIfChanged()

	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*Device, 0, len(r.devices))
	for _, d := range r.devices {
		copied := *d
		out = append(out, &copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// save writes the registry durably.
func (r *Registry) save() error {
	list := r.snapshot()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device registry: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create registry dir: %w", err)
	}

	f, err := os.CreateTemp(dir, ".devices-*")
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
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, r.path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	committed = true

	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return err
	}

	// Record what we just wrote, so our own write is not mistaken for an
	// external edit on the next lookup.
	if info, err := os.Stat(r.path); err == nil {
		r.mu.Lock()
		r.loadedModTime = info.ModTime()
		r.loadedSize = info.Size()
		r.mu.Unlock()
	}
	return nil
}

// snapshot returns a copy of the current devices without triggering a reload.
// save uses this rather than List, because reloading mid-save would discard
// the change being written.
func (r *Registry) snapshot() []*Device {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*Device, 0, len(r.devices))
	for _, d := range r.devices {
		copied := *d
		out = append(out, &copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}
