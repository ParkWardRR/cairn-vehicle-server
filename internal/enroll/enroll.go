package enroll

import (
	"bytes"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
)

var (
	// ErrFingerprintRequired means the operator did not state what the dongle
	// displayed. There is no "approve whatever arrived" mode.
	ErrFingerprintRequired = errors.New("--confirm-fingerprint is required: read the 8-hex FINGERPRINT " +
		"the dongle printed and type it here")
	// ErrFingerprintMismatch means the blob is not from the unit the operator
	// looked at.
	ErrFingerprintMismatch = errors.New("fingerprint mismatch: this blob is not from the device whose " +
		"fingerprint you confirmed — nothing was enrolled")
	// ErrRootMismatch means this device and key version already have a
	// different root escrowed.
	ErrRootMismatch = errors.New("a DIFFERENT storage root is already escrowed for this device and key " +
		"version: the unit was re-keyed (NVS wiped?) or this is a clone claiming its id. Nothing was changed")
	// ErrRootShredded means that version was deliberately destroyed.
	ErrRootShredded = errors.New("that storage key version was crypto-shredded; it cannot be re-escrowed")
	// ErrKeyChanged means the device id is enrolled with another signing key.
	ErrKeyChanged = errors.New("this device id is already enrolled with a DIFFERENT signing key; " +
		"pass --allow-key-change only if you know the unit was re-keyed")
	// ErrRevokedDevice means re-enrolment would silently un-revoke a device.
	ErrRevokedDevice = errors.New("this device is revoked; pass --reinstate to deliberately re-admit it")
)

// Request is one operator-approved enrolment.
type Request struct {
	Blob               []byte
	ConfirmFingerprint string
	Name               string
	AllowKeyChange     bool
	Reinstate          bool
}

// Deps are the server state an enrolment touches. All are required.
type Deps struct {
	Registry  *devices.Registry
	Keys      *keystore.Store
	Counters  *counters.Guard
	ServerKey *ecdh.PrivateKey
}

// Result is what the operator and the provisioning tool need next.
type Result struct {
	DeviceID    string
	Name        string
	Fingerprint string
	KeyIDHex    string
	KeyVersion  uint32
	// CounterFloor is the highest bundle counter the server has accepted from
	// this device. The device raises its own counter to at least this, so its
	// next bundle is numbered above every value already spent.
	CounterFloor uint64
	// RootAlreadyEscrowed is true when this exact root was escrowed before,
	// i.e. the enrolment is a harmless repeat.
	RootAlreadyEscrowed bool
	Reenrolled          bool
}

// NormalizeFingerprint validates the operator's typed fingerprint.
func NormalizeFingerprint(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", ErrFingerprintRequired
	}
	if len(s) != 8 {
		return "", fmt.Errorf("fingerprint must be 8 hex characters, got %d", len(s))
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("fingerprint must be hex: %w", err)
	}
	return s, nil
}

// Enroll verifies, unseals and records a device.
//
// Order is chosen so that every refusal happens before anything is written,
// and so a repeat after a partial failure converges instead of erroring:
//
//  1. structure and signature (no key needed), then the fingerprint the human
//     typed — before any decryption, so a wrong blob is refused cheaply;
//  2. unseal K_root;
//  3. registry checks: a revoked device or a changed signing key stops here;
//  4. escrow — write-once per (device, version), and an identical root is a
//     no-op, so re-running a half-finished enrolment is safe;
//  5. the registry entry;
//  6. the counter floor.
func Enroll(req Request, d Deps) (*Result, error) {
	if d.Registry == nil || d.Keys == nil || d.Counters == nil {
		return nil, errors.New("enroll: registry, keystore and counter guard are all required")
	}
	want, err := NormalizeFingerprint(req.ConfirmFingerprint)
	if err != nil {
		return nil, err
	}

	h, err := Parse(req.Blob)
	if err != nil {
		return nil, err
	}
	if got := h.Fingerprint(); got != want {
		return nil, fmt.Errorf("%w (blob %s, you confirmed %s)", ErrFingerprintMismatch, got, want)
	}

	if d.ServerKey == nil {
		return nil, ErrNoServerKey
	}
	o, err := Open(req.Blob, d.ServerKey)
	if err != nil {
		return nil, err
	}
	defer clear(o.Root[:])

	idHex := hex.EncodeToString(o.DeviceID[:])

	var existing *devices.Device
	for _, dev := range d.Registry.List() {
		if dev.DeviceID == idHex {
			existing = dev
		}
	}
	name, quota := req.Name, int64(0)
	if existing != nil {
		if existing.Revoked && !req.Reinstate {
			return nil, fmt.Errorf("%w (%s: %s)", ErrRevokedDevice, idHex, existing.RevokedReason)
		}
		if pub, perr := existing.PublicKey(); perr != nil || !bytes.Equal(pub, o.PublicKey) {
			if !req.AllowKeyChange {
				return nil, fmt.Errorf("%w (%s)", ErrKeyChanged, idHex)
			}
		}
		if name == "" {
			name = existing.Name
		}
		quota = existing.QuotaBytes
	}
	if name == "" {
		name = "device-" + idHex[:8]
	}

	res := &Result{
		DeviceID:    idHex,
		Name:        name,
		Fingerprint: o.Fingerprint(),
		KeyVersion:  o.KeyVersion,
		Reenrolled:  existing != nil,
	}

	prev, err := d.Keys.Root(idHex, o.KeyVersion)
	switch {
	case err == nil:
		same := subtle.ConstantTimeCompare(prev[:], o.Root[:]) == 1
		clear(prev[:])
		if !same {
			return nil, fmt.Errorf("%w (%s v%d)", ErrRootMismatch, idHex, o.KeyVersion)
		}
		res.RootAlreadyEscrowed = true
	case errors.Is(err, keystore.ErrNoKey):
		if err := d.Keys.Put(idHex, o.KeyVersion, o.Root); err != nil {
			return nil, fmt.Errorf("escrow storage root: %w", err)
		}
	case errors.Is(err, keystore.ErrDestroyed):
		return nil, fmt.Errorf("%w (%s v%d)", ErrRootShredded, idHex, o.KeyVersion)
	default:
		return nil, fmt.Errorf("read escrow: %w", err)
	}

	dev, err := d.Registry.Enroll(o.DeviceID, name, o.PublicKey, quota)
	if err != nil {
		return nil, fmt.Errorf("enrol device: %w", err)
	}
	res.KeyIDHex = dev.KeyIDHex

	floor, err := d.Counters.Resume(idHex)
	if err != nil {
		return nil, fmt.Errorf("counter floor: %w", err)
	}
	res.CounterFloor = floor
	return res, nil
}
