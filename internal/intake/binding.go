package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

var (
	// ErrAssignmentRefused means the manifest's vehicle or assignment is not one
	// the server will accept for this device. It wraps the specific cause from
	// the vehicles registry.
	ErrAssignmentRefused = errors.New("vehicle assignment refused")

	// ErrQuarantined means the bundle was held rather than ingested. A device
	// must not retry it: the same bytes will be refused the same way.
	ErrQuarantined = errors.New("bundle quarantined")

	// ErrNoStorageKey means the server holds no escrowed root for the manifest's
	// storage key version, so it could never decode what it is being sent.
	ErrNoStorageKey = errors.New("no escrowed storage key for this device and key version")
)

// bindManifest applies the v3 checks that a signature cannot provide: that the
// bundle belongs to a vehicle and assignment this server issued, that its
// counter has not been spent on something else, and that the server will be
// able to decode it.
//
// It runs after the signature is verified and the manifest is known coherent,
// and before anything is stored or any chunk requested — a device told "no"
// should learn so before transferring a bundle that will never be accepted.
//
// Nothing here is recorded as accepted. Binding a counter to content happens at
// commit (recordBinding), because an offer that never completes must not spend
// a counter: a retry after a dropped connection is the ordinary case.
func (s *Service) bindManifest(m *format.Manifest, manifestBytes, signature []byte) error {
	deviceHex := hex.EncodeToString(m.DeviceID[:])
	vehicleHex := hex.EncodeToString(m.VehicleID[:])
	assignmentHex := hex.EncodeToString(m.AssignmentID[:])
	rootHex := hex.EncodeToString(m.ContentRoot[:])

	refuse := func(event ledger.Event, reason string) {
		s.record(ledger.Entry{
			Event:       event,
			DeviceID:    ledger.HexID(m.DeviceID[:]),
			BundleID:    ledger.HexID(m.BundleID[:]),
			ContentRoot: ledger.HexID(m.ContentRoot[:]),
			Reason:      reason,
		})
	}

	if err := s.vehicles.CheckBundle(deviceHex, vehicleHex, assignmentHex, m.DeviceCounter); err != nil {
		refuse(ledger.EventAssignmentRefused, err.Error())
		return fmt.Errorf("%w: %w", ErrAssignmentRefused, err)
	}

	// The server must be able to decrypt what it accepts. Checked before the
	// counter so a device that is merely not fully enrolled is told that, rather
	// than being refused for a reason that looks like tampering.
	if _, err := s.keys.Root(deviceHex, m.StorageKeyVersion); err != nil {
		reason := fmt.Sprintf("manifest names storage key version %d: %v", m.StorageKeyVersion, err)
		refuse(ledger.EventKeyMissing, reason)
		if errors.Is(err, keystore.ErrNoKey) || errors.Is(err, keystore.ErrDestroyed) {
			return fmt.Errorf("%w: %w", ErrNoStorageKey, err)
		}
		return err
	}

	_, gap, err := s.counters.Check(deviceHex, m.DeviceCounter, rootHex)
	switch {
	case errors.Is(err, counters.ErrCounterConflict), errors.Is(err, counters.ErrZeroCounter):
		s.quarantine(m, manifestBytes, signature, err)
		return fmt.Errorf("%w: %w", ErrQuarantined, err)
	case err != nil:
		return err
	}

	if gap > 0 {
		// A warning, not a refusal: a device working through a backlog uploads
		// out of order, and refusing would strand its data. The hole is what an
		// operator needs to see, because it is a bundle sealed and never received.
		s.record(ledger.Entry{
			Event:       ledger.EventCounterGap,
			DeviceID:    ledger.HexID(m.DeviceID[:]),
			BundleID:    ledger.HexID(m.BundleID[:]),
			ContentRoot: ledger.HexID(m.ContentRoot[:]),
			Reason: fmt.Sprintf("counter %d skips %d value(s) past the previous high-water mark",
				m.DeviceCounter, gap),
		})
	}
	return nil
}

// quarantine keeps the evidence of a forged or replayed bundle without
// ingesting it. The manifest and signature go to the content-addressed store so
// they can be examined later; the ledger entry says why.
func (s *Service) quarantine(m *format.Manifest, manifestBytes, signature []byte, cause error) {
	manifestDigest := sha256.Sum256(manifestBytes)
	sigDigest := sha256.Sum256(signature)

	// Best effort: failing to preserve evidence must not turn a refusal into an
	// error that hides the refusal.
	_ = s.cas.Put(manifestDigest, manifestBytes)
	_ = s.cas.Put(sigDigest, signature)

	s.record(ledger.Entry{
		Event:       ledger.EventQuarantined,
		DeviceID:    ledger.HexID(m.DeviceID[:]),
		BundleID:    ledger.HexID(m.BundleID[:]),
		ContentRoot: ledger.HexID(m.ContentRoot[:]),
		Reason: fmt.Sprintf("%v (manifest %s, signature %s kept for inspection)",
			cause, hex.EncodeToString(manifestDigest[:8]), hex.EncodeToString(sigDigest[:8])),
	})
}

// recordBinding binds the counter to the bundle's content and notes the
// assignment's counter range. It runs at commit, before the receipt is issued:
// if the receipt then fails, a retry presents the same (counter, content) pair
// and is recognised as the same bundle; if two offers race for one counter with
// different content, exactly one of them wins here.
func (s *Service) recordBinding(m *format.Manifest) error {
	deviceHex := hex.EncodeToString(m.DeviceID[:])
	rootHex := hex.EncodeToString(m.ContentRoot[:])

	if err := s.counters.Record(deviceHex, m.DeviceCounter, rootHex); err != nil {
		if errors.Is(err, counters.ErrCounterConflict) {
			s.record(ledger.Entry{
				Event:       ledger.EventQuarantined,
				DeviceID:    ledger.HexID(m.DeviceID[:]),
				BundleID:    ledger.HexID(m.BundleID[:]),
				ContentRoot: ledger.HexID(m.ContentRoot[:]),
				Reason:      "lost a race for the counter at commit: " + err.Error(),
			})
			return fmt.Errorf("%w: %w", ErrQuarantined, err)
		}
		return err
	}

	assignmentHex := hex.EncodeToString(m.AssignmentID[:])
	if err := s.vehicles.Observe(assignmentHex, m.DeviceCounter); err != nil && !errors.Is(err, vehicles.ErrAssignmentUnknown) {
		return err
	}
	return nil
}
