package intake

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/counters"
	"github.com/ParkWardRR/Cairn/server/internal/ledger"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

// withLedger attaches a ledger so a test can read why something was refused.
func (h *harness) withLedger(t *testing.T) *ledger.Ledger {
	t.Helper()
	book, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { book.Close() })
	h.svc.ledger = book
	return book
}

// build makes a bundle with a distinct payload per (counter, samples) so its
// content root is its own.
func (h *harness) build(t *testing.T, mutate func(*testbundle.Options)) *testbundle.Bundle {
	t.Helper()
	opts := testbundle.Default()
	opts.ChunkSize = 256
	if mutate != nil {
		mutate(&opts)
	}
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// commit pushes a bundle through offer, chunks and commit.
func (h *harness) commit(t *testing.T, b *testbundle.Bundle) {
	t.Helper()
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatalf("offer: %v", err)
	}
	h.sendAll(t, b)
	if _, err := h.svc.Commit(b.Manifest.BundleID); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func events(t *testing.T, book *ledger.Ledger, want ledger.Event) []ledger.Entry {
	t.Helper()
	all, err := book.Read()
	if err != nil {
		t.Fatal(err)
	}
	var out []ledger.Entry
	for _, e := range all {
		if e.Event == want {
			out = append(out, e)
		}
	}
	return out
}

// The case the counter exists for: a genuine device never seals two different
// bundles under one counter.
func TestCounterConflictIsQuarantinedNotIngested(t *testing.T) {
	h := newHarness(t)
	book := h.withLedger(t)

	genuine := h.build(t, func(o *testbundle.Options) { o.DeviceCounter = 5 })
	h.commit(t, genuine)

	forged := h.build(t, func(o *testbundle.Options) {
		o.DeviceCounter = 5
		o.GNSSSamples = 30 // different content
	})
	_, err := h.svc.Offer(forged.ManifestBytes, forged.Signature)
	if !errors.Is(err, ErrQuarantined) || !errors.Is(err, counters.ErrCounterConflict) {
		t.Fatalf("Offer = %v, want a quarantine caused by a counter conflict", err)
	}

	if _, _, err := h.receipts.Lookup(forged.Manifest.ContentRoot); err == nil {
		t.Fatal("a quarantined bundle was receipted")
	}

	q := events(t, book, ledger.EventQuarantined)
	if len(q) != 1 || q[0].Reason == "" {
		t.Fatalf("quarantine ledger entries = %+v", q)
	}
}

// A restored card re-presents bundles the server already has. That is the
// ordinary case, not an attack, and must be answered with the original receipt.
func TestRestoredCardIsAnIdempotentDuplicate(t *testing.T) {
	h := newHarness(t)

	b := h.build(t, func(o *testbundle.Options) { o.DeviceCounter = 3 })
	h.commit(t, b)

	res, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if err != nil {
		t.Fatalf("re-offer of a committed bundle: %v", err)
	}
	if res.ExistingReceipt == nil {
		t.Fatal("expected the existing receipt")
	}
}

func TestUnknownAssignmentRefused(t *testing.T) {
	h := newHarness(t)
	book := h.withLedger(t)

	b := h.build(t, func(o *testbundle.Options) {
		o.AssignmentID = [16]byte{0xde, 0xad}
	})
	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, ErrAssignmentRefused) || !errors.Is(err, vehicles.ErrAssignmentUnknown) {
		t.Fatalf("Offer = %v", err)
	}
	if got := events(t, book, ledger.EventAssignmentRefused); len(got) != 1 {
		t.Fatalf("assignment_refused entries = %d", len(got))
	}
}

// Trips must not land under a vehicle the assignment does not name.
func TestAssignmentForAnotherVehicleRefused(t *testing.T) {
	h := newHarness(t)

	b := h.build(t, func(o *testbundle.Options) {
		o.VehicleID = [16]byte{0xbe, 0xef} // not the assigned car
	})
	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, vehicles.ErrAssignmentMismatch) {
		t.Fatalf("Offer = %v, want ErrAssignmentMismatch", err)
	}
}

// A dongle moved to another car: bundles sealed before the move still upload,
// bundles claiming the old car after the device has used the new one do not.
func TestDeviceMovedBetweenCars(t *testing.T) {
	h := newHarness(t)

	oldAssignment := testbundle.AssignmentID()
	oldVehicle := testbundle.VehicleID()
	deviceHex := hex.EncodeToString(h.deviceID[:])

	// Counter 4 under the first car.
	h.commit(t, h.build(t, func(o *testbundle.Options) { o.DeviceCounter = 4 }))

	// Move the device to a second car.
	newVehicle := [16]byte{0x77, 0x01}
	newAssignment := [16]byte{0x77, 0x02}
	if _, err := h.vehicles.CreateVehicle(vehicles.NewVehicleSpec{
		ID: hex.EncodeToString(newVehicle[:]), DisplayName: "2017 BMW M240i — B58", EngineCode: "B58",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.vehicles.AssignWithID(hex.EncodeToString(newAssignment[:]), deviceHex,
		hex.EncodeToString(newVehicle[:]), "test"); err != nil {
		t.Fatal(err)
	}

	// Counter 7 under the second car establishes that the device has switched.
	h.commit(t, h.build(t, func(o *testbundle.Options) {
		o.DeviceCounter = 7
		o.VehicleID, o.AssignmentID = newVehicle, newAssignment
		o.GNSSSamples = 15
	}))

	// A bundle sealed before the switch (counter 5) under the old car is fine:
	// the device had not yet heard about the move.
	late := h.build(t, func(o *testbundle.Options) {
		o.DeviceCounter = 5
		o.VehicleID, o.AssignmentID = oldVehicle, oldAssignment
		o.GNSSSamples = 16
	})
	if _, err := h.svc.Offer(late.ManifestBytes, late.Signature); err != nil {
		t.Fatalf("a bundle sealed before the move was refused: %v", err)
	}

	// But claiming the old car at counter 8, after counter 7 was the new car, is
	// the device using a superseded identity.
	stale := h.build(t, func(o *testbundle.Options) {
		o.DeviceCounter = 8
		o.VehicleID, o.AssignmentID = oldVehicle, oldAssignment
		o.GNSSSamples = 17
	})
	_, err := h.svc.Offer(stale.ManifestBytes, stale.Signature)
	if !errors.Is(err, vehicles.ErrAssignmentSuperseded) {
		t.Fatalf("Offer = %v, want ErrAssignmentSuperseded", err)
	}
}

// Accepting data the server can never decode would be a slow disaster, found
// only when someone tries to read the trip.
func TestBundleWithNoEscrowedKeyRefused(t *testing.T) {
	h := newHarness(t)
	book := h.withLedger(t)

	other := [format.RootKeySize]byte{9, 9, 9}
	b := h.build(t, func(o *testbundle.Options) {
		o.RootKey = &other
		o.KeyVersion = 2 // never escrowed
	})
	_, err := h.svc.Offer(b.ManifestBytes, b.Signature)
	if !errors.Is(err, ErrNoStorageKey) {
		t.Fatalf("Offer = %v, want ErrNoStorageKey", err)
	}
	if got := events(t, book, ledger.EventKeyMissing); len(got) != 1 {
		t.Fatalf("key_missing entries = %d", len(got))
	}
}

func TestCounterGapIsReportedNotRefused(t *testing.T) {
	h := newHarness(t)
	book := h.withLedger(t)

	h.commit(t, h.build(t, func(o *testbundle.Options) { o.DeviceCounter = 1 }))

	// Counters 2..4 never arrive.
	h.commit(t, h.build(t, func(o *testbundle.Options) {
		o.DeviceCounter = 5
		o.GNSSSamples = 14
	}))

	gaps := events(t, book, ledger.EventCounterGap)
	if len(gaps) != 1 {
		t.Fatalf("counter_gap entries = %d, want 1", len(gaps))
	}
	deviceHex := hex.EncodeToString(h.deviceID[:])
	if missing := h.counters.Missing(deviceHex); len(missing) != 3 || missing[0] != 2 {
		t.Fatalf("Missing = %v, want [2 3 4]", missing)
	}
}

// An offer that never completes must not spend its counter: a dropped
// connection followed by a retry is the ordinary case.
func TestAbandonedOfferDoesNotSpendTheCounter(t *testing.T) {
	h := newHarness(t)

	b := h.build(t, func(o *testbundle.Options) { o.DeviceCounter = 2 })
	if _, err := h.svc.Offer(b.ManifestBytes, b.Signature); err != nil {
		t.Fatal(err)
	}
	// No chunks, no commit. A different bundle may now legitimately take the
	// counter, because nothing was ever bound to it.
	deviceHex := hex.EncodeToString(h.deviceID[:])
	if hw := h.counters.HighWater(deviceHex); hw != 0 {
		t.Fatalf("high water = %d after an offer with no commit", hw)
	}
}
