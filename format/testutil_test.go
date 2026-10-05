package format

import (
	"testing"
)

// testRoot is the fixed storage root for in-package tests. It is a test key and
// protects nothing.
var testRoot = func() (k [RootKeySize]byte) {
	for i := range k {
		k[i] = byte(0xC0 ^ i)
	}
	return
}()

// testKeys returns the provider matching testHeader's key version.
func testKeys() KeyProvider { return &RootKeyProvider{Root: testRoot, Version: 1} }

// testHeader returns a deterministic segment header so vectors are
// reproducible byte-for-byte across runs and implementations.
func testHeader(segmentIndex uint32) SegmentHeader {
	var dev, boot, veh, asg [16]byte
	for i := range dev {
		dev[i] = byte(0x10 + i)
		boot[i] = byte(0xA0 + i)
		veh[i] = byte(0x30 + i)
		asg[i] = byte(0x50 + i)
	}
	return SegmentHeader{
		DeviceID:          dev,
		BootID:            boot,
		VehicleID:         veh,
		AssignmentID:      asg,
		SegmentIndex:      segmentIndex,
		OpenedMonotonicUS: 1_000_000,
		StorageKeyVersion: 1,
		DeviceCounter:     7,
	}
}

// newTestWriter builds a writer under testKeys with random nonces, as a real
// writer would use.
func newTestWriter(t testing.TB, h SegmentHeader, state ScanState) *SegmentWriter {
	t.Helper()
	w, err := NewSegmentWriter(h, state, testKeys(), nil)
	if err != nil {
		t.Fatalf("NewSegmentWriter: %v", err)
	}
	return w
}
