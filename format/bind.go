package format

import (
	"errors"
	"fmt"
	"strings"
)

// ErrManifestBindingMismatch means a segment's header disagrees with the signed
// manifest about whose data it is: a different device, vehicle, assignment,
// boot, bundle counter or key version, or an index that does not match its
// file name.
//
// A valid manifest signature does not exclude this. The signature covers the
// member digests, so a segment swapped for another validly written segment
// would break the digest, but a bundle assembled by someone holding the device
// key could pair any manifest with any segments. Checking the headers against
// the manifest is what ties the signed claim to the bytes it describes.
var ErrManifestBindingMismatch = errors.New("segment header disagrees with manifest")

// SegmentMemberName returns the member name of capture segment index.
func SegmentMemberName(index uint32) string { return fmt.Sprintf("seg-%08d.seg", index) }

// JournalMemberName is the member name of the lifecycle journal.
const JournalMemberName = "journal.seg"

// VerifySegmentAgainstManifest checks one member's parsed header against the
// manifest.
//
// name is the member name the manifest listed it under. For a capture segment
// the header's segment_index must equal the index in the name, and for the
// journal it must be JournalSegmentIndex; otherwise a segment could be renamed
// into another position while keeping its own key derivation inputs.
func VerifySegmentAgainstManifest(m *Manifest, name string, h *SegmentHeader) error {
	mismatch := func(field string, got, want any) error {
		return fmt.Errorf("%w: member %q %s is %v, manifest says %v",
			ErrManifestBindingMismatch, name, field, got, want)
	}

	switch {
	case h.DeviceID != m.DeviceID:
		return mismatch("device_id", fmt.Sprintf("%x", h.DeviceID), fmt.Sprintf("%x", m.DeviceID))
	case h.BootID != m.BootID:
		return mismatch("boot_id", fmt.Sprintf("%x", h.BootID), fmt.Sprintf("%x", m.BootID))
	case h.VehicleID != m.VehicleID:
		return mismatch("vehicle_id", fmt.Sprintf("%x", h.VehicleID), fmt.Sprintf("%x", m.VehicleID))
	case h.AssignmentID != m.AssignmentID:
		return mismatch("assignment_id", fmt.Sprintf("%x", h.AssignmentID), fmt.Sprintf("%x", m.AssignmentID))
	case h.DeviceCounter != m.DeviceCounter:
		return mismatch("device_counter", h.DeviceCounter, m.DeviceCounter)
	case h.StorageKeyVersion != m.StorageKeyVersion:
		return mismatch("storage_key_version", h.StorageKeyVersion, m.StorageKeyVersion)
	}

	if name == JournalMemberName {
		if h.SegmentIndex != JournalSegmentIndex {
			return mismatch("segment_index", h.SegmentIndex, fmt.Sprintf("%d (journal)", JournalSegmentIndex))
		}
		return nil
	}
	if want := SegmentMemberName(h.SegmentIndex); name != want {
		return mismatch("segment_index", h.SegmentIndex, "the index in the member name")
	}
	return nil
}

// VerifyMembersAgainstManifest checks every available segment member against the
// manifest and returns the first disagreement.
//
// members maps member name to the member's bytes. A manifest member absent from
// the map is skipped: this is the check to run when members are in hand, and
// whether a missing member is acceptable is the caller's policy (intake has all
// of them, a partial mirror may not). Members that are not segments are
// ignored. A segment whose header does not parse is an error, since it cannot
// be shown to belong to the bundle.
//
// The manifest's capture segments must also be named contiguously from
// seg-00000000, whether or not their bytes are present: a gap would mean a
// segment, and the frames chained through it, was removed.
func VerifyMembersAgainstManifest(m *Manifest, members map[string][]byte) error {
	captures := 0
	for _, mem := range m.Members {
		isCapture := strings.HasPrefix(mem.Name, "seg-")
		if isCapture {
			if want := SegmentMemberName(uint32(captures)); mem.Name != want {
				return fmt.Errorf("%w: manifest capture segment %d is named %q, want %q",
					ErrManifestBindingMismatch, captures, mem.Name, want)
			}
			captures++
		} else if mem.Name != JournalMemberName {
			continue
		}

		data, ok := members[mem.Name]
		if !ok {
			continue
		}
		h, _, err := ParseSegmentHeader(data)
		if err != nil {
			return fmt.Errorf("member %q: %w", mem.Name, err)
		}
		if err := VerifySegmentAgainstManifest(m, mem.Name, &h); err != nil {
			return err
		}
	}
	return nil
}
