// Package testbundle builds synthetic sealed bundles for tests.
//
// It produces the real thing: framed segments written by the format's own
// writer, members concatenated in canonical order, chunks partitioning that
// stream, and a deterministically-encoded manifest signed with a device key.
// Tests that assembled a bundle by hand would risk agreeing with a buggy
// implementation; building through the real encoder means an end-to-end test
// actually exercises the format.
//
// Everything is deterministic: a fixed device key seed and fixed timestamps, so
// a failure reproduces and a device key stays stable across a simulated
// restart.
package testbundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/ParkWardRR/Cairn/server/format"
)

// DeviceKeySeed is the fixed seed for the synthetic device signing key.
const DeviceKeySeed = "cairn-intake-test-device-key-see"

// Bundle is a synthetic sealed bundle, ready to offer.
type Bundle struct {
	ManifestBytes []byte
	Signature     []byte
	Manifest      *format.Manifest

	// Chunks are in index order, matching Manifest.ChunkDescriptors.
	Chunks [][]byte

	// Stream is the full bundle byte stream the chunks partition.
	Stream []byte
}

// DeviceKey returns the fixed synthetic device signing key.
func DeviceKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed([]byte(DeviceKeySeed))
	return priv.Public().(ed25519.PublicKey), priv
}

// DeviceID returns the conventional synthetic device identifier.
func DeviceID() [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = byte(0x10 + i)
	}
	return id
}

// Options controls bundle generation.
type Options struct {
	// ChunkSize partitions the byte stream. Small values deliberately make
	// chunk boundaries fall inside members, which is the interesting case.
	ChunkSize int

	// GNSSSamples, OBDSamples and JournalEntries size the three segments.
	GNSSSamples    int
	OBDSamples     int
	JournalEntries int

	// GapAfter writes a GNSS_GAP record after this many GNSS samples, and
	// jumps the following samples a long way off, as a tunnel would.
	//
	// Zero means no gap.
	GapAfter int

	// FixlessFrom makes every GNSS sample from this index onwards report no
	// fix, as a receiver losing the sky would. The samples are still written:
	// the absence is data.
	//
	// Zero means every sample has a fix.
	FixlessFrom int

	// Mutate runs after the manifest is built but before it is signed, so a
	// test can produce a validly signed manifest that is nevertheless wrong.
	Mutate func(*format.Manifest)
}

// Default returns sensible options.
func Default() Options {
	return Options{ChunkSize: 256, GNSSSamples: 12, OBDSamples: 7, JournalEntries: 4}
}

// Build produces a bundle.
func Build(opts Options) (*Bundle, error) {
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = 256
	}

	deviceID := DeviceID()
	pub, priv := DeviceKey()

	// Capture chain: segment 1 continues segment 0's sequence and CRC chain.
	w0 := format.NewSegmentWriter(segHeader(deviceID, 0), format.ScanState{})
	for i := 0; i < opts.GNSSSamples; i++ {
		// A receiver that has lost the sky still produces samples; they simply
		// carry no position. Recording them is how the gap stays visible.
		if opts.FixlessFrom > 0 && i >= opts.FixlessFrom {
			if err := w0.Append(format.RecordGNSSSample, 1, 0,
				uint32(i*1000), FixlessGNSSPayload()); err != nil {
				return nil, fmt.Errorf("append fix-less GNSS %d: %w", i, err)
			}
			continue
		}

		// After a gap the vehicle reappears somewhere else entirely, which is
		// exactly the case a decoder must not bridge with a straight line.
		offset := i
		if opts.GapAfter > 0 && i >= opts.GapAfter {
			offset = i + 5000
		}

		if err := w0.Append(format.RecordGNSSSample, 1, 0,
			uint32(i*1000), GNSSPayload(offset)); err != nil {
			return nil, fmt.Errorf("append GNSS %d: %w", i, err)
		}

		// The gap record goes between the last pre-gap sample and the first
		// post-gap one.
		if opts.GapAfter > 0 && i == opts.GapAfter-1 {
			if err := w0.Append(format.RecordGNSSGap, 1, 0,
				uint32(i*1000), GapPayload(42_000, 42, 4)); err != nil {
				return nil, fmt.Errorf("append gap: %w", err)
			}
		}
	}
	seg0 := append([]byte(nil), w0.Bytes()...)

	w1 := format.NewSegmentWriter(segHeader(deviceID, 1), w0.NextState())
	for i := 0; i < opts.OBDSamples; i++ {
		if err := w1.Append(format.RecordOBDSnapshot, 1, 0, uint32(12000+i*1000), OBDPayload()); err != nil {
			return nil, fmt.Errorf("append OBD %d: %w", i, err)
		}
	}
	seg1 := append([]byte(nil), w1.Bytes()...)

	// Journal chain: independent, so it starts from a zero state (spec §3.2.1).
	wj := format.NewSegmentWriter(segHeader(deviceID, 0), format.ScanState{})
	for i := 0; i < opts.JournalEntries; i++ {
		if err := wj.Append(format.RecordStateTransition, 1, 0, uint32(i*500), make([]byte, 20)); err != nil {
			return nil, fmt.Errorf("append journal %d: %w", i, err)
		}
	}
	journal := append([]byte(nil), wj.Bytes()...)

	contents := map[string][]byte{
		"journal.seg":      journal,
		"seg-00000000.seg": seg0,
		"seg-00000001.seg": seg1,
	}

	members := make([]format.Member, 0, len(contents))
	for name, data := range contents {
		members = append(members, format.Member{
			Name:   name,
			Length: uint64(len(data)),
			SHA256: sha256.Sum256(data),
		})
	}
	format.SortMembers(members)

	// The bundle byte stream is members concatenated in canonical order.
	var stream []byte
	for _, m := range members {
		stream = append(stream, contents[m.Name]...)
	}

	var (
		chunks      [][]byte
		descriptors []format.ChunkDescriptor
	)
	for off := 0; off < len(stream); off += opts.ChunkSize {
		end := off + opts.ChunkSize
		if end > len(stream) {
			end = len(stream)
		}
		piece := append([]byte(nil), stream[off:end]...)
		chunks = append(chunks, piece)
		descriptors = append(descriptors, format.ChunkDescriptor{
			Index:      uint32(len(descriptors)),
			ByteLength: uint32(len(piece)),
			SHA256:     sha256.Sum256(piece),
		})
	}

	root, err := format.ContentRoot(members)
	if err != nil {
		return nil, err
	}

	// A real device assigns a fresh ULID per bundle. Deriving the synthetic one
	// from the content root gives distinct bundles distinct IDs, so a test that
	// builds two different bundles does not reuse one identifier for both.
	bundleID := syntheticBundleID(root)

	var bootID [16]byte
	for i := range bootID {
		bootID[i] = byte(0xA0 + i)
	}

	totalRecords := opts.GNSSSamples + opts.OBDSamples
	m := &format.Manifest{
		ManifestVersion:           format.ManifestVersion,
		BundleID:                  bundleID,
		DeviceID:                  deviceID,
		DeviceKeyID:               format.DeviceKeyID(pub),
		BootID:                    bootID,
		FirmwareVersion:           "cairn-v2.0.0-test",
		SchemaVersion:             1,
		CaptureStartedMonotonicUS: 1_000_000,
		CaptureEndedMonotonicUS:   20_000_000,
		UTCBasisMS:                1_790_000_000_000,
		UTCBasisAccMS:             250,
		FirstSeq:                  0,
		LastSeq:                   uint32(max(totalRecords-1, 0)),
		RecordCounts:              recordCounts(&opts),
		Members:                   members,
		ChunkDescriptors:          descriptors,
		ContentRoot:               root,
		PolicyVersion:             1,
		RecoveryState:             format.RecoveryClean,
		SignatureAlgorithm:        format.SignatureAlgorithmEd25519,
	}

	if opts.Mutate != nil {
		opts.Mutate(m)
	}

	encoded, sig, err := m.Sign(priv)
	if err != nil {
		return nil, fmt.Errorf("sign manifest: %w", err)
	}

	return &Bundle{
		ManifestBytes: encoded,
		Signature:     sig,
		Manifest:      m,
		Chunks:        chunks,
		Stream:        stream,
	}, nil
}

// syntheticBundleID derives a stable, content-distinct bundle ID.
//
// Deterministic, so a rebuilt bundle keeps its identity; distinct, so two
// bundles with different content never share one.
func syntheticBundleID(contentRoot [32]byte) [16]byte {
	h := sha256.New()
	h.Write([]byte("cairn-testbundle-id"))
	h.Write(contentRoot[:])

	var id [16]byte
	copy(id[:], h.Sum(nil)[:16])
	return id
}

// recordCounts tallies what was actually written, including any gap record.
func recordCounts(opts *Options) map[format.RecordType]uint32 {
	counts := map[format.RecordType]uint32{
		format.RecordGNSSSample:      uint32(opts.GNSSSamples),
		format.RecordOBDSnapshot:     uint32(opts.OBDSamples),
		format.RecordStateTransition: uint32(opts.JournalEntries),
	}
	if opts.GapAfter > 0 {
		counts[format.RecordGNSSGap] = 1
	}
	return counts
}

func segHeader(deviceID [16]byte, idx uint32) format.SegmentHeader {
	var boot [16]byte
	for i := range boot {
		boot[i] = byte(0xA0 + i)
	}
	return format.SegmentHeader{
		DeviceID:          deviceID,
		BootID:            boot,
		SegmentIndex:      idx,
		OpenedMonotonicUS: 1_000_000,
	}
}

// GNSSPayload builds a 32-byte GNSS sample with a 3D fix, per spec §4.1.
func GNSSPayload(i int) []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p[0:], uint32(int32(340_000_000+i*100)))
	binary.LittleEndian.PutUint32(p[4:], uint32(int32(-1_185_000_000+i*100)))
	binary.LittleEndian.PutUint32(p[8:], 5000)
	binary.LittleEndian.PutUint16(p[12:], 1200)
	binary.LittleEndian.PutUint16(p[14:], 9000)
	binary.LittleEndian.PutUint16(p[16:], 110)
	binary.LittleEndian.PutUint16(p[18:], 350)
	binary.LittleEndian.PutUint16(p[20:], 500)
	p[22] = 2  // 3D fix
	p[23] = 9  // satellites used
	p[24] = 14 // satellites visible
	p[25] = 0x01
	binary.LittleEndian.PutUint16(p[30:], 120)
	return p
}

// OBDPayload builds a 24-byte OBD snapshot with every value available.
func OBDPayload() []byte {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], uint16(int16(64)))   // 64 kph
	binary.LittleEndian.PutUint16(p[2:], uint16(int16(2100))) // 2100 rpm
	binary.LittleEndian.PutUint16(p[4:], 380)                 // fuel pressure
	p[6] = 22                                                 // throttle %
	p[7] = 41                                                 // engine load %
	p[8] = 88                                                 // coolant C
	p[9] = 31                                                 // intake C
	p[10] = 12                                                // timing advance
	p[11] = 0                                                 // no PID errors
	binary.LittleEndian.PutUint32(p[12:], 0x0F)               // requested
	binary.LittleEndian.PutUint32(p[16:], 0x0F)               // answered
	binary.LittleEndian.PutUint16(p[20:], 1000)               // actual cadence
	return p
}

// FixlessGNSSPayload builds a GNSS sample reporting no fix.
//
// Coordinates are zero and every accuracy field is the unknown sentinel, per
// the specification: a consumer must check fix_type rather than inferring
// validity from the coordinates, and must never invent a precision the receiver
// did not claim.
func FixlessGNSSPayload() []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint16(p[16:], 0xFFFF) // HDOP unknown
	binary.LittleEndian.PutUint16(p[18:], 0xFFFF) // horizontal accuracy unknown
	binary.LittleEndian.PutUint16(p[20:], 0xFFFF) // vertical accuracy unknown
	p[22] = 0                                     // no fix
	binary.LittleEndian.PutUint16(p[30:], 0xFFFF) // UTC uncertainty unknown
	return p
}

// GapPayload builds a 12-byte GNSS_GAP record (spec §4.8).
//
// A recorded absence. A decoder renders this as a discontinuity and must never
// join a route across it.
func GapPayload(durationMS uint32, expectedSamples uint16, cause uint8) []byte {
	p := make([]byte, 12)
	binary.LittleEndian.PutUint32(p[0:], durationMS)
	binary.LittleEndian.PutUint16(p[4:], expectedSamples)
	p[6] = cause
	return p
}
