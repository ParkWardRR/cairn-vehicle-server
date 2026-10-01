// Command mkvectors writes the bundle format v2 conformance vectors to
// fixtures/format-v2/.
//
// The vectors are the executable form of docs/bundle-format-v2.md. A
// conformance runner needs no knowledge of this implementation: each vector
// directory holds the input bytes and an expected.json stating the verdict and
// derived values, so the firmware (C) and emulator (Rust) implementations can
// be checked against the specification rather than against Go.
//
// Everything here is deterministic. Keys are derived from fixed seeds and all
// timestamps are constants, so regenerating the vectors produces byte-identical
// output and a clean diff.
//
//	go run ./cmd/mkvectors -out ../fixtures/format-v2
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ParkWardRR/Cairn/server/format"
)

// Fixed seeds. Deterministic vectors matter more than unpredictable keys here:
// these are test artifacts, never used to sign anything real.
var (
	deviceKeySeed = []byte("cairn-format-v2-device-key-seed!")
	serverKeySeed = []byte("cairn-format-v2-server-key-seed!")
)

const (
	fixedUTCBasisMS   = 1_790_000_000_000
	fixedIngestUTCMS  = 1_790_000_123_456
	fixedOpenedMonoUS = 1_000_000
)

// expectation is the machine-readable verdict for a vector.
type expectation struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Asserts     string `json:"asserts"`

	Scan     *scanExpectation     `json:"scan,omitempty"`
	Header   *headerExpectation   `json:"header,omitempty"`
	Manifest *manifestExpectation `json:"manifest,omitempty"`
	Receipt  *receiptExpectation  `json:"receipt,omitempty"`
	Merkle   *merkleExpectation   `json:"merkle,omitempty"`
}

type scanExpectation struct {
	StopReason         string         `json:"stop_reason"`
	FramesRetained     int            `json:"frames_retained"`
	StopOffset         int            `json:"stop_offset"`
	DiscardedTailBytes uint32         `json:"discarded_tail_bytes"`
	UnknownTypeCount   int            `json:"unknown_type_count"`
	RecordCounts       map[string]int `json:"record_counts"`
	FirstSeq           *uint32        `json:"first_seq,omitempty"`
	LastSeq            *uint32        `json:"last_seq,omitempty"`
}

type headerExpectation struct {
	ParseError string `json:"parse_error"`
	Note       string `json:"note"`
}

type manifestExpectation struct {
	Valid              bool   `json:"valid"`
	SignatureValid     bool   `json:"signature_valid"`
	ContentRootHex     string `json:"content_root_hex"`
	DevicePublicKeyHex string `json:"device_public_key_hex"`
	CanonicalBytesHex  string `json:"canonical_bytes_sha256_hex"`
}

type receiptExpectation struct {
	SignatureValid     bool   `json:"signature_valid"`
	Acknowledges       bool   `json:"acknowledges_uploaded_root"`
	UploadedRootHex    string `json:"uploaded_content_root_hex"`
	ReceiptRootHex     string `json:"receipt_content_root_hex"`
	ServerPublicKeyHex string `json:"server_public_key_hex"`
}

type merkleExpectation struct {
	RootHex string   `json:"root_hex"`
	Leaves  []string `json:"leaves_hex"`
	Note    string   `json:"note"`
}

func main() {
	out := flag.String("out", "../fixtures/format-v2", "output directory for the vectors")
	flag.Parse()

	if err := run(*out); err != nil {
		log.Fatal(err)
	}
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	devicePriv := ed25519.NewKeyFromSeed(deviceKeySeed)
	serverPriv := ed25519.NewKeyFromSeed(serverKeySeed)

	builders := []func(string, ed25519.PrivateKey, ed25519.PrivateKey) error{
		vectorValidMinimal,
		vectorValidMultiSegment,
		vectorTornTailMidFrame,
		vectorTornTailMidHeader,
		vectorBadFrameCRC,
		vectorChainBreakSpliced,
		vectorSeqGap,
		vectorBadHeaderCRC,
		vectorUnknownRecordType,
		vectorClockJump,
		vectorGNSSGap,
		vectorEmptySegment,
		vectorMaxFrame,
		vectorMerkleEmpty,
		vectorMerkleOddLeaves,
		vectorContentRootMemberOrder,
		vectorManifestValid,
		vectorManifestBadSignature,
		vectorReceiptValid,
		vectorReceiptWrongContentRoot,
	}

	for _, build := range builders {
		if err := build(outDir, devicePriv, serverPriv); err != nil {
			return err
		}
	}

	if err := writeIndex(outDir, len(builders)); err != nil {
		return err
	}

	fmt.Printf("wrote %d vectors to %s\n", len(builders), outDir)
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func writeVector(dir, name string, exp *expectation, files map[string][]byte) error {
	vdir := filepath.Join(dir, name)
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}

	for fname, data := range files {
		if err := os.WriteFile(filepath.Join(vdir, fname), data, 0o644); err != nil {
			return fmt.Errorf("write %s/%s: %w", name, fname, err)
		}
	}

	exp.Name = name
	encoded, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(filepath.Join(vdir, "expected.json"), encoded, 0o644)
}

func testHeader(segmentIndex uint32) format.SegmentHeader {
	var dev, boot [16]byte
	for i := range dev {
		dev[i] = byte(0x10 + i)
		boot[i] = byte(0xA0 + i)
	}
	return format.SegmentHeader{
		DeviceID:          dev,
		BootID:            boot,
		SegmentIndex:      segmentIndex,
		OpenedMonotonicUS: fixedOpenedMonoUS,
	}
}

func gnssPayload(latE7, lonE7 int32) []byte {
	p := make([]byte, 32)
	binary.LittleEndian.PutUint32(p[0:], uint32(latE7))
	binary.LittleEndian.PutUint32(p[4:], uint32(lonE7))
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

// buildSegment writes n 1 Hz GNSS samples.
func buildSegment(segmentIndex uint32, state format.ScanState, n int) (*format.SegmentWriter, error) {
	w := format.NewSegmentWriter(testHeader(segmentIndex), state)
	for i := 0; i < n; i++ {
		p := gnssPayload(int32(34_000_000+i*100), int32(-118_500_000+i*100))
		if err := w.Append(format.RecordGNSSSample, 1, 0, uint32(i*1000), p); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// scanExpect derives the expectation from the reference scanner. The reference
// implementation defines the expected verdict; the specification defines the
// reference implementation.
func scanExpect(b []byte, state format.ScanState) (*scanExpectation, error) {
	res, err := format.ScanSegment(b, state)
	if err != nil {
		return nil, err
	}

	counts := make(map[string]int, len(res.RecordCounts))
	for rt, n := range res.RecordCounts {
		counts[rt.String()] = n
	}

	exp := &scanExpectation{
		StopReason:         res.Stop.String(),
		FramesRetained:     len(res.Frames),
		StopOffset:         res.StopOffset,
		DiscardedTailBytes: res.DiscardedTailBytes,
		UnknownTypeCount:   res.UnknownTypeCount,
		RecordCounts:       counts,
	}
	if len(res.Frames) > 0 {
		first := res.Frames[0].Seq
		last := res.Frames[len(res.Frames)-1].Seq
		exp.FirstSeq = &first
		exp.LastSeq = &last
	}
	return exp, nil
}

func segmentFiles(b []byte) map[string][]byte {
	return map[string][]byte{"segment.bin": b}
}

// ─── segment vectors ────────────────────────────────────────────────────────

func vectorValidMinimal(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})
	types := []format.RecordType{
		format.RecordGNSSSample, format.RecordIMUSummary, format.RecordIMURawWindow,
		format.RecordOBDSnapshot, format.RecordDeviceHealth, format.RecordTripEvent,
		format.RecordStateTransition, format.RecordGNSSGap, format.RecordPolicySnapshot,
	}
	for i, rt := range types {
		if err := w.Append(rt, 1, 0, uint32(i*100), make([]byte, 16)); err != nil {
			return err
		}
	}

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "valid-minimal", &expectation{
		Description: "One frame of each defined record type, cleanly sealed.",
		Asserts:     "Every record type is parsed and the scan reaches EOF with nothing discarded.",
		Scan:        exp,
	}, segmentFiles(w.Bytes()))
}

func vectorValidMultiSegment(dir string, _, _ ed25519.PrivateKey) error {
	w0, err := buildSegment(0, format.ScanState{}, 5)
	if err != nil {
		return err
	}
	seg0 := append([]byte(nil), w0.Bytes()...)

	w1, err := buildSegment(1, w0.NextState(), 4)
	if err != nil {
		return err
	}
	seg1 := append([]byte(nil), w1.Bytes()...)

	exp0, err := scanExpect(seg0, format.ScanState{})
	if err != nil {
		return err
	}
	exp1, err := scanExpect(seg1, w0.NextState())
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"segment-0.bin": seg0,
		"segment-1.bin": seg1,
	}

	// Both segments' expectations, keyed so a runner can check each in turn.
	type multi struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Asserts     string            `json:"asserts"`
		Segments    []scanExpectation `json:"segments"`
		Note        string            `json:"note"`
	}

	encoded, err := json.MarshalIndent(multi{
		Name:        "valid-multi-segment",
		Description: "A bundle rotated across two segments.",
		Asserts: "Sequence numbers are contiguous across the rotation and the first frame of " +
			"segment 1 chains to the last frame of segment 0. Scanning segment 1 from the zero " +
			"state must report CHAIN_BREAK rather than silently accepting it.",
		Segments: []scanExpectation{*exp0, *exp1},
		Note:     "Scan segment-1.bin with the ScanState returned by segment-0.bin.",
	}, "", "  ")
	if err != nil {
		return err
	}

	vdir := filepath.Join(dir, "valid-multi-segment")
	if err := os.MkdirAll(vdir, 0o755); err != nil {
		return err
	}
	for fname, data := range files {
		if err := os.WriteFile(filepath.Join(vdir, fname), data, 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(vdir, "expected.json"), append(encoded, '\n'), 0o644)
}

func vectorTornTailMidFrame(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 10)
	if err != nil {
		return err
	}
	full := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	truncated := full[:len(full)-frameLen+20]

	exp, err := scanExpect(truncated, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "torn-tail-mid-frame", &expectation{
		Description: "Power cut 20 bytes into the final frame's payload.",
		Asserts: "TORN_TAIL. The nine complete frames are retained and exactly 20 bytes are " +
			"reported discarded. This is the expected outcome of a key-off during a write, not a defect.",
		Scan: exp,
	}, segmentFiles(truncated))
}

func vectorTornTailMidHeader(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 3)
	if err != nil {
		return err
	}
	full := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	truncated := full[:len(full)-frameLen+10]

	exp, err := scanExpect(truncated, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "torn-tail-mid-header", &expectation{
		Description: "Truncation leaving 10 bytes, too few to hold a 24-byte frame envelope.",
		Asserts:     "TORN_TAIL with 10 bytes discarded; the two complete frames survive.",
		Scan:        exp,
	}, segmentFiles(truncated))
}

func vectorBadFrameCRC(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 6)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	b[format.SegmentHeaderSize+3*frameLen+format.FrameHeaderSize+4] ^= 0x01

	exp, err := scanExpect(b, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "bad-frame-crc", &expectation{
		Description: "A single flipped payload bit inside frame index 3.",
		Asserts: "CORRUPT_FRAME at frame 3. The three preceding frames remain usable: " +
			"corruption is isolated to one record and does not invalidate earlier data.",
		Scan: exp,
	}, segmentFiles(b))
}

func vectorChainBreakSpliced(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 6)
	if err != nil {
		return err
	}
	full := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	cutStart := format.SegmentHeaderSize + 2*frameLen
	spliced := append([]byte{}, full[:cutStart]...)
	spliced = append(spliced, full[cutStart+frameLen:]...)

	exp, err := scanExpect(spliced, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "chain-break-spliced", &expectation{
		Description: "Frame index 2 excised from the middle of the segment.",
		Asserts: "CHAIN_BREAK. Every remaining frame is individually CRC-valid, so only " +
			"prev_crc32 can detect the splice. This is what the chain field exists for.",
		Scan: exp,
	}, segmentFiles(spliced))
}

func vectorSeqGap(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	f := format.Frame{
		RecordType:    format.RecordGNSSSample,
		SchemaVersion: 1,
		Seq:           5, // skips 1
		MonotonicMS:   1000,
		PrevCRC32:     w.NextState().ExpectedPrev,
		Payload:       gnssPayload(34_000_100, -118_499_900),
	}
	b, _, err := format.AppendFrame(b, &f)
	if err != nil {
		return err
	}

	exp, err := scanExpect(b, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "seq-gap", &expectation{
		Description: "A second frame declaring seq 5 instead of 1, with a correct prev_crc32.",
		Asserts: "SEQ_GAP. The chain is intact and the CRC is valid, so only the sequence " +
			"check can catch this.",
		Scan: exp,
	}, segmentFiles(b))
}

func vectorBadHeaderCRC(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 3)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)
	b[24] ^= 0xFF // corrupt boot_id, covered by the header CRC

	_, scanErr := format.ScanSegment(b, format.ScanState{})
	if scanErr == nil {
		return fmt.Errorf("bad-header-crc: expected a scan error")
	}

	return writeVector(dir, "bad-header-crc", &expectation{
		Description: "A corrupted boot_id byte in the segment header.",
		Asserts: "The header CRC fails, so the segment is unusable and frame parsing must not " +
			"be attempted. The segment must still not be deleted: unreadable by the device is not " +
			"the same as worthless, since the offline salvage tool may yet recover records.",
		Header: &headerExpectation{
			ParseError: "bad_header_crc",
			Note:       scanErr.Error(),
		},
	}, segmentFiles(b))
}

func vectorUnknownRecordType(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		return err
	}
	if err := w.Append(format.RecordType(0x7F), 1, 0, 1000, []byte("record from the future")); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 2000, gnssPayload(34_000_100, -118_499_900)); err != nil {
		return err
	}

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "unknown-record-type", &expectation{
		Description: "Record type 0x7F between two GNSS samples.",
		Asserts: "EOF, three frames retained, unknown_type_count 1. An unknown type is skipped " +
			"via frame_len, counted and reported — never an error. This is how a newer device stays " +
			"partially readable by an older decoder, and the frame CRC still applies.",
		Scan: exp,
	}, segmentFiles(w.Bytes()))
}

func vectorClockJump(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})

	var ahead int32 = 5_000
	forward := gnssPayload(34_000_000, -118_500_000)
	binary.LittleEndian.PutUint32(forward[26:], uint32(ahead))
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, forward); err != nil {
		return err
	}

	var behind int32 = -25_000
	backward := gnssPayload(34_000_100, -118_499_900)
	binary.LittleEndian.PutUint32(backward[26:], uint32(behind))
	binary.LittleEndian.PutUint16(backward[30:], 0xFFFF)
	if err := w.Append(format.RecordGNSSSample, 1, format.FlagEstimatedUTC, 1000, backward); err != nil {
		return err
	}

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "clock-jump", &expectation{
		Description: "A UTC estimate that jumps 30 seconds backwards while monotonic time advances.",
		Asserts: "EOF with both frames retained and the sequence undisturbed. Ordering truth is " +
			"(boot_id, seq); UTC is an annotation carrying its own uncertainty, so a jump is not " +
			"corruption. The affected sample carries FlagEstimatedUTC and utc_acc_ms 0xFFFF.",
		Scan: exp,
	}, segmentFiles(w.Bytes()))
}

func vectorGNSSGap(dir string, _, _ ed25519.PrivateKey) error {
	gap := make([]byte, 12)
	binary.LittleEndian.PutUint32(gap[0:], 42_000)
	binary.LittleEndian.PutUint16(gap[4:], 42)
	gap[6] = 4 // tunnel / obstruction

	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(34_000_000, -118_500_000)); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSGap, 1, 0, 1000, gap); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 43_000, gnssPayload(34_010_000, -118_490_000)); err != nil {
		return err
	}

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "gnss-gap", &expectation{
		Description: "A 42-second tunnel gap between two fixes 1.1 km apart.",
		Asserts: "The gap record is preserved verbatim. A decoder must render a discontinuity " +
			"and must never join the route across it — honest incompleteness over fabricated continuity.",
		Scan: exp,
	}, segmentFiles(w.Bytes()))
}

func vectorEmptySegment(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "empty-segment", &expectation{
		Description: "A valid 64-byte header with no frames.",
		Asserts:     "EOF, zero frames, nothing discarded. An empty segment is valid, not damaged.",
		Scan:        exp,
	}, segmentFiles(w.Bytes()))
}

func vectorMaxFrame(dir string, _, _ ed25519.PrivateKey) error {
	w := format.NewSegmentWriter(testHeader(0), format.ScanState{})
	if err := w.Append(format.RecordIMURawWindow, 1, 0, 0, make([]byte, format.MaxPayloadSize)); err != nil {
		return err
	}

	exp, err := scanExpect(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "max-frame", &expectation{
		Description: fmt.Sprintf("One frame at the maximum length of %d bytes.", format.MaxFrameLen),
		Asserts: fmt.Sprintf("A frame_len of %d is accepted; %d must be rejected as a torn tail "+
			"rather than trusted, and a frame_len below %d must also be rejected so a scan cannot "+
			"make zero progress.", format.MaxFrameLen, format.MaxFrameLen+1, format.MinFrameLen),
		Scan: exp,
	}, segmentFiles(w.Bytes()))
}

// ─── merkle vectors ─────────────────────────────────────────────────────────

func vectorMerkleEmpty(dir string, _, _ ed25519.PrivateKey) error {
	root := format.MerkleRoot(nil)
	return writeVector(dir, "merkle-empty", &expectation{
		Description: "The empty Merkle tree.",
		Asserts:     "Root is SHA256(0x02), a third domain tag distinct from leaves and internal nodes.",
		Merkle: &merkleExpectation{
			RootHex: hex.EncodeToString(root[:]),
			Leaves:  []string{},
			Note:    "An empty tree must not collide with a tree holding one empty leaf.",
		},
	}, nil)
}

func vectorMerkleOddLeaves(dir string, _, _ ed25519.PrivateKey) error {
	leaves := [][32]byte{
		format.LeafHash([]byte("a")),
		format.LeafHash([]byte("b")),
		format.LeafHash([]byte("c")),
	}
	root := format.MerkleRoot(leaves)

	hexLeaves := make([]string, len(leaves))
	for i, l := range leaves {
		hexLeaves[i] = hex.EncodeToString(l[:])
	}

	return writeVector(dir, "merkle-odd-leaves", &expectation{
		Description: "Three leaves, so one level has an odd node count.",
		Asserts: "The final node is promoted unchanged: root = internal(internal(a,b), c). " +
			"It must not be duplicated — duplication would make the leaf lists [a,b,c] and " +
			"[a,b,c,c] share a root, which is a second-preimage weakness.",
		Merkle: &merkleExpectation{
			RootHex: hex.EncodeToString(root[:]),
			Leaves:  hexLeaves,
			Note:    "leaf(d) = SHA256(0x00||d); internal(l,r) = SHA256(0x01||l||r).",
		},
	}, nil)
}

func vectorContentRootMemberOrder(dir string, _, _ ed25519.PrivateKey) error {
	members := sampleMembers()
	root, err := format.ContentRoot(members)
	if err != nil {
		return err
	}

	permuted := []format.Member{members[2], members[0], members[1]}
	permutedRoot, err := format.ContentRoot(permuted)
	if err != nil {
		return err
	}
	if permutedRoot != root {
		return fmt.Errorf("content root is not order-independent")
	}

	descriptor, err := json.MarshalIndent(membersJSON(members), "", "  ")
	if err != nil {
		return err
	}

	return writeVector(dir, "content-root-member-order", &expectation{
		Description: "Three bundle members supplied in a non-canonical order.",
		Asserts: "Members are sorted by raw name bytes ascending before hashing, so a permuted " +
			"input yields the same content root. Identity depends on content, not on the order a " +
			"directory happened to be walked in. Changing any member's name or digest must change the root.",
		Merkle: &merkleExpectation{
			RootHex: hex.EncodeToString(root[:]),
			Note:    "leaf_input = u16le(len(name)) || name || sha256(contents).",
		},
	}, map[string][]byte{"members.json": append(descriptor, '\n')})
}

func sampleMembers() []format.Member {
	return []format.Member{
		{Name: "seg-00000000.seg", Length: 4096, SHA256: sha256.Sum256([]byte("seg0"))},
		{Name: "seg-00000001.seg", Length: 2048, SHA256: sha256.Sum256([]byte("seg1"))},
		{Name: "journal.seg", Length: 512, SHA256: sha256.Sum256([]byte("journal"))},
	}
}

func membersJSON(members []format.Member) []map[string]any {
	out := make([]map[string]any, len(members))
	for i, m := range members {
		out[i] = map[string]any{
			"name":       m.Name,
			"length":     m.Length,
			"sha256_hex": hex.EncodeToString(m.SHA256[:]),
		}
	}
	return out
}

// ─── manifest and receipt vectors ───────────────────────────────────────────

func sampleManifest() (*format.Manifest, error) {
	members := sampleMembers()
	root, err := format.ContentRoot(members)
	if err != nil {
		return nil, err
	}

	var bundleID, deviceID, bootID [16]byte
	for i := range bundleID {
		bundleID[i] = byte(i)
		deviceID[i] = byte(0x10 + i)
		bootID[i] = byte(0xA0 + i)
	}
	prev := sha256.Sum256([]byte("previous bundle"))

	return &format.Manifest{
		ManifestVersion:           format.ManifestVersion,
		BundleID:                  bundleID,
		DeviceID:                  deviceID,
		DeviceKeyID:               format.DeviceKeyID(ed25519.NewKeyFromSeed(deviceKeySeed).Public().(ed25519.PublicKey)),
		BootID:                    bootID,
		FirmwareVersion:           "cairn-v2.0.0",
		SchemaVersion:             1,
		CaptureStartedMonotonicUS: fixedOpenedMonoUS,
		CaptureEndedMonotonicUS:   1_800_000_000,
		UTCBasisMS:                fixedUTCBasisMS,
		UTCBasisAccMS:             250,
		FirstSeq:                  0,
		LastSeq:                   1799,
		RecordCounts: map[format.RecordType]uint32{
			format.RecordGNSSSample:      1500,
			format.RecordIMUSummary:      280,
			format.RecordOBDSnapshot:     15,
			format.RecordStateTransition: 4,
		},
		Members: members,
		ChunkDescriptors: []format.ChunkDescriptor{
			{Index: 0, ByteLength: 4096, SHA256: sha256.Sum256([]byte("chunk0"))},
			{Index: 1, ByteLength: 2560, SHA256: sha256.Sum256([]byte("chunk1"))},
		},
		ContentRoot:        root,
		PreviousBundleRoot: &prev,
		PolicyVersion:      3,
		RecoveryState:      format.RecoveryClean,
		DiscardedTailBytes: 0,
		SignatureAlgorithm: format.SignatureAlgorithmEd25519,
	}, nil
}

func vectorManifestValid(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}

	encoded, sig, err := m.Sign(devicePriv)
	if err != nil {
		return err
	}
	pub := devicePriv.Public().(ed25519.PublicKey)
	digest := sha256.Sum256(encoded)

	return writeVector(dir, "manifest-valid", &expectation{
		Description: "A correctly signed, canonically encoded manifest.",
		Asserts: "The deterministic CBOR encoding is reproducible byte-for-byte across " +
			"implementations, and the signature covers exactly the bytes of manifest.cbor with " +
			"nothing to strip or re-encode. An implementation that produces different bytes for " +
			"this logical manifest is non-conformant.",
		Manifest: &manifestExpectation{
			Valid:              true,
			SignatureValid:     true,
			ContentRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			DevicePublicKeyHex: hex.EncodeToString(pub),
			CanonicalBytesHex:  hex.EncodeToString(digest[:]),
		},
	}, map[string][]byte{
		"manifest.cbor": encoded,
		"manifest.sig":  sig,
	})
}

func vectorManifestBadSignature(dir string, devicePriv, _ ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}

	encoded, sig, err := m.Sign(devicePriv)
	if err != nil {
		return err
	}
	bad := append([]byte(nil), sig...)
	bad[0] ^= 0x01

	pub := devicePriv.Public().(ed25519.PublicKey)

	return writeVector(dir, "manifest-bad-signature", &expectation{
		Description: "A valid manifest whose signature has one flipped bit.",
		Asserts:     "Verification fails. The manifest bytes themselves are well-formed, so only the signature check rejects it.",
		Manifest: &manifestExpectation{
			Valid:              true,
			SignatureValid:     false,
			ContentRootHex:     hex.EncodeToString(m.ContentRoot[:]),
			DevicePublicKeyHex: hex.EncodeToString(pub),
		},
	}, map[string][]byte{
		"manifest.cbor": encoded,
		"manifest.sig":  bad,
	})
}

func vectorReceiptValid(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}

	r := sampleReceipt(m.ContentRoot)
	encoded, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	pub := serverPriv.Public().(ed25519.PublicKey)

	return writeVector(dir, "receipt-valid", &expectation{
		Description: "A receipt acknowledging the manifest-valid bundle.",
		Asserts: "The signature verifies against the pinned server key and the content root " +
			"matches what was uploaded. Both conditions are required before any byte may be pruned.",
		Receipt: &receiptExpectation{
			SignatureValid:     true,
			Acknowledges:       true,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ReceiptRootHex:     hex.EncodeToString(r.ContentRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		},
	}, map[string][]byte{"receipt.cbor": encoded})
}

func vectorReceiptWrongContentRoot(dir string, _, serverPriv ed25519.PrivateKey) error {
	m, err := sampleManifest()
	if err != nil {
		return err
	}

	otherRoot := sha256.Sum256([]byte("some other bundle"))
	r := sampleReceipt(otherRoot)
	encoded, err := r.Sign(serverPriv)
	if err != nil {
		return err
	}
	pub := serverPriv.Public().(ed25519.PublicKey)

	return writeVector(dir, "receipt-wrong-content-root", &expectation{
		Description: "A genuinely signed receipt that acknowledges a different bundle.",
		Asserts: "The signature verifies, but the receipt must still be rejected as an " +
			"acknowledgement of this upload. Accepting it would let a misconfigured or hostile " +
			"server induce deletion of data it never received.",
		Receipt: &receiptExpectation{
			SignatureValid:     true,
			Acknowledges:       false,
			UploadedRootHex:    hex.EncodeToString(m.ContentRoot[:]),
			ReceiptRootHex:     hex.EncodeToString(otherRoot[:]),
			ServerPublicKeyHex: hex.EncodeToString(pub),
		},
	}, map[string][]byte{"receipt.cbor": encoded})
}

func sampleReceipt(contentRoot [32]byte) *format.Receipt {
	var receiptID, deviceID, bundleID [16]byte
	for i := range receiptID {
		receiptID[i] = byte(0x40 + i)
		deviceID[i] = byte(0x10 + i)
		bundleID[i] = byte(i)
	}

	return &format.Receipt{
		ReceiptVersion:      format.ReceiptVersion,
		ReceiptID:           receiptID,
		DeviceID:            deviceID,
		BundleID:            bundleID,
		ContentRoot:         contentRoot,
		ServerIngestUTCMS:   fixedIngestUTCMS,
		ServerKeyID:         [8]byte{9, 8, 7, 6, 5, 4, 3, 2},
		IngestSchemaVersion: 1,
		StoredObjectIDs:     []string{"cas/ab/abcdef0123", "cas/cd/cdef456789"},
		SignatureAlgorithm:  format.SignatureAlgorithmEd25519,
	}
}

// ─── index ──────────────────────────────────────────────────────────────────

func writeIndex(dir string, count int) error {
	readme := fmt.Sprintf(`# Bundle format v2 conformance vectors

Generated by `+"`server/cmd/mkvectors`"+`. Do not edit by hand — regenerate with:

    cd server && go run ./cmd/mkvectors -out ../fixtures/format-v2

%d vectors. Each directory holds the input bytes plus an `+"`expected.json`"+`
stating the verdict and derived values. A conformance runner needs no knowledge
of any particular implementation: the inputs and expectations together define
the behaviour that docs/bundle-format-v2.md specifies.

An implementation is conformant when it produces the stated verdict for every
vector, and byte-identical output for the encoding vectors.

Generation is deterministic. Keys come from fixed seeds and every timestamp is a
constant, so regenerating produces an empty diff. The keys are test artifacts
and never sign anything real.

## Reading a vector

| File | Meaning |
|---|---|
| `+"`segment.bin`"+` | A segment to scan. Start with the zero ScanState unless the expectation says otherwise. |
| `+"`segment-N.bin`"+` | Multi-segment vectors. Scan in order, threading each scan's resulting state into the next. |
| `+"`manifest.cbor`"+` / `+"`manifest.sig`"+` | Deterministic CBOR manifest and its detached Ed25519 signature. |
| `+"`receipt.cbor`"+` | A server receipt, signature inline at key 11. |
| `+"`members.json`"+` | Member list for content-root vectors. |
| `+"`expected.json`"+` | The verdict. |

## Stop reasons

| Reason | Meaning |
|---|---|
| `+"`EOF`"+` | Clean: the whole segment parsed. |
| `+"`TORN_TAIL`"+` | Ends mid-frame. Expected after a power cut; frames before the tear are retained. |
| `+"`CORRUPT_FRAME`"+` | A frame CRC mismatched. Corruption is isolated to that frame. |
| `+"`CHAIN_BREAK`"+` | prev_crc32 did not match: a record was removed, reordered or spliced. |
| `+"`SEQ_GAP`"+` | The sequence number skipped a value. |
`, count)

	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644)
}
