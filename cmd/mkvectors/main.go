// Command mkvectors writes the bundle format v3 conformance vectors to
// contracts/format/v3/vectors/.
//
// The vectors are the executable form of contracts/format/v3/spec.md. A
// conformance runner needs no knowledge of this implementation: each vector
// directory holds the input bytes and an expected.json stating the verdict and
// derived values, so the firmware (C) and emulator (Rust) implementations can
// be checked against the specification rather than against Go.
//
// Everything here is deterministic. Keys are derived from fixed seeds, all
// timestamps are constants, and frame nonces come from a fixed per-writer
// stream instead of the hardware RNG, so regenerating the vectors produces
// byte-identical output and a clean diff.
//
// THE KEYS IN THESE VECTORS ARE PUBLIC TEST KEYS. They are published in the
// repository and in contracts/format/v3/vectors/README.md. They protect nothing and must
// never be provisioned onto a device or loaded into a real keystore.
//
//	go run ./cmd/mkvectors                       # into $CAIRN_CONTRACTS/format/v3/vectors
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/ParkWardRR/Cairn/server/internal/contracts"
	"log"
	"os"
	"path/filepath"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/testbundle"
)

// Fixed seeds. Deterministic vectors matter more than unpredictable keys here:
// these are test artifacts, never used to sign anything real.
var (
	deviceKeySeed = []byte("cairn-format-v3-device-key-seed!")
	// A third fixed seed for the OTA update key, kept separate from both the
	// device and server keys because the authority it carries is different: it
	// says "this code is safe to run" rather than "this data is mine" or "this
	// data is safe to delete".
	updateKeySeed = []byte("cairn-format-v3-update-key-seed!")
	serverKeySeed = []byte("cairn-format-v3-server-key-seed!")
)

const (
	fixedUTCBasisMS   = 1_790_000_000_000
	fixedIngestUTCMS  = 1_790_000_123_456
	fixedOpenedMonoUS = 1_000_000

	// Binding fields every vector segment and manifest carries.
	vectorDeviceCounter = 42
	vectorKeyVersion    = 1
	altKeyVersion       = 2
)

// The storage roots. Derived from a label so the value is reproducible and
// obviously not random; published in keys.json and the README.
var (
	rootKey    = sha256.Sum256([]byte("cairn-format-v3-test-storage-root-v1 -- PUBLIC TEST KEY"))
	altRootKey = sha256.Sum256([]byte("cairn-format-v3-test-storage-root-v2 -- PUBLIC TEST KEY"))
)

// keys is the provider a conformance verifier is given: root version 1 only.
var keys = &format.RootKeyProvider{Root: rootKey, Version: vectorKeyVersion}

// expectation is the machine-readable verdict for a vector.
type expectation struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Asserts     string `json:"asserts"`

	Scan     *scanExpectation       `json:"scan,omitempty"`
	Keyed    *keyedExpectation      `json:"keyed,omitempty"`
	Binding  *bindingExpectation    `json:"binding,omitempty"`
	Header   *headerExpectation     `json:"header,omitempty"`
	Manifest *manifestExpectation   `json:"manifest,omitempty"`
	Receipt  *receiptExpectation    `json:"receipt,omitempty"`
	Merkle   *merkleExpectation     `json:"merkle,omitempty"`
	Policy   *format.PolicySnapshot `json:"policy,omitempty"`
	Events   *eventsExpectation     `json:"events,omitempty"`
	Health   *healthExpectation     `json:"health,omitempty"`
	Update   *updateExpectation     `json:"update,omitempty"`
	OBDExt   *obdExtExpectation     `json:"obd_ext,omitempty"`
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

// keyedExpectation is the verdict of the same segment scanned with the vector
// key (root version 1). The structural verdict above is what a holder of no key
// sees; this is what the key adds.
//
// Either Error is set (the segment could not even be keyed) or the scan fields
// are. SegmentKeyHex is the derived K_seg for the header as it appears in the
// file, which lets an implementation check its HKDF independently of its AEAD.
type keyedExpectation struct {
	Error              string `json:"error,omitempty"`
	SegmentKeyHex      string `json:"segment_key_hex,omitempty"`
	StopReason         string `json:"stop_reason,omitempty"`
	FramesRetained     *int   `json:"frames_retained,omitempty"`
	StopOffset         *int   `json:"stop_offset,omitempty"`
	PlaintextSHA256Hex string `json:"plaintext_sha256_hex,omitempty"`
}

// bindingExpectation is the verdict of checking the segments in a vector
// against its manifest (VerifyMembersAgainstManifest).
type bindingExpectation struct {
	Match bool   `json:"match"`
	Field string `json:"mismatched_field,omitempty"`
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

type expectedEvent struct {
	EventType     uint8  `json:"event_type"`
	EventTypeName string `json:"event_type_name"`
	LatE7         int32  `json:"lat_e7"`
	LonE7         int32  `json:"lon_e7"`
	Detail        string `json:"detail"`
}

type eventsExpectation struct {
	Events []expectedEvent `json:"events"`
	Note   string          `json:"note"`
}

type expectedHealth struct {
	HealthState uint8    `json:"health_state"`
	Names       []string `json:"names"`
}

type healthExpectation struct {
	Records []expectedHealth `json:"records"`
	Note    string           `json:"note"`
}

type updateExpectation struct {
	SignatureValid     bool   `json:"signature_valid"`
	FirmwareVersion    string `json:"firmware_version"`
	MinFirmwareVersion string `json:"min_firmware_version"`
	ImageSHA256Hex     string `json:"image_sha256_hex"`
	ImageLength        uint32 `json:"image_length"`
	UpdateKeyHex       string `json:"update_public_key_hex"`
	Note               string `json:"note"`
}

type merkleExpectation struct {
	RootHex string   `json:"root_hex"`
	Leaves  []string `json:"leaves_hex"`
	Note    string   `json:"note"`
}

type expectedOBDExt struct {
	MAPkPa           *uint16  `json:"map_kpa"`
	MAFcgps          *uint16  `json:"maf_cgps"`
	LambdaE4         *uint16  `json:"lambda_e4"`
	AbsLoadRaw       *uint16  `json:"abs_load_raw"`
	BaroKPa          *uint8   `json:"baro_kpa"`
	AmbientTempC     *int8    `json:"ambient_temp_c"`
	FuelTrimShortPct *int8    `json:"fuel_trim_short_pct"`
	FuelTrimLongPct  *int8    `json:"fuel_trim_long_pct"`
	PIDsRequested    uint32   `json:"pids_requested"`
	PIDsAnswered     uint32   `json:"pids_answered"`
	PollCadenceMS    uint16   `json:"poll_cadence_ms"`
	MAPSaturated     bool     `json:"map_saturated"`
	BoostPSI         *float64 `json:"boost_psi,omitempty"`
	Lambda           *float64 `json:"lambda,omitempty"`
	AbsLoadPct       *float64 `json:"abs_load_pct,omitempty"`
}

type obdExtExpectation struct {
	Records []expectedOBDExt `json:"records"`
	Note    string           `json:"note"`
}

func main() {
	out := flag.String("out", "", "output directory for the vectors (default: $CAIRN_CONTRACTS/format/v3/vectors)")
	flag.Parse()
	if *out == "" {
		*out = contracts.Vectors("format", "v3")
	}

	if err := run(*out); err != nil {
		log.Fatal(err)
	}
}

type builder struct {
	name string
	fn   func(string, ed25519.PrivateKey, ed25519.PrivateKey) error
}

func run(outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	devicePriv := ed25519.NewKeyFromSeed(deviceKeySeed)
	serverPriv := ed25519.NewKeyFromSeed(serverKeySeed)

	// The name labels each vector's nonce streams, so adding or reordering a
	// vector never changes the bytes of another.
	builders := []builder{
		{"valid-minimal", vectorValidMinimal},
		{"valid-multi-segment", vectorValidMultiSegment},
		{"journal-segment", vectorJournalSegment},
		{"torn-tail-mid-frame", vectorTornTailMidFrame},
		{"torn-tail-mid-header", vectorTornTailMidHeader},
		{"bad-frame-crc", vectorBadFrameCRC},
		{"chain-break-spliced", vectorChainBreakSpliced},
		{"seq-gap", vectorSeqGap},
		{"bad-header-crc", vectorBadHeaderCRC},
		{"auth-tag-tampered", vectorAuthTagTampered},
		{"frame-moved-between-segments", vectorFrameMoved},
		{"wrong-vehicle-key", vectorWrongVehicleKey},
		{"wrong-key-version", vectorWrongKeyVersion},
		{"unknown-record-type", vectorUnknownRecordType},
		{"clock-jump", vectorClockJump},
		{"gnss-gap", vectorGNSSGap},
		{"empty-segment", vectorEmptySegment},
		{"max-frame", vectorMaxFrame},
		{"merkle-empty", vectorMerkleEmpty},
		{"merkle-odd-leaves", vectorMerkleOddLeaves},
		{"content-root-member-order", vectorContentRootMemberOrder},
		{"manifest-valid", vectorManifestValid},
		{"manifest-bad-signature", vectorManifestBadSignature},
		{"manifest-members-match", vectorManifestMembersMatch},
		{"manifest-segment-header-mismatch", vectorManifestSegmentMismatch},
		{"receipt-valid", vectorReceiptValid},
		{"receipt-wrong-content-root", vectorReceiptWrongContentRoot},
		{"policy-snapshot", vectorPolicySnapshot},
		{"trip-event-types", vectorTripEventTypes},
		{"health-bitmap", vectorHealthBitmap},
		{"obd-extended", vectorOBDExtended},
		{"update-descriptor-valid", vectorUpdateDescriptorValid},
		{"update-descriptor-bad-signature", vectorUpdateDescriptorBadSignature},
	}

	for _, b := range builders {
		vecName, writerSeq = b.name, 0
		if err := b.fn(outDir, devicePriv, serverPriv); err != nil {
			return fmt.Errorf("%s: %w", b.name, err)
		}
	}

	if err := writeKeys(outDir); err != nil {
		return err
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
	var dev, boot, veh, asg [16]byte
	for i := range dev {
		dev[i] = byte(0x10 + i)
		boot[i] = byte(0xA0 + i)
		veh[i] = byte(0x30 + i)
		asg[i] = byte(0x50 + i)
	}
	return format.SegmentHeader{
		DeviceID:          dev,
		BootID:            boot,
		VehicleID:         veh,
		AssignmentID:      asg,
		SegmentIndex:      segmentIndex,
		OpenedMonotonicUS: fixedOpenedMonoUS,
		StorageKeyVersion: vectorKeyVersion,
		DeviceCounter:     vectorDeviceCounter,
	}
}

// vecName and writerSeq label the nonce stream of each writer: the vector it
// belongs to and its ordinal within it. Together they make every writer's
// nonces unique and independent of every other vector.
var (
	vecName   string
	writerSeq int
)

// newWriter starts a segment under the vector key with deterministic nonces.
func newWriter(h format.SegmentHeader, state format.ScanState) (*format.SegmentWriter, error) {
	writerSeq++
	label := fmt.Sprintf("%s/%d", vecName, writerSeq)
	return format.NewSegmentWriter(h, state, keys, testbundle.NonceReader(label))
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
	w, err := newWriter(testHeader(segmentIndex), state)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		p := gnssPayload(int32(340_000_000+i*100), int32(-1_185_000_000+i*100))
		if err := w.Append(format.RecordGNSSSample, 1, 0, uint32(i*1000), p); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// scanExpect derives the structural expectation from the reference scanner:
// what a holder of no key sees. The reference implementation defines the
// expected verdict; the specification defines the reference implementation.
func scanExpect(b []byte, state format.ScanState) (*scanExpectation, error) {
	res, err := format.ScanSegment(b, state, nil)
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

// keyedExpect scans with the vector key and records the verdict. A segment the
// provider cannot key is an expected outcome for some vectors, so it is recorded
// as a named error instead of failing generation.
func keyedExpect(b []byte, state format.ScanState) (*keyedExpectation, error) {
	out := &keyedExpectation{}

	res, err := format.ScanSegment(b, state, keys)
	switch {
	case errors.Is(err, format.ErrKeyVersionMismatch):
		out.Error = "KEY_VERSION_MISMATCH"
		return out, nil
	case errors.Is(err, format.ErrNoKey):
		out.Error = "NO_KEY"
		return out, nil
	case err != nil:
		return nil, err
	}

	// Only reported when the verifier can actually key the segment: a key it was
	// refused is not one a conformance runner should be checking against.
	k, err := format.DeriveSegmentKey(rootKey, &res.Header)
	if err != nil {
		return nil, err
	}
	out.SegmentKeyHex = hex.EncodeToString(k[:])

	n := len(res.Frames)
	out.StopReason = res.Stop.String()
	out.FramesRetained = &n
	out.StopOffset = &res.StopOffset

	// Digest over each retained plaintext as u32le(len) || payload, so an
	// implementation proves it decrypted every frame to the exact bytes without
	// the vector carrying the plaintext twice.
	h := sha256.New()
	for i := range res.Frames {
		var l [4]byte
		binary.LittleEndian.PutUint32(l[:], uint32(len(res.Frames[i].Payload)))
		h.Write(l[:])
		h.Write(res.Frames[i].Payload)
	}
	out.PlaintextSHA256Hex = hex.EncodeToString(h.Sum(nil))
	return out, nil
}

// scanBoth derives the structural and keyed expectations together.
func scanBoth(b []byte, state format.ScanState) (*scanExpectation, *keyedExpectation, error) {
	exp, err := scanExpect(b, state)
	if err != nil {
		return nil, nil, err
	}
	keyed, err := keyedExpect(b, state)
	if err != nil {
		return nil, nil, err
	}
	return exp, keyed, nil
}

func segmentFiles(b []byte) map[string][]byte {
	return map[string][]byte{"segment.bin": b}
}

// ─── segment vectors ────────────────────────────────────────────────────────

func vectorValidMinimal(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}
	types := []format.RecordType{
		format.RecordGNSSSample, format.RecordIMUSummary, format.RecordIMURawWindow,
		format.RecordOBDSnapshot, format.RecordDeviceHealth, format.RecordTripEvent,
		format.RecordStateTransition, format.RecordGNSSGap, format.RecordPolicySnapshot,
		format.RecordOBDExtended,
	}
	for i, rt := range types {
		if err := w.Append(rt, 1, 0, uint32(i*100), make([]byte, 16)); err != nil {
			return err
		}
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "valid-minimal", &expectation{
		Description: "One frame of each defined record type, cleanly sealed.",
		Asserts:     "Every record type is parsed and the scan reaches EOF with nothing discarded.",
		Scan:        exp,
		Keyed:       keyed,
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

	exp0, keyed0, err := scanBoth(seg0, format.ScanState{})
	if err != nil {
		return err
	}
	exp1, keyed1, err := scanBoth(seg1, w0.NextState())
	if err != nil {
		return err
	}
	// Keyed scanning of segment 1 from the zero state must also break the chain;
	// the structural verdict is recorded for that so a runner can check it.
	expZero, _, err := scanBoth(seg1, format.ScanState{})
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"segment-0.bin": seg0,
		"segment-1.bin": seg1,
	}

	// Both segments' expectations, keyed so a runner can check each in turn.
	type multi struct {
		Name              string             `json:"name"`
		Description       string             `json:"description"`
		Asserts           string             `json:"asserts"`
		Segments          []scanExpectation  `json:"segments"`
		Keyed             []keyedExpectation `json:"keyed"`
		Segment1ZeroState scanExpectation    `json:"segment_1_from_zero_state"`
		Note              string             `json:"note"`
	}

	encoded, err := json.MarshalIndent(multi{
		Name:        "valid-multi-segment",
		Description: "A bundle rotated across two segments.",
		Asserts: "Sequence numbers are contiguous across the rotation and the first frame of " +
			"segment 1 chains to the last frame of segment 0. Scanning segment 1 from the zero " +
			"state must report CHAIN_BREAK rather than silently accepting it.",
		Segments:          []scanExpectation{*exp0, *exp1},
		Keyed:             []keyedExpectation{*keyed0, *keyed1},
		Segment1ZeroState: *expZero,
		Note:              "Scan segment-1.bin with the ScanState returned by segment-0.bin.",
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

	exp, keyed, err := scanBoth(truncated, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "torn-tail-mid-frame", &expectation{
		Description: "Power cut 20 bytes into the final frame (inside its nonce).",
		Asserts: "TORN_TAIL. The nine complete frames are retained and exactly 20 bytes are " +
			"reported discarded. This is the expected outcome of a key-off during a write, not a defect.",
		Scan:  exp,
		Keyed: keyed,
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

	exp, keyed, err := scanBoth(truncated, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "torn-tail-mid-header", &expectation{
		Description: "Truncation leaving 10 bytes of the final frame, too few to hold a frame (minimum 68 bytes).",
		Asserts:     "TORN_TAIL with 10 bytes discarded; the two complete frames survive.",
		Scan:        exp,
		Keyed:       keyed,
	}, segmentFiles(truncated))
}

func vectorBadFrameCRC(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 6)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	frameLen := format.FrameOverhead + 32
	b[format.SegmentHeaderSize+3*frameLen+format.FrameHeaderSize+format.NonceSize+4] ^= 0x01

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "bad-frame-crc", &expectation{
		Description: "A single flipped ciphertext bit inside frame index 3. The CRC is not repaired.",
		Asserts: "CORRUPT_FRAME at frame 3. The three preceding frames remain usable: " +
			"corruption is isolated to one record and does not invalidate earlier data.",
		Scan:  exp,
		Keyed: keyed,
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

	exp, keyed, err := scanBoth(spliced, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "chain-break-spliced", &expectation{
		Description: "Frame index 2 excised from the middle of the segment.",
		Asserts: "CHAIN_BREAK. Every remaining frame is individually CRC-valid, so only " +
			"prev_crc32 can detect the splice. This is what the chain field exists for.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(spliced))
}

func vectorSeqGap(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(340_000_000, -1_185_000_000)); err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)

	f := format.Frame{
		RecordType:    format.RecordGNSSSample,
		SchemaVersion: 1,
		Seq:           5, // skips 1
		MonotonicMS:   1000,
		PrevCRC32:     w.NextState().ExpectedPrev,
		Payload:       gnssPayload(340_000_100, -1_184_999_900),
	}
	b, _, err = format.AppendFrame(b, &f, w.Cipher())
	if err != nil {
		return err
	}

	exp, keyed, err := scanBoth(b, format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "seq-gap", &expectation{
		Description: "A second frame declaring seq 5 instead of 1, with a correct prev_crc32.",
		Asserts: "SEQ_GAP. The chain is intact and the CRC is valid, so only the sequence " +
			"check can catch this.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(b))
}

func vectorBadHeaderCRC(dir string, _, _ ed25519.PrivateKey) error {
	w, err := buildSegment(0, format.ScanState{}, 3)
	if err != nil {
		return err
	}
	b := append([]byte(nil), w.Bytes()...)
	b[24] ^= 0xFF // corrupt boot_id, covered by the header CRC (and by every frame's AAD)

	_, scanErr := format.ScanSegment(b, format.ScanState{}, keys)
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
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(340_000_000, -1_185_000_000)); err != nil {
		return err
	}
	if err := w.Append(format.RecordType(0x7F), 1, 0, 1000, []byte("record from the future")); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 2000, gnssPayload(340_000_100, -1_184_999_900)); err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "unknown-record-type", &expectation{
		Description: "Record type 0x7F between two GNSS samples.",
		Asserts: "EOF, three frames retained, unknown_type_count 1. An unknown type is skipped " +
			"via frame_len, counted and reported — never an error. This is how a newer device stays " +
			"partially readable by an older decoder, and the frame CRC still applies.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(w.Bytes()))
}

func vectorClockJump(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}

	var ahead int32 = 5_000
	forward := gnssPayload(340_000_000, -1_185_000_000)
	binary.LittleEndian.PutUint32(forward[26:], uint32(ahead))
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, forward); err != nil {
		return err
	}

	var behind int32 = -25_000
	backward := gnssPayload(340_000_100, -1_184_999_900)
	binary.LittleEndian.PutUint32(backward[26:], uint32(behind))
	binary.LittleEndian.PutUint16(backward[30:], 0xFFFF)
	if err := w.Append(format.RecordGNSSSample, 1, format.FlagEstimatedUTC, 1000, backward); err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "clock-jump", &expectation{
		Description: "A UTC estimate that jumps 30 seconds backwards while monotonic time advances.",
		Asserts: "EOF with both frames retained and the sequence undisturbed. Ordering truth is " +
			"(boot_id, seq); UTC is an annotation carrying its own uncertainty, so a jump is not " +
			"corruption. The affected sample carries FlagEstimatedUTC and utc_acc_ms 0xFFFF.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(w.Bytes()))
}

func vectorGNSSGap(dir string, _, _ ed25519.PrivateKey) error {
	gap := make([]byte, 12)
	binary.LittleEndian.PutUint32(gap[0:], 42_000)
	binary.LittleEndian.PutUint16(gap[4:], 42)
	gap[6] = 4 // tunnel / obstruction

	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 0, gnssPayload(340_000_000, -1_185_000_000)); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSGap, 1, 0, 1000, gap); err != nil {
		return err
	}
	if err := w.Append(format.RecordGNSSSample, 1, 0, 43_000, gnssPayload(340_100_000, -1_184_900_000)); err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "gnss-gap", &expectation{
		Description: "A 42-second tunnel gap between two fixes 1.1 km apart.",
		Asserts: "The gap record is preserved verbatim. A decoder must render a discontinuity " +
			"and must never join the route across it — honest incompleteness over fabricated continuity.",
		Scan:  exp,
		Keyed: keyed,
	}, segmentFiles(w.Bytes()))
}

func vectorEmptySegment(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "empty-segment", &expectation{
		Description: "A valid 128-byte header with no frames.",
		Asserts:     "EOF, zero frames, nothing discarded. An empty segment is valid, not damaged.",
		Scan:        exp,
		Keyed:       keyed,
	}, segmentFiles(w.Bytes()))
}

func vectorMaxFrame(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}
	if err := w.Append(format.RecordIMURawWindow, 1, 0, 0, make([]byte, format.MaxPayloadSize)); err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}
	return writeVector(dir, "max-frame", &expectation{
		Description: fmt.Sprintf("One frame at the maximum length of %d bytes.", format.MaxFrameLen),
		Asserts: fmt.Sprintf("A frame_len of %d is accepted; %d must be rejected as a torn tail "+
			"rather than trusted, and a frame_len below %d must also be rejected so a scan cannot "+
			"make zero progress.", format.MaxFrameLen, format.MaxFrameLen+1, format.MinFrameLen),
		Scan:  exp,
		Keyed: keyed,
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
		FirmwareVersion:           "cairn-v3.0.0",
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

		HasTripSeq: true,
		TripSeq:    42,

		VehicleID:         testHeader(0).VehicleID,
		AssignmentID:      testHeader(0).AssignmentID,
		DeviceCounter:     vectorDeviceCounter,
		StorageKeyVersion: vectorKeyVersion,
		EncryptionSuite:   format.EncryptionSuiteV1,
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
	readme := fmt.Sprintf(readmeTemplate, count, hex.EncodeToString(rootKey[:]), vectorKeyVersion,
		hex.EncodeToString(altRootKey[:]), altKeyVersion)
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644)
}

// ── POLICY_SNAPSHOT ─────────────────────────────────────────────────────────

// A bundle's own account of the thresholds it was captured under. The payload
// is committed so that an implementation encoding the same policy to different
// bytes is caught — which is the whole reason the encoding is deterministic.
func vectorPolicySnapshot(dir string, _, _ ed25519.PrivateKey) error {
	p := format.PolicySnapshot{
		PolicyVersion:         1,
		GNSSPeriodMS:          1000,
		IMUWindowMS:           1000,
		OBDPeriodMS:           2000,
		HealthPeriodMS:        30000,
		StartScoreThresholdE2: 150,
		StopScoreThresholdE2:  40,
		StartDwellMS:          3000,
		StopDwellMS:           120000,
		MotionAccelRMSmg:      120,
		MotionSpeedCMPS:       280,
		PrerollWindowMS:       45000,
		PrerollRingSamples:    128,
		SegmentMaxBytes:       1048576,
		AdaptiveSampling:      true,
	}

	encoded, err := p.MarshalCBOR()
	if err != nil {
		return err
	}

	return writeVector(dir, "policy-snapshot", &expectation{
		Name:        "policy-snapshot",
		Description: "A POLICY_SNAPSHOT carrying the default capture policy.",
		Asserts: "The deterministic CBOR encoding is reproducible byte-for-byte, " +
			"so two bundles captured under identical policy have identical " +
			"snapshots and can be grouped without trusting the version number. " +
			"A version number identifies a policy but does not describe one.",
		// The real struct, not a parallel copy: a second definition is one
		// more thing to keep in step, and the vector exists to catch drift.
		Policy: &p,
	}, map[string][]byte{"policy.cbor": encoded})
}

// ── TRIP_EVENT ──────────────────────────────────────────────────────────────

// Every defined event type, including the one that exists to admit ignorance.
func vectorTripEventTypes(dir string, _, _ ed25519.PrivateKey) error {
	type spec struct {
		t      uint8
		lat    int32
		lon    int32
		detail string
	}

	specs := []spec{
		{format.EventTripStart, 340000000, -1185000000, ""},
		{format.EventHarshBrake, 340000100, -1185000100, "rms=1800mg dv=-640cm/s"},
		{format.EventHarshAcceleration, 340000200, -1185000200, "dv=+710cm/s"},
		{format.EventHarshCornering, 340000300, -1185000300, "lateral"},
		{format.EventImpact, 0, 0, "rms=2400mg"},
		{format.EventHarshMotion, 0, 0, "no speed signal"},
		{format.EventCaptureRecovered, 0, 0, "state=1 discarded=40"},
		{format.EventTripEnd, 340000400, -1185000400, ""},
		// An event type this build does not define. A decoder must name it
		// rather than discard the record, so a newer device's events still
		// appear with their position and timing intact.
		{200, 340000500, -1185000500, "from newer firmware"},
	}

	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}

	var expected []expectedEvent
	for i, sp := range specs {
		payload, err := format.EncodeTripEvent(sp.t, sp.lat, sp.lon, sp.detail)
		if err != nil {
			return err
		}
		if err := w.Append(format.RecordTripEvent, 1, 0, uint32(i*500), payload); err != nil {
			return err
		}
		expected = append(expected, expectedEvent{
			EventType:     sp.t,
			EventTypeName: format.EventTypeName(sp.t),
			LatE7:         sp.lat,
			LonE7:         sp.lon,
			Detail:        sp.detail,
		})
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}

	return writeVector(dir, "trip-event-types", &expectation{
		Name:        "trip-event-types",
		Description: "One TRIP_EVENT of every defined type, plus one unknown type.",
		Asserts: "Each event decodes with its position and detail intact. " +
			"HARSH_MOTION carries no attribution on purpose: braking and " +
			"cornering are indistinguishable without the mounting orientation " +
			"or a speed signal, and a guessed label would be indistinguishable " +
			"from a measured one. An unknown type is named, never discarded.",
		Scan:  exp,
		Keyed: keyed,
		Events: &eventsExpectation{
			Events: expected,
			Note: "lat_e7/lon_e7 are zero when no valid fix was available; " +
				"position validity travels with the nearest GNSS_SAMPLE.",
		},
	}, segmentFiles(w.Bytes()))
}

// ── degraded-state bitmap ───────────────────────────────────────────────────

// The bitmap exists so simultaneous conditions all survive. A scalar severity
// would force a priority between them and discard the rest.
func vectorHealthBitmap(dir string, _, _ ed25519.PrivateKey) error {
	states := []uint8{
		0,
		format.HealthDegradedGNSS,
		format.HealthDegradedGNSS | format.HealthDegradedTime | format.HealthLowPower,
		format.HealthDegradedStorage | format.HealthRecoveryRequired,
		// Includes the reserved bit, which a decoder must preserve rather than
		// mask away.
		format.HealthDegradedTime | 0x80,
	}

	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}

	var expected []expectedHealth
	for i, st := range states {
		payload := make([]byte, 16)
		payload[12] = st
		payload[13] = uint8(i)
		if err := w.Append(format.RecordDeviceHealth, 1, 0, uint32(i*1000), payload); err != nil {
			return err
		}

		names := format.HealthStateNames(st)
		if names == nil {
			names = []string{}
		}
		expected = append(expected, expectedHealth{HealthState: st, Names: names})
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}

	return writeVector(dir, "health-bitmap", &expectation{
		Name:        "health-bitmap",
		Description: "DEVICE_HEALTH records covering no degradation, one condition, several at once, and a reserved bit.",
		Asserts: "health_state is a bitmap, not a severity. Several conditions " +
			"are active simultaneously and every one must be recoverable: a low " +
			"battery must not hide an unavailable fix. An unknown bit is " +
			"preserved rather than masked, so a bundle from newer firmware stays " +
			"interpretable for the conditions this build does understand.",
		Scan:  exp,
		Keyed: keyed,
		Health: &healthExpectation{
			Records: expected,
			Note:    "0x00 means no condition on the list is active, which is not the same as healthy in every respect.",
		},
	}, segmentFiles(w.Bytes()))
}

// ── OBD_EXTENDED ────────────────────────────────────────────────────────────

func obdExtPayload(mapKpa, mafCgps, lambdaE4, absLoadRaw uint16,
	baroKpa uint8, ambientC, stftPct, ltftPct int8,
	requested, answered uint32, cadence uint16) []byte {
	p := make([]byte, 24)
	binary.LittleEndian.PutUint16(p[0:], mapKpa)
	binary.LittleEndian.PutUint16(p[2:], mafCgps)
	binary.LittleEndian.PutUint16(p[4:], lambdaE4)
	binary.LittleEndian.PutUint16(p[6:], absLoadRaw)
	p[8] = baroKpa
	p[9] = uint8(ambientC)
	p[10] = uint8(stftPct)
	p[11] = uint8(ltftPct)
	binary.LittleEndian.PutUint32(p[12:], requested)
	binary.LittleEndian.PutUint32(p[16:], answered)
	binary.LittleEndian.PutUint16(p[20:], cadence)
	return p
}

func ptrU16(v uint16) *uint16   { return &v }
func ptrU8(v uint8) *uint8      { return &v }
func ptrI8(v int8) *int8        { return &v }
func ptrF64(v float64) *float64 { return &v }

func vectorOBDExtended(dir string, _, _ ed25519.PrivateKey) error {
	w, err := newWriter(testHeader(0), format.ScanState{})
	if err != nil {
		return err
	}

	// Record 0: full boost scenario.
	// MAP 230 kPa, baro 101 kPa → 129 kPa gauge → 18.71 psi.
	// Lambda 0.88 → raw = 0.88 * 32768 = 28835.84 → 28836.
	// Abs load 190% → raw = 190 * 255 / 100 = 484 (truncated; 484*100/255=189.8%).
	// STFT -5%, LTFT +18%, ambient 28 C, MAF 15000 cgps.
	p0 := obdExtPayload(230, 15000, 28836, 484, 101, 28, -5, 18, 6, 6, 200)
	if err := w.Append(format.RecordOBDExtended, 1, 0, 0, p0); err != nil {
		return err
	}

	// Record 1: all sentinels — a cold-only cycle where nothing was sampled.
	p1 := obdExtPayload(0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFF, -128, -128, -128, 0, 0, 1200)
	if err := w.Append(format.RecordOBDExtended, 1, 0, 1000, p1); err != nil {
		return err
	}

	// Record 2: MAP saturated at 255 kPa. Lambda 0.85 → raw 27852.
	// No baro (sentinel) so boost PSI is uncomputable.
	p2 := obdExtPayload(255, 0xFFFF, 27852, 0xFFFF, 0xFF, -128, -128, -128, 2, 2, 200)
	if err := w.Append(format.RecordOBDExtended, 1, 0, 2000, p2); err != nil {
		return err
	}

	exp, keyed, err := scanBoth(w.Bytes(), format.ScanState{})
	if err != nil {
		return err
	}

	// Derived values for record 0.
	boostPSI0 := float64(230-101) * 0.1450377   // 18.71 psi
	lambda0 := float64(28836) / 10000.0         // 0.8836 (ten-thousandths resolution)
	absLoadPct0 := float64(484) * 100.0 / 255.0 // 189.80%

	// Derived values for record 2.
	lambda2 := float64(27852) / 10000.0 // 0.7852 (ten-thousandths)

	records := []expectedOBDExt{
		{
			MAPkPa: ptrU16(230), MAFcgps: ptrU16(15000),
			LambdaE4: ptrU16(28836), AbsLoadRaw: ptrU16(484),
			BaroKPa: ptrU8(101), AmbientTempC: ptrI8(28),
			FuelTrimShortPct: ptrI8(-5), FuelTrimLongPct: ptrI8(18),
			PIDsRequested: 6, PIDsAnswered: 6, PollCadenceMS: 200,
			MAPSaturated: false,
			BoostPSI:     ptrF64(boostPSI0), Lambda: ptrF64(lambda0),
			AbsLoadPct: ptrF64(absLoadPct0),
		},
		{
			PIDsRequested: 0, PIDsAnswered: 0, PollCadenceMS: 1200,
			MAPSaturated: false,
		},
		{
			MAPkPa: ptrU16(255), LambdaE4: ptrU16(27852),
			PIDsRequested: 2, PIDsAnswered: 2, PollCadenceMS: 200,
			MAPSaturated: true,
			Lambda:       ptrF64(lambda2),
		},
	}

	return writeVector(dir, "obd-extended", &expectation{
		Description: "Three OBD_EXTENDED records: full boost, all sentinels, and MAP saturated.",
		Asserts: "Every field decodes to the expected value or is absent when sentinel. " +
			"MAPSaturated is true only when MAP is 255 kPa. BoostPSI requires both MAP " +
			"and baro; with either absent it is uncomputable, not assumed from sea level.",
		Scan:  exp,
		Keyed: keyed,
		OBDExt: &obdExtExpectation{
			Records: records,
			Note: "Sentinels: u16 0xFFFF, u8 0xFF, i8 0x80 (-128). A sentinel field " +
				"is absent, not zero. Derived values use the standard's own formulas.",
		},
	}, segmentFiles(w.Bytes()))
}

// ── update descriptor ───────────────────────────────────────────────────────

func buildUpdateDescriptor() format.UpdateDescriptor {
	var image [32]byte
	for i := range image {
		image[i] = byte(0x10 + i)
	}

	return format.UpdateDescriptor{
		DescriptorVersion:  format.UpdateDescriptorVersion,
		FirmwareVersion:    "cairn-v2.1.0",
		ImageSHA256:        image,
		ImageLength:        1114112,
		MinFirmwareVersion: "cairn-v2.0.0",
		BuildUTCMS:         1790000123456,
		SignatureAlgorithm: format.SignatureAlgorithmEd25519,
	}
}

func vectorUpdateDescriptorValid(dir string, _, _ ed25519.PrivateKey) error {
	priv := ed25519.NewKeyFromSeed(updateKeySeed)
	pub := priv.Public().(ed25519.PublicKey)

	d := buildUpdateDescriptor()
	encoded, sig, err := d.Sign(priv)
	if err != nil {
		return err
	}

	return writeVector(dir, "update-descriptor-valid", &expectation{
		Name:        "update-descriptor-valid",
		Description: "A correctly signed OTA update descriptor.",
		Asserts: "The signature covers exactly the bytes of descriptor.cbor, " +
			"verified against an update key that is deliberately separate from " +
			"the receipt key. A device downloads megabytes on the strength of " +
			"this check, so it must be made before anything in the descriptor " +
			"is used.",
		Update: &updateExpectation{
			SignatureValid:     true,
			FirmwareVersion:    d.FirmwareVersion,
			MinFirmwareVersion: d.MinFirmwareVersion,
			ImageSHA256Hex:     hex.EncodeToString(d.ImageSHA256[:]),
			ImageLength:        d.ImageLength,
			UpdateKeyHex:       hex.EncodeToString(pub),
			Note: "The receipt key says this data is safe to delete; the update " +
				"key says this code is safe to run. Different authorities, so " +
				"different keys.",
		},
	}, map[string][]byte{
		"descriptor.cbor": encoded,
		"descriptor.sig":  sig,
	})
}

func vectorUpdateDescriptorBadSignature(dir string, _, _ ed25519.PrivateKey) error {
	priv := ed25519.NewKeyFromSeed(updateKeySeed)
	pub := priv.Public().(ed25519.PublicKey)

	d := buildUpdateDescriptor()
	encoded, sig, err := d.Sign(priv)
	if err != nil {
		return err
	}

	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0x01

	return writeVector(dir, "update-descriptor-bad-signature", &expectation{
		Name:        "update-descriptor-bad-signature",
		Description: "A valid descriptor whose signature has one flipped bit.",
		Asserts: "Verification fails and nothing is installed. This is the one " +
			"signature whose failure mode is an unbootable device, so a " +
			"descriptor that parses must still be refused when the signature " +
			"does not verify.",
		Update: &updateExpectation{
			SignatureValid:     false,
			FirmwareVersion:    d.FirmwareVersion,
			MinFirmwareVersion: d.MinFirmwareVersion,
			ImageSHA256Hex:     hex.EncodeToString(d.ImageSHA256[:]),
			ImageLength:        d.ImageLength,
			UpdateKeyHex:       hex.EncodeToString(pub),
		},
	}, map[string][]byte{
		"descriptor.cbor": encoded,
		"descriptor.sig":  tampered,
	})
}
