package format

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
)

// ManifestVersion is the manifest schema version this package implements.
const ManifestVersion uint8 = 2

// SignatureAlgorithmEd25519 is the only algorithm v2 defines. "SHA-256 sign"
// conflates a digest with a signature; these are separate operations and the
// manifest names the signature algorithm explicitly.
const SignatureAlgorithmEd25519 = "ed25519"

// RecoveryState records how the bundle's data came to be, so a consumer can
// tell clean capture from recovered capture without re-deriving it.
type RecoveryState uint8

const (
	// RecoveryClean means every segment scanned to EOF with no damage.
	RecoveryClean RecoveryState = 0
	// RecoveryRecoveredTail means an incomplete tail was discarded at boot.
	// This is the normal outcome of a power cut and is not a defect.
	RecoveryRecoveredTail RecoveryState = 1
	// RecoverySalvaged means the offline tool resynchronized past a damaged
	// region. Salvaged bundles are ineligible for the normal upload path.
	RecoverySalvaged RecoveryState = 2
)

func (r RecoveryState) String() string {
	switch r {
	case RecoveryClean:
		return "clean"
	case RecoveryRecoveredTail:
		return "recovered_tail"
	case RecoverySalvaged:
		return "salvaged"
	default:
		return fmt.Sprintf("RecoveryState(%d)", uint8(r))
	}
}

// ChunkDescriptor describes one transfer chunk. Chunks are a transport concern:
// they are addressed by hash during upload so that re-chunking and
// deduplication both work, and they carry no identity of their own.
type ChunkDescriptor struct {
	Index      uint32
	ByteLength uint32
	SHA256     [32]byte
}

// Manifest is the immutable, signed description of a sealed bundle.
type Manifest struct {
	ManifestVersion           uint8
	BundleID                  [16]byte // ULID: the operational handle
	DeviceID                  [16]byte
	DeviceKeyID               [8]byte
	BootID                    [16]byte
	FirmwareVersion           string
	SchemaVersion             uint8
	CaptureStartedMonotonicUS uint64
	CaptureEndedMonotonicUS   uint64

	// UTCBasisMS and UTCBasisAccMS are the basis that GNSS sample UTC deltas
	// are relative to, with its own uncertainty. UTC is an annotation here, not
	// an ordering key — ordering truth is (BootID, seq).
	UTCBasisMS    uint64
	UTCBasisAccMS uint32

	FirstSeq uint32
	LastSeq  uint32

	RecordCounts     map[RecordType]uint32
	Members          []Member
	ChunkDescriptors []ChunkDescriptor

	ContentRoot [32]byte

	// PreviousBundleRoot chains bundle history. Populated but not enforced in
	// v2: detecting deleted historical bundles is a different threat model from
	// detecting corruption within one bundle.
	PreviousBundleRoot *[32]byte

	PolicyVersion      uint8
	RecoveryState      RecoveryState
	DiscardedTailBytes uint32
	SignatureAlgorithm string

	HasTripSeq bool
	TripSeq    uint32
}

// Manifest CBOR keys. Integer keys keep the encoding compact and unambiguous.
const (
	keyManifestVersion = 1
	keyBundleID        = 2
	keyDeviceID        = 3
	keyDeviceKeyID     = 4
	keyBootID          = 5
	keyFirmwareVersion = 6
	keySchemaVersion   = 7
	keyCaptureStarted  = 8
	keyCaptureEnded    = 9
	keyUTCBasisMS      = 10
	keyUTCBasisAccMS   = 11
	keyFirstSeq        = 12
	keyLastSeq         = 13
	keyRecordCounts    = 14
	keyMembers         = 15
	keyChunkDescs      = 16
	keyContentRoot     = 17
	keyPreviousRoot    = 18
	keyPolicyVersion   = 19
	keyRecoveryState   = 20
	keyDiscardedTail   = 21
	keySignatureAlgo   = 22
	keyTripSeq         = 23

	manifestFieldCountBase = 22
	manifestFieldCountMax  = 23
)

var (
	// ErrContentRootMismatch means the manifest's signed content root does not
	// match the root recomputed from its members.
	ErrContentRootMismatch = errors.New("content root does not match members")
	// ErrBadSignature means the manifest signature did not verify.
	ErrBadSignature = errors.New("manifest signature verification failed")
)

// MarshalCBOR encodes the manifest in deterministic CBOR. The result is exactly
// the bytes of manifest.cbor and exactly the bytes the signature covers, so
// there is nothing to strip or re-encode before verifying.
func (m *Manifest) MarshalCBOR() ([]byte, error) {
	if m.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("unsupported signature algorithm %q", m.SignatureAlgorithm)
	}
	if err := validateMembers(m.Members); err != nil {
		return nil, err
	}

	e := &cborEncoder{}
	fieldCount := manifestFieldCountBase
	if m.HasTripSeq {
		fieldCount = manifestFieldCountMax
	}
	e.mapHeader(fieldCount)

	e.key(keyManifestVersion)
	e.uint(uint64(m.ManifestVersion))
	e.key(keyBundleID)
	e.bytes(m.BundleID[:])
	e.key(keyDeviceID)
	e.bytes(m.DeviceID[:])
	e.key(keyDeviceKeyID)
	e.bytes(m.DeviceKeyID[:])
	e.key(keyBootID)
	e.bytes(m.BootID[:])
	e.key(keyFirmwareVersion)
	e.text(m.FirmwareVersion)
	e.key(keySchemaVersion)
	e.uint(uint64(m.SchemaVersion))
	e.key(keyCaptureStarted)
	e.uint(m.CaptureStartedMonotonicUS)
	e.key(keyCaptureEnded)
	e.uint(m.CaptureEndedMonotonicUS)
	e.key(keyUTCBasisMS)
	e.uint(m.UTCBasisMS)
	e.key(keyUTCBasisAccMS)
	e.uint(uint64(m.UTCBasisAccMS))
	e.key(keyFirstSeq)
	e.uint(uint64(m.FirstSeq))
	e.key(keyLastSeq)
	e.uint(uint64(m.LastSeq))

	// Record counts: a nested map, keys ascending by record type.
	e.key(keyRecordCounts)
	types := make([]int, 0, len(m.RecordCounts))
	for t := range m.RecordCounts {
		types = append(types, int(t))
	}
	sort.Ints(types)
	inner := &cborEncoder{}
	inner.mapHeader(len(types))
	for _, t := range types {
		inner.key(uint64(t))
		inner.uint(uint64(m.RecordCounts[RecordType(t)]))
	}
	e.buf = append(e.buf, inner.buf...)

	// Members: sorted by raw name bytes ascending, as the content root requires.
	e.key(keyMembers)
	members := make([]Member, len(m.Members))
	copy(members, m.Members)
	SortMembers(members)
	e.arrayHeader(len(members))
	for _, mem := range members {
		e.arrayHeader(3)
		e.text(mem.Name)
		e.uint(mem.Length)
		e.bytes(mem.SHA256[:])
	}

	e.key(keyChunkDescs)
	e.arrayHeader(len(m.ChunkDescriptors))
	for _, c := range m.ChunkDescriptors {
		e.arrayHeader(3)
		e.uint(uint64(c.Index))
		e.uint(uint64(c.ByteLength))
		e.bytes(c.SHA256[:])
	}

	e.key(keyContentRoot)
	e.bytes(m.ContentRoot[:])

	e.key(keyPreviousRoot)
	if m.PreviousBundleRoot == nil {
		e.null()
	} else {
		e.bytes(m.PreviousBundleRoot[:])
	}

	e.key(keyPolicyVersion)
	e.uint(uint64(m.PolicyVersion))
	e.key(keyRecoveryState)
	e.uint(uint64(m.RecoveryState))
	e.key(keyDiscardedTail)
	e.uint(uint64(m.DiscardedTailBytes))
	e.key(keySignatureAlgo)
	e.text(m.SignatureAlgorithm)

	if m.HasTripSeq {
		e.key(keyTripSeq)
		e.uint(uint64(m.TripSeq))
	}

	return e.buf, nil
}

// ParseManifest decodes a manifest and verifies that it is canonically
// encoded.
//
// Canonicality is checked by re-encoding the decoded manifest and requiring
// byte equality with the input. This is deliberately strict: a manifest whose
// bytes we would not ourselves have produced cannot be safely re-serialized,
// and any discrepancy would silently break signature verification.
func ParseManifest(b []byte) (*Manifest, error) {
	m, err := decodeManifest(b)
	if err != nil {
		return nil, err
	}

	reencoded, err := m.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("re-encode decoded manifest: %w", err)
	}
	if !bytes.Equal(reencoded, b) {
		return nil, fmt.Errorf("%w: manifest does not round-trip to identical bytes", ErrNonCanonical)
	}

	return m, nil
}

func decodeManifest(b []byte) (*Manifest, error) {
	d := &cborDecoder{buf: b}

	n, err := d.mapHeader()
	if err != nil {
		return nil, fmt.Errorf("manifest map header: %w", err)
	}
	if n != manifestFieldCountBase && n != manifestFieldCountMax {
		return nil, fmt.Errorf("manifest has %d fields, expected %d or %d",
			n, manifestFieldCountBase, manifestFieldCountMax)
	}

	m := &Manifest{}

	for i := 0; i < n; i++ {
		key, err := d.uint()
		if err != nil {
			return nil, fmt.Errorf("manifest key %d: %w", i, err)
		}

		switch key {
		case keyManifestVersion:
			if m.ManifestVersion, err = d.uint8(); err != nil {
				return nil, fmt.Errorf("manifest_version: %w", err)
			}
			if m.ManifestVersion != ManifestVersion {
				return nil, fmt.Errorf("unsupported manifest_version %d (this implementation reads %d only)",
					m.ManifestVersion, ManifestVersion)
			}
		case keyBundleID:
			if err = copyFixed(d, m.BundleID[:]); err != nil {
				return nil, fmt.Errorf("bundle_id: %w", err)
			}
		case keyDeviceID:
			if err = copyFixed(d, m.DeviceID[:]); err != nil {
				return nil, fmt.Errorf("device_id: %w", err)
			}
		case keyDeviceKeyID:
			if err = copyFixed(d, m.DeviceKeyID[:]); err != nil {
				return nil, fmt.Errorf("device_key_id: %w", err)
			}
		case keyBootID:
			if err = copyFixed(d, m.BootID[:]); err != nil {
				return nil, fmt.Errorf("boot_id: %w", err)
			}
		case keyFirmwareVersion:
			if m.FirmwareVersion, err = d.text(); err != nil {
				return nil, fmt.Errorf("firmware_version: %w", err)
			}
		case keySchemaVersion:
			if m.SchemaVersion, err = d.uint8(); err != nil {
				return nil, fmt.Errorf("schema_version: %w", err)
			}
		case keyCaptureStarted:
			if m.CaptureStartedMonotonicUS, err = d.uint(); err != nil {
				return nil, fmt.Errorf("capture_started: %w", err)
			}
		case keyCaptureEnded:
			if m.CaptureEndedMonotonicUS, err = d.uint(); err != nil {
				return nil, fmt.Errorf("capture_ended: %w", err)
			}
		case keyUTCBasisMS:
			if m.UTCBasisMS, err = d.uint(); err != nil {
				return nil, fmt.Errorf("utc_basis_ms: %w", err)
			}
		case keyUTCBasisAccMS:
			if m.UTCBasisAccMS, err = d.uint32(); err != nil {
				return nil, fmt.Errorf("utc_basis_acc_ms: %w", err)
			}
		case keyFirstSeq:
			if m.FirstSeq, err = d.uint32(); err != nil {
				return nil, fmt.Errorf("first_sequence: %w", err)
			}
		case keyLastSeq:
			if m.LastSeq, err = d.uint32(); err != nil {
				return nil, fmt.Errorf("last_sequence: %w", err)
			}
		case keyRecordCounts:
			if m.RecordCounts, err = decodeRecordCounts(d); err != nil {
				return nil, fmt.Errorf("record_counts: %w", err)
			}
		case keyMembers:
			if m.Members, err = decodeMembers(d); err != nil {
				return nil, fmt.Errorf("members: %w", err)
			}
		case keyChunkDescs:
			if m.ChunkDescriptors, err = decodeChunkDescriptors(d); err != nil {
				return nil, fmt.Errorf("chunk_descriptors: %w", err)
			}
		case keyContentRoot:
			if err = copyFixed(d, m.ContentRoot[:]); err != nil {
				return nil, fmt.Errorf("content_root: %w", err)
			}
		case keyPreviousRoot:
			if d.isNull() {
				m.PreviousBundleRoot = nil
			} else {
				var root [32]byte
				if err = copyFixed(d, root[:]); err != nil {
					return nil, fmt.Errorf("previous_bundle_root: %w", err)
				}
				m.PreviousBundleRoot = &root
			}
		case keyPolicyVersion:
			if m.PolicyVersion, err = d.uint8(); err != nil {
				return nil, fmt.Errorf("policy_version: %w", err)
			}
		case keyRecoveryState:
			v, err := d.uint8()
			if err != nil {
				return nil, fmt.Errorf("recovery_state: %w", err)
			}
			if v > uint8(RecoverySalvaged) {
				return nil, fmt.Errorf("recovery_state %d is not defined", v)
			}
			m.RecoveryState = RecoveryState(v)
		case keyDiscardedTail:
			if m.DiscardedTailBytes, err = d.uint32(); err != nil {
				return nil, fmt.Errorf("discarded_tail_bytes: %w", err)
			}
		case keySignatureAlgo:
			if m.SignatureAlgorithm, err = d.text(); err != nil {
				return nil, fmt.Errorf("signature_algorithm: %w", err)
			}
			if m.SignatureAlgorithm != SignatureAlgorithmEd25519 {
				return nil, fmt.Errorf("unsupported signature algorithm %q", m.SignatureAlgorithm)
			}
		case keyTripSeq:
			if m.TripSeq, err = d.uint32(); err != nil {
				return nil, fmt.Errorf("trip_seq: %w", err)
			}
			m.HasTripSeq = true
		default:
			return nil, fmt.Errorf("unknown manifest key %d", key)
		}
	}

	if !d.atEnd() {
		return nil, fmt.Errorf("%d trailing bytes after manifest", len(b)-d.pos)
	}

	return m, nil
}

func copyFixed(d *cborDecoder, dst []byte) error {
	b, err := d.bytesN(len(dst))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

func decodeRecordCounts(d *cborDecoder) (map[RecordType]uint32, error) {
	n, err := d.mapHeader()
	if err != nil {
		return nil, err
	}
	out := make(map[RecordType]uint32, n)
	prev := -1
	for i := 0; i < n; i++ {
		k, err := d.uint8()
		if err != nil {
			return nil, err
		}
		if int(k) <= prev {
			return nil, fmt.Errorf("%w: record_counts key %d follows %d", ErrNonCanonical, k, prev)
		}
		prev = int(k)
		v, err := d.uint32()
		if err != nil {
			return nil, err
		}
		out[RecordType(k)] = v
	}
	return out, nil
}

func decodeMembers(d *cborDecoder) ([]Member, error) {
	n, err := d.arrayHeader()
	if err != nil {
		return nil, err
	}
	out := make([]Member, 0, n)
	for i := 0; i < n; i++ {
		fields, err := d.arrayHeader()
		if err != nil {
			return nil, err
		}
		if fields != 3 {
			return nil, fmt.Errorf("member %d has %d fields, expected 3", i, fields)
		}
		var mem Member
		if mem.Name, err = d.text(); err != nil {
			return nil, err
		}
		if mem.Length, err = d.uint(); err != nil {
			return nil, err
		}
		if err = copyFixed(d, mem.SHA256[:]); err != nil {
			return nil, err
		}
		if i > 0 && mem.Name <= out[i-1].Name {
			return nil, fmt.Errorf("%w: member %q follows %q", ErrNonCanonical, mem.Name, out[i-1].Name)
		}
		out = append(out, mem)
	}
	return out, nil
}

func decodeChunkDescriptors(d *cborDecoder) ([]ChunkDescriptor, error) {
	n, err := d.arrayHeader()
	if err != nil {
		return nil, err
	}
	out := make([]ChunkDescriptor, 0, n)
	for i := 0; i < n; i++ {
		fields, err := d.arrayHeader()
		if err != nil {
			return nil, err
		}
		if fields != 3 {
			return nil, fmt.Errorf("chunk %d has %d fields, expected 3", i, fields)
		}
		var c ChunkDescriptor
		if c.Index, err = d.uint32(); err != nil {
			return nil, err
		}
		if c.ByteLength, err = d.uint32(); err != nil {
			return nil, err
		}
		if err = copyFixed(d, c.SHA256[:]); err != nil {
			return nil, err
		}
		if c.Index != uint32(i) {
			return nil, fmt.Errorf("chunk at position %d declares index %d", i, c.Index)
		}
		out = append(out, c)
	}
	return out, nil
}

// ─── signing ────────────────────────────────────────────────────────────────

// DeviceKeyID derives the 8-byte key identifier from a public key: the
// truncated SHA-256 of the key bytes.
func DeviceKeyID(pub ed25519.PublicKey) [8]byte {
	sum := sha256.Sum256(pub)
	var id [8]byte
	copy(id[:], sum[:8])
	return id
}

// Sign returns the Ed25519 signature over the manifest's deterministic
// encoding, along with those encoded bytes. The caller writes the bytes to
// manifest.cbor and the signature to manifest.sig.
func (m *Manifest) Sign(priv ed25519.PrivateKey) (encoded, signature []byte, err error) {
	encoded, err = m.MarshalCBOR()
	if err != nil {
		return nil, nil, err
	}
	return encoded, ed25519.Sign(priv, encoded), nil
}

// VerifyManifest checks a signature against the raw manifest bytes and returns
// the parsed manifest.
//
// The signature is verified against the bytes as received, before parsing, so
// verification never depends on this implementation's ability to re-encode.
func VerifyManifest(encoded, signature []byte, pub ed25519.PublicKey) (*Manifest, error) {
	if !ed25519.Verify(pub, encoded, signature) {
		return nil, ErrBadSignature
	}
	return ParseManifest(encoded)
}

// VerifyContentRoot recomputes the content root from the manifest's members and
// checks it against the signed value.
//
// A caller holding the actual member bytes must additionally confirm that each
// member's SHA-256 matches, since this check only proves the manifest is
// internally consistent.
func (m *Manifest) VerifyContentRoot() error {
	computed, err := ContentRoot(m.Members)
	if err != nil {
		return err
	}
	if computed != m.ContentRoot {
		return fmt.Errorf("%w: computed %x, signed %x", ErrContentRootMismatch, computed, m.ContentRoot)
	}
	return nil
}
