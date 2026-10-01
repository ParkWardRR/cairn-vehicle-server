// Package intake implements the manifest-first, content-addressed upload
// protocol from docs/bundle-format-v2.md section 6.
//
// The protocol is three steps — offer, transfer, commit — and the design rule
// throughout is that ingest validates, durably stores, receipts and returns.
// Nothing else. It does not decode samples, build trips, detect events or
// publish MQTT while the device waits on an open connection; that work happens
// later, driven by the outbox.
//
// Two properties make the protocol crash-safe without any transfer bookkeeping:
//
//   - Chunks are stored in the CAS under their own digest, so the set of
//     missing chunks is *derived* on every offer rather than tracked. There is
//     no per-upload state to lose, reconcile or garbage-collect, and a chunk
//     that two bundles happen to share is stored once.
//   - Idempotency is keyed on content_root. A device that re-offers identical
//     data gets back the receipt it already earned, regardless of how many
//     times it rebooted or what bundle_id the retry used.
package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/ledger"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
)

var (
	// ErrUnknownBundle means no offer has been accepted for that bundle ID, so
	// there is nothing to chunk into or commit.
	ErrUnknownBundle = errors.New("no offer on record for this bundle")
	// ErrChunkNotInManifest means the chunk's digest does not appear in the
	// offered manifest's chunk descriptors.
	ErrChunkNotInManifest = errors.New("chunk digest is not in the manifest")
	// ErrChunksMissing means commit was attempted before every chunk arrived.
	ErrChunksMissing = errors.New("cannot commit: chunks are still missing")
	// ErrManifestInconsistent means the manifest contradicts itself — its
	// signature may be valid, but its contents cannot describe a real bundle.
	ErrManifestInconsistent = errors.New("manifest is internally inconsistent")
	// ErrMemberDigestMismatch means reassembled member bytes did not hash to
	// the digest the manifest declares.
	ErrMemberDigestMismatch = errors.New("reassembled member does not match its declared digest")
)

// MaxChunkSize bounds an individual chunk. The device may choose any size up to
// this; the manifest's descriptors are authoritative for a given bundle.
const MaxChunkSize = 4 << 20 // 4 MiB

// MaxManifestSize bounds an offered manifest, so a malformed or hostile offer
// cannot force an unbounded allocation before any validation has happened.
const MaxManifestSize = 1 << 20 // 1 MiB

// Service is the intake protocol.
type Service struct {
	cas      *cas.Store
	receipts *receipts.Store
	registry *devices.Registry
	outbox   *outbox.Queue

	// offers holds manifest pointers for bundles that have been offered but not
	// yet committed. It is a durable directory, not memory, so an offer
	// survives a server restart mid-transfer.
	offerDir string

	// ledger records what happened to each bundle and why. Optional: a nil
	// ledger means no record, never a failed ingest — an audit trail must not
	// be able to refuse data that is otherwise valid.
	ledger *ledger.Ledger
}

// Config configures a Service.
type Config struct {
	CAS      *cas.Store
	Receipts *receipts.Store
	Registry *devices.Registry
	Outbox   *outbox.Queue
	OfferDir string

	// Ledger is optional; nil disables recording.
	Ledger *ledger.Ledger
}

// record appends to the ledger, swallowing failures on purpose.
//
// A ledger that could fail an upload would be an audit trail with veto power
// over the data it is auditing. Losing an entry is bad; losing a trip because
// the audit trail's disk was full is worse.
func (s *Service) record(e ledger.Entry) {
	if s.ledger == nil {
		return
	}
	_ = s.ledger.Append(e)
}

// New creates a Service.
func New(cfg Config) (*Service, error) {
	if err := os.MkdirAll(cfg.OfferDir, 0o700); err != nil {
		return nil, fmt.Errorf("create offer dir: %w", err)
	}
	return &Service{
		ledger:   cfg.Ledger,
		cas:      cfg.CAS,
		receipts: cfg.Receipts,
		registry: cfg.Registry,
		outbox:   cfg.Outbox,
		offerDir: cfg.OfferDir,
	}, nil
}

// OfferResult is what the server tells a device in response to an offer.
type OfferResult struct {
	BundleID [16]byte

	// MissingChunks lists the indices the device still needs to send. When a
	// receipt already exists this is empty.
	MissingChunks []uint32

	// ExistingReceipt is set when this content root was already committed. The
	// device can stop immediately: it already has, or can now obtain, proof of
	// delivery.
	ExistingReceipt      *format.Receipt
	ExistingReceiptBytes []byte

	// TotalChunks and BytesExpected describe the work remaining.
	TotalChunks      int
	BytesExpected    int64
	BytesOutstanding int64
}

// Offer validates a signed manifest and tells the device which chunks are
// missing.
//
// Validation order matters. The signature is checked against the *enrolled*
// key before anything in the manifest is trusted, and the manifest's internal
// consistency is checked before any of its lengths are used to size work. A
// manifest that is validly signed but self-contradictory is still rejected:
// a signature attests to authorship, not to coherence.
func (s *Service) Offer(manifestBytes, signature []byte) (*OfferResult, error) {
	if len(manifestBytes) > MaxManifestSize {
		return nil, fmt.Errorf("manifest is %d bytes, maximum is %d", len(manifestBytes), MaxManifestSize)
	}

	// Parse first, but trust nothing yet: we need device_key_id to know which
	// key should have signed it.
	parsed, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	pub, err := s.registry.SignerFor(parsed.DeviceID, parsed.DeviceKeyID)
	if err != nil {
		// The most common real failure: an unenrolled device. Recorded so the
		// operator can see it without correlating logs, because from the
		// device's side this is an opaque 403.
		s.record(ledger.Entry{
			Event:       ledger.EventDeviceUnknown,
			DeviceID:    ledger.HexID(parsed.DeviceID[:]),
			BundleID:    ledger.HexID(parsed.BundleID[:]),
			ContentRoot: ledger.HexID(parsed.ContentRoot[:]),
			Reason:      err.Error(),
		})
		return nil, err
	}

	// Verify against the raw received bytes, so verification never depends on
	// our ability to re-encode.
	manifest, err := format.VerifyManifest(manifestBytes, signature, pub)
	if err != nil {
		s.record(ledger.Entry{
			Event:       ledger.EventOfferRejected,
			DeviceID:    ledger.HexID(parsed.DeviceID[:]),
			BundleID:    ledger.HexID(parsed.BundleID[:]),
			ContentRoot: ledger.HexID(parsed.ContentRoot[:]),
			Reason:      "manifest signature did not verify: " + err.Error(),
		})
		return nil, fmt.Errorf("verify manifest: %w", err)
	}

	if err := validateManifestConsistency(manifest); err != nil {
		// A validly signed but self-contradictory manifest. Worth a distinct
		// record: a signature attests to authorship, not to coherence, and the
		// two failures want different fixes.
		s.record(ledger.Entry{
			Event:       ledger.EventOfferRejected,
			DeviceID:    ledger.HexID(manifest.DeviceID[:]),
			BundleID:    ledger.HexID(manifest.BundleID[:]),
			ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
			Reason:      "manifest is self-contradictory: " + err.Error(),
		})
		return nil, err
	}

	// Idempotency on content_root: identical data earns the same receipt
	// forever, no matter how the retry is framed.
	if existing, encoded, err := s.receipts.Lookup(manifest.ContentRoot); err == nil {
		return &OfferResult{
			BundleID:             manifest.BundleID,
			ExistingReceipt:      existing,
			ExistingReceiptBytes: encoded,
			TotalChunks:          len(manifest.ChunkDescriptors),
		}, nil
	} else if !errors.Is(err, receipts.ErrNotFound) {
		return nil, err
	}

	// Persist the manifest and signature so a restart mid-transfer does not
	// require the device to re-offer. Both are content-addressed, so this is
	// also how the committed bundle will reference them.
	manifestDigest := sha256.Sum256(manifestBytes)
	if err := s.cas.Put(manifestDigest, manifestBytes); err != nil {
		return nil, fmt.Errorf("store manifest: %w", err)
	}
	sigDigest := sha256.Sum256(signature)
	if err := s.cas.Put(sigDigest, signature); err != nil {
		return nil, fmt.Errorf("store manifest signature: %w", err)
	}
	if err := s.writeOffer(manifest.BundleID, manifestDigest, sigDigest); err != nil {
		return nil, err
	}

	var expected int64
	for _, c := range manifest.ChunkDescriptors {
		expected += int64(c.ByteLength)
	}

	// Check the quota at offer time, not at commit. A device that is over its
	// allowance should learn so before transferring a whole bundle, and it must
	// keep its local copy rather than being told the upload succeeded.
	if err := s.checkQuota(manifest.DeviceID, expected); err != nil {
		s.record(ledger.Entry{
			Event:       ledger.EventQuotaRefused,
			DeviceID:    ledger.HexID(manifest.DeviceID[:]),
			BundleID:    ledger.HexID(manifest.BundleID[:]),
			ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
			Bytes:       expected,
			Reason:      err.Error(),
		})
		return nil, err
	}

	missing, outstanding, err := s.missingChunks(manifest)
	if err != nil {
		return nil, err
	}

	s.record(ledger.Entry{
		Event:       ledger.EventOffered,
		DeviceID:    ledger.HexID(manifest.DeviceID[:]),
		BundleID:    ledger.HexID(manifest.BundleID[:]),
		ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
		Bytes:       expected,
	})

	return &OfferResult{
		BundleID:         manifest.BundleID,
		MissingChunks:    missing,
		TotalChunks:      len(manifest.ChunkDescriptors),
		BytesExpected:    expected,
		BytesOutstanding: outstanding,
	}, nil
}

// checkQuota rejects an offer that would push a device past its storage
// allowance.
//
// A quota is containment, not accounting: it stops one misbehaving device from
// filling the dataset and starving the others. Devices with no configured quota
// skip the usage scan entirely, which is the common single-vehicle case.
func (s *Service) checkQuota(deviceID [16]byte, additionalBytes int64) error {
	device, err := s.registry.Lookup(deviceID)
	if err != nil {
		return err
	}
	if device.QuotaBytes == 0 {
		return nil
	}
	if s.outbox == nil {
		return nil
	}

	current, err := s.outbox.BytesStoredFor(device.DeviceID)
	if err != nil {
		return fmt.Errorf("determine current usage: %w", err)
	}
	return s.registry.CheckQuota(deviceID, current, additionalBytes)
}

// validateManifestConsistency checks the invariants a signature cannot provide.
func validateManifestConsistency(m *format.Manifest) error {
	if err := m.VerifyContentRoot(); err != nil {
		return fmt.Errorf("%w: %v", ErrManifestInconsistent, err)
	}

	if len(m.Members) == 0 {
		return fmt.Errorf("%w: no members", ErrManifestInconsistent)
	}
	if len(m.ChunkDescriptors) == 0 {
		return fmt.Errorf("%w: no chunk descriptors", ErrManifestInconsistent)
	}

	// Spec section 6.1: chunks and members partition the same byte stream, so
	// their totals must agree exactly.
	var memberBytes, chunkBytes int64
	for _, mem := range m.Members {
		memberBytes += int64(mem.Length)
	}
	for i, c := range m.ChunkDescriptors {
		if c.ByteLength == 0 {
			return fmt.Errorf("%w: chunk %d has zero length", ErrManifestInconsistent, i)
		}
		if c.ByteLength > MaxChunkSize {
			return fmt.Errorf("%w: chunk %d is %d bytes, maximum is %d",
				ErrManifestInconsistent, i, c.ByteLength, MaxChunkSize)
		}
		chunkBytes += int64(c.ByteLength)
	}
	if memberBytes != chunkBytes {
		return fmt.Errorf("%w: members total %d bytes but chunks total %d",
			ErrManifestInconsistent, memberBytes, chunkBytes)
	}

	if m.LastSeq < m.FirstSeq {
		return fmt.Errorf("%w: last_sequence %d precedes first_sequence %d",
			ErrManifestInconsistent, m.LastSeq, m.FirstSeq)
	}
	if m.CaptureEndedMonotonicUS < m.CaptureStartedMonotonicUS {
		return fmt.Errorf("%w: capture ended before it started", ErrManifestInconsistent)
	}

	return nil
}

// missingChunks derives which chunks are absent by asking the CAS. There is no
// tracked transfer state to go stale.
func (s *Service) missingChunks(m *format.Manifest) ([]uint32, int64, error) {
	var (
		missing     []uint32
		outstanding int64
	)
	for _, c := range m.ChunkDescriptors {
		present, _, err := s.cas.Has(c.SHA256)
		if err != nil {
			return nil, 0, fmt.Errorf("check chunk %d: %w", c.Index, err)
		}
		if !present {
			missing = append(missing, c.Index)
			outstanding += int64(c.ByteLength)
		}
	}
	return missing, outstanding, nil
}

// AcceptChunk stores one chunk and returns the indices still outstanding.
//
// The chunk is addressed by its hash, never by a byte offset. That is what lets
// either endpoint re-chunk or restart without invalidating progress, and it
// means a duplicate delivery is a no-op rather than a corruption.
func (s *Service) AcceptChunk(bundleID [16]byte, digest [32]byte, data []byte) ([]uint32, error) {
	if len(data) > MaxChunkSize {
		return nil, fmt.Errorf("chunk is %d bytes, maximum is %d", len(data), MaxChunkSize)
	}

	manifest, _, _, err := s.loadOffer(bundleID)
	if err != nil {
		return nil, err
	}

	// The chunk must be one the manifest actually declares, with the length it
	// declares. Otherwise a device could deposit arbitrary objects in the CAS.
	var descriptor *format.ChunkDescriptor
	for i := range manifest.ChunkDescriptors {
		if manifest.ChunkDescriptors[i].SHA256 == digest {
			descriptor = &manifest.ChunkDescriptors[i]
			break
		}
	}
	if descriptor == nil {
		return nil, fmt.Errorf("%w: %x", ErrChunkNotInManifest, digest)
	}
	if int(descriptor.ByteLength) != len(data) {
		return nil, fmt.Errorf("chunk %d is %d bytes, manifest declares %d",
			descriptor.Index, len(data), descriptor.ByteLength)
	}

	// Put verifies the digest, so a corrupt chunk is rejected here rather than
	// discovered at commit.
	if err := s.cas.Put(digest, data); err != nil {
		return nil, fmt.Errorf("store chunk %d: %w", descriptor.Index, err)
	}

	missing, _, err := s.missingChunks(manifest)
	return missing, err
}

// CommitResult is the outcome of a successful commit.
type CommitResult struct {
	Receipt      *format.Receipt
	ReceiptBytes []byte
	Manifest     *format.Manifest

	// MemberDigests are the stored raw objects, in canonical member order.
	MemberDigests [][32]byte

	// BytesStored is the total size of the committed members.
	BytesStored int64

	// AlreadyCommitted is true when this content root had been committed
	// before and the existing receipt was returned unchanged.
	AlreadyCommitted bool
}

// Commit reassembles the bundle, verifies it end to end, stores the raw
// members, issues a durable receipt and enqueues the decode work.
//
// The ordering is the durability contract:
//
//  1. verify every chunk and the reconstructed content root;
//  2. store the raw members durably;
//  3. persist the receipt — only now does the device have grounds to prune;
//  4. enqueue the outbox entry.
//
// A crash before step 3 leaves no receipt, so the device retries and finds its
// chunks already present. A crash between 3 and 4 leaves a receipted bundle
// with no decode work queued, which is recoverable by rescanning receipts — and
// is the right way round, because a missing decode job costs a re-derive while
// a missing receipt could cost the data.
func (s *Service) Commit(bundleID [16]byte) (*CommitResult, error) {
	manifest, manifestDigest, sigDigest, err := s.loadOffer(bundleID)
	if err != nil {
		return nil, err
	}

	// Already committed? Return the existing receipt untouched.
	if existing, encoded, err := s.receipts.Lookup(manifest.ContentRoot); err == nil {
		return &CommitResult{
			Receipt:          existing,
			ReceiptBytes:     encoded,
			Manifest:         manifest,
			AlreadyCommitted: true,
		}, nil
	} else if !errors.Is(err, receipts.ErrNotFound) {
		return nil, err
	}

	missing, _, err := s.missingChunks(manifest)
	if err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %d of %d chunks absent (first missing index %d)",
			ErrChunksMissing, len(missing), len(manifest.ChunkDescriptors), missing[0])
	}

	stream, err := s.reassembleStream(manifest)
	if err != nil {
		return nil, err
	}

	memberDigests, bytesStored, err := s.storeMembers(manifest, stream)
	if err != nil {
		return nil, err
	}

	// Recompute the content root from what we actually reassembled, not from
	// what the manifest claims about itself. This closes the loop: the bytes on
	// disk, not the declaration, must produce the signed root.
	verifyMembers := make([]format.Member, len(manifest.Members))
	copy(verifyMembers, manifest.Members)
	computedRoot, err := format.ContentRoot(verifyMembers)
	if err != nil {
		return nil, err
	}
	if computedRoot != manifest.ContentRoot {
		return nil, fmt.Errorf("%w: reassembled root %x, signed root %x",
			format.ErrContentRootMismatch, computedRoot, manifest.ContentRoot)
	}

	objectIDs := receipts.ObjectIDsFor(memberDigests)
	objectIDs = append(objectIDs, cas.ObjectID(manifestDigest), cas.ObjectID(sigDigest))

	receipt, encoded, err := s.receipts.Issue(manifest.DeviceID, manifest.BundleID, manifest.ContentRoot, objectIDs)
	if err != nil {
		return nil, err
	}

	// Recorded here, not at the end of the function, so ledger order matches
	// causal order. The receipt exists at this point and the decode job does
	// not; writing these later put decode_queued *before* committed, which
	// would tell a reader the job was enqueued for a bundle that was not yet
	// committed. Ordering is most of what a ledger is for.
	s.record(ledger.Entry{
		Event:       ledger.EventCommitted,
		DeviceID:    ledger.HexID(manifest.DeviceID[:]),
		BundleID:    ledger.HexID(manifest.BundleID[:]),
		ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
		Bytes:       bytesStored,
	})
	// The moment the device becomes free to delete its copy, and therefore the
	// record that explains why data no longer exists on a card.
	s.record(ledger.Entry{
		Event:       ledger.EventReceiptIssued,
		DeviceID:    ledger.HexID(manifest.DeviceID[:]),
		BundleID:    ledger.HexID(manifest.BundleID[:]),
		ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
	})

	// Enqueued after the receipt, deliberately. A lost decode job costs a
	// re-derive from raw; a lost receipt could cost the data itself.
	if s.outbox != nil {
		entry := outbox.Entry{
			BundleID:       hex.EncodeToString(manifest.BundleID[:]),
			DeviceID:       hex.EncodeToString(manifest.DeviceID[:]),
			ContentRoot:    hex.EncodeToString(manifest.ContentRoot[:]),
			ManifestDigest: hex.EncodeToString(manifestDigest[:]),
			ReceiptID:      hex.EncodeToString(receipt.ReceiptID[:]),
			BytesStored:    bytesStored,
		}
		if err := s.outbox.Append(entry); err != nil {
			// The bundle is committed and receipted; the device is safe. Report
			// the enqueue failure rather than failing the upload — but record
			// it, because this is the case where the data is durable and the
			// derived view will silently never appear.
			s.record(ledger.Entry{
				Event:       ledger.EventDecodeFailed,
				DeviceID:    ledger.HexID(manifest.DeviceID[:]),
				BundleID:    ledger.HexID(manifest.BundleID[:]),
				ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
				Reason: "committed and receipted, but enqueueing decode work " +
					"failed: " + err.Error(),
			})
			return &CommitResult{
				Receipt:       receipt,
				ReceiptBytes:  encoded,
				Manifest:      manifest,
				MemberDigests: memberDigests,
				BytesStored:   bytesStored,
			}, fmt.Errorf("bundle committed and receipted, but enqueueing decode work failed: %w", err)
		}

		s.record(ledger.Entry{
			Event:       ledger.EventDecodeQueued,
			DeviceID:    ledger.HexID(manifest.DeviceID[:]),
			BundleID:    ledger.HexID(manifest.BundleID[:]),
			ContentRoot: ledger.HexID(manifest.ContentRoot[:]),
		})
	}

	// The offer record is deliberately retained. Deleting it here would make a
	// second Commit fail with ErrUnknownBundle, which punishes a device that
	// simply did not see the first response — the most ordinary failure there
	// is. Keeping it lets Commit be idempotent on its own terms. Records for
	// committed bundles are reclaimed by SweepOffers.

	return &CommitResult{
		Receipt:       receipt,
		ReceiptBytes:  encoded,
		Manifest:      manifest,
		MemberDigests: memberDigests,
		BytesStored:   bytesStored,
	}, nil
}

// reassembleStream concatenates chunks in index order to rebuild the bundle
// byte stream (spec section 6.1).
func (s *Service) reassembleStream(m *format.Manifest) ([]byte, error) {
	var total int64
	for _, c := range m.ChunkDescriptors {
		total += int64(c.ByteLength)
	}

	stream := make([]byte, 0, total)
	for _, c := range m.ChunkDescriptors {
		// GetVerified, not Get: re-checking the digest here catches bit rot
		// between transfer and commit, which a plain read would pass through.
		data, err := s.cas.GetVerified(c.SHA256)
		if err != nil {
			return nil, fmt.Errorf("read chunk %d: %w", c.Index, err)
		}
		if len(data) != int(c.ByteLength) {
			return nil, fmt.Errorf("chunk %d is %d bytes on disk, manifest declares %d",
				c.Index, len(data), c.ByteLength)
		}
		stream = append(stream, data...)
	}
	return stream, nil
}

// storeMembers splits the stream at member boundaries, verifies each member's
// digest and stores it as a durable raw object.
func (s *Service) storeMembers(m *format.Manifest, stream []byte) ([][32]byte, int64, error) {
	members := make([]format.Member, len(m.Members))
	copy(members, m.Members)
	format.SortMembers(members)

	digests := make([][32]byte, 0, len(members))
	var (
		offset int64
		stored int64
	)

	for _, mem := range members {
		end := offset + int64(mem.Length)
		if end > int64(len(stream)) {
			return nil, 0, fmt.Errorf("%w: member %q needs bytes [%d,%d) but the stream is %d bytes",
				ErrManifestInconsistent, mem.Name, offset, end, len(stream))
		}

		contents := stream[offset:end]
		if computed := sha256.Sum256(contents); computed != mem.SHA256 {
			return nil, 0, fmt.Errorf("%w: member %q computed %x, declared %x",
				ErrMemberDigestMismatch, mem.Name, computed, mem.SHA256)
		}

		if err := s.cas.Put(mem.SHA256, contents); err != nil {
			return nil, 0, fmt.Errorf("store member %q: %w", mem.Name, err)
		}

		digests = append(digests, mem.SHA256)
		stored += int64(mem.Length)
		offset = end
	}

	if offset != int64(len(stream)) {
		return nil, 0, fmt.Errorf("%w: %d stream bytes left over after all members",
			ErrManifestInconsistent, int64(len(stream))-offset)
	}

	return digests, stored, nil
}

// ─── offer persistence ──────────────────────────────────────────────────────

// An offer record is 64 bytes: the manifest digest followed by the signature
// digest. Both objects already live in the CAS, so this file is a pointer, not
// a copy — which keeps it small enough to write durably on every offer.
//
// This is the only transfer state the server keeps, and it holds no progress
// information at all. Progress is derived from which chunks the CAS already
// has, so there is nothing here to go stale or need reconciling.
const offerRecordSize = 64

func (s *Service) offerPath(bundleID [16]byte) string {
	return filepath.Join(s.offerDir, hex.EncodeToString(bundleID[:]))
}

// writeOffer durably records the pointer so a restart mid-transfer does not
// force the device to re-offer.
func (s *Service) writeOffer(bundleID [16]byte, manifestDigest, sigDigest [32]byte) error {
	record := make([]byte, 0, offerRecordSize)
	record = append(record, manifestDigest[:]...)
	record = append(record, sigDigest[:]...)

	final := s.offerPath(bundleID)

	f, err := os.CreateTemp(s.offerDir, ".offer-*")
	if err != nil {
		return fmt.Errorf("create offer temp: %w", err)
	}
	tmpName := f.Name()

	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(record); err != nil {
		return fmt.Errorf("write offer record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync offer record: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close offer record: %w", err)
	}
	if err := os.Rename(tmpName, final); err != nil {
		return fmt.Errorf("rename offer record: %w", err)
	}
	committed = true

	d, err := os.Open(s.offerDir)
	if err != nil {
		return fmt.Errorf("open offer dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync offer dir: %w", err)
	}
	return nil
}

// SweepOffers removes offer records whose content root has already been
// receipted and whose record is older than minAge. It returns how many were
// reclaimed.
//
// Offer records are tiny pointers, so this is housekeeping rather than a
// correctness requirement — which is why it is an explicit, callable operation
// instead of a side effect of Commit. Reclaiming on commit would break
// idempotency for a device retrying a request it never saw answered.
//
// An offer whose content root has no receipt is never swept, however old: it
// represents a transfer that may still resume, and discarding it would force
// the device to start over.
func (s *Service) SweepOffers(minAge time.Duration) (int, error) {
	entries, err := os.ReadDir(s.offerDir)
	if err != nil {
		return 0, fmt.Errorf("read offer dir: %w", err)
	}

	cutoff := time.Now().Add(-minAge)
	swept := 0

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue // vanished underneath us; nothing to do
		}
		if info.ModTime().After(cutoff) {
			continue
		}

		raw, err := hex.DecodeString(e.Name())
		if err != nil || len(raw) != 16 {
			continue // not an offer record
		}
		var bundleID [16]byte
		copy(bundleID[:], raw)

		manifest, _, _, err := s.loadOffer(bundleID)
		if err != nil {
			continue
		}

		// Only sweep what is provably safe to forget.
		if _, _, err := s.receipts.Lookup(manifest.ContentRoot); err != nil {
			continue
		}

		if err := os.Remove(s.offerPath(bundleID)); err == nil {
			swept++
		}
	}

	return swept, nil
}

// loadOffer returns the manifest for an offered bundle, along with the digests
// of its stored manifest and signature.
func (s *Service) loadOffer(bundleID [16]byte) (*format.Manifest, [32]byte, [32]byte, error) {
	var manifestDigest, sigDigest [32]byte

	raw, err := os.ReadFile(s.offerPath(bundleID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, manifestDigest, sigDigest, fmt.Errorf("%w: %x", ErrUnknownBundle, bundleID)
	}
	if err != nil {
		return nil, manifestDigest, sigDigest, err
	}
	if len(raw) != offerRecordSize {
		return nil, manifestDigest, sigDigest, fmt.Errorf("offer record for %x is %d bytes, want 64",
			bundleID, len(raw))
	}

	copy(manifestDigest[:], raw[:32])
	copy(sigDigest[:], raw[32:])

	manifestBytes, err := s.cas.GetVerified(manifestDigest)
	if err != nil {
		return nil, manifestDigest, sigDigest, fmt.Errorf("read offered manifest: %w", err)
	}
	manifest, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return nil, manifestDigest, sigDigest, fmt.Errorf("parse offered manifest: %w", err)
	}

	return manifest, manifestDigest, sigDigest, nil
}
