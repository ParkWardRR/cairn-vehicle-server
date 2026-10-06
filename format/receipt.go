package format

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ReceiptVersion is the receipt schema version this package implements.
const ReceiptVersion uint8 = 2

// Receipt is the server's durable, signed proof that it committed a
// reconstructable bundle.
//
// A chunk acknowledgement is not a receipt: it means bytes were accepted, not
// that a recoverable record exists. Only a receipt justifies deletion, and only
// when both its signature verifies against the pinned server key and its
// ContentRoot equals what the device uploaded.
type Receipt struct {
	ReceiptVersion      uint8
	ReceiptID           [16]byte
	DeviceID            [16]byte
	BundleID            [16]byte
	ContentRoot         [32]byte
	ServerIngestUTCMS   uint64
	ServerKeyID         [8]byte
	IngestSchemaVersion uint8
	StoredObjectIDs     []string
	SignatureAlgorithm  string
	Signature           [64]byte
}

// Receipt CBOR keys. Keys 1 through 10 are covered by the signature; key 11 is
// the signature itself.
const (
	keyReceiptVersion  = 1
	keyReceiptID       = 2
	keyReceiptDeviceID = 3
	keyReceiptBundleID = 4
	keyReceiptRoot     = 5
	keyServerIngestUTC = 6
	keyServerKeyID     = 7
	keyIngestSchemaVer = 8
	keyStoredObjectIDs = 9
	keyReceiptSigAlgo  = 10
	keyReceiptSig      = 11

	receiptSignedFieldCount = 10
	receiptFieldCount       = 11
)

var (
	// ErrBadReceiptSignature means the receipt signature did not verify against
	// the pinned server key.
	ErrBadReceiptSignature = errors.New("receipt signature verification failed")
	// ErrReceiptRootMismatch means the receipt is validly signed but
	// acknowledges a different bundle than the one uploaded. A valid signature
	// over someone else's content root is not an acknowledgement of this one.
	ErrReceiptRootMismatch = errors.New("receipt content root does not match the uploaded bundle")
)

// encodeFields writes the receipt's fields. When includeSignature is false the
// result is the byte sequence the signature covers.
func (r *Receipt) encodeFields(includeSignature bool) ([]byte, error) {
	if r.SignatureAlgorithm != SignatureAlgorithmEd25519 {
		return nil, fmt.Errorf("unsupported signature algorithm %q", r.SignatureAlgorithm)
	}

	count := receiptSignedFieldCount
	if includeSignature {
		count = receiptFieldCount
	}

	e := &cborEncoder{}
	e.mapHeader(count)

	e.key(keyReceiptVersion)
	e.uint(uint64(r.ReceiptVersion))
	e.key(keyReceiptID)
	e.bytes(r.ReceiptID[:])
	e.key(keyReceiptBundleID)
	e.bytes(r.BundleID[:])
	e.key(keyReceiptDeviceID)
	e.bytes(r.DeviceID[:])
	e.key(keyReceiptRoot)
	e.bytes(r.ContentRoot[:])
	e.key(keyServerIngestUTC)
	e.uint(r.ServerIngestUTCMS)
	e.key(keyServerKeyID)
	e.bytes(r.ServerKeyID[:])
	e.key(keyIngestSchemaVer)
	e.uint(uint64(r.IngestSchemaVersion))

	e.key(keyStoredObjectIDs)
	e.arrayHeader(len(r.StoredObjectIDs))
	for _, id := range r.StoredObjectIDs {
		e.text(id)
	}

	e.key(keyReceiptSigAlgo)
	e.text(r.SignatureAlgorithm)

	if includeSignature {
		e.key(keyReceiptSig)
		e.bytes(r.Signature[:])
	}

	return e.buf, nil
}

// SigningBytes returns the deterministic encoding of keys 1 through 10, which
// is what the signature covers.
func (r *Receipt) SigningBytes() ([]byte, error) { return r.encodeFields(false) }

// MarshalCBOR encodes the complete receipt, signature included.
func (r *Receipt) MarshalCBOR() ([]byte, error) { return r.encodeFields(true) }

// Sign populates r.Signature and returns the complete encoded receipt.
func (r *Receipt) Sign(priv ed25519.PrivateKey) ([]byte, error) {
	signing, err := r.SigningBytes()
	if err != nil {
		return nil, err
	}
	copy(r.Signature[:], ed25519.Sign(priv, signing))
	return r.MarshalCBOR()
}

// Verify checks the receipt's signature against a pinned server public key.
//
// This is the device-side gate on deletion. It re-derives the signed byte
// sequence from the parsed fields rather than trusting any portion of the
// received bytes, so a receipt that is not canonically encoded cannot verify.
func (r *Receipt) Verify(pub ed25519.PublicKey) error {
	signing, err := r.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, signing, r.Signature[:]) {
		return ErrBadReceiptSignature
	}
	return nil
}

// VerifyAcknowledges checks that the receipt both verifies against the pinned
// key and acknowledges the specific content root the device uploaded.
//
// Both conditions are required. A validly signed receipt for a different bundle
// is not an acknowledgement of this one, and treating it as one would let a
// misconfigured or hostile server induce deletion of unacknowledged data.
func (r *Receipt) VerifyAcknowledges(pub ed25519.PublicKey, uploaded [32]byte) error {
	if err := r.Verify(pub); err != nil {
		return err
	}
	if r.ContentRoot != uploaded {
		return fmt.Errorf("%w: receipt covers %x, uploaded %x",
			ErrReceiptRootMismatch, r.ContentRoot, uploaded)
	}
	return nil
}

// ParseReceipt decodes a receipt and verifies that it is canonically encoded.
//
// The canonicality check matters more here than for the manifest: a receipt
// carries its signature inline, so verification must re-encode the signed
// fields. Accepting a non-canonical receipt would mean verifying bytes other
// than those received.
func ParseReceipt(b []byte) (*Receipt, error) {
	r, err := decodeReceipt(b)
	if err != nil {
		return nil, err
	}

	reencoded, err := r.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("re-encode decoded receipt: %w", err)
	}
	if !bytes.Equal(reencoded, b) {
		return nil, fmt.Errorf("%w: receipt does not round-trip to identical bytes", ErrNonCanonical)
	}

	return r, nil
}

func decodeReceipt(b []byte) (*Receipt, error) {
	d := &cborDecoder{buf: b}

	n, err := d.mapHeader()
	if err != nil {
		return nil, fmt.Errorf("receipt map header: %w", err)
	}
	if n != receiptFieldCount {
		return nil, fmt.Errorf("receipt has %d fields, expected %d", n, receiptFieldCount)
	}

	r := &Receipt{}

	for i := 0; i < n; i++ {
		key, err := d.uint()
		if err != nil {
			return nil, fmt.Errorf("receipt key %d: %w", i, err)
		}

		switch key {
		case keyReceiptVersion:
			if r.ReceiptVersion, err = d.uint8(); err != nil {
				return nil, fmt.Errorf("receipt_version: %w", err)
			}
			if r.ReceiptVersion != ReceiptVersion {
				return nil, fmt.Errorf("unsupported receipt_version %d (this implementation reads %d only)",
					r.ReceiptVersion, ReceiptVersion)
			}
		case keyReceiptID:
			if err = copyFixed(d, r.ReceiptID[:]); err != nil {
				return nil, fmt.Errorf("receipt_id: %w", err)
			}
		case keyReceiptDeviceID:
			if err = copyFixed(d, r.DeviceID[:]); err != nil {
				return nil, fmt.Errorf("device_id: %w", err)
			}
		case keyReceiptBundleID:
			if err = copyFixed(d, r.BundleID[:]); err != nil {
				return nil, fmt.Errorf("bundle_id: %w", err)
			}
		case keyReceiptRoot:
			if err = copyFixed(d, r.ContentRoot[:]); err != nil {
				return nil, fmt.Errorf("content_root: %w", err)
			}
		case keyServerIngestUTC:
			if r.ServerIngestUTCMS, err = d.uint(); err != nil {
				return nil, fmt.Errorf("server_ingest_utc_ms: %w", err)
			}
		case keyServerKeyID:
			if err = copyFixed(d, r.ServerKeyID[:]); err != nil {
				return nil, fmt.Errorf("server_key_id: %w", err)
			}
		case keyIngestSchemaVer:
			if r.IngestSchemaVersion, err = d.uint8(); err != nil {
				return nil, fmt.Errorf("ingest_schema_version: %w", err)
			}
		case keyStoredObjectIDs:
			count, err := d.arrayHeader()
			if err != nil {
				return nil, fmt.Errorf("stored_object_ids: %w", err)
			}
			r.StoredObjectIDs = make([]string, 0, count)
			for j := 0; j < count; j++ {
				s, err := d.text()
				if err != nil {
					return nil, fmt.Errorf("stored_object_ids[%d]: %w", j, err)
				}
				r.StoredObjectIDs = append(r.StoredObjectIDs, s)
			}
		case keyReceiptSigAlgo:
			if r.SignatureAlgorithm, err = d.text(); err != nil {
				return nil, fmt.Errorf("signature_algorithm: %w", err)
			}
			if r.SignatureAlgorithm != SignatureAlgorithmEd25519 {
				return nil, fmt.Errorf("unsupported signature algorithm %q", r.SignatureAlgorithm)
			}
		case keyReceiptSig:
			if err = copyFixed(d, r.Signature[:]); err != nil {
				return nil, fmt.Errorf("signature: %w", err)
			}
		default:
			return nil, fmt.Errorf("unknown receipt key %d", key)
		}
	}

	if !d.atEnd() {
		return nil, fmt.Errorf("%d trailing bytes after receipt", len(b)-d.pos)
	}

	return r, nil
}
