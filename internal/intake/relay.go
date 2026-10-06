package intake

import (
	"errors"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
)

// ErrNoReceipt means the bundle is known but has no receipt yet: it has been
// offered and not (successfully) committed.
var ErrNoReceipt = errors.New("no receipt for this bundle yet")

// OfferedVehicle returns the vehicle an offered bundle's manifest binds it to.
//
// The relay needs it to check a client's scope on the requests that do not carry
// the manifest (chunk upload, commit, receipt fetch): the manifest was verified
// at offer time, so what is stored is the signed claim, not the caller's word.
// A bundle that was never offered, or whose offer record has been swept, is
// ErrUnknownBundle.
func (s *Service) OfferedVehicle(bundleID [16]byte) ([16]byte, error) {
	m, _, _, err := s.loadOffer(bundleID)
	if err != nil {
		return [16]byte{}, err
	}
	return m.VehicleID, nil
}

// ReceiptFor returns the committed receipt for an offered bundle, byte-for-byte
// as issued (the device verifies a signature over exactly those bytes).
//
// It exists for a relay that lost the receipt between commit and handing it to
// the device. It does not commit anything: a bundle that is not yet committed is
// ErrNoReceipt, and one whose offer record is gone is ErrUnknownBundle, in which
// case re-offering returns the existing receipt by content root.
func (s *Service) ReceiptFor(bundleID [16]byte) (*format.Receipt, []byte, error) {
	m, _, _, err := s.loadOffer(bundleID)
	if err != nil {
		return nil, nil, err
	}
	r, encoded, err := s.receipts.Lookup(m.ContentRoot)
	if errors.Is(err, receipts.ErrNotFound) {
		return nil, nil, ErrNoReceipt
	}
	if err != nil {
		return nil, nil, err
	}
	return r, encoded, nil
}

// OfferOutstanding reports whether a bundle has an offer on record that has not
// been committed: the offer record exists and its content root has no receipt.
//
// The relay uses it to count how many transfers a client has in flight. A
// committed bundle, a swept record and a bundle that was never offered all answer
// false, so a slot held for one of them is free to be reused.
func (s *Service) OfferOutstanding(bundleID [16]byte) bool {
	m, _, _, err := s.loadOffer(bundleID)
	if err != nil {
		return false
	}
	return !s.HasReceipt(m.ContentRoot)
}

// HasReceipt reports whether a content root has already been receipted. A
// lookup failure other than "not found" is treated as no receipt: the callers
// use this to decide whether something is still outstanding, and counting it
// as outstanding is the safe direction.
func (s *Service) HasReceipt(contentRoot [32]byte) bool {
	_, _, err := s.receipts.Lookup(contentRoot)
	return err == nil
}
