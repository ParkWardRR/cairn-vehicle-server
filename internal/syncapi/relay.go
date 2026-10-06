package syncapi

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/intake"
)

// The bundle relay: the enrolled phone uploads a dongle's sealed bundles on its
// behalf (contracts/sync/v1/spec.md section 13, contracts/ble/v1/offload.md).
//
// The dongle has no network, so these endpoints replace the device-facing intake
// listener for it. They add NO trust decisions of their own. Every check that
// decides whether a bundle is accepted (the device's manifest signature, the
// open assignment, the counter guard, quarantine, the escrowed storage key, chunk
// hashes, the content root) is intake.Service's, unchanged. What the relay adds is
// the authentication of the CALLER, and one extra rule: the caller's scope must
// include the bundle's vehicle.
//
// The caller is trusted for availability only. It can refuse to relay, or relay
// garbage, and the worst outcome is that no receipt is issued and the data stays
// on the dongle.

const (
	// relayChunkLimit bounds a chunk body. The app API caps ordinary bodies at 1
	// MiB; a chunk may be as large as intake accepts.
	relayChunkLimit = intake.MaxChunkSize + 1<<10

	// SignatureHeader carries the device's hex Ed25519 signature over the manifest.
	SignatureHeader = "X-Cairn-Signature"
)

type relayChunk struct {
	Index  uint32 `json:"index"`
	Offset uint64 `json:"offset"`
	Length uint32 `json:"length"`
	SHA256 string `json:"sha256"`
}

type relayOfferResponse struct {
	BundleID         string       `json:"bundle_id"`
	MissingChunks    []relayChunk `json:"missing_chunks"`
	TotalChunks      int          `json:"total_chunks"`
	BytesExpected    int64        `json:"bytes_expected"`
	BytesOutstanding int64        `json:"bytes_outstanding"`
	ReceiptAvailable bool         `json:"receipt_available"`
}

func (s *Server) registerRelay(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/relay/bundles/offer",
		s.route("POST /v1/relay/bundles/offer", authEither, s.handleRelayOffer))
	mux.HandleFunc("PUT /v1/relay/bundles/{bundleID}/chunks/{digest}",
		s.routeLimit("PUT /v1/relay/bundles/{id}/chunks/{digest}", authEither, relayChunkLimit, s.handleRelayChunk))
	mux.HandleFunc("POST /v1/relay/bundles/{bundleID}/commit",
		s.route("POST /v1/relay/bundles/{id}/commit", authEither, s.handleRelayCommit))
	mux.HandleFunc("GET /v1/relay/bundles/{bundleID}/receipt",
		s.route("GET /v1/relay/bundles/{id}/receipt", authEither, s.handleRelayReceipt))
}

// inScope answers the scope question for a vehicle. The answer is the same
// whether or not the vehicle exists, so the relay cannot be used to probe for
// other cars.
func (s *Server) relayScope(q *request, vehicle [16]byte) (int, string, bool) {
	if q.client.InScope(hex.EncodeToString(vehicle[:])) {
		return 0, "", true
	}
	s.writeError(q.w, http.StatusForbidden, "scope", "that vehicle is outside this client's scope")
	return http.StatusForbidden, "vehicle out of scope", false
}

// maxOffers is the effective per-client cap on outstanding offers; negative
// means unlimited.
func (s *Server) maxOffers() int {
	if s.cfg.MaxOffersPerClient == 0 {
		return DefaultMaxOffersPerClient
	}
	return s.cfg.MaxOffersPerClient
}

// clientOffers is one client's set of outstanding offers. The lock is per client,
// so the cap is exact under concurrent offers without one client's slow offer
// holding up another's.
type clientOffers struct {
	mu      sync.Mutex
	bundles map[[16]byte]struct{}
}

func (s *Server) offersOf(clientID string) *clientOffers {
	s.offerMu.Lock()
	defer s.offerMu.Unlock()
	c := s.offers[clientID]
	if c == nil {
		c = &clientOffers{bundles: map[[16]byte]struct{}{}}
		s.offers[clientID] = c
	}
	return c
}

// offerAllowed reports whether the client may open a transfer for this bundle.
// The caller holds c.mu.
//
// A slot is only ever spent on work that is still outstanding. A bundle the
// client already holds is not counted twice (a phone retrying an offer must never
// lock itself out), a content root that already has a receipt costs nothing, and
// slots whose bundle has since been committed or swept are reclaimed here, before
// the cap is enforced, whoever committed them. Nothing is released eagerly: a
// slot that no longer has an outstanding offer behind it is simply not counted.
func (s *Server) offerAllowed(c *clientOffers, bundle [16]byte, root [32]byte) bool {
	limit := s.maxOffers()
	if _, dup := c.bundles[bundle]; dup || limit < 0 {
		return true
	}
	if len(c.bundles) >= limit {
		for id := range c.bundles {
			if !s.cfg.Intake.OfferOutstanding(id) {
				delete(c.bundles, id)
			}
		}
	}
	if len(c.bundles) < limit {
		return true
	}
	// Full of genuinely outstanding transfers. Only an offer that will be answered
	// from an existing receipt, which records nothing, may pass.
	return s.cfg.Intake.HasReceipt(root)
}

// offerWithinCap runs intake's Offer under the client's cap. tooMany means the
// cap refused it and intake was not called, so nothing was written.
func (s *Server) offerWithinCap(clientID string, m *format.Manifest, body, sig []byte) (res *intake.OfferResult, tooMany bool, err error) {
	if s.maxOffers() < 0 {
		res, err = s.cfg.Intake.Offer(body, sig)
		return res, false, err
	}
	c := s.offersOf(clientID)
	c.mu.Lock()
	defer c.mu.Unlock()

	if !s.offerAllowed(c, m.BundleID, m.ContentRoot) {
		return nil, true, nil
	}
	res, err = s.cfg.Intake.Offer(body, sig)
	// Only an offer intake accepted and left outstanding takes a slot: a refused or
	// forged manifest, or one answered from a receipt, wrote nothing to wait on.
	if err == nil && res.ExistingReceipt == nil {
		c.bundles[m.BundleID] = struct{}{}
	}
	return res, false, err
}

func (s *Server) handleRelayOffer(q *request) (int, string) {
	sig, err := hex.DecodeString(strings.TrimSpace(q.r.Header.Get(SignatureHeader)))
	if err != nil || len(sig) != 64 {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", SignatureHeader+" must be 128 hex characters")
		return http.StatusBadRequest, "bad signature header"
	}

	// Parse before trusting: only to learn the claimed vehicle for the scope
	// check. The signature is verified over these exact bytes inside Offer, so a
	// forged claim fails there; an out-of-scope one is refused before any state is
	// written.
	manifest, err := format.ParseManifest(q.body)
	if err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "the manifest could not be parsed")
		return http.StatusBadRequest, "unparseable manifest"
	}
	q.target = hex.EncodeToString(manifest.BundleID[:])
	q.device = hex.EncodeToString(manifest.DeviceID[:])

	if status, reason, ok := s.relayScope(q, manifest.VehicleID); !ok {
		return status, reason
	}

	// The cap is per authenticated client, so one phone cannot use up another's
	// slots.
	result, tooMany, err := s.offerWithinCap(q.client.ID, manifest, q.body, sig)
	if tooMany {
		s.writeError(q.w, http.StatusTooManyRequests, "too_many_offers",
			"too many bundles are offered and not yet committed; commit some, then retry")
		return http.StatusTooManyRequests, "too many outstanding offers"
	}
	if err != nil {
		return s.relayFail(q, err)
	}

	resp := relayOfferResponse{
		BundleID:         hex.EncodeToString(result.BundleID[:]),
		MissingChunks:    []relayChunk{},
		TotalChunks:      result.TotalChunks,
		BytesExpected:    result.BytesExpected,
		BytesOutstanding: result.BytesOutstanding,
		ReceiptAvailable: result.ExistingReceipt != nil,
	}

	// Offsets are the sum of the preceding chunk lengths: chunks partition the
	// bundle byte stream in order, without gaps (bundle-format-v3 section 6.1). The
	// phone reads exactly these ranges from the dongle, so it needs no CBOR parser.
	offsets := make([]uint64, len(manifest.ChunkDescriptors))
	var at uint64
	for i, c := range manifest.ChunkDescriptors {
		offsets[i] = at
		at += uint64(c.ByteLength)
	}
	for _, idx := range result.MissingChunks {
		if int(idx) >= len(manifest.ChunkDescriptors) {
			continue // cannot happen for a manifest intake accepted; never index blind
		}
		c := manifest.ChunkDescriptors[idx]
		resp.MissingChunks = append(resp.MissingChunks, relayChunk{
			Index: c.Index, Offset: offsets[idx], Length: c.ByteLength,
			SHA256: hex.EncodeToString(c.SHA256[:]),
		})
	}

	s.writeJSON(q.w, http.StatusOK, resp)
	return http.StatusOK, ""
}

// relayBundle resolves {bundleID} and applies the scope rule through the stored,
// verified manifest. A false return means the response has been written.
func (s *Server) relayBundle(q *request) ([16]byte, int, string, bool) {
	var id [16]byte
	raw, err := hex.DecodeString(q.r.PathValue("bundleID"))
	if err != nil || len(raw) != 16 {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "bundle id must be 32 hex characters")
		return id, http.StatusBadRequest, "bad bundle id", false
	}
	copy(id[:], raw)
	q.target = hex.EncodeToString(id[:])

	vehicle, err := s.cfg.Intake.OfferedVehicle(id)
	if err != nil {
		status, reason := s.relayFail(q, err)
		return id, status, reason, false
	}
	if status, reason, ok := s.relayScope(q, vehicle); !ok {
		return id, status, reason, false
	}
	return id, 0, "", true
}

func (s *Server) handleRelayChunk(q *request) (int, string) {
	id, status, reason, ok := s.relayBundle(q)
	if !ok {
		return status, reason
	}
	raw, err := hex.DecodeString(q.r.PathValue("digest"))
	if err != nil || len(raw) != 32 {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "chunk digest must be 64 hex characters")
		return http.StatusBadRequest, "bad digest"
	}
	var digest [32]byte
	copy(digest[:], raw)

	missing, err := s.cfg.Intake.AcceptChunk(id, digest, q.body)
	if err != nil {
		return s.relayFail(q, err)
	}
	if missing == nil {
		missing = []uint32{}
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"accepted": true, "missing_chunks": missing})
	return http.StatusOK, ""
}

// writeReceipt returns the receipt as raw CBOR. The device verifies a signature
// over exactly these bytes, so they are never wrapped or re-encoded.
func (s *Server) writeReceipt(q *request, r *format.Receipt, encoded []byte, already bool) {
	q.w.Header().Set("Content-Type", "application/cbor")
	q.w.Header().Set("X-Cairn-Receipt-Id", hex.EncodeToString(r.ReceiptID[:]))
	if already {
		q.w.Header().Set("X-Cairn-Already-Committed", "1")
	}
	q.w.WriteHeader(http.StatusOK)
	if _, err := q.w.Write(encoded); err != nil {
		s.log.Warn("writing receipt failed", "error", err)
	}
}

func (s *Server) handleRelayCommit(q *request) (int, string) {
	id, status, reason, ok := s.relayBundle(q)
	if !ok {
		return status, reason
	}

	result, err := s.cfg.Intake.Commit(id)

	// Commit can return a usable receipt alongside an error: the bundle is
	// durable and receipted but enqueueing the decode work failed. The data is
	// safe and the dongle must be told so; withholding the receipt would make it
	// keep data that has already been delivered.
	if result != nil && result.Receipt != nil {
		if err != nil {
			s.log.Error("bundle committed and receipted but post-commit work failed",
				"bundle_id", q.target, "error", err)
		}
		s.writeReceipt(q, result.Receipt, result.ReceiptBytes, result.AlreadyCommitted)
		return http.StatusOK, ""
	}
	if err != nil {
		return s.relayFail(q, err)
	}
	s.writeError(q.w, http.StatusInternalServerError, "internal", "commit produced no receipt and no error")
	return http.StatusInternalServerError, "no receipt"
}

func (s *Server) handleRelayReceipt(q *request) (int, string) {
	id, status, reason, ok := s.relayBundle(q)
	if !ok {
		return status, reason
	}
	r, encoded, err := s.cfg.Intake.ReceiptFor(id)
	if err != nil {
		return s.relayFail(q, err)
	}
	s.writeReceipt(q, r, encoded, true)
	return http.StatusOK, ""
}

// relayFail maps an intake error to a status and a stable machine-readable
// code. The distinction that matters to the phone is retry versus stop: a
// 4xx other than 409/429 will not succeed on retry, a quarantined bundle never
// will, and 5xx is worth trying again later.
//
// Not every relay error comes through here. Two are decided by the relay itself:
//   - 403 scope: the bundle's vehicle is outside the caller's scope.
//   - 429 too_many_offers: the caller already has Config.MaxOffersPerClient
//     bundles offered and not committed. Retry after committing one; unlike a
//     refused bundle, nothing is wrong with the data.
func (s *Server) relayFail(q *request, err error) (int, string) {
	status, code, msg := http.StatusInternalServerError, "internal", "internal error"
	switch {
	case errors.Is(err, devices.ErrUnknown):
		status, code, msg = http.StatusForbidden, "device_not_enrolled", "device not enrolled"
	case errors.Is(err, devices.ErrRevoked):
		status, code, msg = http.StatusForbidden, "device_revoked", "device revoked"
	case errors.Is(err, devices.ErrKeyIDMismatch):
		status, code, msg = http.StatusForbidden, "device_key_mismatch", "manifest key does not match the enrolled device key"
	case errors.Is(err, devices.ErrQuotaExceeded):
		status, code, msg = http.StatusInsufficientStorage, "quota_exceeded", "device storage quota exceeded"

	case errors.Is(err, intake.ErrAssignmentRefused):
		status, code, msg = http.StatusForbidden, "assignment_refused", "vehicle assignment refused"
	case errors.Is(err, intake.ErrNoStorageKey):
		status, code, msg = http.StatusForbidden, "no_storage_key", "no escrowed storage key for this device"
	case errors.Is(err, intake.ErrQuarantined):
		status, code, msg = http.StatusUnprocessableEntity, "quarantined", "bundle quarantined"

	case errors.Is(err, format.ErrBadSignature):
		status, code, msg = http.StatusUnauthorized, "bad_manifest_signature", "manifest signature verification failed"
	case errors.Is(err, format.ErrNonCanonical):
		status, code, msg = http.StatusBadRequest, "non_canonical_manifest", "manifest is not canonically encoded"
	case errors.Is(err, format.ErrContentRootMismatch):
		status, code, msg = http.StatusUnprocessableEntity, "content_root_mismatch", "content root does not match the data"
	case errors.Is(err, intake.ErrManifestInconsistent):
		status, code, msg = http.StatusUnprocessableEntity, "manifest_inconsistent", "manifest is internally inconsistent"
	case errors.Is(err, intake.ErrMemberDigestMismatch):
		status, code, msg = http.StatusUnprocessableEntity, "data_mismatch", "uploaded data does not match the manifest"

	case errors.Is(err, intake.ErrUnknownBundle):
		status, code, msg = http.StatusNotFound, "unknown_bundle", "no offer on record for this bundle; offer it first"
	case errors.Is(err, intake.ErrNoReceipt):
		status, code, msg = http.StatusNotFound, "no_receipt", "this bundle has no receipt yet"
	case errors.Is(err, intake.ErrChunkNotInManifest):
		status, code, msg = http.StatusBadRequest, "chunk_not_in_manifest", "chunk is not part of this bundle"
	case errors.Is(err, intake.ErrChunkLength):
		status, code, msg = http.StatusConflict, "chunk_mismatch", "chunk length does not match the manifest"
	case errors.Is(err, intake.ErrChunksMissing):
		status, code, msg = http.StatusConflict, "chunks_missing", "chunks are still missing"
	case errors.Is(err, cas.ErrDigestMismatch):
		status, code, msg = http.StatusConflict, "chunk_mismatch", "data does not match its declared digest"
	}

	if status >= 500 {
		s.log.Error("relay request failed", "bundle", q.target, "error", err)
	}
	s.writeError(q.w, status, code, msg)
	return status, fmt.Sprintf("%s: %v", code, err)
}
