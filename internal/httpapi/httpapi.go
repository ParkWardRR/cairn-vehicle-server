// Package httpapi exposes the v2 intake protocol over HTTP.
//
// The transport is deliberately thin. All validation lives in the intake
// service, so these handlers only decode requests, enforce request-level
// limits, map errors to status codes, and encode responses. A handler that
// made its own trust decisions would be a second place for the rules to drift.
//
// Wire shapes are chosen for a constrained client. The manifest and chunks
// travel as raw bodies rather than wrapped in a container, and the signature
// travels in a fixed-width hex header, so the firmware never has to build a
// multipart body or stream-encode anything. Control responses are JSON because
// they are small and worth being able to read with curl; the receipt is
// returned as raw CBOR because the device verifies a signature over exactly
// those bytes.
package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
	"github.com/ParkWardRR/Cairn/server/internal/devices"
	"github.com/ParkWardRR/Cairn/server/internal/intake"
	"github.com/ParkWardRR/Cairn/server/internal/outbox"
	"github.com/ParkWardRR/Cairn/server/internal/receipts"
)

// SignatureHeader carries the hex-encoded Ed25519 manifest signature.
const SignatureHeader = "X-Cairn-Signature"

// ContentTypeCBOR is used for manifests and receipts.
const ContentTypeCBOR = "application/cbor"

// Server wires the intake service to HTTP.
type Server struct {
	intake   *intake.Service
	receipts *receipts.Store
	registry *devices.Registry
	outbox   *outbox.Queue
	limiter  *Limiter
	log      *slog.Logger

	// requireClientCert makes the handlers insist that the mTLS client
	// certificate identify the same device the manifest claims.
	requireClientCert bool

	// firmwareDir holds signed update descriptors and images. Empty disables
	// the firmware endpoints entirely rather than serving 404s, so a deployment
	// that does not do OTA presents no such surface.
	firmwareDir string
}

// Config configures a Server.
type Config struct {
	Intake   *intake.Service
	Receipts *receipts.Store
	Registry *devices.Registry
	Outbox   *outbox.Queue
	Limiter  *Limiter
	Log      *slog.Logger

	// RequireClientCert should be true whenever TLS client authentication is
	// configured. It is what binds the transport identity to the manifest's
	// claimed identity; without it, a valid signature from any enrolled device
	// would be accepted over any connection.
	RequireClientCert bool

	// FirmwareDir enables the OTA endpoints. Empty leaves them unregistered.
	FirmwareDir string
}

// New creates a Server.
func New(cfg Config) *Server {
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		intake:            cfg.Intake,
		receipts:          cfg.Receipts,
		registry:          cfg.Registry,
		outbox:            cfg.Outbox,
		limiter:           cfg.Limiter,
		log:               log,
		requireClientCert: cfg.RequireClientCert,
		firmwareDir:       cfg.FirmwareDir,
	}
}

// Routes returns the HTTP handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v2/health", s.handleHealth)
	mux.HandleFunc("GET /api/v2/server/receipt-key", s.handleReceiptKey)

	// Firmware. Served only when a directory was configured, so a deployment
	// that does not do OTA has no such surface at all.
	if s.firmwareDir != "" {
		mux.HandleFunc("GET /api/v2/firmware/latest", s.handleFirmwareLatest)
		mux.HandleFunc("GET /api/v2/firmware/{digest}/image", s.handleFirmwareImage)
	}

	mux.HandleFunc("POST /api/v2/bundles/offer", s.handleOffer)
	mux.HandleFunc("PUT /api/v2/bundles/{bundleID}/chunks/{digest}", s.handleChunk)
	mux.HandleFunc("POST /api/v2/bundles/{bundleID}/commit", s.handleCommit)

	return s.withLogging(mux)
}

// ─── health and provisioning ────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	backlog, err := s.outbox.PendingCount()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "outbox unreadable", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "ok",
		"ingest_schema_version": receipts.IngestSchemaVersion,
		"format_version":        format.FormatVersion,
		"decode_backlog":        backlog,
	})
}

// handleReceiptKey serves the receipt verification key for device provisioning.
// A device pins this and refuses to prune on anything it cannot verify.
func (s *Server) handleReceiptKey(w http.ResponseWriter, r *http.Request) {
	keyID := s.receipts.KeyID()
	writeJSON(w, http.StatusOK, map[string]any{
		"public_key": s.receipts.PublicKeyHex(),
		"key_id":     hex.EncodeToString(keyID[:]),
		"algorithm":  format.SignatureAlgorithmEd25519,
	})
}

// ─── offer ──────────────────────────────────────────────────────────────────

type offerResponse struct {
	BundleID         string   `json:"bundle_id"`
	MissingChunks    []uint32 `json:"missing_chunks"`
	TotalChunks      int      `json:"total_chunks"`
	BytesExpected    int64    `json:"bytes_expected"`
	BytesOutstanding int64    `json:"bytes_outstanding"`

	// ReceiptAvailable tells the device to fetch its receipt via commit rather
	// than transferring anything. The bytes are not inlined here because the
	// device verifies a signature over the exact CBOR encoding, and embedding
	// them in JSON would invite a re-encoding step.
	ReceiptAvailable bool `json:"receipt_available"`
}

func (s *Server) handleOffer(w http.ResponseWriter, r *http.Request) {
	sigHex := r.Header.Get(SignatureHeader)
	if sigHex == "" {
		s.fail(w, r, http.StatusBadRequest, "missing "+SignatureHeader, nil)
		return
	}
	signature, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "signature is not valid hex", err)
		return
	}

	manifestBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intake.MaxManifestSize+1))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, "manifest body too large or unreadable", err)
		return
	}

	// Bind the transport identity to the claimed identity before doing work.
	if err := s.checkClientIdentity(r, manifestBytes); err != nil {
		s.fail(w, r, http.StatusForbidden, "client certificate does not match the manifest device", err)
		return
	}

	if err := s.allow(r, manifestBytes); err != nil {
		s.fail(w, r, http.StatusTooManyRequests, "rate limit exceeded", err)
		return
	}

	result, err := s.intake.Offer(manifestBytes, signature)
	if err != nil {
		s.failIntake(w, r, err)
		return
	}

	resp := offerResponse{
		BundleID:         hex.EncodeToString(result.BundleID[:]),
		MissingChunks:    result.MissingChunks,
		TotalChunks:      result.TotalChunks,
		BytesExpected:    result.BytesExpected,
		BytesOutstanding: result.BytesOutstanding,
		ReceiptAvailable: result.ExistingReceipt != nil,
	}
	if resp.MissingChunks == nil {
		resp.MissingChunks = []uint32{}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ─── chunk ──────────────────────────────────────────────────────────────────

type chunkResponse struct {
	Accepted      bool     `json:"accepted"`
	MissingChunks []uint32 `json:"missing_chunks"`
}

func (s *Server) handleChunk(w http.ResponseWriter, r *http.Request) {
	bundleID, err := parseID16(r.PathValue("bundleID"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid bundle id", err)
		return
	}
	digest, err := parseDigest(r.PathValue("digest"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid chunk digest", err)
		return
	}

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, intake.MaxChunkSize+1))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, "chunk too large or unreadable", err)
		return
	}

	missing, err := s.intake.AcceptChunk(bundleID, digest, data)
	if err != nil {
		s.failIntake(w, r, err)
		return
	}

	if missing == nil {
		missing = []uint32{}
	}
	writeJSON(w, http.StatusOK, chunkResponse{Accepted: true, MissingChunks: missing})
}

// ─── commit ─────────────────────────────────────────────────────────────────

// handleCommit returns the receipt as raw CBOR.
//
// The device verifies an Ed25519 signature over exactly these bytes, so they
// are returned verbatim rather than wrapped in JSON. Any envelope would create
// a decode-and-re-encode step on the device, which is precisely where a
// canonical-encoding bug would hide.
func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request) {
	bundleID, err := parseID16(r.PathValue("bundleID"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid bundle id", err)
		return
	}

	result, err := s.intake.Commit(bundleID)

	// Commit can return a usable receipt alongside an error: the bundle is
	// durably stored and receipted, but enqueueing the decode work failed. The
	// device is safe and must be told so, because withholding the receipt would
	// make it retain data it has already successfully delivered.
	if result != nil && result.Receipt != nil {
		if err != nil {
			s.log.Error("bundle committed and receipted but post-commit work failed",
				"bundle_id", hex.EncodeToString(bundleID[:]), "error", err)
		}

		w.Header().Set("Content-Type", ContentTypeCBOR)
		w.Header().Set("X-Cairn-Receipt-Id", hex.EncodeToString(result.Receipt.ReceiptID[:]))
		if result.AlreadyCommitted {
			w.Header().Set("X-Cairn-Already-Committed", "1")
		}
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write(result.ReceiptBytes); writeErr != nil {
			s.log.Warn("writing receipt to client failed", "error", writeErr)
		}
		return
	}

	if err != nil {
		s.failIntake(w, r, err)
		return
	}

	s.fail(w, r, http.StatusInternalServerError, "commit produced no receipt and no error", nil)
}

// ─── identity binding ───────────────────────────────────────────────────────

// checkClientIdentity requires the mTLS client certificate to name the same
// device the manifest claims.
//
// mTLS alone proves only that *some* enrolled device opened the connection.
// Without this check, a device could upload bundles attributed to another, and
// a compromised unit's reach would extend to every identity whose signing key
// it could obtain.
func (s *Server) checkClientIdentity(r *http.Request, manifestBytes []byte) error {
	if !s.requireClientCert {
		return nil
	}

	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate presented")
	}

	certDevice := r.TLS.PeerCertificates[0].Subject.CommonName
	manifest, err := format.ParseManifest(manifestBytes)
	if err != nil {
		return fmt.Errorf("parse manifest for identity check: %w", err)
	}

	claimed := hex.EncodeToString(manifest.DeviceID[:])
	if !strings.EqualFold(certDevice, claimed) {
		return fmt.Errorf("certificate names device %q but the manifest claims %q", certDevice, claimed)
	}
	return nil
}

// allow applies the per-device rate limit.
func (s *Server) allow(r *http.Request, manifestBytes []byte) error {
	if s.limiter == nil {
		return nil
	}

	key := "anonymous"
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		key = r.TLS.PeerCertificates[0].Subject.CommonName
	} else if m, err := format.ParseManifest(manifestBytes); err == nil {
		key = hex.EncodeToString(m.DeviceID[:])
	}

	if !s.limiter.Allow(key) {
		return fmt.Errorf("device %s exceeded its request allowance", key)
	}
	return nil
}

// ─── error mapping ──────────────────────────────────────────────────────────

// failIntake maps a domain error to a status code.
//
// The distinction that matters is 4xx versus 5xx: a device must be able to tell
// "stop retrying, this will never work" from "try again later". Getting this
// wrong makes a device either give up on recoverable trouble or hammer the
// server over a permanent rejection.
func (s *Server) failIntake(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, devices.ErrUnknown):
		s.fail(w, r, http.StatusForbidden, "device not enrolled", err)
	case errors.Is(err, devices.ErrRevoked):
		s.fail(w, r, http.StatusForbidden, "device revoked", err)
	case errors.Is(err, devices.ErrKeyIDMismatch):
		s.fail(w, r, http.StatusForbidden, "manifest key does not match the enrolled device key", err)
	case errors.Is(err, devices.ErrQuotaExceeded):
		s.fail(w, r, http.StatusInsufficientStorage, "device storage quota exceeded", err)

	// v3 binding. A refused assignment or a missing storage key is the device's
	// enrolment being wrong, fixable by an administrator, so 403 like the other
	// enrolment failures. A quarantined bundle is permanent — the same bytes
	// will be refused the same way — so 422 tells the device to stop retrying.
	case errors.Is(err, intake.ErrAssignmentRefused):
		s.fail(w, r, http.StatusForbidden, "vehicle assignment refused", err)
	case errors.Is(err, intake.ErrNoStorageKey):
		s.fail(w, r, http.StatusForbidden, "no escrowed storage key for this device", err)
	case errors.Is(err, intake.ErrQuarantined):
		s.fail(w, r, http.StatusUnprocessableEntity, "bundle quarantined", err)

	case errors.Is(err, format.ErrBadSignature):
		s.fail(w, r, http.StatusUnauthorized, "manifest signature verification failed", err)
	case errors.Is(err, format.ErrNonCanonical):
		s.fail(w, r, http.StatusBadRequest, "manifest is not canonically encoded", err)
	case errors.Is(err, format.ErrContentRootMismatch):
		s.fail(w, r, http.StatusUnprocessableEntity, "content root does not match the data", err)

	case errors.Is(err, intake.ErrManifestInconsistent):
		s.fail(w, r, http.StatusUnprocessableEntity, "manifest is internally inconsistent", err)
	case errors.Is(err, intake.ErrMemberDigestMismatch):
		s.fail(w, r, http.StatusUnprocessableEntity, "uploaded data does not match the manifest", err)
	case errors.Is(err, intake.ErrUnknownBundle):
		s.fail(w, r, http.StatusNotFound, "no offer on record for this bundle", err)
	case errors.Is(err, intake.ErrChunkNotInManifest):
		s.fail(w, r, http.StatusBadRequest, "chunk is not part of this bundle", err)
	case errors.Is(err, intake.ErrChunksMissing):
		// Not an error the device should give up on: it simply has more to send.
		s.fail(w, r, http.StatusConflict, "chunks are still missing", err)
	case errors.Is(err, cas.ErrDigestMismatch):
		s.fail(w, r, http.StatusBadRequest, "data does not match its declared digest", err)

	default:
		s.fail(w, r, http.StatusInternalServerError, "internal error", err)
	}
}

type errorResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, code int, message string, err error) {
	resp := errorResponse{Error: message}

	// 4xx is the device's problem to fix, so detail helps it and its operator.
	// 5xx detail stays in the log: it describes server internals.
	if err != nil && code < 500 {
		resp.Detail = err.Error()
	}

	level := slog.LevelWarn
	if code >= 500 {
		level = slog.LevelError
	}
	s.log.Log(r.Context(), level, "request rejected",
		"status", code, "message", message, "method", r.Method, "path", r.URL.Path, "error", err)

	writeJSON(w, code, resp)
}

// ─── helpers ────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func parseID16(s string) ([16]byte, error) {
	var id [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return id, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != 16 {
		return id, fmt.Errorf("%d bytes, want 16", len(raw))
	}
	copy(id[:], raw)
	return id, nil
}

func parseDigest(s string) ([32]byte, error) {
	var d [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return d, fmt.Errorf("not hex: %w", err)
	}
	if len(raw) != 32 {
		return d, fmt.Errorf("%d bytes, want 32", len(raw))
	}
	copy(d[:], raw)
	return d, nil
}

// withLogging records every request. Receipt verification failures and
// certificate problems are the events worth auditing, and they all arrive here.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		device := ""
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			device = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		next.ServeHTTP(w, r)

		s.log.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"device", device,
			"duration_ms", time.Since(start).Milliseconds())
	})
}
