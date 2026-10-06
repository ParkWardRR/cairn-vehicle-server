package syncapi

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/audit"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/buildinfo"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/httpapi"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/intake"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/jsonstore"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// ProtocolVersion is reported by /v1/health so a client can refuse a server it
// does not speak.
const ProtocolVersion = 1

const (
	// maxBody bounds every request body, enrolment and push included, before
	// anything is parsed.
	maxBody = 1 << 20

	// maxOpsPerPush bounds one push. A backlog is split across several.
	maxOpsPerPush = 200

	defaultPullLimit = 100
	maxPullLimit     = 500

	// skew is how far a request timestamp may be from the server's clock. Wide
	// enough for a phone that has not synced its clock lately, narrow enough
	// that the nonce cache covering the window stays small.
	skew = 120 * time.Second

	// TokenTTL is how long a bearer token lasts.
	TokenTTL = time.Hour
)

// Config wires the app API to its dependencies.
type Config struct {
	Clients  *clients.Registry
	Vehicles *vehicles.Registry
	Devices  *devices.Registry

	// Intake, when set, enables the bundle relay (relay.go): the enrolled phone
	// uploads a dongle's sealed bundles on its behalf. Nil leaves the relay
	// routes unregistered, so a deployment without it presents no such surface.
	Intake *intake.Service
	Store  *Store
	Audit  *audit.Log

	Classifier *Classifier

	// InstanceID is the server's stable identifier, returned at enrolment and
	// by /v1/health so an app can tell it is talking to the same server over
	// the LAN and the tailnet.
	InstanceID string

	// SPKIPin is the SHA-256 of the TLS leaf's SubjectPublicKeyInfo, hex, handed
	// to the app at enrolment so it can pin. Empty when the listener is plain
	// HTTP behind a proxy that owns the certificate.
	SPKIPin string

	// SnapshotURL is the loopback cairn-tsdb base URL that /v1/snapshot proxies.
	// Empty disables the endpoint.
	SnapshotURL string

	// AckPath is where client acknowledgements are kept.
	AckPath string

	// MaxOffersPerClient bounds how many bundle offers one client may have
	// outstanding on the relay: offered and not yet committed. Zero means
	// DefaultMaxOffersPerClient; a negative value disables the limit. Beyond it
	// the relay answers 429 too_many_offers until the client commits one.
	// Re-offering a bundle the client already has outstanding, or one that is
	// already receipted, never counts. The count lives in memory, so a restart
	// starts every client at zero.
	MaxOffersPerClient int

	Limiter *httpapi.Limiter
	Log     *slog.Logger
	Now     func() time.Time
}

// DefaultMaxOffersPerClient is the relay's per-client cap on outstanding offers
// when Config.MaxOffersPerClient is zero. A phone moves a bundle at a time, so
// this is generous for a backlog of a few trips while still bounding the offer
// records and verified manifests one client can make the server hold.
const DefaultMaxOffersPerClient = 32

// Server is the app-facing API.
type Server struct {
	cfg  Config
	acks *jsonstore.Store[ackDoc]
	log  *slog.Logger
	now  func() time.Time

	mu     sync.Mutex
	nonces map[string]time.Time // client|nonce -> expiry
	tokens map[string]token     // sha256(token) hex -> token

	offerMu sync.Mutex
	offers  map[string]*clientOffers // client id -> its outstanding relay offers (relay.go)
}

type token struct {
	ClientID string
	Expires  time.Time
}

type ackDoc struct {
	Clients map[string]ackEntry `json:"clients"`
}

type ackEntry struct {
	Sequence uint64    `json:"sequence"`
	At       time.Time `json:"at"`
}

// New creates the server.
func New(cfg Config) (*Server, error) {
	if cfg.Clients == nil || cfg.Vehicles == nil || cfg.Store == nil || cfg.Audit == nil || cfg.Classifier == nil {
		return nil, errors.New("syncapi: clients, vehicles, store, audit and classifier are required")
	}
	if cfg.AckPath == "" {
		return nil, errors.New("syncapi: AckPath is required")
	}
	acks, err := jsonstore.Open(cfg.AckPath, func() ackDoc { return ackDoc{Clients: map[string]ackEntry{}} })
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, acks: acks,
		nonces: map[string]time.Time{}, tokens: map[string]token{},
		offers: map[string]*clientOffers{},
		log:    cfg.Log, now: cfg.Now,
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = func() time.Time { return time.Now().UTC() }
	}
	return s, nil
}

// Routes returns the handler.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/health", s.route("GET /v1/health", authNone, s.handleHealth))
	mux.HandleFunc("POST /v1/enroll/app", s.route("POST /v1/enroll/app", authNone, s.handleEnroll))
	mux.HandleFunc("POST /v1/auth/token", s.route("POST /v1/auth/token", authSigned, s.handleToken))

	mux.HandleFunc("POST /v1/sync/push", s.route("POST /v1/sync/push", authEither, s.handlePush))
	mux.HandleFunc("GET /v1/sync/pull", s.route("GET /v1/sync/pull", authEither, s.handlePull))
	mux.HandleFunc("POST /v1/sync/ack", s.route("POST /v1/sync/ack", authEither, s.handleAck))

	if s.cfg.Intake != nil {
		s.registerRelay(mux)
	}

	mux.HandleFunc("GET /v1/snapshot", s.route("GET /v1/snapshot", authEither, s.handleSnapshot))

	mux.HandleFunc("GET /v1/devices", s.route("GET /v1/devices", authAdmin, s.handleListDevices))
	mux.HandleFunc("POST /v1/devices/{id}/revoke", s.route("POST /v1/devices/{id}/revoke", authAdmin, s.handleRevokeDevice))
	mux.HandleFunc("GET /v1/clients", s.route("GET /v1/clients", authAdmin, s.handleListClients))
	mux.HandleFunc("POST /v1/clients/{id}/revoke", s.route("POST /v1/clients/{id}/revoke", authAdmin, s.handleRevokeClient))

	return mux
}

// ─── request pipeline ───────────────────────────────────────────────────────

type authMode int

const (
	authNone authMode = iota
	authSigned
	authEither // a signed request or a bearer token
	authAdmin  // a signed request from an admin client
)

// request is what a handler receives once the pipeline has accepted it.
type request struct {
	w      http.ResponseWriter
	r      *http.Request
	body   []byte
	info   TransportInfo
	client *clients.Client // nil for authNone routes

	// audit fields a handler may fill in
	target, device string
}

type handler func(*request) (status int, reason string)

// route wraps a handler in the pipeline, in the order that matters:
//
//  1. Funnel is refused first, before anything is read: a Funnel-exposed
//     listener has already stopped being private, and no later check restores
//     that.
//  2. The tailnet-identity rule, if configured.
//  3. A per-peer rate limit for unauthenticated routes, then per-client.
//  4. The body is read once, bounded, so the signature can cover its hash.
//  5. Authentication.
//  6. The handler, then one audit entry whatever happened.
func (s *Server) route(pattern string, mode authMode, h handler) http.HandlerFunc {
	return s.routeLimit(pattern, mode, maxBody, h)
}

// routeLimit is route with its own bound on the request body. Everything but the
// bundle relay's chunk upload uses the 1 MiB default.
func (s *Server) routeLimit(pattern string, mode authMode, limit int, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := s.cfg.Classifier.Classify(r)
		req := &request{w: w, r: r, info: info}

		entry := audit.Entry{
			Transport:      info.Class,
			TailscaleLogin: info.Login,
			Method:         r.Method,
			Route:          pattern,
			ActorType:      audit.ActorAnonymous,
		}
		finish := func(status int, reason string) {
			entry.Status, entry.Reason = status, reason
			if req.client != nil {
				entry.ActorType, entry.ActorID, entry.ClientID = audit.ActorApp, req.client.ID, req.client.ID
			}
			entry.TargetID, entry.DeviceID = req.target, req.device
			if len(req.body) > 0 {
				sum := sha256.Sum256(req.body)
				entry.BodySHA256 = hex.EncodeToString(sum[:])
			}
			if err := s.cfg.Audit.Append(entry); err != nil {
				s.log.Error("audit write failed", "error", err)
			}
		}

		if info.Funnel {
			s.writeError(w, http.StatusForbidden, "funnel_refused",
				"this service is private and must not be exposed through Tailscale Funnel")
			finish(http.StatusForbidden, "funnel marker present")
			return
		}
		if !s.cfg.Classifier.IdentityOK(info) {
			s.writeError(w, http.StatusForbidden, "tailnet_identity_required", "tailnet identity not permitted")
			finish(http.StatusForbidden, "tailnet identity rule")
			return
		}
		if s.cfg.Classifier.DenyOther && info.Class == TransportOther {
			s.writeError(w, http.StatusForbidden, "network_refused", "request arrived from an unexpected network")
			finish(http.StatusForbidden, "denied network")
			return
		}

		// Unauthenticated routes are limited by peer. Behind Serve every caller
		// is loopback, so this is coarse there — which is acceptable, because
		// what these routes expose is a health probe and a single-use code.
		if mode == authNone && s.cfg.Limiter != nil && !s.cfg.Limiter.Allow("peer:"+info.Peer.String()) {
			s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			finish(http.StatusTooManyRequests, "peer rate limit")
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)+1))
		if err != nil || len(body) > limit {
			s.writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			finish(http.StatusRequestEntityTooLarge, "body too large")
			return
		}
		req.body = body

		if mode != authNone {
			client, aerr := s.authenticate(r, body, mode)
			if aerr != nil {
				s.writeAuthError(w, aerr)
				// A failed signature names no actor: the claimed client is not
				// proven, so it is not recorded as the actor.
				finish(aerr.status, aerr.reason)
				return
			}
			req.client = client
			s.cfg.Clients.Touch(client.ID, info.Class)

			if s.cfg.Limiter != nil && !s.cfg.Limiter.Allow("client:"+client.ID) {
				s.writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				finish(http.StatusTooManyRequests, "client rate limit")
				return
			}
		}

		status, reason := h(req)
		finish(status, reason)
	}
}

type authError struct {
	status int
	code   string
	reason string
}

func (s *Server) writeAuthError(w http.ResponseWriter, e *authError) {
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", SigScheme)
	}
	s.writeError(w, e.status, e.code, "authentication failed")
}

// authenticate resolves the caller. Every failure reports the same generic
// message to the client and a specific reason to the audit log only, so a probe
// cannot learn which client IDs exist or which check it failed.
func (s *Server) authenticate(r *http.Request, body []byte, mode authMode) (*clients.Client, *authError) {
	header := r.Header.Get("Authorization")

	if rest, ok := strings.CutPrefix(header, "Bearer "); ok {
		if mode == authSigned || mode == authAdmin {
			return nil, &authError{http.StatusUnauthorized, "signature_required", "bearer token on a signed-only route"}
		}
		return s.authBearer(strings.TrimSpace(rest))
	}

	rest, ok := strings.CutPrefix(header, SigScheme+" ")
	if !ok {
		return nil, &authError{http.StatusUnauthorized, "unauthenticated", "no usable Authorization header"}
	}
	client, aerr := s.authSigned(r, body, rest)
	if aerr != nil {
		return nil, aerr
	}
	if mode == authAdmin && !client.IsAdmin() {
		return nil, &authError{http.StatusForbidden, "admin_required", "client is not an admin"}
	}
	return client, nil
}

func parseParams(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return out
}

func (s *Server) authSigned(r *http.Request, body []byte, params string) (*clients.Client, *authError) {
	p := parseParams(params)
	clientID, tsText, nonce, sigText := strings.ToLower(p["client"]), p["ts"], p["nonce"], p["sig"]
	bad := func(reason string) (*clients.Client, *authError) {
		return nil, &authError{http.StatusUnauthorized, "unauthenticated", reason}
	}
	if clientID == "" || tsText == "" || nonce == "" || sigText == "" {
		return bad("missing Authorization parameter")
	}
	if len(nonce) < 16 || len(nonce) > 64 {
		return bad("nonce length")
	}

	tsUnix, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil {
		return bad("timestamp is not an integer")
	}
	ts := time.Unix(tsUnix, 0)
	now := s.now()
	if d := now.Sub(ts); d > skew || d < -skew {
		return bad("timestamp outside the allowed window")
	}

	client, err := s.cfg.Clients.Get(clientID)
	if err != nil {
		return bad("unknown client")
	}
	pub, err := client.PublicKey()
	if err != nil {
		return bad("stored key unusable")
	}
	sig, err := clients.DecodeSignature(sigText)
	if err != nil {
		return bad("signature encoding")
	}

	msg := SigningString(r.Method, r.RequestURI, tsText, nonce, BodyHashHex(body), clientID)
	if !clients.VerifyDER(pub, []byte(msg), sig) {
		return bad("signature does not verify")
	}

	// Verified signature, so from here the claimed identity is proven; a
	// revoked client is told apart from a stranger in the audit log only.
	if !client.Active() {
		return nil, &authError{http.StatusUnauthorized, "unauthenticated", "client revoked"}
	}

	// Replay: a nonce is accepted once per client within the window. Checked
	// after the signature so unauthenticated junk cannot fill the cache.
	if !s.claimNonce(clientID, nonce, now) {
		return bad("nonce reused")
	}
	return client, nil
}

// claimNonce records a nonce, reporting false if it was already seen. The cache
// lives in memory: a restart clears it, so for up to the skew window after a
// restart an intercepted request could be replayed once more. That exposure is
// bounded by the timestamp window, and closing it would mean an fsync per
// request, which is not worth it for a single-user, private-network API.
func (s *Server) claimNonce(clientID, nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, k)
		}
	}
	key := clientID + "|" + nonce
	if _, seen := s.nonces[key]; seen {
		return false
	}
	s.nonces[key] = now.Add(2 * skew)
	return true
}

func (s *Server) authBearer(raw string) (*clients.Client, *authError) {
	sum := sha256.Sum256([]byte(raw))
	key := hex.EncodeToString(sum[:])

	s.mu.Lock()
	t, ok := s.tokens[key]
	if ok && s.now().After(t.Expires) {
		delete(s.tokens, key)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		return nil, &authError{http.StatusUnauthorized, "unauthenticated", "unknown or expired token"}
	}
	client, err := s.cfg.Clients.Get(t.ClientID)
	if err != nil || !client.Active() {
		// Revoking a client kills its tokens at the next request: they are
		// re-checked against the registry every time, not only at issue.
		return nil, &authError{http.StatusUnauthorized, "unauthenticated", "token's client is gone or revoked"}
	}
	return client, nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeJSON(w, status, errorBody{Error: code, Message: message})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ─── handlers ───────────────────────────────────────────────────────────────

func (s *Server) handleHealth(q *request) (int, string) {
	// Deliberately tiny and free of anything about devices or vehicles: it is
	// unauthenticated, and exists so an app can probe a route cheaply.
	s.writeJSON(q.w, http.StatusOK, map[string]any{
		"status":           "ok",
		"protocol_version": ProtocolVersion,
		"instance_id":      s.cfg.InstanceID,
		"server_time":      s.now().Format(time.RFC3339),
		"build":            buildinfo.Get(),
	})
	return http.StatusOK, ""
}

type enrollRequest struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`
}

func (s *Server) handleEnroll(q *request) (int, string) {
	var in enrollRequest
	if err := decodeStrict(q.body, &in); err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "malformed enrolment request")
		return http.StatusBadRequest, "malformed body"
	}
	proof, err := clients.DecodeSignature(in.Proof)
	if err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "proof is not base64")
		return http.StatusBadRequest, "proof encoding"
	}

	c, err := s.cfg.Clients.Enroll(clients.EnrollRequest{
		Code: in.Code, Name: in.Name, PublicKeyHex: in.PublicKey, Proof: proof,
	})
	switch {
	case err == nil:
	case errors.Is(err, clients.ErrBadKey), errors.Is(err, clients.ErrBadProof):
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "enrolment rejected")
		return http.StatusBadRequest, err.Error()
	default:
		// An invalid, expired or already-used code all look the same from
		// outside, so a stranger cannot tell which codes were ever real.
		s.writeError(q.w, http.StatusForbidden, "enrolment_refused", "enrolment rejected")
		return http.StatusForbidden, err.Error()
	}

	q.target = c.ID
	reason := ""
	if c.Replaces != "" {
		// Audit-only: which client this enrolment revoked.
		reason = "replaced_client=" + c.Replaces
	}
	s.writeJSON(q.w, http.StatusCreated, map[string]any{
		"client_id":   c.ID,
		"role":        c.Role,
		"vehicles":    c.Vehicles,
		"server_time": s.now().Format(time.RFC3339),
		"server_identity": map[string]any{
			"instance_id": s.cfg.InstanceID,
			"spki_sha256": s.cfg.SPKIPin,
		},
	})
	return http.StatusCreated, reason
}

func (s *Server) handleToken(q *request) (int, string) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not mint a token")
		return http.StatusInternalServerError, "rng"
	}
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(tok))
	exp := s.now().Add(TokenTTL)

	s.mu.Lock()
	now := s.now()
	for k, t := range s.tokens {
		if now.After(t.Expires) {
			delete(s.tokens, k)
		}
	}
	// Stored only as a hash: the token is a credential, and the server never
	// needs to see it again once it has been issued.
	s.tokens[hex.EncodeToString(sum[:])] = token{ClientID: q.client.ID, Expires: exp}
	s.mu.Unlock()

	s.writeJSON(q.w, http.StatusOK, map[string]any{
		"token":      tok,
		"expires_at": exp.Format(time.RFC3339),
		"scope":      "sync",
	})
	return http.StatusOK, ""
}

// gate implements Gate for one authenticated client.
type gate struct {
	client   *clients.Client
	vehicles *vehicles.Registry
}

func (g gate) InScope(vehicleID string) bool { return g.client.InScope(strings.ToLower(vehicleID)) }

func (g gate) VehicleStatus(vehicleID string) string {
	v, err := g.vehicles.Vehicle(vehicleID)
	switch {
	case err != nil:
		return ReasonUnknownVehicle
	case v.Archived():
		return ReasonArchivedVehicle
	}
	return ""
}

type pushRequest struct {
	Operations []Op `json:"operations"`
}

func (s *Server) handlePush(q *request) (int, string) {
	var in pushRequest
	if err := json.Unmarshal(q.body, &in); err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "malformed push")
		return http.StatusBadRequest, "malformed body"
	}
	if len(in.Operations) == 0 || len(in.Operations) > maxOpsPerPush {
		s.writeError(q.w, http.StatusBadRequest, "bad_request",
			fmt.Sprintf("a push carries 1 to %d operations", maxOpsPerPush))
		return http.StatusBadRequest, "operation count"
	}

	results, err := s.cfg.Store.ApplyBatch(q.client.ID, in.Operations, gate{q.client, s.cfg.Vehicles})
	if err != nil {
		s.log.Error("sync push failed", "error", err)
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not record the operations")
		return http.StatusInternalServerError, "store error"
	}

	s.writeJSON(q.w, http.StatusOK, map[string]any{
		"results": results,
		"head":    s.cfg.Store.Head(),
	})
	return http.StatusOK, ""
}

// ─── pull ───────────────────────────────────────────────────────────────────

func (s *Server) encodeCursor(seq uint64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("c1:" + s.cfg.Store.Epoch() + ":" + strconv.FormatUint(seq, 10)))
}

// decodeCursor parses a cursor. reset is true when it belongs to a different
// epoch — a wiped or replaced data directory — in which case the client must
// resync from scratch rather than be told it is up to date.
func (s *Server) decodeCursor(c string) (seq uint64, reset bool, err error) {
	if c == "" {
		return 0, false, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, false, errors.New("cursor is not valid")
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 3 || parts[0] != "c1" {
		return 0, false, errors.New("cursor is not valid")
	}
	n, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return 0, false, errors.New("cursor is not valid")
	}
	if parts[1] != s.cfg.Store.Epoch() {
		return 0, true, nil
	}
	return n, false, nil
}

type change struct {
	ServerSequence uint64          `json:"server_sequence"`
	At             int64           `json:"at"`
	Type           string          `json:"type"` // "operation" or "entity"
	Operation      *storedOp       `json:"operation,omitempty"`
	EntityType     string          `json:"entity_type,omitempty"`
	EntityID       string          `json:"entity_id,omitempty"`
	VehicleID      string          `json:"vehicle_id,omitempty"`
	Data           json.RawMessage `json:"data,omitempty"`
}

func (s *Server) handlePull(q *request) (int, string) {
	after, reset, err := s.decodeCursor(q.r.URL.Query().Get("cursor"))
	if err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_cursor", err.Error())
		return http.StatusBadRequest, "bad cursor"
	}
	if reset {
		// 410: the log this cursor points into no longer exists. Saying
		// "nothing new" would leave the client silently missing everything.
		s.writeJSON(q.w, http.StatusGone, map[string]any{
			"error": "cursor_reset", "message": "the server's data was reset; resync from scratch",
			"epoch": s.cfg.Store.Epoch(),
		})
		return http.StatusGone, "epoch changed"
	}

	limit := defaultPullLimit
	if v := q.r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			s.writeError(q.w, http.StatusBadRequest, "bad_request", "limit must be a positive integer")
			return http.StatusBadRequest, "bad limit"
		}
		limit = min(n, maxPullLimit)
	}

	// Bring the registries' vehicles and assignments into the log first, so a
	// pull always reflects them; unchanged ones are no-ops.
	if err := s.reconcile(); err != nil {
		s.log.Error("reconciling registries into the sync log failed", "error", err)
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not prepare the pull")
		return http.StatusInternalServerError, "reconcile"
	}

	recs, last, head, err := s.cfg.Store.scan(after, limit, func(rec *record) bool {
		return q.client.InScope(rec.vehicle())
	})
	switch {
	case errors.Is(err, ErrBehindLog):
		s.writeJSON(q.w, http.StatusGone, map[string]any{"error": "cursor_reset", "epoch": s.cfg.Store.Epoch()})
		return http.StatusGone, "behind log"
	case err != nil:
		s.writeError(q.w, http.StatusBadRequest, "bad_cursor", err.Error())
		return http.StatusBadRequest, "cursor ahead"
	}

	changes := make([]change, 0, len(recs))
	for _, rec := range recs {
		c := change{ServerSequence: rec.Seq, At: rec.At}
		if rec.Op != nil {
			c.Type, c.Operation = "operation", rec.Op
		} else {
			c.Type, c.EntityType, c.EntityID, c.VehicleID, c.Data = "entity", rec.EntityType, rec.EntityID, rec.VehicleID, rec.Data
		}
		changes = append(changes, c)
	}

	s.writeJSON(q.w, http.StatusOK, map[string]any{
		"epoch":    s.cfg.Store.Epoch(),
		"changes":  changes,
		"cursor":   s.encodeCursor(last),
		"has_more": last < head,
	})
	return http.StatusOK, ""
}

// reconcile publishes the vehicle and assignment registries into the log as
// entities, so clients receive them through the same cursor as everything else.
// Only display fields go out: the VIN is never among them, not even sealed.
func (s *Server) reconcile() error {
	var ents []Entity
	for _, v := range s.cfg.Vehicles.Vehicles() {
		data, err := json.Marshal(map[string]any{
			"id": v.ID, "display_name": v.DisplayName, "year": v.Year, "make": v.Make,
			"model": v.Model, "engine_code": v.EngineCode, "vin_last4": v.VINLast4,
			"archived": v.Archived(),
		})
		if err != nil {
			return err
		}
		ents = append(ents, Entity{Type: entityTypeVehicle, ID: v.ID, VehicleID: v.ID, Data: data})
	}
	for _, a := range s.cfg.Vehicles.Assignments("") {
		data, err := json.Marshal(map[string]any{
			"id": a.ID, "device_id": a.DeviceID, "vehicle_id": a.VehicleID, "seq": a.Seq,
			"starts_at": a.StartsAt.Format(time.RFC3339), "open": a.Open(),
		})
		if err != nil {
			return err
		}
		ents = append(ents, Entity{Type: entityTypeAssignment, ID: a.ID, VehicleID: a.VehicleID, Data: data})
	}
	_, err := s.cfg.Store.publishMany(ents)
	return err
}

type ackRequest struct {
	Cursor string `json:"cursor"`
}

func (s *Server) handleAck(q *request) (int, string) {
	var in ackRequest
	if err := decodeStrict(q.body, &in); err != nil {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "malformed ack")
		return http.StatusBadRequest, "malformed body"
	}
	seq, reset, err := s.decodeCursor(in.Cursor)
	if err != nil || reset {
		s.writeError(q.w, http.StatusBadRequest, "bad_cursor", "cursor is not valid for this server")
		return http.StatusBadRequest, "bad cursor"
	}

	err = s.acks.Update(func(d *ackDoc) error {
		if d.Clients == nil {
			d.Clients = map[string]ackEntry{}
		}
		// Only ever forward: a delayed ack from a retry must not move the mark
		// back and make the client look further behind than it is.
		if cur := d.Clients[q.client.ID]; seq >= cur.Sequence {
			d.Clients[q.client.ID] = ackEntry{Sequence: seq, At: s.now()}
		}
		return nil
	})
	if err != nil {
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not record the acknowledgement")
		return http.StatusInternalServerError, "ack store"
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"acknowledged": seq})
	return http.StatusOK, ""
}

// ─── administration ─────────────────────────────────────────────────────────

func (s *Server) handleListDevices(q *request) (int, string) {
	type out struct {
		DeviceID string `json:"device_id"`
		Name     string `json:"name"`
		KeyID    string `json:"key_id"`
		Status   string `json:"status"`
	}
	var list []out
	if s.cfg.Devices != nil {
		for _, d := range s.cfg.Devices.List() {
			status := "active"
			if d.Revoked {
				status = "revoked"
			}
			list = append(list, out{d.DeviceID, d.Name, d.KeyIDHex, status})
		}
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"devices": list})
	return http.StatusOK, ""
}

type revokeRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) handleRevokeDevice(q *request) (int, string) {
	if s.cfg.Devices == nil {
		s.writeError(q.w, http.StatusNotFound, "not_found", "device administration is not enabled")
		return http.StatusNotFound, "no device registry"
	}
	var in revokeRequest
	if len(q.body) > 0 {
		if err := decodeStrict(q.body, &in); err != nil {
			s.writeError(q.w, http.StatusBadRequest, "bad_request", "malformed revoke request")
			return http.StatusBadRequest, "malformed body"
		}
	}
	if in.Reason == "" {
		in.Reason = "revoked by app admin"
	}

	raw, err := hex.DecodeString(q.r.PathValue("id"))
	if err != nil || len(raw) != 16 {
		s.writeError(q.w, http.StatusBadRequest, "bad_request", "device id must be 32 hex characters")
		return http.StatusBadRequest, "bad device id"
	}
	var id [16]byte
	copy(id[:], raw)
	q.device = hex.EncodeToString(id[:])

	if err := s.cfg.Devices.Revoke(id, in.Reason); err != nil {
		if errors.Is(err, devices.ErrUnknown) {
			s.writeError(q.w, http.StatusNotFound, "not_found", "no such device")
			return http.StatusNotFound, "unknown device"
		}
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not revoke")
		return http.StatusInternalServerError, "revoke failed"
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"revoked": q.device})
	return http.StatusOK, "device revoked"
}

func (s *Server) handleListClients(q *request) (int, string) {
	type out struct {
		ID            string    `json:"id"`
		Name          string    `json:"name"`
		Role          string    `json:"role"`
		KeyID         string    `json:"key_id"`
		Status        string    `json:"status"`
		LastSeenAt    time.Time `json:"last_seen_at,omitzero"`
		LastTransport string    `json:"last_transport,omitempty"`
	}
	var list []out
	for _, c := range s.cfg.Clients.List() {
		list = append(list, out{c.ID, c.Name, string(c.Role), c.KeyID, c.Status, c.LastSeenAt, c.LastTransport})
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"clients": list})
	return http.StatusOK, ""
}

func (s *Server) handleRevokeClient(q *request) (int, string) {
	var in revokeRequest
	if len(q.body) > 0 {
		if err := decodeStrict(q.body, &in); err != nil {
			s.writeError(q.w, http.StatusBadRequest, "bad_request", "malformed revoke request")
			return http.StatusBadRequest, "malformed body"
		}
	}
	if in.Reason == "" {
		in.Reason = "revoked by app admin"
	}
	id := strings.ToLower(q.r.PathValue("id"))
	q.target = id

	if err := s.cfg.Clients.Revoke(id, in.Reason); err != nil {
		if errors.Is(err, clients.ErrUnknownClient) {
			s.writeError(q.w, http.StatusNotFound, "not_found", "no such client")
			return http.StatusNotFound, "unknown client"
		}
		s.writeError(q.w, http.StatusInternalServerError, "internal", "could not revoke")
		return http.StatusInternalServerError, "revoke failed"
	}
	s.writeJSON(q.w, http.StatusOK, map[string]any{"revoked": id})
	return http.StatusOK, "client revoked"
}

// LoadOrCreateInstanceID returns the server's stable instance identifier,
// creating it on first use. Wiping the data directory mints a new one, which is
// the right behaviour: it is a different server's data.
func LoadOrCreateInstanceID(path string) (string, error) {
	if raw, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(raw)); len(id) == 32 {
			return id, nil
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}
