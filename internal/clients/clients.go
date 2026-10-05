// Package clients is the registry of enrolled iOS app installations.
//
// An OBD dongle is enrolled with a certificate and an Ed25519 manifest key. The
// phone is a different kind of principal: it belongs to a person, it reaches the
// server over more than one network path, and on one of them (Tailscale Serve
// terminating TLS in front of a loopback listener) a client certificate cannot
// arrive at all. So the app is enrolled here, separately, with its own identity,
// and proves it per request with a signature rather than per connection with a
// certificate. Tailscale decides who may reach the server; this registry decides
// who may *act* on it. Conflating the two would make "is on my tailnet" mean
// "may read my GPS history".
//
// # Why P-256
//
// The app's key lives in the iOS Secure Enclave, which holds only P-256 keys.
// The private key therefore never leaves the phone and cannot be copied off a
// backup, which is what makes a stolen server-side registry file (public keys
// only) worthless to an attacker.
//
// # Invitations
//
// Enrolment is by one-time invitation. An administrator creates one at the
// command line; it carries the role and the vehicle scope the new client will
// get, so authorisation is decided by a human before the phone ever connects,
// not requested by it. The code is 128 random bits, shown once and stored only
// as a SHA-256, so a copy of the registry file cannot be turned into an
// enrolment. It expires quickly and works once.
//
// At enrolment the app also signs the code together with its new public key.
// Without that proof anyone holding the code could register a key of their
// choosing on someone else's behalf — or register a public key they do not hold
// the private half of. With it, the enrolled key is demonstrably the one the
// enrolling device controls.
//
// # Storage and revocation
//
// The registry is a jsonstore document, so a revocation made from the command
// line by another process is noticed by the running server on its next request
// with no restart. That is the property that makes "my phone is lost" an
// immediate action rather than a maintenance window.
package clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/ParkWardRR/Cairn/server/internal/jsonstore"
	"github.com/ParkWardRR/Cairn/server/internal/vehicles"
)

// Role is what a client may do beyond syncing its own vehicles.
type Role string

const (
	// RoleUser syncs the vehicles in its scope and nothing else.
	RoleUser Role = "user"
	// RoleAdmin may additionally revoke devices and clients and list them.
	RoleAdmin Role = "admin"
)

// ScopeAll is the vehicle scope that means every vehicle, including ones
// created after the client was enrolled.
const ScopeAll = "*"

// Status values.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

// DefaultInviteTTL is how long an invitation lives. Long enough to type a code
// on a phone, short enough that a code photographed over a shoulder is dead
// by the time anyone could use it.
const DefaultInviteTTL = 10 * time.Minute

// MaxInviteTTL caps what an administrator may request.
const MaxInviteTTL = 24 * time.Hour

// lastSeenGranularity bounds how often last-seen is rewritten. Every write is
// an fsync of the whole registry; an app syncing in a burst must not pay that
// per request.
const lastSeenGranularity = 5 * time.Minute

var (
	// ErrUnknownClient means no client has this ID.
	ErrUnknownClient = errors.New("client not found")
	// ErrInviteInvalid covers an unknown, expired or already-used invitation.
	// One error for all three: telling a caller which one it was would turn the
	// enrolment endpoint into an oracle for probing codes.
	ErrInviteInvalid = errors.New("invitation is not valid")
	// ErrBadProof means the proof-of-possession signature did not verify.
	ErrBadProof = errors.New("proof of possession failed")
	// ErrBadKey means the supplied public key is not a valid P-256 point.
	ErrBadKey = errors.New("public key is not a valid uncompressed P-256 point")
)

// Client is one enrolled app installation.
type Client struct {
	ID      string `json:"id"` // hex of a 16-byte UUIDv7
	Name    string `json:"name"`
	OwnerID string `json:"owner_id,omitempty"`
	Role    Role   `json:"role"`

	// Vehicles is the allowed vehicle scope: vehicle IDs, or ["*"].
	Vehicles []string `json:"vehicles"`

	// PublicKeyHex is the uncompressed X9.63 P-256 point (65 bytes, 130 hex).
	PublicKeyHex string `json:"public_key"`
	// KeyID is a short fingerprint of the public key, safe to show and log; it
	// is what listings print instead of the key itself.
	KeyID string `json:"key_id"`

	Status        string    `json:"status"`
	EnrolledAt    time.Time `json:"enrolled_at"`
	RevokedAt     time.Time `json:"revoked_at,omitzero"`
	RevokedReason string    `json:"revoked_reason,omitempty"`

	LastSeenAt    time.Time `json:"last_seen_at,omitzero"`
	LastTransport string    `json:"last_transport,omitempty"`
}

// Active reports whether the client may authenticate.
func (c *Client) Active() bool { return c.Status == StatusActive }

// IsAdmin reports whether the client holds the admin role.
func (c *Client) IsAdmin() bool { return c.Role == RoleAdmin }

// InScope reports whether the client may touch the vehicle.
func (c *Client) InScope(vehicleID string) bool {
	vehicleID = strings.ToLower(vehicleID)
	for _, v := range c.Vehicles {
		if v == ScopeAll || v == vehicleID {
			return true
		}
	}
	return false
}

// PublicKey parses the stored key.
func (c *Client) PublicKey() (*ecdsa.PublicKey, error) { return ParsePublicKey(c.PublicKeyHex) }

// Invite is a pending or spent enrolment invitation.
type Invite struct {
	// CodeHash is the SHA-256 of the normalised code. The code itself exists
	// only in the administrator's terminal and, later, on the phone.
	CodeHash string `json:"code_hash"`

	Role      Role     `json:"role"`
	Vehicles  []string `json:"vehicles"`
	Name      string   `json:"name,omitempty"`
	OwnerID   string   `json:"owner_id,omitempty"`
	CreatedBy string   `json:"created_by,omitempty"`

	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	ConsumedAt time.Time `json:"consumed_at,omitzero"`
	ConsumedBy string    `json:"consumed_by,omitempty"`
}

type document struct {
	Clients []*Client `json:"clients"`
	Invites []*Invite `json:"invites"`
}

// Registry is the client store.
type Registry struct {
	store *jsonstore.Store[document]
	now   func() time.Time
}

// Option configures a Registry.
type Option func(*Registry)

// WithClock replaces the time source, so tests can expire invitations without
// sleeping.
func WithClock(now func() time.Time) Option { return func(r *Registry) { r.now = now } }

// Open loads the registry at path, creating it on first write.
func Open(path string, opts ...Option) (*Registry, error) {
	store, err := jsonstore.Open(path, func() document { return document{} })
	if err != nil {
		return nil, err
	}
	r := &Registry{store: store, now: func() time.Time { return time.Now().UTC() }}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// InviteSpec describes an invitation to create.
type InviteSpec struct {
	Role      Role
	Vehicles  []string
	Name      string
	OwnerID   string
	CreatedBy string
	TTL       time.Duration
}

// CreateInvite makes a single-use invitation and returns its code. The code is
// returned exactly once; the registry keeps only its hash.
func (r *Registry) CreateInvite(spec InviteSpec) (string, *Invite, error) {
	if spec.Role == "" {
		spec.Role = RoleUser
	}
	if spec.Role != RoleUser && spec.Role != RoleAdmin {
		return "", nil, fmt.Errorf("role must be %q or %q, got %q", RoleUser, RoleAdmin, spec.Role)
	}
	scope, err := NormalizeScope(spec.Vehicles)
	if err != nil {
		return "", nil, err
	}
	ttl := spec.TTL
	if ttl == 0 {
		ttl = DefaultInviteTTL
	}
	if ttl < 0 || ttl > MaxInviteTTL {
		return "", nil, fmt.Errorf("invitation lifetime must be between 0 and %s", MaxInviteTTL)
	}
	name, err := cleanName(spec.Name, true)
	if err != nil {
		return "", nil, err
	}

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", nil, fmt.Errorf("generate invitation code: %w", err)
	}
	code := hex.EncodeToString(raw[:])

	now := r.now()
	inv := &Invite{
		CodeHash:  hashCode(code),
		Role:      spec.Role,
		Vehicles:  scope,
		Name:      name,
		OwnerID:   spec.OwnerID,
		CreatedBy: spec.CreatedBy,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}

	err = r.store.Update(func(d *document) error {
		// Spent and expired invitations are dead weight in a file that is
		// rewritten and fsynced whole. A day's grace keeps them around long
		// enough to explain "why did my code not work".
		kept := d.Invites[:0]
		for _, old := range d.Invites {
			end := old.ExpiresAt
			if !old.ConsumedAt.IsZero() && old.ConsumedAt.Before(end) {
				end = old.ConsumedAt
			}
			if now.Sub(end) < 24*time.Hour {
				kept = append(kept, old)
			}
		}
		d.Invites = append(kept, inv)
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	c := *inv
	return code, &c, nil
}

// EnrollRequest is what the app submits.
type EnrollRequest struct {
	Code         string
	Name         string
	PublicKeyHex string
	// Proof is the DER ECDSA-P256-SHA256 signature over EnrollProofMessage.
	Proof []byte
}

// EnrollProofMessage is the byte string the app signs at enrolment. The domain
// prefix keeps a signature made here from being replayable as a request
// signature (or the reverse), whatever the rest of the content looks like.
func EnrollProofMessage(code, publicKeyHex string) []byte {
	return []byte("CAIRN-ENROLL-V1\n" + code + "\n" + strings.ToLower(publicKeyHex))
}

// Enroll consumes an invitation and registers the client.
//
// The proof is checked before the invitation is touched, and a bad proof does
// not consume it: otherwise anyone who learned a code could burn it, and the
// administrator's legitimate enrolment would be the casualty.
func (r *Registry) Enroll(req EnrollRequest) (*Client, error) {
	code, err := NormalizeCode(req.Code)
	if err != nil {
		return nil, ErrInviteInvalid
	}
	pub, err := ParsePublicKey(req.PublicKeyHex)
	if err != nil {
		return nil, err
	}
	if !VerifyDER(pub, EnrollProofMessage(code, req.PublicKeyHex), req.Proof) {
		return nil, ErrBadProof
	}
	reqName, err := cleanName(req.Name, true)
	if err != nil {
		return nil, err
	}

	hash := hashCode(code)
	now := r.now()
	var created *Client

	err = r.store.Update(func(d *document) error {
		var inv *Invite
		for _, i := range d.Invites {
			// Constant-time on the hash so response timing does not reveal how
			// much of a guessed code matched. The hash makes this belt and
			// braces, but it costs nothing.
			if subtle.ConstantTimeCompare([]byte(i.CodeHash), []byte(hash)) == 1 {
				inv = i
			}
		}
		if inv == nil || !inv.ConsumedAt.IsZero() || !now.Before(inv.ExpiresAt) {
			return ErrInviteInvalid
		}

		id, err := vehicles.NewID()
		if err != nil {
			return err
		}
		keyID := sha256.Sum256(mustHex(req.PublicKeyHex))

		name := inv.Name
		if name == "" {
			name = reqName
		}
		if name == "" {
			name = "app-" + hex.EncodeToString(id[:])[:8]
		}
		owner := inv.OwnerID
		if owner == "" {
			owner = hex.EncodeToString(id[:])
		}

		created = &Client{
			ID:           hex.EncodeToString(id[:]),
			Name:         name,
			OwnerID:      owner,
			Role:         inv.Role,
			Vehicles:     append([]string(nil), inv.Vehicles...),
			PublicKeyHex: strings.ToLower(req.PublicKeyHex),
			KeyID:        hex.EncodeToString(keyID[:8]),
			Status:       StatusActive,
			EnrolledAt:   now,
		}
		inv.ConsumedAt = now
		inv.ConsumedBy = created.ID
		d.Clients = append(d.Clients, created)
		return nil
	})
	if err != nil {
		return nil, err
	}
	c := *created
	return &c, nil
}

// Get returns a copy of one client, whatever its status.
func (r *Registry) Get(id string) (*Client, error) {
	id = strings.ToLower(id)
	var out *Client
	r.store.View(func(d *document) {
		for _, c := range d.Clients {
			if c.ID == id {
				cp := *c
				cp.Vehicles = append([]string(nil), c.Vehicles...)
				out = &cp
				return
			}
		}
	})
	if out == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownClient, id)
	}
	return out, nil
}

// List returns every client, oldest first.
func (r *Registry) List() []*Client {
	var out []*Client
	r.store.View(func(d *document) {
		for _, c := range d.Clients {
			cp := *c
			cp.Vehicles = append([]string(nil), c.Vehicles...)
			out = append(out, &cp)
		}
	})
	return out
}

// Revoke disables a client immediately. Its key stays in the file so a later
// request signed by it can be told apart from a stranger's and answered as
// "revoked" rather than "unknown".
func (r *Registry) Revoke(id, reason string) error {
	id = strings.ToLower(id)
	return r.store.Update(func(d *document) error {
		for _, c := range d.Clients {
			if c.ID != id {
				continue
			}
			if c.Status == StatusRevoked {
				return nil
			}
			c.Status = StatusRevoked
			c.RevokedAt = r.now()
			c.RevokedReason = reason
			return nil
		}
		return fmt.Errorf("%w: %s", ErrUnknownClient, id)
	})
}

// Touch records that the client was seen on a transport. It writes only when
// the transport changed or the last write is old, so a sync burst costs one
// fsync rather than one per request.
func (r *Registry) Touch(id, transport string) {
	id = strings.ToLower(id)
	now := r.now()

	stale := false
	r.store.View(func(d *document) {
		for _, c := range d.Clients {
			if c.ID == id {
				stale = c.LastTransport != transport || now.Sub(c.LastSeenAt) >= lastSeenGranularity
			}
		}
	})
	if !stale {
		return
	}
	// Best effort: failing to note a timestamp must never fail a sync.
	_ = r.store.Update(func(d *document) error {
		for _, c := range d.Clients {
			if c.ID == id && c.Active() {
				c.LastSeenAt, c.LastTransport = now, transport
			}
		}
		return nil
	})
}

// ─── keys and codes ─────────────────────────────────────────────────────────

// ParsePublicKey decodes an uncompressed X9.63 P-256 point, rejecting anything
// that is not on the curve. Checking on-curve matters: accepting an arbitrary
// 65 bytes would let a crafted point reach signature verification.
func ParsePublicKey(hexKey string) (*ecdsa.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(raw) != 65 || raw[0] != 0x04 {
		return nil, ErrBadKey
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, ErrBadKey
	}
	return pub, nil
}

// PublicKeyHex encodes a key in the stored form.
func PublicKeyHex(pub *ecdsa.PublicKey) string {
	raw, err := pub.Bytes()
	if err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

// VerifyDER checks an ASN.1 DER ECDSA signature over SHA-256(message). DER is
// what Apple's Security framework emits for ecdsaSignatureMessageX962SHA256,
// so the app can send what it is given.
func VerifyDER(pub *ecdsa.PublicKey, message, sig []byte) bool {
	sum := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, sum[:], sig)
}

// DecodeSignature accepts standard base64 with or without padding.
func DecodeSignature(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// NormalizeCode turns what a person typed or scanned into the canonical form:
// 32 lowercase hex digits. Dashes and spaces are tolerated because codes are
// displayed in groups to be readable.
func NormalizeCode(s string) (string, error) {
	var b strings.Builder
	for _, r := range s {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	code := b.String()
	if raw, err := hex.DecodeString(code); err != nil || len(raw) != 16 {
		return "", ErrInviteInvalid
	}
	return code, nil
}

// FormatCode groups a code for display: xxxx-xxxx-...
func FormatCode(code string) string {
	var parts []string
	for i := 0; i < len(code); i += 4 {
		end := min(i+4, len(code))
		parts = append(parts, code[i:end])
	}
	return strings.Join(parts, "-")
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(strings.TrimSpace(s))
	return b
}

// NormalizeScope validates and canonicalises a vehicle scope. "*" must stand
// alone: mixing it with IDs would be a scope that looks narrower than it is.
func NormalizeScope(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("a vehicle scope is required (vehicle IDs, or * for all)")
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" {
			continue
		}
		if v == ScopeAll {
			if len(in) != 1 {
				return nil, errors.New("scope * cannot be combined with vehicle IDs")
			}
			return []string{ScopeAll}, nil
		}
		if raw, err := hex.DecodeString(v); err != nil || len(raw) != 16 {
			return nil, fmt.Errorf("vehicle scope entry %q is not a 32-hex vehicle ID", v)
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("a vehicle scope is required (vehicle IDs, or * for all)")
	}
	return out, nil
}

// cleanName trims and bounds a human label. Labels end up in logs and
// terminals, so control characters are refused rather than escaped.
func cleanName(s string, optional bool) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" && optional {
		return "", nil
	}
	if len(s) > 64 {
		return "", errors.New("name is longer than 64 bytes")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", errors.New("name contains control characters")
		}
	}
	return s, nil
}
