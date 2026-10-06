package clients

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"testing"
)

func openReg(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(filepath.Join(t.TempDir(), "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func enrol(t *testing.T, r *Registry, spec InviteSpec) (*Client, error) {
	t.Helper()
	code, _, err := r.CreateInvite(spec)
	if err != nil {
		t.Fatal(err)
	}
	return enrolCode(t, r, code)
}

func enrolCode(t *testing.T, r *Registry, code string) (*Client, error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := PublicKeyHex(&key.PublicKey)
	norm, _ := NormalizeCode(code)
	h := sha256.Sum256(EnrollProofMessage(norm, pub))
	proof, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return r.Enroll(EnrollRequest{Code: code, Name: "phone", PublicKeyHex: pub, Proof: proof})
}

func TestReplacesRevokesOldAndKeepsOwner(t *testing.T) {
	r := openReg(t)
	old, err := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}, Replaces: old.ID})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get(old.ID)
	if got.Active() || got.RevokedAt.IsZero() || got.RevokedReason != "replaced by "+fresh.ID {
		t.Fatalf("old not revoked as replaced: %+v", got)
	}
	if !fresh.Active() || fresh.Replaces != old.ID || fresh.OwnerID != old.OwnerID {
		t.Fatalf("new client: %+v (old owner %s)", fresh, old.OwnerID)
	}
}

// Nothing may change when the invitation is not consumed: a bad proof must not revoke.
func TestBadProofDoesNotRevokeTheReplacedClient(t *testing.T) {
	r := openReg(t)
	old, _ := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}})
	code, _, err := r.CreateInvite(InviteSpec{Vehicles: []string{ScopeAll}, Replaces: old.ID})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = r.Enroll(EnrollRequest{Code: code, PublicKeyHex: PublicKeyHex(&key.PublicKey), Proof: []byte("not a signature")})
	if !errors.Is(err, ErrBadProof) {
		t.Fatalf("err = %v, want ErrBadProof", err)
	}
	if got, _ := r.Get(old.ID); !got.Active() {
		t.Fatal("a failed enrolment revoked the client it would have replaced")
	}
	// ...and the invitation is still good.
	if _, err := enrolCode(t, r, code); err != nil {
		t.Fatalf("invitation burned by the bad proof: %v", err)
	}
}

func TestReplacesUnknownClientIsRefusedAtInvite(t *testing.T) {
	r := openReg(t)
	_, _, err := r.CreateInvite(InviteSpec{Vehicles: []string{ScopeAll}, Replaces: "00000000000000000000000000000000"})
	if !errors.Is(err, ErrUnknownClient) {
		t.Fatalf("err = %v, want ErrUnknownClient", err)
	}
}

func TestReplacingAnAlreadyRevokedClientKeepsItsReason(t *testing.T) {
	r := openReg(t)
	old, _ := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}})
	if err := r.Revoke(old.ID, "lost phone"); err != nil {
		t.Fatal(err)
	}
	if _, err := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}, Replaces: old.ID}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(old.ID); got.RevokedReason != "lost phone" {
		t.Fatalf("reason overwritten: %q", got.RevokedReason)
	}
}

// Without Replaces, enrolment touches nobody else.
func TestPlainEnrolmentLeavesOthersAlone(t *testing.T) {
	r := openReg(t)
	a, _ := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}})
	if _, err := enrol(t, r, InviteSpec{Vehicles: []string{ScopeAll}}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Get(a.ID); !got.Active() {
		t.Fatal("an unrelated enrolment revoked a client")
	}
}
