package syncapi

import (
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// The per-client cap on outstanding offers: offered, not yet committed.

const testOfferCap = 2

func newCappedRelayEnv(t *testing.T) *relayEnv {
	t.Helper()
	return newRelayEnv(t, func(c *Config) { c.MaxOffersPerClient = testOfferCap })
}

// offerOK offers a bundle and fails the test unless it is accepted.
func (a *app) offerOK(t *testing.T, b *testbundle.Bundle) offerOut {
	t.Helper()
	st, out, body := a.offer(t, b)
	if st != http.StatusOK {
		t.Fatalf("offer: %d %s", st, body)
	}
	return out
}

// deliver uploads every chunk of an already-offered bundle and commits it.
func (a *app) deliver(t *testing.T, b *testbundle.Bundle) {
	t.Helper()
	for i := range b.Chunks {
		if st, body := a.putChunk(b, i, b.Chunks[i]); st != http.StatusOK {
			t.Fatalf("chunk %d: %d %s", i, st, body)
		}
	}
	if st, body, _ := a.commit(b); st != http.StatusOK {
		t.Fatalf("commit: %d %s", st, body)
	}
}

func (a *app) wantTooManyOffers(t *testing.T, b *testbundle.Bundle) {
	t.Helper()
	st, _, body := a.offer(t, b)
	if st != http.StatusTooManyRequests || errCode(body) != "too_many_offers" {
		t.Fatalf("offer over the cap: %d %s, want 429 too_many_offers", st, body)
	}
}

func TestRelayRefusesOffersBeyondTheClientsCap(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	for i := uint64(1); i <= testOfferCap; i++ {
		phone.offerOK(t, r.bundle(t, i))
	}
	over := r.bundle(t, testOfferCap+1)
	phone.wantTooManyOffers(t, over)

	// The refusal wrote nothing: there is no offer to upload chunks against.
	if st, body := phone.putChunk(over, 0, over.Chunks[0]); st != http.StatusNotFound || errCode(body) != "unknown_bundle" {
		t.Fatalf("a refused offer left state behind: %d %s", st, body)
	}
}

func TestRelayOfferCapIsPerClient(t *testing.T) {
	r := newCappedRelayEnv(t)
	hog := r.enrol(clients.RoleUser, clients.ScopeAll)
	other := r.enrol(clients.RoleUser, clients.ScopeAll)

	for i := uint64(1); i <= testOfferCap; i++ {
		hog.offerOK(t, r.bundle(t, i))
	}
	hog.wantTooManyOffers(t, r.bundle(t, 10))

	// One client at its cap does not starve another.
	for i := uint64(20); i < 20+testOfferCap; i++ {
		other.offerOK(t, r.bundle(t, i))
	}
}

func TestRelayReofferingTheSameBundleIsNotCounted(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	first := r.bundle(t, 1)

	// A phone retrying the same offer many times, at and beyond the cap, is never
	// locked out by its own retries.
	for i := 0; i < 3*testOfferCap; i++ {
		phone.offerOK(t, first)
	}
	// The retries took one slot, not one each: another bundle still fits.
	phone.offerOK(t, r.bundle(t, 2))
	// And re-offering a bundle it already holds works even when full.
	phone.offerOK(t, first)
	phone.wantTooManyOffers(t, r.bundle(t, 3))
}

func TestRelayCommittedOffersDoNotCountAndFreeTheirSlot(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	done := r.bundle(t, 1)
	phone.offerOK(t, done)
	phone.offerOK(t, r.bundle(t, 2))
	phone.wantTooManyOffers(t, r.bundle(t, 3))

	phone.deliver(t, done)

	// The slot is free again.
	phone.offerOK(t, r.bundle(t, 3))
	phone.wantTooManyOffers(t, r.bundle(t, 4))

	// A committed bundle re-offered is answered from its receipt and costs nothing,
	// even with the client at its cap.
	if out := phone.offerOK(t, done); !out.ReceiptAvailable {
		t.Fatalf("re-offer of a committed bundle: %+v", out)
	}
	phone.wantTooManyOffers(t, r.bundle(t, 4))
}

func TestRelayReceiptedReofferIsAnsweredEvenAtTheCap(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)
	other := r.enrol(clients.RoleUser, clients.ScopeAll)

	done := r.bundle(t, 1)
	phone.offerOK(t, done)
	phone.deliver(t, done)

	// Another client, full of its own outstanding offers, can still learn that a
	// bundle already has a receipt: that records nothing.
	other.offerOK(t, r.bundle(t, 2))
	other.offerOK(t, r.bundle(t, 3))
	other.wantTooManyOffers(t, r.bundle(t, 4))
	if out := other.offerOK(t, done); !out.ReceiptAvailable {
		t.Fatalf("receipted bundle at the cap: %+v", out)
	}
}

func TestRelayOfferSlotsAreFreedWhenTheOfferIsSwept(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	a, b := r.bundle(t, 1), r.bundle(t, 2)
	phone.offerOK(t, a)
	phone.offerOK(t, b)
	phone.wantTooManyOffers(t, r.bundle(t, 3))

	// The bundles are delivered and their offer records swept without the relay's
	// commit endpoint being involved (the device listener, or another client). The
	// server must notice the slots are free rather than trust a stale count.
	for _, x := range []*testbundle.Bundle{a, b} {
		for i := range x.Chunks {
			if _, err := r.intake.AcceptChunk(x.Manifest.BundleID, x.Manifest.ChunkDescriptors[i].SHA256, x.Chunks[i]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.intake.Commit(x.Manifest.BundleID); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := r.intake.SweepOffers(-time.Hour); err != nil || n != 2 {
		t.Fatalf("sweep = %d, %v; want both offer records reclaimed", n, err)
	}

	phone.offerOK(t, r.bundle(t, 3))
	phone.offerOK(t, r.bundle(t, 4))
	phone.wantTooManyOffers(t, r.bundle(t, 5))
}

func TestRelayFailedOfferDoesNotHoldASlot(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	// Offers intake refuses (a manifest the enrolled device did not sign) must not
	// leak slots, or a hostile device could lock a phone out of the relay.
	for i := uint64(100); i < 100+3*testOfferCap; i++ {
		bad := r.bundle(t, i)
		bad.Signature = make([]byte, len(bad.Signature))
		if st, _, _ := phone.offer(t, bad); st != http.StatusUnauthorized {
			t.Fatalf("forged offer: %d", st)
		}
	}
	for i := uint64(2); i < 2+testOfferCap; i++ {
		phone.offerOK(t, r.bundle(t, i))
	}
}

func TestRelayRevokedClientsOffersDoNotAffectOthers(t *testing.T) {
	r := newCappedRelayEnv(t)
	gone := r.enrol(clients.RoleUser, clients.ScopeAll)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	for i := uint64(1); i <= testOfferCap; i++ {
		gone.offerOK(t, r.bundle(t, i))
	}
	if err := r.clients.Revoke(gone.id, "test"); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := gone.offer(t, r.bundle(t, 9)); st != http.StatusUnauthorized {
		t.Fatalf("a revoked client reached the relay: %d", st)
	}

	for i := uint64(20); i < 20+testOfferCap; i++ {
		phone.offerOK(t, r.bundle(t, i))
	}
}

func TestRelayOfferCapHoldsUnderConcurrentOffers(t *testing.T) {
	r := newCappedRelayEnv(t)
	phone := r.enrol(clients.RoleUser, clients.ScopeAll)

	const n = 8
	bundles := make([]*testbundle.Bundle, n)
	for i := range bundles {
		bundles[i] = r.bundle(t, uint64(i+1))
	}
	statuses := make([]int, n)
	var wg sync.WaitGroup
	for i := range bundles {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i], _, _ = phone.offer(t, bundles[i])
		}()
	}
	wg.Wait()

	accepted := 0
	for _, st := range statuses {
		if st == http.StatusOK {
			accepted++
		}
	}
	if accepted != testOfferCap {
		t.Fatalf("%d concurrent offers accepted, want exactly the cap of %d (%v)", accepted, testOfferCap, statuses)
	}
}

func TestRelayOfferCapDefaultsAndCanBeDisabled(t *testing.T) {
	r := newRelayEnv(t)
	if got := r.srv.maxOffers(); got != DefaultMaxOffersPerClient {
		t.Fatalf("default cap = %d, want %d", got, DefaultMaxOffersPerClient)
	}

	off := newRelayEnv(t, func(c *Config) { c.MaxOffersPerClient = -1 })
	phone := off.enrol(clients.RoleUser, clients.ScopeAll)
	for i := uint64(1); i <= DefaultMaxOffersPerClient+3; i++ {
		phone.offerOK(t, off.bundle(t, i))
	}
}
