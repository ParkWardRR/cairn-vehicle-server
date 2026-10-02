package main

import (
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/Cairn/server/internal/receipts"
)

// The receipt-signing key is what authorizes a device to delete data. If it
// changes without the device being reflashed, every receipt is rejected and the
// card fills up — so "which key signs" must not depend on an unrelated flag.
func TestResolveReceiptKeyPathIgnoresDevMode(t *testing.T) {
	const dataDir = "/var/lib/cairn"
	want := filepath.Join(dataDir, "keys", "receipt.seed")

	// There is deliberately no dev parameter: the regression being locked down
	// is a dev flag reaching this decision at all.
	if got := resolveReceiptKeyPath("", dataDir); got != want {
		t.Errorf("default path = %q, want %q", got, want)
	}

	// An explicit path still wins, which is how an ephemeral key is requested.
	if got := resolveReceiptKeyPath("/tmp/throwaway.seed", dataDir); got != "/tmp/throwaway.seed" {
		t.Errorf("explicit path = %q, want /tmp/throwaway.seed", got)
	}
}

// End-to-end on the property that actually matters: a data directory yields the
// same public key every time it is opened, so a key pinned in firmware stays
// valid across restarts.
func TestReceiptKeyIsStableAcrossOpens(t *testing.T) {
	dataDir := t.TempDir()
	keyPath := resolveReceiptKeyPath("", dataDir)

	open := func(dev bool) string {
		t.Helper()
		store, err := receipts.Open(receipts.Config{
			Dir:     filepath.Join(dataDir, "receipts"),
			KeyPath: keyPath,
			Dev:     dev,
		})
		if err != nil {
			t.Fatalf("open receipt store (dev=%v): %v", dev, err)
		}
		return store.PublicKeyHex()
	}

	first := open(false)
	if first == "" {
		t.Fatal("empty public key")
	}

	if again := open(false); again != first {
		t.Errorf("key changed on reopen: %s then %s", first, again)
	}

	// The case that was broken: the same directory under dev mode must still
	// sign with the key an operator has already pinned.
	if inDev := open(true); inDev != first {
		t.Errorf("dev mode rotated the receipt key: %s then %s", first, inDev)
	}
}
