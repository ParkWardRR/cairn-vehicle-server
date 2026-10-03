package tsdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/ParkWardRR/Cairn/server/format"
	"github.com/ParkWardRR/Cairn/server/internal/cas"
)

// Ref names one bundle to load: its identity and the CAS digest of its manifest,
// which is all the decoder needs.
type Ref struct {
	ContentRoot    [32]byte
	ManifestDigest [32]byte
	Origin         string
}

// Snapshot is a private, throwaway CAS holding verified copies of every object
// the loaded bundles reference.
//
// It exists instead of pointing the decoder at the live data directory for one
// reason: cas.Open clears the store's tmp directory, and in the server's own
// data directory that tmp directory holds an upload in flight. A second process
// opening it would delete another process's partial writes. Copying through
// cas.Put costs a few hundred kilobytes and re-verifies every digest on the
// way, which is a check worth having anyway.
type Snapshot struct {
	Store *cas.Store
	Refs  []Ref
	dir   string
}

// Close removes the scratch store.
func (s *Snapshot) Close() error {
	if s == nil || s.dir == "" {
		return nil
	}
	return os.RemoveAll(s.dir)
}

// SnapshotSources gathers every bundle from the server's data directory and the
// SD card into one scratch CAS. Either source may be empty.
//
// A bundle present in both is loaded once, under whichever source named it
// first, keyed on content root. That is the dedup that makes loading the card
// after the server idempotent.
func SnapshotSources(scratchParent, dataDir, sdRoot string) (*Snapshot, []string, error) {
	dir, err := os.MkdirTemp(scratchParent, "cairn-tsdb-")
	if err != nil {
		return nil, nil, fmt.Errorf("create scratch: %w", err)
	}
	store, err := cas.Open(dir)
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	snap := &Snapshot{Store: store, dir: dir}

	var notes []string
	seen := map[[32]byte]bool{}

	add := func(ref Ref) {
		if seen[ref.ContentRoot] {
			notes = append(notes, fmt.Sprintf("bundle %x from %s already loaded; skipped", ref.ContentRoot[:6], ref.Origin))
			return
		}
		seen[ref.ContentRoot] = true
		snap.Refs = append(snap.Refs, ref)
	}

	if dataDir != "" {
		refs, n, err := snapshotServer(store, dataDir)
		notes = append(notes, n...)
		if err != nil {
			snap.Close()
			return nil, nil, err
		}
		for _, r := range refs {
			add(r)
		}
	}
	if sdRoot != "" {
		refs, n, err := snapshotSD(store, sdRoot)
		notes = append(notes, n...)
		if err != nil {
			snap.Close()
			return nil, nil, err
		}
		for _, r := range refs {
			add(r)
		}
	}

	sort.SliceStable(snap.Refs, func(i, j int) bool {
		return hex.EncodeToString(snap.Refs[i].ContentRoot[:]) < hex.EncodeToString(snap.Refs[j].ContentRoot[:])
	})
	return snap, notes, nil
}

// copyObject copies one verified object from a source CAS directory into dst.
func copyObject(dst *cas.Store, srcCAS string, digest [32]byte) error {
	h := hex.EncodeToString(digest[:])
	data, err := os.ReadFile(filepath.Join(srcCAS, "objects", h[:2], h))
	if err != nil {
		return err
	}
	return dst.Put(digest, data)
}

// snapshotServer reads committed bundles from the server's data directory.
//
// A bundle counts as committed when its receipt exists. An offer alone is a
// promise the device made, not data the server accepted.
func snapshotServer(dst *cas.Store, dataDir string) ([]Ref, []string, error) {
	offers, err := os.ReadDir(filepath.Join(dataDir, "offers"))
	if err != nil {
		return nil, nil, fmt.Errorf("read offers: %w", err)
	}
	srcCAS := filepath.Join(dataDir, "cas")

	var refs []Ref
	var notes []string
	for _, e := range offers {
		raw, err := os.ReadFile(filepath.Join(dataDir, "offers", e.Name()))
		if err != nil || len(raw) != 64 {
			notes = append(notes, fmt.Sprintf("offer %s unreadable; skipped", e.Name()))
			continue
		}
		var manifestDigest [32]byte
		copy(manifestDigest[:], raw[:32])

		if err := copyObject(dst, srcCAS, manifestDigest); err != nil {
			notes = append(notes, fmt.Sprintf("offer %s: manifest: %v; skipped", e.Name(), err))
			continue
		}
		mb, err := dst.GetVerified(manifestDigest)
		if err != nil {
			notes = append(notes, fmt.Sprintf("offer %s: %v; skipped", e.Name(), err))
			continue
		}
		m, err := format.ParseManifest(mb)
		if err != nil {
			notes = append(notes, fmt.Sprintf("offer %s: parse manifest: %v; skipped", e.Name(), err))
			continue
		}

		receipt := filepath.Join(dataDir, "receipts", hex.EncodeToString(m.ContentRoot[:])+".cbor")
		if _, err := os.Stat(receipt); err != nil {
			notes = append(notes, fmt.Sprintf("offer %s has no receipt; not committed, skipped", e.Name()))
			continue
		}

		missing := false
		for _, mem := range m.Members {
			if err := copyObject(dst, srcCAS, mem.SHA256); err != nil {
				notes = append(notes, fmt.Sprintf("bundle %x: member %q: %v; skipped", m.ContentRoot[:6], mem.Name, err))
				missing = true
				break
			}
		}
		if missing {
			continue
		}
		refs = append(refs, Ref{ContentRoot: m.ContentRoot, ManifestDigest: manifestDigest, Origin: "server"})
	}
	return refs, notes, nil
}

// snapshotSD reads sealed v2 bundles from <sdRoot>/bundles.
//
// Only that directory is read. The card's trips/ directory holds v1 trips; v1
// is dead (see docs/trip-file-format.md), has no read path, and is deliberately
// not touched here. Likewise capture/, which is a bundle still being written.
//
// The manifest's own member list decides which files are read and what they
// must hash to, so a stray or truncated file on the card fails verification
// instead of being quietly decoded.
func snapshotSD(dst *cas.Store, sdRoot string) ([]Ref, []string, error) {
	dir := filepath.Join(sdRoot, "bundles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var refs []Ref
	var notes []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		bdir := filepath.Join(dir, e.Name())

		mb, err := os.ReadFile(filepath.Join(bdir, "manifest.cbor"))
		if err != nil {
			notes = append(notes, fmt.Sprintf("sd bundle %s: %v; skipped", e.Name(), err))
			continue
		}
		m, err := format.ParseManifest(mb)
		if err != nil {
			notes = append(notes, fmt.Sprintf("sd bundle %s: parse manifest: %v; skipped", e.Name(), err))
			continue
		}
		manifestDigest := sha256.Sum256(mb)
		if err := dst.Put(manifestDigest, mb); err != nil {
			return nil, nil, err
		}

		bad := false
		for _, mem := range m.Members {
			data, err := os.ReadFile(filepath.Join(bdir, mem.Name))
			if err != nil {
				notes = append(notes, fmt.Sprintf("sd bundle %s: member %q: %v; skipped", e.Name(), mem.Name, err))
				bad = true
				break
			}
			if err := dst.Put(mem.SHA256, data); err != nil {
				notes = append(notes, fmt.Sprintf("sd bundle %s: member %q fails its manifest digest: %v; skipped", e.Name(), mem.Name, err))
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		refs = append(refs, Ref{ContentRoot: m.ContentRoot, ManifestDigest: manifestDigest, Origin: "sd"})
	}
	return refs, notes, nil
}
