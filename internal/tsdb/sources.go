package tsdb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
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
	// Meta is what the server's ledger says about how each bundle arrived, keyed by hex
	// content root. A bundle with no entry here has no recorded path.
	Meta map[string]BundleMeta
	dir  string
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
	snap := &Snapshot{Store: store, dir: dir, Meta: map[string]BundleMeta{}}

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
		meta, n, err := ledgerMeta(filepath.Join(dataDir, "ledger"))
		notes = append(notes, n...)
		if err != nil {
			// The path columns are an annotation. A damaged ledger must not stop the
			// store from loading the data the receipts prove exists.
			notes = append(notes, fmt.Sprintf("ledger: %v; bundle paths are unknown", err))
		}
		snap.Meta = meta
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
// Discovery is keyed on receipts rather than offers: a receipt is the durable
// proof that a bundle was committed, while an offer is housekeeping state that
// is swept after receipting. Reading from receipts means every committed bundle
// is visible regardless of whether its offer record still exists.
func snapshotServer(dst *cas.Store, dataDir string) ([]Ref, []string, error) {
	receiptDir := filepath.Join(dataDir, "receipts")
	entries, err := os.ReadDir(receiptDir)
	if err != nil {
		return nil, nil, fmt.Errorf("read receipts: %w", err)
	}
	srcCAS := filepath.Join(dataDir, "cas")

	var refs []Ref
	var notes []string
	for _, e := range entries {
		encoded, err := os.ReadFile(filepath.Join(receiptDir, e.Name()))
		if err != nil {
			continue
		}
		r, err := format.ParseReceipt(encoded)
		if err != nil {
			notes = append(notes, fmt.Sprintf("receipt %s: parse: %v; skipped", e.Name(), err))
			continue
		}

		// The manifest is the second-to-last stored object (members, manifest,
		// signature — see intake.go Commit).
		if len(r.StoredObjectIDs) < 2 {
			notes = append(notes, fmt.Sprintf("receipt %s: no stored objects; skipped", e.Name()))
			continue
		}
		manifestDigest, err := objectIDToDigest(r.StoredObjectIDs[len(r.StoredObjectIDs)-2])
		if err != nil {
			notes = append(notes, fmt.Sprintf("receipt %s: bad manifest object id: %v; skipped", e.Name(), err))
			continue
		}

		if err := copyObject(dst, srcCAS, manifestDigest); err != nil {
			notes = append(notes, fmt.Sprintf("receipt %s: manifest: %v; skipped", e.Name(), err))
			continue
		}
		mb, err := dst.GetVerified(manifestDigest)
		if err != nil {
			notes = append(notes, fmt.Sprintf("receipt %s: %v; skipped", e.Name(), err))
			continue
		}
		m, err := format.ParseManifest(mb)
		if err != nil {
			notes = append(notes, fmt.Sprintf("receipt %s: parse manifest: %v; skipped", e.Name(), err))
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

// objectIDToDigest extracts the SHA-256 digest from a CAS object ID
// (format: "cas/XX/XXXX...").
func objectIDToDigest(id string) ([32]byte, error) {
	var d [32]byte
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 || parts[0] != "cas" {
		return d, fmt.Errorf("malformed object id %q", id)
	}
	b, err := hex.DecodeString(parts[2])
	if err != nil || len(b) != 32 {
		return d, fmt.Errorf("bad digest in object id %q", id)
	}
	copy(d[:], b)
	return d, nil
}

// snapshotSD reads sealed v2 bundles from <sdRoot>/bundles.
//
// Only that directory is read. The card's trips/ directory holds v1 trips; v1
// is dead, has no read path, and is deliberately
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
