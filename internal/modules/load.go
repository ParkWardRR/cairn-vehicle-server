package modules

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads one module directory: its manifest, the SQL it declares, its queries file if
// it names one, and its digest.
func Load(dir string) (*Module, error) {
	name := filepath.Base(dir)
	mpath := filepath.Join(dir, "module.yaml")
	raw, err := os.ReadFile(mpath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", mpath, err)
	}

	var man Manifest
	if err := strictYAML(raw, &man); err != nil {
		return nil, fmt.Errorf("%s: %w", mpath, err)
	}

	m := &Module{Manifest: man, Dir: dir}

	for _, rel := range man.Views {
		if err := safeRelPath(rel); err != nil {
			return nil, fmt.Errorf("%s: views %q: %w", mpath, rel, err)
		}
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Join(dir, rel), err)
		}
		m.Views = append(m.Views, ViewFile{Path: rel, SQL: string(b)})
	}

	if man.Queries != "" {
		if err := safeRelPath(man.Queries); err != nil {
			return nil, fmt.Errorf("%s: queries %q: %w", mpath, man.Queries, err)
		}
		qpath := filepath.Join(dir, man.Queries)
		qraw, err := os.ReadFile(qpath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", qpath, err)
		}
		var qf QueriesFile
		if err := strictYAML(qraw, &qf); err != nil {
			return nil, fmt.Errorf("%s: %w", qpath, err)
		}
		m.Queries = &qf
	}

	digest, err := hashDeclarations(dir, &man)
	if err != nil {
		return nil, err
	}
	m.SHA256 = digest

	if errs := Check(&man, name, m.Queries, nil); len(errs) > 0 {
		return nil, fmt.Errorf("%s:\n  - %s", dir, joinErrs(errs))
	}
	return m, nil
}

// LoadDir reads every module under dir, in id order. A missing or empty directory is not
// an error: a server with no modules is a server that records drives and interprets
// nothing, which is the core doing its job.
func LoadDir(dir string) ([]*Module, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var out []*Module
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		m, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out, nil
}

// strictYAML decodes with unknown fields rejected, so an extra key is an error and not an
// extension point, and a duplicate mapping key is refused — many YAML readers keep the
// last value silently, which would let a reviewer see `status: verified` while the loader
// read `status: stub`.
func strictYAML(b []byte, v any) error {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func joinErrs(errs []error) string {
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = e.Error()
	}
	return strings.Join(parts, "\n  - ")
}

// hashDeclarations is module/v1 §7: SHA-256 over the manifest and every file the manifest
// names — views[], queries — manifest first, then the named paths sorted. Each contributes
// its module-relative path, a 0x00, its bytes with CRLF read as LF, and a 0x00.
//
// Declarations only, not the directory. A README cannot change what a derivation computes,
// so it must not move the digest: the module-set identity reaches the store contract
// digest, and a prose fix that made a rebuilt store look like a different store would be a
// false mismatch.
func hashDeclarations(dir string, m *Manifest) ([32]byte, error) {
	named := append([]string(nil), m.Views...)
	if m.Queries != "" {
		named = append(named, m.Queries)
	}
	sort.Strings(named)
	named = dedup(named)

	h := sha256.New()
	for _, rel := range append([]string{"module.yaml"}, named...) {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return [32]byte{}, fmt.Errorf("hash %s: %w", filepath.Join(dir, rel), err)
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(normaliseEOL(b))
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func dedup(xs []string) []string {
	out := xs[:0]
	var prev string
	for i, x := range xs {
		if i == 0 || x != prev {
			out = append(out, x)
		}
		prev = x
	}
	return out
}

func normaliseEOL(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == '\r' && i+1 < len(b) && b[i+1] == '\n' {
			out = append(out, '\n')
			i++
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// SetIdentity is module/v1 §7's module-set identity: SHA-256 of the domain separator then,
// for each module in id order, "<id>\n<version>\n<hex digest>\n".
//
// A module set changes what a derived store contains, so by the project's fifth invariant
// the set is part of that store's identity. Without this, a store rebuilt under a
// different module set would be a silent mismatch rather than a visible one.
func SetIdentity(ms []*Module) [32]byte {
	sorted := append([]*Module(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })

	h := sha256.New()
	h.Write([]byte(SetDomain))
	for _, m := range sorted {
		h.Write([]byte(m.ID()))
		h.Write([]byte{'\n'})
		h.Write([]byte(strconv.Itoa(m.Manifest.Version)))
		h.Write([]byte{'\n'})
		h.Write([]byte(hex.EncodeToString(m.SHA256[:])))
		h.Write([]byte{'\n'})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// IdentityString is the one-line form a consumer reports:
// "modules=<id>@<version>/<hash16>,... set=<hash16>", or "modules=none" for an empty set.
//
// The same shape as the firmware's engine identity, deliberately: one habit to learn, and
// a reader who knows one can read the other.
func IdentityString(ms []*Module) string {
	if len(ms) == 0 {
		return "modules=none"
	}
	sorted := append([]*Module(nil), ms...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID() < sorted[j].ID() })

	parts := make([]string, len(sorted))
	for i, m := range sorted {
		parts[i] = fmt.Sprintf("%s@%d/%s", m.ID(), m.Manifest.Version,
			hex.EncodeToString(m.SHA256[:])[:16])
	}
	set := SetIdentity(sorted)
	return fmt.Sprintf("modules=%s set=%s", strings.Join(parts, ","),
		hex.EncodeToString(set[:])[:16])
}

// Availability is why a module can or cannot be used against the store that is serving.
type Availability struct {
	ID        string `json:"id"`
	Available bool   `json:"available"`
	// Missing names the requirements the store does not satisfy, so a reader is told what
	// is absent rather than that something is.
	Missing []string `json:"missing,omitempty"`
}

// Resolve reports, per module, whether the live store satisfies its requirements.
//
// A module whose requirements are missing is marked unavailable with a reason, never
// dropped silently: "this car has never reported manifold pressure" is a useful thing for
// a dashboard to be able to say, and an empty page is not.
func Resolve(ms []*Module, cat *Catalogue) []Availability {
	owner := map[string]bool{}
	for _, m := range ms {
		for _, d := range m.Manifest.Derives {
			owner[d.Column] = true
		}
	}
	out := make([]Availability, 0, len(ms))
	for _, m := range ms {
		a := Availability{ID: m.ID(), Available: true}
		if m.Manifest.Requires != nil {
			for _, ref := range m.Manifest.Requires.Store {
				if !cat.Has(ref) && !owner[ref] {
					a.Available = false
					a.Missing = append(a.Missing, ref)
				}
			}
		}
		out = append(out, a)
	}
	return out
}
