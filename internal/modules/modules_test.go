package modules

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeModule lays out a module directory and returns its path.
func writeModule(t *testing.T, root, id, manifest string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "module.yaml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const stubManifest = `schema: cairn.module/v1-draft
id: alpha
version: 1
name: Alpha
status: stub
sources: [a fixture]
`

// A module may legitimately be nothing but a manifest. The server must load one, because
// the places module will be close to it and a reader that assumed the full shape would
// reject it.
func TestDeclarationOnlyModuleLoads(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "alpha", stubManifest, nil)

	m, err := Load(dir)
	if err != nil {
		t.Fatalf("a declaration-only module must load: %v", err)
	}
	if m.ID() != "alpha" || m.Manifest.Status != "stub" {
		t.Fatalf("unexpected: %+v", m.Manifest)
	}
	if len(m.Views) != 0 || m.Queries != nil {
		t.Fatal("a stub declared nothing but something was loaded")
	}
}

func TestLoadDirIsIDOrderedAndToleratesAbsence(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "zulu", strings.Replace(stubManifest, "id: alpha", "id: zulu", 1), nil)
	writeModule(t, root, "alpha", stubManifest, nil)

	ms, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].ID() != "alpha" || ms[1].ID() != "zulu" {
		t.Fatalf("not id-ordered: %v", ids(ms))
	}

	// A server with no modules records drives and interprets nothing. That is the core
	// doing its job, not a failure.
	if ms, err := LoadDir(filepath.Join(root, "nope")); err != nil || ms != nil {
		t.Fatalf("a missing directory should be empty and fine, got %v %v", ids(ms), err)
	}
	if ms, err := LoadDir(""); err != nil || ms != nil {
		t.Fatalf("an unset directory should be empty and fine, got %v %v", ids(ms), err)
	}
}

func ids(ms []*Module) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.ID()
	}
	return out
}

// The id names the module everywhere — its views, its queries, its generated symbols — so
// a manifest selected under a directory name that is not in it is refused.
func TestIDMustMatchDirectory(t *testing.T) {
	root := t.TempDir()
	dir := writeModule(t, root, "turbo", stubManifest, nil) // manifest says alpha
	if _, err := Load(dir); err == nil {
		t.Fatal("a mismatched directory was accepted")
	} else if !strings.Contains(err.Error(), "directory name") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// An extra key is an error, not an extension point: a manifest is not a place to stash
// data. And a duplicate mapping key must be refused — many YAML readers keep the last
// value silently, which would let a reviewer see one status while the loader reads another.
func TestStrictYAML(t *testing.T) {
	root := t.TempDir()

	dir := writeModule(t, root, "alpha", stubManifest+"cache_ttl_s: 30\n", nil)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "field cache_ttl_s") {
		t.Fatalf("an unknown field was accepted or misreported: %v", err)
	}

	dup := `schema: cairn.module/v1-draft
id: beta
version: 1
name: Beta
status: verified
status: stub
sources: [a fixture]
`
	dir = writeModule(t, root, "beta", dup, nil)
	if _, err := Load(dir); err == nil {
		t.Fatal("a duplicate mapping key was accepted")
	} else if !strings.Contains(strings.ToLower(err.Error()), "already defined") &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// module/v1 §7: declarations, not the directory. A README cannot change what a derivation
// computes, so it must not move the digest — the module-set identity reaches the store
// contract digest, and a prose fix that made a rebuilt store look like a different store
// would be a false mismatch.
func TestDigestCoversDeclarationsNotProse(t *testing.T) {
	root := t.TempDir()
	manifest := `schema: cairn.module/v1-draft
id: alpha
version: 1
name: Alpha
status: derived
sources: [a fixture]
views: [store/views.sql]
`
	dir := writeModule(t, root, "alpha", manifest, map[string]string{
		"store/views.sql": "CREATE VIEW v_alpha_x AS SELECT 1;\n",
		"README.md":       "# alpha\n\nFirst draft.\n",
	})

	digest := func() [32]byte {
		m, err := Load(dir)
		if err != nil {
			t.Fatal(err)
		}
		return m.SHA256
	}
	before := digest()

	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# alpha\n\nRewritten.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if digest() != before {
		t.Fatal("editing README.md changed the module digest")
	}

	if err := os.WriteFile(filepath.Join(dir, "scratch.txt"), []byte("notes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if digest() != before {
		t.Fatal("an undeclared file changed the module digest")
	}

	if err := os.WriteFile(filepath.Join(dir, "store/views.sql"), []byte("CREATE VIEW v_alpha_x AS SELECT 2;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	afterSQL := digest()
	if afterSQL == before {
		t.Fatal("editing a declared view did not change the digest")
	}

	if err := os.WriteFile(filepath.Join(dir, "module.yaml"),
		[]byte(strings.Replace(manifest, "version: 1", "version: 2", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if digest() == afterSQL {
		t.Fatal("editing the manifest did not change the digest")
	}

	// A declared file that is missing is an error, not a skipped one: a manifest claiming
	// a view that is not there would otherwise hash as though it had none.
	if err := os.Remove(filepath.Join(dir, "store/views.sql")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("a missing declared view was skipped instead of refused")
	}
}

// The identity string must be stable, and must move when a version or a digest moves —
// it is the whole mechanism by which a derived store proves which module set produced it.
func TestSetIdentity(t *testing.T) {
	root := t.TempDir()
	writeModule(t, root, "alpha", stubManifest, nil)
	writeModule(t, root, "beta", strings.Replace(stubManifest, "id: alpha", "id: beta", 1), nil)

	ms, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	first := IdentityString(ms)
	for i := 0; i < 4; i++ {
		again, err := LoadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if IdentityString(again) != first {
			t.Fatal("the identity string is not stable across loads")
		}
	}
	if !strings.HasPrefix(first, "modules=alpha@1/") || !strings.Contains(first, " set=") {
		t.Fatalf("unexpected shape: %s", first)
	}

	// Order of the input must not matter; id order is the rule.
	swapped := []*Module{ms[1], ms[0]}
	if IdentityString(swapped) != first {
		t.Fatal("the identity depends on input order")
	}

	bumped := []*Module{{Manifest: ms[0].Manifest, SHA256: ms[0].SHA256}, ms[1]}
	bumped[0].Manifest.Version = 2
	if SetIdentity(bumped) == SetIdentity(ms) {
		t.Fatal("a version bump did not change the set identity")
	}

	rehashed := []*Module{{Manifest: ms[0].Manifest, SHA256: ms[0].SHA256}, ms[1]}
	rehashed[0].SHA256[0] ^= 0xff
	if SetIdentity(rehashed) == SetIdentity(ms) {
		t.Fatal("a digest change did not change the set identity")
	}

	// An empty set says so rather than hashing nothing into something.
	if got := IdentityString(nil); got != "modules=none" {
		t.Fatalf("empty set identity is %q", got)
	}
	// And the domain separator is actually used, so a set identity can never collide with
	// a bare concatenation of its parts.
	empty := SetIdentity(nil)
	if hex.EncodeToString(empty[:]) == strings.Repeat("0", 64) {
		t.Fatal("an empty set hashed to zero")
	}
}

func derived(id string, derives, requires string) string {
	return "schema: cairn.module/v1-draft\nid: " + id +
		"\nversion: 1\nname: " + id + "\nstatus: derived\nsources: [a fixture]\n" + derives + requires
}

// Exactly one module owns a derived column: two owners would make the stored value depend
// on load order, which invariant 5 cannot tolerate.
func TestTwoModulesCannotOwnOneColumn(t *testing.T) {
	a := &Module{Manifest: Manifest{ID: "alpha", Derives: []Derive{{Column: "boost.boost_psi"}}}}
	b := &Module{Manifest: Manifest{ID: "beta", Derives: []Derive{{Column: "boost.boost_psi"}}}}
	errs := CheckSet([]*Module{a, b}, nil)
	if len(errs) == 0 || !strings.Contains(errs[0].Error(), "exactly one module owns") {
		t.Fatalf("two owners were accepted: %v", errs)
	}
}

// A cycle means no load order exists. A chain must still work, because fuel-economy
// genuinely needs the lambda fuel-mixture derives.
func TestDerivationOrder(t *testing.T) {
	mk := func(id, owns, reads string) *Module {
		m := &Module{Manifest: Manifest{ID: id}}
		if owns != "" {
			m.Manifest.Derives = []Derive{{Column: owns}}
		}
		if reads != "" {
			m.Manifest.Requires = &Requires{Store: []string{reads}}
		}
		return m
	}

	cyc := []*Module{mk("alpha", "boost.a", "boost.b"), mk("beta", "boost.b", "boost.a")}
	if errs := CheckSet(cyc, nil); len(errs) == 0 {
		t.Fatal("a cycle was accepted")
	}
	if _, err := Order(cyc); err == nil {
		t.Fatal("Order returned an order for a cycle")
	}

	chain := []*Module{mk("gamma", "", "boost.b"), mk("beta", "boost.b", "boost.a"), mk("alpha", "boost.a", "")}
	if errs := CheckSet(chain, nil); len(errs) != 0 {
		t.Fatalf("a chain was rejected: %v", errs)
	}
	ordered, err := Order(chain)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(ordered); got[0] != "alpha" || got[1] != "beta" || got[2] != "gamma" {
		t.Fatalf("wrong derivation order: %v", got)
	}

	// Self-reference is not a cycle: a module may read a column it derives itself.
	if _, err := Order([]*Module{mk("alpha", "boost.a", "boost.a")}); err != nil {
		t.Fatalf("self-reference treated as a cycle: %v", err)
	}
}

// A module whose requirements the live store does not satisfy is unavailable WITH A
// REASON, never dropped silently: "this car never reported manifold pressure" is useful,
// an empty page is not.
func TestResolveNamesWhatIsMissing(t *testing.T) {
	cat := &Catalogue{
		Columns: map[string]bool{"obd.rpm": true},
		Objects: map[string]bool{"obd": true},
	}
	a := &Module{Manifest: Manifest{ID: "alpha",
		Requires: &Requires{Store: []string{"obd.rpm", "boost.map_kpa"}}}}
	b := &Module{Manifest: Manifest{ID: "beta",
		Requires: &Requires{Store: []string{"obd.rpm"}}}}

	got := Resolve([]*Module{a, b}, cat)
	if len(got) != 2 {
		t.Fatalf("expected two results, got %d", len(got))
	}
	if got[0].Available {
		t.Fatal("alpha should be unavailable")
	}
	if len(got[0].Missing) != 1 || got[0].Missing[0] != "boost.map_kpa" {
		t.Fatalf("alpha should name what is missing, got %v", got[0].Missing)
	}
	if !got[1].Available || len(got[1].Missing) != 0 {
		t.Fatalf("beta should be available: %+v", got[1])
	}

	// A requirement another module derives counts as satisfied.
	c := &Module{Manifest: Manifest{ID: "gamma",
		Derives:  []Derive{{Column: "boost.map_kpa"}},
		Requires: &Requires{Store: []string{"obd.rpm"}}}}
	if r := Resolve([]*Module{a, c}, cat); !r[0].Available {
		t.Fatalf("alpha should be available once gamma derives the column: %+v", r[0])
	}
}

// Nothing a module declares may write to the store, and a literal must not be mistaken
// for a placeholder or a statement separator.
func TestQueryRules(t *testing.T) {
	q := func(sql string, params ...Param) *QueriesFile {
		return &QueriesFile{Schema: QueriesSchema, Module: "alpha",
			Queries: []Query{{Name: "q", SQL: sql, Params: params}}}
	}
	vid := Param{Name: "vehicle_id", Type: "vehicle_id"}

	if errs := CheckQueries(q("SELECT 1 WHERE a = $vehicle_id"), "alpha"); !anyContains(errs, "not declared") {
		t.Errorf("an unbound parameter was accepted: %v", errs)
	}
	if errs := CheckQueries(q("SELECT 1", vid), "alpha"); !anyContains(errs, "does not appear") {
		t.Errorf("an unused parameter was accepted: %v", errs)
	}
	for _, bad := range []string{"DELETE FROM boost", "UPDATE boost SET x = 1", "ATTACH 'x.db'"} {
		if errs := CheckQueries(q(bad), "alpha"); len(errs) == 0 {
			t.Errorf("%q was accepted", bad)
		}
	}
	if errs := CheckQueries(q("WITH x AS (SELECT 1 AS n) SELECT n FROM x"), "alpha"); len(errs) != 0 {
		t.Errorf("a WITH query was rejected: %v", errs)
	}
	ok := q("SELECT 'a;b' AS s, '$nope' AS l FROM boost WHERE vehicle_id = $vehicle_id", vid)
	if errs := CheckQueries(ok, "alpha"); len(errs) != 0 {
		t.Errorf("a literal was mistaken for syntax: %v", errs)
	}
	if errs := CheckQueries(q("SELECT 1 WHERE a = $vehicle_id", vid), "beta"); !anyContains(errs, "does not match") {
		t.Errorf("a query file claiming another module was accepted: %v", errs)
	}
}

func anyContains(errs []error, want string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), want) {
			return true
		}
	}
	return false
}

// A stub claims nothing. That is what makes a stub honest rather than empty.
func TestStubClaimsNothing(t *testing.T) {
	base := func() *Manifest {
		return &Manifest{Schema: ManifestSchema, ID: "alpha", Version: 1, Name: "Alpha",
			Status: "stub", Sources: []string{"a"}}
	}
	if errs := Check(base(), "alpha", nil, nil); len(errs) != 0 {
		t.Fatalf("a bare stub was rejected: %v", errs)
	}
	for name, mutate := range map[string]func(*Manifest){
		"a derivation": func(m *Manifest) { m.Derives = []Derive{{Column: "boost.x", Type: "DOUBLE", Expr: "1"}} },
		"a metric": func(m *Manifest) {
			m.Metrics = []Metric{{Key: "k", Label: "K", Sample: "boot", SourceView: "v_alpha_x", SourceColumn: "c"}}
		},
		"an engine field": func(m *Manifest) { m.Requires = &Requires{EngineFields: []string{"rpm"}} },
	} {
		m := base()
		mutate(m)
		if errs := Check(m, "alpha", nil, nil); !anyContains(errs, "a stub claims nothing") {
			t.Errorf("a stub with %s was accepted: %v", name, errs)
		}
	}
}

// A path in a manifest must not reach outside the module's own directory.
func TestPathsCannotEscape(t *testing.T) {
	for _, bad := range []string{"/etc/passwd", "../other/views.sql", "a/../../b.sql", "./x.sql", ""} {
		if err := safeRelPath(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{"store/views.sql", "api/queries.yaml", "x.sql"} {
		if err := safeRelPath(good); err != nil {
			t.Errorf("%q was rejected: %v", good, err)
		}
	}
}

func TestDirPrefersTheEnvironment(t *testing.T) {
	t.Setenv("CAIRN_MODULES", "/somewhere/modules")
	if got := Dir(); got != "/somewhere/modules" {
		t.Fatalf("CAIRN_MODULES ignored, got %q", got)
	}
	t.Setenv("CAIRN_MODULES", "")
	// With nothing set and nothing on disk, no module set is configured, which is not an
	// error: it is a server that records drives and interprets nothing.
	if got := Dir(); got != "" && got != "modules" && got != ".modules/modules" {
		t.Fatalf("unexpected fallback %q", got)
	}
}
