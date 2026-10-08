// Package modules reads a Cairn module set: the manifests that say what a reading
// means, as against the core, which says what a drive was.
//
// A module is interpretation — boost, fuel economy, fuel trims, driving style, the
// speedometer check, place kinds — and `contracts/module/v1` is the shape of one. This
// package is the server's reader: it loads manifests from a directory at startup,
// validates them, resolves what they require against the store that is actually serving,
// and computes the module-set identity.
//
// What a module may not do is worth stating here too, because this is the code that would
// have to be subverted for any of it: a module never sees plaintext bundle bytes, holds or
// derives a key, influences whether a receipt verifies, influences a prune, adds a
// listener, or writes to the store. The manifest has no field through which any of it
// could be asked for, and nothing in this package adds one.
//
// It deliberately does not evaluate anything. A derived value is a SQL expression and
// DuckDB is the evaluator; no interpreter is added on this host, which is the line between
// a module and the plugin system the project retired.
package modules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Schema identifiers this package accepts.
const (
	ManifestSchema = "cairn.module/v1-draft"
	QueriesSchema  = "cairn.module-queries/v1-draft"
)

// SetDomain is the domain separator for the module-set identity (module/v1 §7).
const SetDomain = "cairn.module-set/v1-draft\n"

// Manifest is one module's declarations.
type Manifest struct {
	Schema   string    `yaml:"schema" json:"schema"`
	ID       string    `yaml:"id" json:"id"`
	Version  int       `yaml:"version" json:"version"`
	Name     string    `yaml:"name" json:"name"`
	Status   string    `yaml:"status" json:"status"`
	Sources  []string  `yaml:"sources" json:"sources"`
	Requires *Requires `yaml:"requires,omitempty" json:"requires,omitempty"`
	Derives  []Derive  `yaml:"derives,omitempty" json:"derives,omitempty"`
	Metrics  []Metric  `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	Views    []string  `yaml:"views,omitempty" json:"views,omitempty"`
	Queries  string    `yaml:"queries,omitempty" json:"queries,omitempty"`
	UI       *UI       `yaml:"ui,omitempty" json:"ui,omitempty"`
	IOS      *IOS      `yaml:"ios,omitempty" json:"ios,omitempty"`
}

// Requires is what a module needs before it can say anything.
type Requires struct {
	Store        []string `yaml:"store,omitempty" json:"store,omitempty"`
	EngineFields []string `yaml:"engine_fields,omitempty" json:"engine_fields,omitempty"`
}

// Derive is a column a module defines on a core table: a SQL scalar expression over the
// columns of that row's own table, evaluated by DuckDB during load.
type Derive struct {
	Column string `yaml:"column" json:"column"`
	Type   string `yaml:"type" json:"type"`
	Expr   string `yaml:"expr" json:"expr"`
	Note   string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Table and Name split a derived column reference.
func (d Derive) Table() string { t, _, _ := cut(d.Column); return t }

// Name is the column's own name.
func (d Derive) Name() string { _, c, _ := cut(d.Column); return c }

func cut(ref string) (table, col string, ok bool) {
	i := strings.IndexByte(ref, '.')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// Metric is one quantity a module contributes to the generic machinery.
type Metric struct {
	Key                string       `yaml:"key" json:"key"`
	Label              string       `yaml:"label" json:"label"`
	Unit               string       `yaml:"unit" json:"unit"`
	Sample             string       `yaml:"sample" json:"sample"`
	SourceView         string       `yaml:"source_view" json:"source_view"`
	SourceColumn       string       `yaml:"source_column" json:"source_column"`
	TripInsight        *TripInsight `yaml:"trip_insight,omitempty" json:"trip_insight,omitempty"`
	DashboardHighlight bool         `yaml:"dashboard_highlight,omitempty" json:"dashboard_highlight,omitempty"`
	IOSGauge           *IOSGauge    `yaml:"ios_gauge,omitempty" json:"ios_gauge,omitempty"`
}

// TripInsight is a metric's contribution to the trip-detail insight list.
type TripInsight struct {
	Label     string `yaml:"label" json:"label"`
	Agg       string `yaml:"agg" json:"agg"`
	Precision int    `yaml:"precision" json:"precision"`
}

// IOSGauge is a metric's contribution to the app's live gauge grid.
type IOSGauge struct {
	Field     string `yaml:"field" json:"field"`
	Label     string `yaml:"label" json:"label"`
	Unit      string `yaml:"unit" json:"unit"`
	Precision int    `yaml:"precision" json:"precision"`
}

// UI is a module's page.
type UI struct {
	Route        string `yaml:"route" json:"route"`
	Nav          Nav    `yaml:"nav" json:"nav"`
	VehicleScope string `yaml:"vehicle_scope" json:"vehicle_scope"`
}

// Nav is a module's entry in the shell's navigation.
type Nav struct {
	Label string `yaml:"label" json:"label"`
	Group string `yaml:"group" json:"group"`
	Order int    `yaml:"order" json:"order"`
	Icon  string `yaml:"icon,omitempty" json:"icon,omitempty"`
}

// IOS is a module's participation in the app, deliberately narrow.
type IOS struct {
	TripSection *struct {
		Label string `yaml:"label" json:"label"`
		Order int    `yaml:"order" json:"order"`
	} `yaml:"trip_section,omitempty" json:"trip_section,omitempty"`
}

// QueriesFile is a module's named, parameterised queries.
type QueriesFile struct {
	Schema  string  `yaml:"schema" json:"schema"`
	Module  string  `yaml:"module" json:"module"`
	Queries []Query `yaml:"queries" json:"queries"`
}

// Query is one named question. Parameters are bound, never interpolated.
type Query struct {
	Name           string  `yaml:"name" json:"name"`
	Summary        string  `yaml:"summary,omitempty" json:"summary,omitempty"`
	Params         []Param `yaml:"params,omitempty" json:"params,omitempty"`
	SQL            string  `yaml:"sql" json:"sql"`
	AgeThresholdMS *int    `yaml:"age_threshold_ms,omitempty" json:"age_threshold_ms,omitempty"`
}

// Param is one bound query parameter.
type Param struct {
	Name     string `yaml:"name" json:"name"`
	Type     string `yaml:"type" json:"type"`
	Required *bool  `yaml:"required,omitempty" json:"required,omitempty"`
	Summary  string `yaml:"summary,omitempty" json:"summary,omitempty"`
}

// Module is a loaded module: its declarations, where they came from, and the digest that
// goes into the module-set identity.
type Module struct {
	Manifest Manifest
	Dir      string
	Queries  *QueriesFile
	// SHA256 is over the manifest and every file the manifest names (module/v1 §7).
	SHA256 [32]byte
	// Views is the SQL read from Manifest.Views, in declaration order.
	Views []ViewFile
}

// ViewFile is one SQL file a module declares.
type ViewFile struct {
	Path string
	SQL  string
}

// ID is the module's id.
func (m *Module) ID() string { return m.Manifest.ID }

var (
	idRe     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	colRefRe = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
	keyRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	viewRe   = regexp.MustCompile(`^v_[a-z][a-z0-9_]*$`)
	routeRe  = regexp.MustCompile(`^/[a-z0-9][a-z0-9-/]*$`)
	qNameRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	pNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// Deliberately looser than pNameRe, so a wrongly cased placeholder is reported as
	// undeclared rather than not noticed.
	placeholderRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)
)

var (
	statuses   = set("stub", "derived", "verified")
	samples    = set("sample", "pull", "boot", "trip")
	aggs       = set("min", "max", "avg", "median")
	navGroups  = set("everyday", "detail")
	scopes     = set("all", "single", "none")
	paramTypes = set("vehicle_id", "boot_id", "date", "int", "number", "string")
	duckTypes  = set("BOOLEAN", "TINYINT", "SMALLINT", "INTEGER", "BIGINT", "UTINYINT",
		"USMALLINT", "UINTEGER", "UBIGINT", "FLOAT", "DOUBLE", "VARCHAR", "DATE", "TIMESTAMP")
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func sortedKeys(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Catalogue is what a module's requirements are resolved against: the objects and columns
// the store that is actually serving has. Empty skips those checks.
type Catalogue struct {
	// Columns holds "table.column" for every table and view.
	Columns map[string]bool
	// Objects holds every table and view name.
	Objects map[string]bool
}

// Has reports whether the live store has a table.column.
func (c *Catalogue) Has(ref string) bool { return c != nil && c.Columns[ref] }

// HasObject reports whether the live store has a table or view.
func (c *Catalogue) HasObject(name string) bool { return c != nil && c.Objects[name] }

// Check validates one manifest. dirName is the directory it was loaded from; the id must
// equal it, or a module can be selected under a name that is not in it.
//
// This duplicates rules that `modgen` and the contracts repository's `modulecheck` also
// enforce, on purpose. Those two run in CI on a reviewed module set; this runs on whatever
// directory an operator points the server at, and a server that trusted an unvalidated
// manifest would fail later and less clearly.
func Check(m *Manifest, dirName string, queries *QueriesFile, cat *Catalogue) []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if m.Schema != ManifestSchema {
		add("schema %q is not %q", m.Schema, ManifestSchema)
	}
	if !idRe.MatchString(m.ID) || len(m.ID) > 31 {
		add("id %q must be lowercase alphanumeric with single hyphens, at most 31 characters", m.ID)
	} else if dirName != "" && m.ID != dirName {
		add("id %q does not match the directory name %q", m.ID, dirName)
	}
	if m.Version < 1 || m.Version > 65535 {
		add("version %d must be between 1 and 65535", m.Version)
	}
	if strings.TrimSpace(m.Name) == "" {
		add("a module needs a name")
	}
	if !statuses[m.Status] {
		add("status %q is not stub, derived or verified", m.Status)
	}
	if len(m.Sources) == 0 {
		add("sources must name at least one source: a claim without one is not reviewable")
	}

	// A stub names the module and claims nothing.
	if m.Status == "stub" {
		switch {
		case len(m.Derives) > 0:
			add("a stub claims nothing, but it derives %d column(s)", len(m.Derives))
		case len(m.Metrics) > 0:
			add("a stub claims nothing, but it states %d metric(s)", len(m.Metrics))
		case m.Requires != nil && len(m.Requires.EngineFields) > 0:
			add("a stub claims nothing, but it requires %d engine field(s)", len(m.Requires.EngineFields))
		}
	}

	owned := map[string]bool{}
	for i, d := range m.Derives {
		switch {
		case !colRefRe.MatchString(d.Column):
			add("derives[%d].column %q must be table.column in lowercase", i, d.Column)
		case owned[d.Column]:
			add("derives[%d]: %q is already owned; exactly one derivation owns a column", i, d.Column)
		default:
			owned[d.Column] = true
		}
		if !duckTypes[d.Type] {
			add("derives[%d].type %q is not a store type (%s)", i, d.Type, sortedKeys(duckTypes))
		}
		if strings.TrimSpace(d.Expr) == "" {
			add("derives[%d].expr is empty", i)
		}
		if strings.Contains(stripStrings(d.Expr), ";") {
			add("derives[%d].expr holds a semicolon: a derivation is one expression", i)
		}
	}

	if m.Requires != nil {
		for _, ref := range m.Requires.Store {
			if !colRefRe.MatchString(ref) {
				add("requires.store %q must be table.column in lowercase", ref)
				continue
			}
			// A column this module derives is legitimate; so is one another module in the
			// set derives, which CheckSet resolves.
			if cat != nil && len(cat.Columns) > 0 && !cat.Has(ref) && !owned[ref] {
				add("requires.store %q is not in the store and this module does not derive it", ref)
			}
		}
	}

	ownPrefix := "v_" + strings.ReplaceAll(m.ID, "-", "_") + "_"
	seen := map[string]bool{}
	for i, mt := range m.Metrics {
		where := fmt.Sprintf("metrics[%d] (%s)", i, mt.Key)
		switch {
		case !keyRe.MatchString(mt.Key):
			add("metrics[%d].key %q must be lowercase snake_case", i, mt.Key)
		case seen[mt.Key]:
			add("metrics[%d].key %q is repeated", i, mt.Key)
		default:
			seen[mt.Key] = true
		}
		if strings.TrimSpace(mt.Label) == "" {
			add("%s needs a label", where)
		}
		if !samples[mt.Sample] {
			add("%s: sample %q is not one of %s", where, mt.Sample, sortedKeys(samples))
		}
		if !viewRe.MatchString(mt.SourceView) {
			add("%s: source_view %q must be named v_<something>", where, mt.SourceView)
		} else if !cat.HasObject(mt.SourceView) && !strings.HasPrefix(mt.SourceView, ownPrefix) {
			add("%s: source_view %q is neither in the store nor named for this module (%s*)",
				where, mt.SourceView, ownPrefix)
		}
		if mt.SourceColumn == "" {
			add("%s needs a source_column", where)
		}
		if ti := mt.TripInsight; ti != nil {
			if !aggs[ti.Agg] {
				add("%s: trip_insight.agg %q is not one of %s", where, ti.Agg, sortedKeys(aggs))
			}
			if ti.Precision < 0 || ti.Precision > 4 {
				add("%s: trip_insight.precision %d is outside 0..4", where, ti.Precision)
			}
		}
	}

	for i, v := range m.Views {
		if err := safeRelPath(v); err != nil {
			add("views[%d] %q: %v", i, v, err)
		}
	}
	if m.Queries != "" {
		if err := safeRelPath(m.Queries); err != nil {
			add("queries %q: %v", m.Queries, err)
		}
	}

	if ui := m.UI; ui != nil {
		if !routeRe.MatchString(ui.Route) {
			add("ui.route %q must be a lowercase path starting with /", ui.Route)
		}
		if !navGroups[ui.Nav.Group] {
			add("ui.nav.group %q is not one of %s", ui.Nav.Group, sortedKeys(navGroups))
		}
		if !scopes[ui.VehicleScope] {
			add("ui.vehicle_scope %q is not one of %s", ui.VehicleScope, sortedKeys(scopes))
		}
	}

	if queries != nil {
		errs = append(errs, CheckQueries(queries, m.ID)...)
	}
	return errs
}

// CheckQueries validates a query file. module is the owning manifest's id; empty skips
// the ownership check.
func CheckQueries(q *QueriesFile, module string) []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if q.Schema != QueriesSchema {
		add("queries schema %q is not %q", q.Schema, QueriesSchema)
	}
	if !idRe.MatchString(q.Module) {
		add("queries module %q must be lowercase with single hyphens", q.Module)
	} else if module != "" && q.Module != module {
		add("queries module %q does not match the manifest's module %q", q.Module, module)
	}
	if len(q.Queries) == 0 {
		add("queries must hold at least one query")
	}

	seen := map[string]bool{}
	for i, qq := range q.Queries {
		where := fmt.Sprintf("queries[%d]", i)
		if qq.Name != "" {
			where = fmt.Sprintf("queries[%d] (%s)", i, qq.Name)
		}
		switch {
		case !qNameRe.MatchString(qq.Name):
			add("%s: name %q must be lowercase, digits and hyphens", where, qq.Name)
		case seen[qq.Name]:
			add("%s: duplicate query name %q", where, qq.Name)
		default:
			seen[qq.Name] = true
		}

		declared := map[string]bool{}
		for j, p := range qq.Params {
			switch {
			case !pNameRe.MatchString(p.Name):
				add("%s: params[%d] name %q must be lowercase snake_case", where, j, p.Name)
			case declared[p.Name]:
				add("%s: params[%d] name %q is repeated", where, j, p.Name)
			default:
				declared[p.Name] = true
			}
			if !paramTypes[p.Type] {
				add("%s: params[%d] (%s) type %q is not one of %s", where, j, p.Name, p.Type, sortedKeys(paramTypes))
			}
		}

		sql := strings.TrimSpace(qq.SQL)
		if sql == "" {
			add("%s: sql is empty", where)
			continue
		}
		upper := strings.ToUpper(sql)
		if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
			add("%s: a query must be a SELECT (or a WITH leading to one); nothing a module declares may write to the store", where)
		}
		bare := stripStrings(sql)
		if strings.Contains(bare, ";") {
			add("%s: sql holds a semicolon outside a string; one statement per query", where)
		}

		// Both directions: a query may neither read an unbound parameter nor silently
		// ignore an argument a caller passed.
		used := map[string]bool{}
		for _, mm := range placeholderRe.FindAllStringSubmatch(bare, -1) {
			used[mm[1]] = true
		}
		for name := range used {
			if !declared[name] {
				add("%s: sql reads $%s, which is not declared in params", where, name)
			}
		}
		for name := range declared {
			if !used[name] {
				add("%s: params declares %s, which does not appear as $%s in the sql", where, name, name)
			}
		}
	}
	return errs
}

// CheckSet validates a whole set: one owner per derived column, no cycle in derivation
// order, no repeated id, and requirements satisfiable by the store plus the set itself.
func CheckSet(ms []*Module, cat *Catalogue) []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	ids := map[string]bool{}
	owner := map[string]string{}
	for _, m := range ms {
		if ids[m.ID()] {
			add("two modules share the id %q", m.ID())
		}
		ids[m.ID()] = true
		for _, d := range m.Manifest.Derives {
			if prev, ok := owner[d.Column]; ok {
				add("column %q is derived by both %q and %q; exactly one module owns a column",
					d.Column, prev, m.ID())
				continue
			}
			owner[d.Column] = m.ID()
		}
	}

	// A requirement may be met by the store or by any module in the set.
	if cat != nil && len(cat.Columns) > 0 {
		for _, m := range ms {
			if m.Manifest.Requires == nil {
				continue
			}
			for _, ref := range m.Manifest.Requires.Store {
				if !cat.Has(ref) && owner[ref] == "" {
					add("%s requires %q, which the store does not have and no module derives", m.ID(), ref)
				}
			}
		}
	}

	if cycle := findCycle(ms, owner); len(cycle) > 0 {
		add("derivation order has a cycle: %s", strings.Join(cycle, " -> "))
	}
	return errs
}

// Order returns the modules sorted so that every module runs after each module whose
// derived columns it reads. Errors when no such order exists.
//
// This is what makes a derived store reproducible: with a cycle, or with an arbitrary
// order, the column values would depend on which order a particular run happened to pick.
func Order(ms []*Module) ([]*Module, error) {
	owner := map[string]string{}
	for _, m := range ms {
		for _, d := range m.Manifest.Derives {
			owner[d.Column] = m.ID()
		}
	}
	if cycle := findCycle(ms, owner); len(cycle) > 0 {
		return nil, fmt.Errorf("derivation order has a cycle: %s", strings.Join(cycle, " -> "))
	}

	byID := map[string]*Module{}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		byID[m.ID()] = m
		ids = append(ids, m.ID())
	}
	sort.Strings(ids) // deterministic: a tie is broken by id, never by map order

	var out []*Module
	done := map[string]bool{}
	var visit func(string)
	visit = func(id string) {
		if done[id] {
			return
		}
		done[id] = true
		m := byID[id]
		if m == nil {
			return
		}
		var deps []string
		if m.Manifest.Requires != nil {
			for _, ref := range m.Manifest.Requires.Store {
				if o := owner[ref]; o != "" && o != id {
					deps = append(deps, o)
				}
			}
		}
		sort.Strings(deps)
		for _, d := range deps {
			visit(d)
		}
		out = append(out, m)
	}
	for _, id := range ids {
		visit(id)
	}
	return out, nil
}

func findCycle(ms []*Module, owner map[string]string) []string {
	deps := map[string][]string{}
	for _, m := range ms {
		var d []string
		if m.Manifest.Requires != nil {
			for _, ref := range m.Manifest.Requires.Store {
				if o := owner[ref]; o != "" && o != m.ID() {
					d = append(d, o)
				}
			}
		}
		sort.Strings(d)
		deps[m.ID()] = d
	}
	const (
		white = 0
		grey  = 1
		black = 2
	)
	state := map[string]int{}
	var path []string
	var walk func(string) []string
	walk = func(n string) []string {
		state[n] = grey
		path = append(path, n)
		for _, d := range deps[n] {
			if _, known := deps[d]; !known {
				continue
			}
			switch state[d] {
			case grey:
				for i, p := range path {
					if p == d {
						return append(append([]string{}, path[i:]...), d)
					}
				}
			case white:
				if c := walk(d); c != nil {
					return c
				}
			}
		}
		path = path[:len(path)-1]
		state[n] = black
		return nil
	}
	ids := make([]string, 0, len(deps))
	for id := range deps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if state[id] == white {
			path = nil
			if c := walk(id); c != nil {
				return c
			}
		}
	}
	return nil
}

// safeRelPath refuses anything that could reach outside the module's own directory.
func safeRelPath(p string) error {
	if p == "" {
		return errors.New("path is empty")
	}
	if strings.HasPrefix(p, "/") {
		return errors.New("path must be relative to the module directory")
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return errors.New("path must not leave the module directory")
		}
	}
	if filepath.Clean(p) != p {
		return errors.New("path must be in cleaned form")
	}
	return nil
}

// stripStrings blanks single-quoted SQL literals, so a semicolon or a $ inside one is not
// mistaken for a statement separator or a placeholder. A doubled quote escapes.
func stripStrings(sql string) string {
	out := make([]byte, 0, len(sql))
	inside := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == '\'' {
			if inside && i+1 < len(sql) && sql[i+1] == '\'' {
				out = append(out, ' ', ' ')
				i++
				continue
			}
			inside = !inside
			out = append(out, ' ')
			continue
		}
		if inside {
			out = append(out, ' ')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}

// Dir resolves where the module set is read from: CAIRN_MODULES wins, so a module set and
// the server can change together on a workstation; otherwise the fetched copy. Empty means
// no module set is configured, which is not an error — it is a server with no modules.
func Dir() string {
	if v := os.Getenv("CAIRN_MODULES"); v != "" {
		return v
	}
	for _, p := range []string{"modules", ".modules/modules"} {
		if fi, err := os.Stat(p); err == nil && fi.IsDir() {
			return p
		}
	}
	return ""
}
