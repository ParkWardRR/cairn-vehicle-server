// Package storeschema is the machine-readable form of the store/v1 contract: the tables,
// views and columns the web layer relies on, as contracts/store/v1/schema.json pins them,
// and the rule for deciding whether a store's native schema still satisfies them.
//
// The pinned file is a compatible RANGE, not a snapshot. A release may add tables, views
// and columns (that is what a store/v1 minor is) but must keep, with a compatible type,
// everything the file lists. Compare is therefore run against the schema a real store
// built for itself (cmd/dump-schema), never against a store loaded with the expected
// schema, which would pass for a release that does not produce it.
package storeschema

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

// Schema is schema.json.
type Schema struct {
	// Contract is the major version the file belongs to, "store/v1".
	Contract string `json:"contract"`
	// StoreContract is the store/vN.M the file was generated from: the least a release
	// must claim to satisfy it.
	StoreContract string            `json:"store_contract"`
	Tables        map[string]Object `json:"tables"`
	Views         map[string]Object `json:"views"`
}

// Object is one table or view.
type Object struct {
	Columns []Column `json:"columns"`
}

// Column is a column's name and its DuckDB type as information_schema spells it.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// FromCapabilities turns what a live store reports into a Schema. Columns keep the
// store's own order, so a regenerated file differs only where the schema did.
func FromCapabilities(c tsdb.Capabilities) Schema {
	s := Schema{
		Contract:      "store/v" + strconv.Itoa(major(c.StoreContract)),
		StoreContract: c.StoreContract,
		Tables:        map[string]Object{},
		Views:         map[string]Object{},
	}
	obj := func(name string) Object {
		var o Object
		for i, col := range c.Columns[name] {
			o.Columns = append(o.Columns, Column{Name: col, Type: c.ColumnTypes[name][i]})
		}
		return o
	}
	for _, n := range c.Tables {
		s.Tables[n] = obj(n)
	}
	for _, n := range c.Views {
		s.Views[n] = obj(n)
	}
	return s
}

// Marshal renders s as the indented, key-sorted JSON that is committed to the contracts.
func Marshal(s Schema) ([]byte, error) {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Load reads a schema.json.
func Load(path string) (Schema, error) {
	var s Schema
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Compare reports every way native fails to satisfy pinned; none means it does.
//
// A release satisfies the contract when it has the same major, at least the pinned minor,
// and every pinned table and view is the same kind of object in native with every pinned
// column present under a compatible type. Anything native has beyond that is allowed.
// Column order is not part of the contract: consumers read columns by name.
func Compare(pinned, native Schema) []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	pm, pn := parse(pinned.StoreContract)
	nm, nn := parse(native.StoreContract)
	switch {
	case pm == 0:
		add("pinned store_contract %q is not store/vN.M", pinned.StoreContract)
	case nm != pm:
		add("store_contract %q: the pinned contract is store/v%d, and a different major is a different contract", native.StoreContract, pm)
	case nn < pn:
		add("store_contract %q is older than the pinned %q", native.StoreContract, pinned.StoreContract)
	}

	for _, k := range []struct {
		kind, otherKind  string
		want, got, other map[string]Object
	}{
		{"table", "view", pinned.Tables, native.Tables, native.Views},
		{"view", "table", pinned.Views, native.Views, native.Tables},
	} {
		for _, name := range sortedKeys(k.want) {
			have, ok := k.got[name]
			if !ok {
				if _, elsewhere := k.other[name]; elsewhere {
					add("%s %s is now a %s", k.kind, name, k.otherKind)
				} else {
					add("%s %s is missing", k.kind, name)
				}
				continue
			}
			types := map[string]string{}
			for _, c := range have.Columns {
				types[strings.ToLower(c.Name)] = c.Type
			}
			for _, c := range k.want[name].Columns {
				got, ok := types[strings.ToLower(c.Name)]
				switch {
				case !ok:
					add("%s %s: column %s is missing", k.kind, name, c.Name)
				case !Compatible(c.Type, got):
					add("%s %s: column %s is %s, the contract requires %s", k.kind, name, c.Name, got, c.Type)
				}
			}
		}
	}
	return out
}

// Integer types in widening order. A column may grow within its family without breaking
// a reader (values that fit before still fit, and JSON has one number type); moving
// between families, or narrowing, can change what a value means or lose it.
var families = [][]string{
	{"TINYINT", "SMALLINT", "INTEGER", "BIGINT", "HUGEINT"},
	{"UTINYINT", "USMALLINT", "UINTEGER", "UBIGINT", "UHUGEINT"},
}

// Compatible reports whether a column the contract types as pinned may be native.
// Identical is compatible; so is a wider integer of the same signedness. Every other
// change (VARCHAR to INTEGER, TIMESTAMP to DATE, FLOAT to DOUBLE, signed to unsigned) is
// a retype.
func Compatible(pinned, native string) bool {
	p, n := strings.ToUpper(strings.TrimSpace(pinned)), strings.ToUpper(strings.TrimSpace(native))
	if p == n {
		return true
	}
	for _, fam := range families {
		if pi := index(fam, p); pi >= 0 && index(fam, n) >= pi {
			return true
		}
	}
	return false
}

func index(list []string, s string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return -1
}

// parse reads "store/v1.2" as (1, 2); a string that is not one gives (0, 0).
func parse(s string) (major, minor int) {
	rest, ok := strings.CutPrefix(s, "store/v")
	if !ok {
		return 0, 0
	}
	a, b, _ := strings.Cut(rest, ".")
	major, err := strconv.Atoi(a)
	if err != nil || major < 1 {
		return 0, 0
	}
	if b != "" {
		minor, _ = strconv.Atoi(b)
	}
	return major, minor
}

func major(s string) int { m, _ := parse(s); return m }

func sortedKeys(m map[string]Object) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
