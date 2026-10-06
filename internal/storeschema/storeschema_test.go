package storeschema

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/contracts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

// native is the schema a real store builds for itself.
func native(t *testing.T) Schema {
	t.Helper()
	ctx := context.Background()
	db, err := tsdb.BuildSynthetic(ctx, func(tsdb.Appenders) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	caps, err := db.Capabilities(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return FromCapabilities(caps)
}

// The release's native schema must satisfy contracts/store/v1/schema.json. The pinned
// file is read as a range (see Compare), and the store is the one this tree builds, not
// one loaded with the expected schema.
func TestNativeSchemaSatisfiesThePinnedContract(t *testing.T) {
	path := contracts.Path("store", "v1", "schema.json")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("the pinned contracts have no store/v1/schema.json (looked for %s), so this release's native schema was NOT compared with anything. "+
			"It appears in the first contracts release after the one contracts.lock pins; tag that, then bump contracts.lock. "+
			"To check locally, point CAIRN_CONTRACTS at a contracts checkout that has it.", path)
	}
	pinned, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pinned.Tables) == 0 || len(pinned.Views) == 0 {
		t.Fatalf("%s lists no tables or no views: a contract that requires nothing cannot fail", path)
	}
	for _, p := range Compare(pinned, native(t)) {
		t.Error(p)
	}
}

// The schema dump-schema writes must be accepted by the contract it is meant to produce:
// regenerating schema.json from the same tree can never be a breaking change.
func TestNativeSchemaSatisfiesItself(t *testing.T) {
	n := native(t)
	if got := Compare(n, n); len(got) != 0 {
		t.Fatalf("a schema does not satisfy itself: %v", got)
	}
	if n.Contract != "store/v1" || n.StoreContract != tsdb.StoreContract {
		t.Fatalf("contract %q, store_contract %q", n.Contract, n.StoreContract)
	}
}

// A comparison that cannot fail proves nothing. Each case breaks a copy of the native
// schema one way and must be reported, and the extras case must not be.
func TestCompareFailsOnABreakingChange(t *testing.T) {
	pinned := native(t)

	cases := []struct {
		name   string
		mutate func(s *Schema)
		want   string // "" means compatible
	}{
		{"unchanged", func(s *Schema) {}, ""},
		{"a table dropped", func(s *Schema) { delete(s.Tables, "boost") }, "table boost is missing"},
		{"a view dropped", func(s *Schema) { delete(s.Views, "v_pulls") }, "view v_pulls is missing"},
		{"a table became a view", func(s *Schema) {
			s.Views["gap"] = s.Tables["gap"]
			delete(s.Tables, "gap")
		}, "table gap is now a view"},
		{"a column dropped", func(s *Schema) { s.Tables["position"] = withoutColumn(s.Tables["position"], "lat") }, "table position: column lat is missing"},
		{"vehicle_id dropped from a view", func(s *Schema) { s.Views["v_telemetry"] = withoutColumn(s.Views["v_telemetry"], "vehicle_id") }, "view v_telemetry: column vehicle_id is missing"},
		{"a column retyped", func(s *Schema) { s.Tables["position"] = retyped(s.Tables["position"], "lat", "VARCHAR") }, "column lat is VARCHAR, the contract requires DOUBLE"},
		{"a column narrowed", func(s *Schema) { s.Tables["position"] = retyped(s.Tables["position"], "mono_ms", "USMALLINT") }, "column mono_ms is USMALLINT"},
		{"a column changed sign", func(s *Schema) { s.Tables["position"] = retyped(s.Tables["position"], "mono_ms", "INTEGER") }, "column mono_ms is INTEGER"},
		{"another major", func(s *Schema) { s.StoreContract = "store/v2.0" }, "different major"},

		// what a minor adds is allowed
		{"a new table, view and column", func(s *Schema) {
			s.Tables["extra"] = Object{Columns: []Column{{"vehicle_id", "VARCHAR"}}}
			s.Views["v_extra"] = Object{Columns: []Column{{"vehicle_id", "VARCHAR"}}}
			o := s.Tables["position"]
			o.Columns = append(append([]Column{}, o.Columns...), Column{"extra", "INTEGER"})
			s.Tables["position"] = o
		}, ""},
		{"a column widened", func(s *Schema) { s.Tables["position"] = retyped(s.Tables["position"], "mono_ms", "UBIGINT") }, ""},
		{"columns reordered", func(s *Schema) {
			o := s.Tables["position"]
			o.Columns = append(append([]Column{}, o.Columns[1:]...), o.Columns[0])
			s.Tables["position"] = o
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clone(t, pinned)
			c.mutate(&got)
			report := strings.Join(Compare(pinned, got), "\n")
			if c.want == "" {
				if report != "" {
					t.Fatalf("a compatible change was reported: %s", report)
				}
			} else if !strings.Contains(report, c.want) {
				t.Fatalf("want a report containing %q, got %q", c.want, report)
			}
		})
	}
}

// A release that claims an older minor than the file was generated from cannot have what
// that minor added.
func TestCompareChecksTheMinor(t *testing.T) {
	n := native(t)
	p := clone(t, n)
	p.StoreContract = "store/v1.9"
	if r := strings.Join(Compare(p, n), "\n"); !strings.Contains(r, "is older") {
		t.Fatalf("a release older than the pinned minor was accepted: %q", r)
	}
}

func TestCompatibleTypes(t *testing.T) {
	for _, c := range []struct {
		pinned, native string
		ok             bool
	}{
		{"VARCHAR", "VARCHAR", true},
		{"varchar", "VARCHAR", true},
		{"UINTEGER", "UBIGINT", true},
		{"INTEGER", "BIGINT", true},
		{"BIGINT", "HUGEINT", true},
		{"UBIGINT", "UINTEGER", false},
		{"BIGINT", "INTEGER", false},
		{"INTEGER", "UINTEGER", false},
		{"UINTEGER", "BIGINT", false},
		{"DOUBLE", "FLOAT", false},
		{"FLOAT", "DOUBLE", false},
		{"TIMESTAMP", "DATE", false},
		{"INTEGER", "VARCHAR", false},
		{"DECIMAL(10,2)", "DECIMAL(18,2)", false},
	} {
		if got := Compatible(c.pinned, c.native); got != c.ok {
			t.Errorf("Compatible(%s, %s) = %v, want %v", c.pinned, c.native, got, c.ok)
		}
	}
}

func clone(t *testing.T, s Schema) Schema {
	t.Helper()
	b, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out Schema
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func withoutColumn(o Object, name string) Object {
	var out Object
	for _, c := range o.Columns {
		if c.Name != name {
			out.Columns = append(out.Columns, c)
		}
	}
	return out
}

func retyped(o Object, name, typ string) Object {
	out := Object{Columns: append([]Column{}, o.Columns...)}
	for i := range out.Columns {
		if out.Columns[i].Name == name {
			out.Columns[i].Type = typ
		}
	}
	return out
}
