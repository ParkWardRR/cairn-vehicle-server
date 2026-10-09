package tsdb

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/duckdb/duckdb-go/v2"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

func deriveDB(t *testing.T) *sql.DB {
	t.Helper()
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Skipf("duckdb unavailable: %v", err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(context.Background(), schemaSQL); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return db
}

// mod builds a module with one derivation, as the loader will see it.
func mod(id, column, typ, expr string, requires ...string) *modules.Module {
	m := &modules.Module{Manifest: modules.Manifest{
		Schema: modules.ManifestSchema, ID: id, Version: 1, Name: id, Status: "derived",
		Sources: []string{"a fixture"},
		Derives: []modules.Derive{{Column: column, Type: typ, Expr: expr}},
	}}
	if len(requires) > 0 {
		m.Manifest.Requires = &modules.Requires{Store: requires}
	}
	return m
}

func insertBoost(t *testing.T, db *sql.DB, mapKPa, baro any) {
	t.Helper()
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO boost (vehicle_id, boot_id, mono_ms, seq, map_kpa, baro_kpa, lambda_e4)
		 VALUES ('v', 'b', 1, 1, ?, ?, 10000)`, mapKPa, baro)
	if err != nil {
		t.Fatal(err)
	}
}

// The grandfathered takeover of module/v1 §4: the module's expression replaces the core's
// definition, and the value must not change. This is the loader's half of the proof —
// internal/modules proves the expression against format.OBDExtended.BoostPSI(); this
// proves the loader actually applies it, to every row, through the real schema.
func TestDerivationFillsTheGrandfatheredColumn(t *testing.T) {
	db := deriveDB(t)
	ctx := context.Background()

	// Three rows: ordinary, saturated manifold, and a missing barometric reading.
	insertBoost(t, db, 230, 101)
	insertBoost(t, db, 255, 101)
	insertBoost(t, db, 150, nil)

	// The column starts empty, as it would if the decode path had not filled it.
	var nulls int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM boost WHERE boost_psi IS NULL`).Scan(&nulls); err != nil {
		t.Fatal(err)
	}
	if nulls != 3 {
		t.Fatalf("expected an empty column to start, got %d nulls of 3", nulls)
	}

	m := mod("boost", "boost.boost_psi", "DOUBLE",
		`CASE WHEN map_kpa IS NOT NULL AND baro_kpa IS NOT NULL
		   THEN (map_kpa::DOUBLE - baro_kpa::DOUBLE) * 0.1450377 END`,
		"boost.map_kpa", "boost.baro_kpa")

	var report Report
	if err := applyDerivations(ctx, db, []*modules.Module{m}, &report); err != nil {
		t.Fatalf("applyDerivations: %v", err)
	}

	type row struct {
		mapKPa int
		psi    sql.NullFloat64
	}
	var got []row
	rows, err := db.QueryContext(ctx, `SELECT map_kpa, boost_psi FROM boost ORDER BY map_kpa`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.mapKPa, &r.psi); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(got))
	}

	// 150 kPa with no barometric reading: unknown, not guessed from sea level.
	if got[0].mapKPa != 150 || got[0].psi.Valid {
		t.Fatalf("a missing barometric reading must leave the value unknown: %+v", got[0])
	}
	// 230 - 101 = 129 kPa gauge.
	if !got[1].psi.Valid || !closeTo(got[1].psi.Float64, 129*0.1450377) {
		t.Fatalf("map=230 baro=101: %+v", got[1])
	}
	// A saturated manifold still produces a value: saturation is the views' business.
	if !got[2].psi.Valid || !closeTo(got[2].psi.Float64, 154*0.1450377) {
		t.Fatalf("a saturated manifold must still derive a value: %+v", got[2])
	}

	// The report says who defined what, and does not claim to have added a grandfathered
	// column.
	if len(report.Derived) != 1 {
		t.Fatalf("expected one derived column in the report, got %+v", report.Derived)
	}
	d := report.Derived[0]
	if d.Column != "boost.boost_psi" || d.Module != "boost" || d.Added {
		t.Fatalf("a grandfathered column must not be reported as added: %+v", d)
	}
	if d.Rows != 3 {
		t.Fatalf("expected 3 rows updated, got %d", d.Rows)
	}
	if !strings.HasPrefix(report.Modules, "modules=boost@1/") {
		t.Fatalf("the report must carry the module-set identity, got %q", report.Modules)
	}
}

// closeTo compares two float64s. The package already has a `near` with a different
// signature, for pointer-valued view results.
func closeTo(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// An INTRODUCED column is added and filled. Without its module it would simply not exist,
// which is the difference from a grandfathered one.
func TestDerivationIntroducesAColumn(t *testing.T) {
	db := deriveDB(t)
	ctx := context.Background()
	insertBoost(t, db, 230, 101)

	m := mod("alpha", "boost.map_bar", "DOUBLE", `map_kpa::DOUBLE / 100.0`, "boost.map_kpa")
	var report Report
	if err := applyDerivations(ctx, db, []*modules.Module{m}, &report); err != nil {
		t.Fatalf("applyDerivations: %v", err)
	}

	var v sql.NullFloat64
	if err := db.QueryRowContext(ctx, `SELECT map_bar FROM boost`).Scan(&v); err != nil {
		t.Fatalf("the column should exist: %v", err)
	}
	if !v.Valid || !closeTo(v.Float64, 2.30) {
		t.Fatalf("map_bar = %+v", v)
	}
	if len(report.Derived) != 1 || !report.Derived[0].Added {
		t.Fatalf("an introduced column must be reported as added: %+v", report.Derived)
	}
}

// With no module set, nothing happens and nothing is claimed. That is every deployment
// that existed before modules did.
func TestNoModulesChangesNothing(t *testing.T) {
	db := deriveDB(t)
	var report Report
	if err := applyDerivations(context.Background(), db, nil, &report); err != nil {
		t.Fatal(err)
	}
	if report.Modules != "" || len(report.Derived) != 0 {
		t.Fatalf("an empty module set should claim nothing: %q %+v", report.Modules, report.Derived)
	}
}

// Derivation order: a module that reads another's derived column runs after it, or the
// second would compute from nulls. This is what makes the result independent of the order
// the modules happened to be listed in.
func TestDerivationOrderIsRespected(t *testing.T) {
	db := deriveDB(t)
	ctx := context.Background()
	insertBoost(t, db, 230, 101)

	first := mod("alpha", "boost.gauge_kpa", "DOUBLE",
		`CASE WHEN map_kpa IS NOT NULL AND baro_kpa IS NOT NULL
		   THEN map_kpa::DOUBLE - baro_kpa::DOUBLE END`,
		"boost.map_kpa", "boost.baro_kpa")
	// beta reads what alpha derives, so it must run second whatever order it is given in.
	second := mod("beta", "boost.gauge_psi", "DOUBLE", `gauge_kpa * 0.1450377`, "boost.gauge_kpa")

	var report Report
	if err := applyDerivations(ctx, db, []*modules.Module{second, first}, &report); err != nil {
		t.Fatalf("applyDerivations: %v", err)
	}

	var psi sql.NullFloat64
	if err := db.QueryRowContext(ctx, `SELECT gauge_psi FROM boost`).Scan(&psi); err != nil {
		t.Fatal(err)
	}
	if !psi.Valid {
		t.Fatal("the dependent derivation computed from nulls: order was not respected")
	}
	if !closeTo(psi.Float64, 129*0.1450377) {
		t.Fatalf("gauge_psi = %v", psi.Float64)
	}
	if report.Derived[0].Module != "alpha" {
		t.Fatalf("alpha should have been applied first: %+v", report.Derived)
	}
}

func TestDerivationCycleIsRefused(t *testing.T) {
	db := deriveDB(t)
	a := mod("alpha", "boost.a_col", "DOUBLE", `b_col`, "boost.b_col")
	b := mod("beta", "boost.b_col", "DOUBLE", `a_col`, "boost.a_col")
	if err := applyDerivations(context.Background(), db, []*modules.Module{a, b}, &Report{}); err == nil {
		t.Fatal("a cycle was accepted")
	} else if !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// A derivation is a scalar expression over its own row. Anything that could read another
// table, reach the filesystem or change the engine is refused at the point of execution,
// not only by the manifest validator — a module set is first-party and released by tag,
// but the server runs whatever directory it is pointed at.
func TestDerivationExpressionIsConfined(t *testing.T) {
	// The columns of `boost`, as the loader would supply them.
	cols := map[string]bool{"map_kpa": true, "baro_kpa": true, "lambda_e4": true,
		"health_state": true, "boost_psi": true}

	for _, bad := range []string{
		"(SELECT max(rpm) FROM obd)",
		"map_kpa; DROP TABLE boost",
		"read_csv('/etc/passwd')",
		"read_parquet('x')",
		"glob('*')",
		"(SELECT 1)",
		"rpm", // a real column, but of another table
		"nextval('s')",
	} {
		if err := checkDeriveExpr(bad, cols); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}

	// The expressions actually in use must pass, including a banned-looking word inside a
	// string literal and a column whose name merely starts with a keyword.
	for _, good := range []string{
		`CASE WHEN map_kpa IS NOT NULL AND baro_kpa IS NOT NULL THEN (map_kpa::DOUBLE - baro_kpa::DOUBLE) * 0.1450377 END`,
		`CASE WHEN lambda_e4 > 0 THEN lambda_e4::DOUBLE / 10000.0 END`,
		`CASE WHEN health_state = 1 THEN 'select * from obd' ELSE NULL END`,
		`coalesce(round(abs(map_kpa::DOUBLE), 2), 0)`,
		`least(greatest(map_kpa, 0), 255)::DOUBLE`,
	} {
		if err := checkDeriveExpr(good, cols); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

// A derivation on a table the store does not have is an error, not a silent no-op: a
// module claiming a column on a table nobody has is a module nobody can use.
func TestDerivationOnAMissingTableIsRefused(t *testing.T) {
	db := deriveDB(t)
	m := mod("alpha", "turbo.x", "DOUBLE", `1`)
	if err := applyDerivations(context.Background(), db, []*modules.Module{m}, &Report{}); err == nil {
		t.Fatal("a derivation on a missing table was accepted")
	} else if !strings.Contains(err.Error(), "no table") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}
