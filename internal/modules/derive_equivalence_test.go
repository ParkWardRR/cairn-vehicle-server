package modules_test

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"testing"

	"github.com/duckdb/duckdb-go/v2"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
)

// The gate of contracts/module/v1 §4: a module may take over the DEFINITION of a
// grandfathered derived column, but the column, its type and its values must not change.
//
// `boost.boost_psi` is computed today in the decode path from
// format.OBDExtended.BoostPSI(), and store/v1 declares the column. When the boost module
// takes it over, the value becomes a SQL expression DuckDB evaluates at load. These tests
// prove the two agree, over every interesting input rather than by inspection — because
// "by inspection" is exactly how a silent change of a stored column happens.
//
// This found a real defect. The expression first written into the contract's own
// `valid-boost.json` vector was:
//
//	CASE WHEN map_kpa < 255 AND baro_kpa > 0 THEN (map_kpa - baro_kpa) * 0.1450377 END
//
// which does NOT reproduce the column. BoostPSI() returns a value whenever both readings
// are present: it does not exclude a saturated manifold reading, and it does not treat a
// barometric reading of 0 as absent. Saturation is excluded by the VIEWS that read the
// column (v_boost_curve, v_pulls), not by the column itself. Had the vector's expression
// shipped, every saturated sample's boost would have silently become NULL.

// boostPSIExpr is the expression that does reproduce the column. Kept here, beside the
// test that proves it, so the two cannot drift: the module manifest carries the same text.
const boostPSIExpr = `CASE WHEN map_kpa IS NOT NULL AND baro_kpa IS NOT NULL
	THEN (map_kpa::DOUBLE - baro_kpa::DOUBLE) * 0.1450377 END`

// lambdaRatioExpr is the other grandfathered derivation, from OBDExtended.Lambda().
const lambdaRatioExpr = `CASE WHEN lambda_e4 IS NOT NULL THEN lambda_e4::DOUBLE / 10000.0 END`

func openDuck(t *testing.T) *sql.DB {
	t.Helper()
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		t.Skipf("duckdb unavailable: %v", err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("duckdb unavailable: %v", err)
	}
	return db
}

func u16p(v uint16) *uint16 { return &v }
func u8p(v uint8) *uint8    { return &v }

// TestBoostPSIDerivationReproducesTheReference sweeps the whole meaningful input space:
// every manifold reading 0..255 inclusive of the saturation boundary, against a set of
// barometric readings including 0 and the absent case.
func TestBoostPSIDerivationReproducesTheReference(t *testing.T) {
	db := openDuck(t)

	// SQL evaluates the expression against the row's own columns, so the test builds a
	// one-row table per case exactly as the loader will.
	eval := func(mapKPa *uint16, baro *uint8) (float64, bool) {
		t.Helper()
		var m, b any
		if mapKPa != nil {
			m = int(*mapKPa)
		}
		if baro != nil {
			b = int(*baro)
		}
		q := fmt.Sprintf(
			`SELECT %s AS v FROM (SELECT ?::USMALLINT AS map_kpa, ?::UTINYINT AS baro_kpa)`,
			boostPSIExpr)
		var out sql.NullFloat64
		if err := db.QueryRowContext(context.Background(), q, m, b).Scan(&out); err != nil {
			t.Fatalf("map=%v baro=%v: %v", m, b, err)
		}
		return out.Float64, out.Valid
	}

	baros := []*uint8{nil, u8p(0), u8p(1), u8p(50), u8p(99), u8p(101), u8p(200), u8p(255)}
	checked := 0
	for mv := 0; mv <= 255; mv++ {
		for _, baro := range baros {
			o := &format.OBDExtended{MAPkPa: u16p(uint16(mv)), BaroKPa: baro}
			wantV, wantOK := o.BoostPSI()
			gotV, gotOK := eval(o.MAPkPa, o.BaroKPa)

			if wantOK != gotOK {
				t.Fatalf("map=%d baro=%v: reference ok=%v, SQL ok=%v", mv, baro, wantOK, gotOK)
			}
			if wantOK && math.Abs(wantV-gotV) > 1e-9 {
				t.Fatalf("map=%d baro=%v: reference %.12f, SQL %.12f", mv, baro, wantV, gotV)
			}
			checked++
		}
	}
	// And the absent-manifold case, which must be unknown rather than zero.
	for _, baro := range baros {
		o := &format.OBDExtended{MAPkPa: nil, BaroKPa: baro}
		if _, ok := o.BoostPSI(); ok {
			t.Fatal("the reference claimed a value with no manifold reading")
		}
		if _, ok := eval(nil, baro); ok {
			t.Fatalf("baro=%v: SQL claimed a value with no manifold reading", baro)
		}
		checked++
	}
	t.Logf("%d (map, baro) combinations agree", checked)
}

// TestTheRejectedExpressionReallyDiffers pins the defect, so nobody reintroduces it
// believing it equivalent. A test that only proves the right answer right does not stop
// the wrong answer coming back.
func TestTheRejectedExpressionReallyDiffers(t *testing.T) {
	db := openDuck(t)
	const wrong = `CASE WHEN map_kpa < 255 AND baro_kpa > 0
		THEN (map_kpa::DOUBLE - baro_kpa::DOUBLE) * 0.1450377 END`

	eval := func(expr string, mapKPa uint16, baro uint8) (float64, bool) {
		q := fmt.Sprintf(
			`SELECT %s AS v FROM (SELECT ?::USMALLINT AS map_kpa, ?::UTINYINT AS baro_kpa)`, expr)
		var out sql.NullFloat64
		if err := db.QueryRowContext(context.Background(), q, int(mapKPa), int(baro)).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out.Float64, out.Valid
	}

	// A saturated manifold: the reference reports a value, the rejected expression nulls.
	o := &format.OBDExtended{MAPkPa: u16p(255), BaroKPa: u8p(101)}
	if _, ok := o.BoostPSI(); !ok {
		t.Fatal("the reference should report a value for a saturated manifold")
	}
	if _, ok := eval(wrong, 255, 101); ok {
		t.Fatal("the rejected expression no longer differs at saturation; this test is stale")
	}
	if _, ok := eval(boostPSIExpr, 255, 101); !ok {
		t.Fatal("the accepted expression must report a value at saturation, as the reference does")
	}

	// A barometric reading of zero: same story.
	o = &format.OBDExtended{MAPkPa: u16p(100), BaroKPa: u8p(0)}
	if _, ok := o.BoostPSI(); !ok {
		t.Fatal("the reference should report a value for baro 0")
	}
	if _, ok := eval(wrong, 100, 0); ok {
		t.Fatal("the rejected expression no longer differs at baro 0; this test is stale")
	}
}

// TestLambdaRatioDerivationReproducesTheReference: the second grandfathered column,
// exhaustively over every value the record can hold.
func TestLambdaRatioDerivationReproducesTheReference(t *testing.T) {
	db := openDuck(t)

	stmt, err := db.PrepareContext(context.Background(), fmt.Sprintf(
		`SELECT %s AS v FROM (SELECT ?::USMALLINT AS lambda_e4)`, lambdaRatioExpr))
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()

	for v := 0; v <= 65535; v++ {
		e4 := uint16(v)
		o := &format.OBDExtended{LambdaE4: &e4}
		wantV, wantOK := o.Lambda()

		var out sql.NullFloat64
		if err := stmt.QueryRowContext(context.Background(), v).Scan(&out); err != nil {
			t.Fatalf("lambda_e4=%d: %v", v, err)
		}
		if wantOK != out.Valid {
			t.Fatalf("lambda_e4=%d: reference ok=%v, SQL ok=%v", v, wantOK, out.Valid)
		}
		if wantOK && math.Abs(wantV-out.Float64) > 1e-12 {
			t.Fatalf("lambda_e4=%d: reference %.12f, SQL %.12f", v, wantV, out.Float64)
		}
	}

	// Absent is unknown, not 1.0: a mixture nobody measured is not stoichiometric.
	o := &format.OBDExtended{LambdaE4: nil}
	if _, ok := o.Lambda(); ok {
		t.Fatal("the reference claimed a lambda with no reading")
	}
	var out sql.NullFloat64
	q := fmt.Sprintf(`SELECT %s AS v FROM (SELECT NULL::USMALLINT AS lambda_e4)`, lambdaRatioExpr)
	if err := db.QueryRowContext(context.Background(), q).Scan(&out); err != nil {
		t.Fatal(err)
	}
	if out.Valid {
		t.Fatal("SQL claimed a lambda with no reading")
	}
}
