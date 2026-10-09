package tsdb

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// The shipped boost module, applied through the loader, against the values the decode path
// computes. This is the end of the chain the other tests cover in pieces:
//
//	internal/modules  the expression equals format.OBDExtended.BoostPSI(), 2,056 inputs
//	derive_test.go    the loader applies a derivation to every row, in order
//	here              the module as actually written, read off disk, is the one that does it
//
// Without this, all three could pass while the real manifest carried something else — which
// is exactly the failure that was found in the contract's own vector.
//
// It needs a cairn-modules checkout: set CAIRN_MODULES, or have one beside this
// repository. Otherwise it skips rather than silently proving nothing — which it does in
// CI, where there is no second checkout. The guarantees that hold everywhere are the two
// above it: the expression equals the reference, and the loader applies what it is given.
// This one closes the gap between them on a workstation, and is where a drifted manifest
// would be caught before it was tagged.
func TestShippedBoostModuleDerivesTheColumn(t *testing.T) {
	dir := shippedModulesDir(t)

	mods, err := modules.LoadDir(dir)
	if err != nil {
		t.Fatalf("load %s: %v", dir, err)
	}
	var boost *modules.Module
	for _, m := range mods {
		if m.ID() == "boost" {
			boost = m
		}
	}
	if boost == nil {
		t.Skipf("no boost module in %s", dir)
	}
	if len(boost.Manifest.Derives) == 0 {
		t.Skip("the boost module claims no derivation yet")
	}

	db := deriveDB(t)
	ctx := context.Background()
	insertBoost(t, db, 230, 101) // ordinary
	insertBoost(t, db, 255, 101) // saturated manifold: must still derive
	insertBoost(t, db, 150, nil) // no barometric reading: must stay unknown

	var report Report
	if err := applyDerivations(ctx, db, []*modules.Module{boost}, &report); err != nil {
		t.Fatalf("the shipped module failed to apply: %v", err)
	}

	type row struct {
		mapKPa int
		psi    sql.NullFloat64
	}
	rows, err := db.QueryContext(ctx, `SELECT map_kpa, boost_psi FROM boost ORDER BY map_kpa`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []row
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

	if got[0].psi.Valid {
		t.Errorf("map=150 with no barometric reading must be unknown, got %v", got[0].psi.Float64)
	}
	if !got[1].psi.Valid || !closeTo(got[1].psi.Float64, 129*0.1450377) {
		t.Errorf("map=230 baro=101: %+v", got[1].psi)
	}
	// The one the contract's own vector got wrong. If this fails, the shipped manifest has
	// drifted back into excluding saturation, and every saturated sample's boost is NULL.
	if !got[2].psi.Valid || !closeTo(got[2].psi.Float64, 154*0.1450377) {
		t.Errorf("a saturated manifold must still derive a value, got %+v", got[2].psi)
	}

	if report.Modules == "" {
		t.Error("the report must carry the module-set identity")
	}
	if len(report.Derived) != 1 || report.Derived[0].Added {
		t.Errorf("boost_psi is grandfathered and must not be reported as added: %+v", report.Derived)
	}
}

// shippedModulesDir finds a cairn-modules checkout, or skips.
func shippedModulesDir(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("CAIRN_MODULES"); v != "" {
		return v
	}
	// Beside this repository, which is how the five (now six) checkouts sit on a
	// workstation.
	for _, rel := range []string{"../../../cairn-modules/modules", "../../cairn-modules/modules"} {
		if fi, err := os.Stat(rel); err == nil && fi.IsDir() {
			abs, _ := filepath.Abs(rel)
			return abs
		}
	}
	t.Skip("no cairn-modules checkout found; set CAIRN_MODULES to run this")
	return ""
}
