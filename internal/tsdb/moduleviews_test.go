package tsdb

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// viewMod builds a module that declares view files, as the loader will have read them.
func viewMod(id string, files ...modules.ViewFile) *modules.Module {
	return &modules.Module{
		Manifest: modules.Manifest{
			Schema: modules.ManifestSchema, ID: id, Version: 1, Name: id, Status: "derived",
			Sources: []string{"a fixture"},
			Views:   pathsOf(files),
		},
		Views: files,
	}
}

func pathsOf(files []modules.ViewFile) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	return out
}

// viewDB is deriveDB plus the core views, which is the state module views are created in.
func viewDB(t *testing.T) *sql.DB {
	t.Helper()
	db := deriveDB(t)
	if _, err := db.ExecContext(context.Background(), viewsSQL); err != nil {
		t.Fatalf("core views: %v", err)
	}
	return db
}

func TestAModuleViewIsCreatedAndReadsTheCoreStore(t *testing.T) {
	db := viewDB(t)
	ctx := context.Background()
	insertBoost(t, db, 230, 101)

	m := viewMod("boost", modules.ViewFile{
		Path: "store/views.sql",
		SQL: `CREATE VIEW v_boost_peak AS
		      SELECT vehicle_id, boot_id, max(map_kpa) AS peak_kpa
		      FROM boost GROUP BY vehicle_id, boot_id`,
	})

	var report Report
	if err := createModuleViews(ctx, db, []*modules.Module{m}, &report); err != nil {
		t.Fatalf("createModuleViews: %v", err)
	}

	var peak int
	if err := db.QueryRowContext(ctx, `SELECT peak_kpa FROM v_boost_peak`).Scan(&peak); err != nil {
		t.Fatalf("query the module's view: %v", err)
	}
	if peak != 230 {
		t.Errorf("peak_kpa = %d, want 230", peak)
	}

	if len(report.ModuleViews) != 1 {
		t.Fatalf("report holds %d views, want 1", len(report.ModuleViews))
	}
	got := report.ModuleViews[0]
	if got.Name != "v_boost_peak" || got.Module != "boost" || got.Path != "store/views.sql" {
		t.Errorf("report row = %+v", got)
	}
}

// A module view may read a core view, which is why these are created after viewsSQL.
func TestAModuleViewMayReadACoreView(t *testing.T) {
	db := viewDB(t)
	m := viewMod("boost", modules.ViewFile{
		Path: "store/views.sql",
		SQL:  `CREATE VIEW v_boost_over_core AS SELECT count(*) AS n FROM v_boost_curve`,
	})
	if err := createModuleViews(context.Background(), db, []*modules.Module{m}, &Report{}); err != nil {
		t.Fatalf("createModuleViews: %v", err)
	}
}

// Several files, and several statements in one file, in declaration order — so a later view
// may read an earlier one.
func TestViewsAreCreatedInDeclarationOrder(t *testing.T) {
	db := viewDB(t)
	m := viewMod("boost",
		modules.ViewFile{Path: "store/a.sql", SQL: `CREATE VIEW v_a AS SELECT 1 AS n`},
		modules.ViewFile{
			Path: "store/b.sql",
			SQL: `CREATE VIEW v_b AS SELECT n + 1 AS n FROM v_a;
			      CREATE VIEW v_c AS SELECT n + 1 AS n FROM v_b;`,
		},
	)
	var report Report
	if err := createModuleViews(context.Background(), db, []*modules.Module{m}, &report); err != nil {
		t.Fatalf("createModuleViews: %v", err)
	}
	var n int
	if err := db.QueryRowContext(context.Background(), `SELECT n FROM v_c`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("v_c = %d, want 3 (the chain did not build in order)", n)
	}
	if len(report.ModuleViews) != 3 {
		t.Errorf("report holds %d views, want 3", len(report.ModuleViews))
	}
}

// With no module set nothing happens, because the core must build without one.
func TestNoModuleSetCreatesNothing(t *testing.T) {
	db := viewDB(t)
	before, err := relationSet(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := createModuleViews(context.Background(), db, nil, &report); err != nil {
		t.Fatalf("createModuleViews: %v", err)
	}
	after, err := relationSet(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || len(report.ModuleViews) != 0 {
		t.Errorf("a nil module set changed the store: %d -> %d relations, %d views reported",
			len(before), len(after), len(report.ModuleViews))
	}
}

// The guard has to be able to fail, and these are the ways it must.
func TestAModuleViewsFileIsRefusedWhen(t *testing.T) {
	for _, c := range []struct{ name, sql, want string }{{
		name: "it is not a CREATE VIEW at all",
		sql:  `CREATE TABLE t (a INTEGER)`,
		want: "not a bare `CREATE VIEW",
	}, {
		name: "it replaces rather than creates",
		sql:  `CREATE OR REPLACE VIEW v_x AS SELECT 1 AS n`,
		want: "may not replace one",
	}, {
		name: "a second statement rides along behind the first",
		sql:  `CREATE VIEW v_ok AS SELECT 1 AS n; ATTACH 'x.db' AS x`,
		want: "not a bare `CREATE VIEW",
	}, {
		name: "it names a view that already exists",
		sql:  `CREATE VIEW v_boost_curve AS SELECT 1 AS n`,
		// Not "already exists": DuckDB says that too, so asserting it would pass with
		// this check removed. The phrase below is only ours, and it is the part that
		// matters -- that takeover is refused rather than guessed at.
		want: "refused rather than guessed",
	}, {
		name: "it reads a relation that does not exist",
		sql:  `CREATE VIEW v_nope AS SELECT * FROM not_a_table`,
		want: "create view v_nope",
	}, {
		name: "the file declares nothing",
		sql:  "-- a comment and no statement\n",
		want: "declares no statement",
	}, {
		name: "a string literal is unterminated",
		sql:  `CREATE VIEW v_x AS SELECT 'unclosed AS n`,
		want: "unterminated string",
	}} {
		t.Run(c.name, func(t *testing.T) {
			db := viewDB(t)
			m := viewMod("boost", modules.ViewFile{Path: "store/views.sql", SQL: c.sql})
			err := createModuleViews(context.Background(), db, []*modules.Module{m}, &Report{})
			if err == nil {
				t.Fatalf("accepted %q", c.sql)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// One module must not be able to shadow another's view, not only the core's.
func TestOneModuleCannotShadowAnothersView(t *testing.T) {
	db := viewDB(t)
	a := viewMod("aaa", modules.ViewFile{Path: "store/views.sql", SQL: `CREATE VIEW v_shared AS SELECT 1 AS n`})
	b := viewMod("bbb", modules.ViewFile{Path: "store/views.sql", SQL: `CREATE VIEW v_shared AS SELECT 2 AS n`})
	err := createModuleViews(context.Background(), db, []*modules.Module{a, b}, &Report{})
	if err == nil {
		t.Fatal("two modules both created v_shared")
	}
	if !strings.Contains(err.Error(), "refused rather than guessed") || !strings.Contains(err.Error(), "bbb") {
		t.Errorf("error should be our refusal and should name the second module, got %q", err)
	}
}

// splitStatements is the thing a smuggled second statement has to get past, so it is worth
// testing on its own rather than only through the refusals above.
func TestSplitStatementsKeepsSemicolonsInStringsAndComments(t *testing.T) {
	for _, c := range []struct {
		name string
		sql  string
		want int
	}{
		{"one statement, no terminator", `SELECT 1`, 1},
		{"a trailing terminator is not a second statement", `SELECT 1;`, 1},
		{"blank between terminators is dropped", `SELECT 1;;  ;SELECT 2`, 2},
		{"a semicolon inside a literal does not split", `SELECT ';'`, 1},
		{"a doubled quote is an escape, not an end", `SELECT 'it''s; fine'`, 1},
		{"a semicolon in a line comment does not split", "SELECT 1 -- ; not a split\n", 1},
		{"a semicolon in a block comment does not split", `SELECT /* ; */ 1`, 1},
		{"two real statements split", `SELECT 1; SELECT 2`, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := splitStatements(c.sql)
			if err != nil {
				t.Fatalf("splitStatements(%q): %v", c.sql, err)
			}
			if len(got) != c.want {
				t.Errorf("split %q into %d statements (%q), want %d", c.sql, len(got), got, c.want)
			}
		})
	}
}
