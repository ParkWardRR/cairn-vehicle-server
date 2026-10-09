package tsdb

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// Derivations: the module-owned columns of contracts/module/v1 §4.
//
// A module may define a column on a core table. The value is a SQL scalar expression over
// the columns of that row's own table, and DuckDB evaluates it during the load — which is
// the whole reason no interpreter is added to this process. The server reads declarations
// and the engine it already runs does the arithmetic.
//
// Two kinds of column, which behave differently when no module provides the definition:
//
//   - INTRODUCED by a module: the column is added and is all-null without its module.
//   - GRANDFATHERED (boost.boost_psi, boost.lambda_ratio): store/v1 declares it and the
//     decode path computes it, so the core's value stands until a module takes over. The
//     module's expression then replaces it — identically, which is what
//     internal/modules' equivalence tests prove.
//
// So a derivation is applied as an UPDATE over the already-loaded rows rather than being
// folded into the insert. For a grandfathered column that makes the takeover observable
// and reversible: remove the module and the core's value is what is there.

// A derivation is a scalar expression over the columns of its own row (module/v1 §4). So
// every identifier in it must be one of four things, and anything else is refused:
//
//   - a column of the table the derivation writes to,
//   - a type name, for a `::` cast,
//   - a SQL keyword the expression grammar needs,
//   - a scalar function on the short list below.
//
// A WHITELIST, not a denylist. DuckDB's SQL can read files, fetch URLs and write them
// back out, and its reader functions are many and growing — `read_csv`, `read_parquet`,
// `glob`, and whatever the next release adds. Enumerating what to forbid would be a list
// that silently falls behind the engine; enumerating what a scalar expression actually
// needs does not, because that does not grow when DuckDB does.
//
// The manifest validator refuses a semicolon too, so this is not the only guard. It is the
// one at the point of execution, which is where a guard is worth most: a module set is
// first-party and released by tag, but the server runs whatever directory it is pointed at.
var deriveKeywords = words(
	"case", "when", "then", "else", "end", "is", "not", "null", "and", "or",
	"between", "in", "cast", "as", "distinct", "true", "false",
)

// deriveFunctions is deliberately short. It holds what the expressions in use need, plus
// the obvious neighbours; adding one is a visible, reviewable change, which is the point.
var deriveFunctions = words(
	"abs", "round", "floor", "ceil", "ceiling", "trunc", "sign",
	"least", "greatest", "coalesce", "nullif", "ifnull",
	"sqrt", "pow", "power", "exp", "ln", "log", "log2", "log10",
	"mod", "div", "degrees", "radians",
	"try_cast", "epoch_ms",
)

// deriveTypes are the type names a `::` cast may name: store/v1's vocabulary.
var deriveTypes = words(
	"boolean", "tinyint", "smallint", "integer", "bigint", "utinyint", "usmallint",
	"uinteger", "ubigint", "float", "double", "varchar", "date", "timestamp",
	"int", "hugeint", "decimal", "real",
)

func words(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

var deriveWordRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// checkDeriveExpr refuses an expression that is not a scalar over its own row. cols is the
// set of column names of the table the derivation writes to.
func checkDeriveExpr(expr string, cols map[string]bool) error {
	bare := stripSQLStrings(expr)
	if strings.Contains(bare, ";") {
		return fmt.Errorf("holds a semicolon: a derivation is one expression")
	}
	for _, raw := range deriveWordRe.FindAllString(bare, -1) {
		w := strings.ToLower(raw)
		switch {
		case cols[w], deriveKeywords[w], deriveFunctions[w], deriveTypes[w]:
			continue
		}
		return fmt.Errorf("uses %q, which is not a column of its own table, a type, a keyword "+
			"or an allowed function: a derivation is a scalar expression over its own row, so it "+
			"cannot read another table or reach the filesystem", raw)
	}
	return nil
}

// stripSQLStrings blanks single-quoted literals so a keyword inside one is not mistaken
// for syntax. A doubled quote escapes.
func stripSQLStrings(sql string) string {
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

// identRe guards every identifier spliced into the SQL below. The manifest validator has
// already checked them, but these strings reach a statement, so they are checked again
// here: a splice protected only by a check somewhere else is a splice protected by nothing
// a reader of this file can see.
var identRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// DerivedColumn records that a module defined a column, for the build report.
type DerivedColumn struct {
	Column string `json:"column"`
	Module string `json:"module"`
	Added  bool   `json:"added,omitempty"` // true when the column was introduced, not grandfathered
	Rows   int64  `json:"rows"`
}

// applyDerivations runs each module's derivations, in an order where a module that reads
// another's derived column runs after it.
//
// It must happen after the rows are loaded and before the views are created, because a
// view may read a derived column.
func applyDerivations(ctx context.Context, sdb *sql.DB, mods []*modules.Module, report *Report) error {
	if len(mods) == 0 {
		return nil
	}
	ordered, err := modules.Order(mods)
	if err != nil {
		return err
	}

	existing, err := columnSet(ctx, sdb)
	if err != nil {
		return err
	}

	for _, m := range ordered {
		for _, d := range m.Manifest.Derives {
			table, col := d.Table(), d.Name()
			if !identRe.MatchString(table) || !identRe.MatchString(col) {
				return fmt.Errorf("module %s: derives %q is not a lowercase table.column", m.ID(), d.Column)
			}
			if !identRe.MatchString(strings.ToLower(d.Type)) && !isDuckType(d.Type) {
				return fmt.Errorf("module %s: derives %s type %q is not a type", m.ID(), d.Column, d.Type)
			}
			if !existing[table] {
				return fmt.Errorf("module %s: derives %s, but the store has no table %q",
					m.ID(), d.Column, table)
			}
			// Checked against the table's own columns, which is what makes the whitelist
			// in checkDeriveExpr possible: anything not a column, a type, a keyword or an
			// allowed function has no business in a scalar expression.
			if err := checkDeriveExpr(d.Expr, tableColumns(existing, table)); err != nil {
				return fmt.Errorf("module %s: derives %s: %w", m.ID(), d.Column, err)
			}

			rec := DerivedColumn{Column: d.Column, Module: m.ID()}
			if !existing[d.Column] {
				// Introduced, not grandfathered: the column has to exist before it can be
				// filled, and it stays all-null if this module is ever removed.
				q := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, col, d.Type)
				if _, err := sdb.ExecContext(ctx, q); err != nil {
					return fmt.Errorf("module %s: add %s: %w", m.ID(), d.Column, err)
				}
				existing[d.Column] = true
				rec.Added = true
			}

			q := fmt.Sprintf("UPDATE %s SET %s = (%s)", table, col, d.Expr)
			res, err := sdb.ExecContext(ctx, q)
			if err != nil {
				return fmt.Errorf("module %s: derive %s: %w", m.ID(), d.Column, err)
			}
			if n, err := res.RowsAffected(); err == nil {
				rec.Rows = n
			}
			report.Derived = append(report.Derived, rec)
		}
	}
	report.Modules = modules.IdentityString(ordered)
	return nil
}

// tableColumns picks one table's column names out of the flat catalogue set. The column
// a derivation writes is included: a derivation may read the value it replaces.
func tableColumns(catalogue map[string]bool, table string) map[string]bool {
	prefix := table + "."
	out := map[string]bool{}
	for k := range catalogue {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			out[rest] = true
		}
	}
	return out
}

func isDuckType(t string) bool {
	switch strings.ToUpper(t) {
	case "BOOLEAN", "TINYINT", "SMALLINT", "INTEGER", "BIGINT", "UTINYINT", "USMALLINT",
		"UINTEGER", "UBIGINT", "FLOAT", "DOUBLE", "VARCHAR", "DATE", "TIMESTAMP":
		return true
	}
	return false
}

// columnSet reads the live catalogue: every table name, and every "table.column".
func columnSet(ctx context.Context, sdb *sql.DB) (map[string]bool, error) {
	rows, err := sdb.QueryContext(ctx,
		`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'main'`)
	if err != nil {
		return nil, fmt.Errorf("read catalogue: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return nil, err
		}
		out[t] = true
		out[t+"."+c] = true
	}
	return out, rows.Err()
}
