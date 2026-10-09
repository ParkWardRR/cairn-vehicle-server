package tsdb

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// Module views: the `views[]` of contracts/module/v1 §5, created after the core views so a
// module view may read one.
//
// A view is not confined the way a derivation is. A derivation is a scalar expression over
// its own row, so internal/tsdb/derive.go can whitelist every identifier in it; a view
// legitimately joins core tables and reads core views, which is the point of having one. So
// the guard here is a different shape, and it rests on three things rather than one list:
//
//  1. **Only CREATE VIEW.** Every statement in a module's file must be exactly that. No
//     CREATE TABLE, MACRO or SECRET, no ATTACH, no COPY, no INSTALL or LOAD, no SET or
//     PRAGMA. This is checked per statement, after splitting on semicolons outside string
//     literals and comments, so a second statement cannot ride along behind the first.
//
//  2. **DuckDB binds the names itself.** CREATE VIEW resolves every relation the body
//     reads, so a view over a table that does not exist fails here, at load, naming the
//     relation — not later, on a page, as an empty result.
//
//  3. **The engine is locked down before any query runs.** A view body is lazy: it
//     evaluates at query time, by which point enable_external_access is false and the
//     configuration is frozen. So a reader function smuggled into a view body fails closed
//     when it is used, and this file does not have to enumerate DuckDB's readers — which is
//     the enumeration the derivation guard's comment explains cannot be kept current.
//
// What it deliberately does NOT do is let a module replace a view that already exists. See
// errViewExists.
var createViewRe = regexp.MustCompile(`(?is)^create\s+view\s+([a-z_][a-z0-9_]*)\s`)

// ModuleView records that a module created a view, for the build report.
type ModuleView struct {
	Name   string `json:"name"`
	Module string `json:"module"`
	Path   string `json:"path"`
}

// createModuleViews creates every view the module set declares, modules in dependency
// order and each module's files in declaration order, so a later view may read an earlier
// one.
//
// It must run after viewsSQL: a module view reading a core view is the ordinary case, and
// the reverse — a core view reading a module's — is not allowed to become possible, because
// the core must build with no module set at all.
func createModuleViews(ctx context.Context, sdb *sql.DB, mods []*modules.Module, report *Report) error {
	if len(mods) == 0 {
		return nil
	}
	ordered, err := modules.Order(mods)
	if err != nil {
		return err
	}

	existing, err := relationSet(ctx, sdb)
	if err != nil {
		return err
	}

	for _, m := range ordered {
		for _, f := range m.Views {
			stmts, err := splitStatements(f.SQL)
			if err != nil {
				return fmt.Errorf("module %s: %s: %w", m.ID(), f.Path, err)
			}
			if len(stmts) == 0 {
				return fmt.Errorf("module %s: %s declares no statement: a views file that "+
					"creates nothing is a declaration that lies", m.ID(), f.Path)
			}
			for _, stmt := range stmts {
				name, err := viewName(stmt)
				if err != nil {
					return fmt.Errorf("module %s: %s: %w", m.ID(), f.Path, err)
				}
				if existing[name] {
					return fmt.Errorf("module %s: %s creates view %q, which already exists: "+
						"a module may not shadow a core view or another module's. Taking over an "+
						"existing view is a different thing from adding one and module/v1 does not "+
						"yet say how, so it is refused rather than guessed", m.ID(), f.Path, name)
				}
				// DuckDB binds the body here, so an unresolvable relation fails now.
				if _, err := sdb.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("module %s: %s: create view %s: %w", m.ID(), f.Path, name, err)
				}
				existing[name] = true
				report.ModuleViews = append(report.ModuleViews, ModuleView{
					Name: name, Module: m.ID(), Path: f.Path,
				})
			}
		}
	}
	return nil
}

// viewName checks one statement is a bare CREATE VIEW and returns the name it creates.
func viewName(stmt string) (string, error) {
	m := createViewRe.FindStringSubmatch(stmt)
	if m == nil {
		// Named precisely, because the most likely mistake is CREATE OR REPLACE VIEW,
		// which is refused on purpose and not for syntax.
		head := stmt
		if i := strings.IndexAny(head, "\n"); i > 0 {
			head = head[:i]
		}
		if len(head) > 80 {
			head = head[:80]
		}
		return "", fmt.Errorf("statement %q is not a bare `CREATE VIEW <name> AS`: a module's "+
			"views file may only create views, and may not replace one", strings.TrimSpace(head))
	}
	return strings.ToLower(m[1]), nil
}

// splitStatements splits on semicolons that are outside string literals and comments, and
// drops what is left blank. It exists so that a check on "the statement" cannot be defeated
// by putting a second one after it.
//
// Emptiness is judged on the code, not the raw text: a file holding only a comment declares
// nothing, and saying so is a better error than complaining that the comment is not a
// CREATE VIEW. The comment itself stays in the statement handed to DuckDB.
func splitStatements(sql string) ([]string, error) {
	var out []string
	var cur, code strings.Builder
	inString, inLine, inBlock := false, false, false

	flush := func() {
		if strings.TrimSpace(code.String()) != "" {
			out = append(out, strings.TrimSpace(cur.String()))
		}
		cur.Reset()
		code.Reset()
	}

	for i := 0; i < len(sql); i++ {
		c := sql[i]
		two := ""
		if i+1 < len(sql) {
			two = sql[i : i+2]
		}

		switch {
		case inLine:
			cur.WriteByte(c)
			if c == '\n' {
				inLine = false
			}
			continue
		case inBlock:
			cur.WriteByte(c)
			if two == "*/" {
				cur.WriteByte(sql[i+1])
				i++
				inBlock = false
			}
			continue
		case inString:
			cur.WriteByte(c)
			code.WriteByte(c)
			if c == '\'' {
				// A doubled quote is an escape, not the end.
				if i+1 < len(sql) && sql[i+1] == '\'' {
					cur.WriteByte(sql[i+1])
					code.WriteByte(sql[i+1])
					i++
					continue
				}
				inString = false
			}
			continue
		}

		switch {
		case two == "--":
			inLine = true
			cur.WriteString(two)
			i++
		case two == "/*":
			inBlock = true
			cur.WriteString(two)
			i++
		case c == '\'':
			inString = true
			cur.WriteByte(c)
			code.WriteByte(c)
		case c == ';':
			flush()
		default:
			cur.WriteByte(c)
			code.WriteByte(c)
		}
	}
	if inString {
		return nil, fmt.Errorf("an unterminated string literal")
	}
	if inBlock {
		return nil, fmt.Errorf("an unterminated /* block comment")
	}
	flush()
	return out, nil
}

// relationSet reads every table and view name the store currently holds.
func relationSet(ctx context.Context, sdb *sql.DB) (map[string]bool, error) {
	rows, err := sdb.QueryContext(ctx,
		`SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'`)
	if err != nil {
		return nil, fmt.Errorf("read relations: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[strings.ToLower(n)] = true
	}
	return out, rows.Err()
}
