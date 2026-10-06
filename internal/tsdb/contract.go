package tsdb

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// StoreContract names the store/v1 contract this build implements: the contract's major
// version and an additive minor. A new view or column bumps the minor and never changes
// what an existing one means; removing or repurposing one needs store/v2.
//
// The web layer reads this from /healthz, so a server that dropped a view is refused
// at deploy time instead of failing in a browser. TestStoreContractMatchesSchema ties
// the string to the schema this package actually builds: change the schema and that
// test fails until the minor and schemaFingerprint are updated together.
const StoreContract = "store/v1.1"

// schemaFingerprint is the fingerprint of the schema StoreContract describes.
const schemaFingerprint = "a066320ab0ceb06137bd5dabf8ab197fccc05875a45012499020e70e8178477a"

// Capabilities is what a running store offers: the objects present in its database.
type Capabilities struct {
	StoreContract string   `json:"store_contract"`
	Fingerprint   string   `json:"schema_fingerprint"`
	Tables        []string `json:"tables"`
	Views         []string `json:"views"`
	// Columns maps every table and view to its column names in order.
	Columns map[string][]string `json:"columns"`
	// ColumnTypes is parallel to Columns: the DuckDB type of each column, as the catalogue
	// spells it. The schema fingerprint covers these, so a retyped column is a different
	// schema, not an unnoticed one.
	ColumnTypes map[string][]string `json:"column_types"`
	// Macros are the table macros: queries that take parameters, which a view cannot. They
	// are part of the contract and the fingerprint like a view is, and a caller reaches one
	// through POST /query as SELECT * FROM name(args).
	Macros map[string]Macro `json:"macros"`
}

// Macro is a table macro: its parameter names in order, and the columns it returns.
type Macro struct {
	Parameters  []string `json:"parameters"`
	Columns     []string `json:"columns"`
	ColumnTypes []string `json:"column_types"`
}

// Capabilities reads the live catalogue, so it reports the store that is serving, not a
// list that was true when someone last edited the code.
func (d *DB) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{StoreContract: StoreContract, Columns: map[string][]string{}, ColumnTypes: map[string][]string{}, Macros: map[string]Macro{}}

	rows, err := d.db.QueryContext(ctx,
		`SELECT table_name, table_type FROM information_schema.tables
		  WHERE table_schema = 'main' ORDER BY table_name`)
	if err != nil {
		return c, fmt.Errorf("list objects: %w", err)
	}
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			rows.Close()
			return c, err
		}
		if typ == "VIEW" {
			c.Views = append(c.Views, name)
		} else {
			c.Tables = append(c.Tables, name)
		}
	}
	if err := rows.Close(); err != nil {
		return c, err
	}

	cols, err := d.db.QueryContext(ctx,
		`SELECT table_name, column_name, data_type FROM information_schema.columns
		  WHERE table_schema = 'main' ORDER BY table_name, ordinal_position`)
	if err != nil {
		return c, fmt.Errorf("list columns: %w", err)
	}
	defer cols.Close()
	var lines []string
	for cols.Next() {
		var table, col, typ string
		if err := cols.Scan(&table, &col, &typ); err != nil {
			return c, err
		}
		c.Columns[table] = append(c.Columns[table], col)
		c.ColumnTypes[table] = append(c.ColumnTypes[table], typ)
		lines = append(lines, table+"."+col+" "+typ)
	}
	if err := cols.Err(); err != nil {
		return c, err
	}

	if err := d.macros(ctx, &c, &lines); err != nil {
		return c, err
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	c.Fingerprint = hex.EncodeToString(sum[:])
	return c, nil
}

// macros adds the table macros to c and to the lines the fingerprint hashes. information_schema
// does not list them, so they are read from duckdb_functions(), and the columns each returns are
// found by binding it (DESCRIBE plans a query without running it) with NULL for every argument.
func (d *DB) macros(ctx context.Context, c *Capabilities, lines *[]string) error {
	rows, err := d.db.QueryContext(ctx,
		`SELECT function_name, array_to_string(parameters, ',') FROM duckdb_functions()
		  WHERE function_type = 'table_macro' AND schema_name = 'main' AND NOT internal
		  ORDER BY function_name`)
	if err != nil {
		return fmt.Errorf("list macros: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var params sql.NullString
		if err := rows.Scan(&name, &params); err != nil {
			return err
		}
		m := Macro{Parameters: []string{}}
		if params.String != "" {
			m.Parameters = strings.Split(params.String, ",")
		}
		c.Macros[name] = m
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()

	for name, m := range c.Macros {
		nulls := strings.TrimSuffix(strings.Repeat("NULL,", len(m.Parameters)), ",")
		desc, err := d.db.QueryContext(ctx, fmt.Sprintf("DESCRIBE SELECT * FROM %s(%s)", name, nulls))
		if err != nil {
			return fmt.Errorf("describe macro %s: %w", name, err)
		}
		for desc.Next() {
			var col, typ string
			var rest [4]sql.NullString
			if err := desc.Scan(&col, &typ, &rest[0], &rest[1], &rest[2], &rest[3]); err != nil {
				desc.Close()
				return err
			}
			m.Columns = append(m.Columns, col)
			m.ColumnTypes = append(m.ColumnTypes, typ)
			*lines = append(*lines, "macro "+name+"."+col+" "+typ)
		}
		if err := desc.Err(); err != nil {
			desc.Close()
			return err
		}
		desc.Close()
		c.Macros[name] = m
		*lines = append(*lines, "macro "+name+"("+strings.Join(m.Parameters, ",")+")")
	}
	return nil
}
