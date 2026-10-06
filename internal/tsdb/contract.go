package tsdb

import (
	"context"
	"crypto/sha256"
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
//
// store/v1.1 adds, all additive: the bundles columns path, size_bytes, duration_ms and
// received_at; the tune table; and the views v_boot_start, v_metric_samples, v_tune_effect
// and v_health_stats.
const StoreContract = "store/v1.1"

// schemaFingerprint is the fingerprint of the schema StoreContract describes.
const schemaFingerprint = "b7e0e527a7c3f9067b7e94b1c2426ac01a36a9c2e1b543aef53e90286992760c"

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
}

// Capabilities reads the live catalogue, so it reports the store that is serving, not a
// list that was true when someone last edited the code.
func (d *DB) Capabilities(ctx context.Context) (Capabilities, error) {
	c := Capabilities{StoreContract: StoreContract, Columns: map[string][]string{}, ColumnTypes: map[string][]string{}}

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
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	c.Fingerprint = hex.EncodeToString(sum[:])
	return c, nil
}
