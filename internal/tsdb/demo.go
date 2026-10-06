package tsdb

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// Appenders hands a synthetic-data generator the same strict appenders the
// decoder path uses, one per physical table.
type Appenders map[string]*duckdb.Appender

// Append adds one row to table. Argument types must match the column types in
// schemaSQL exactly; the appender does not coerce.
func (a Appenders) Append(table string, args ...driver.Value) error {
	if err := a[table].AppendRow(args...); err != nil {
		return fmt.Errorf("%s: %w", table, err)
	}
	return nil
}

// BuildSynthetic builds a store with the production schema and views, filled by
// fill instead of by decoding bundles. It exists so the web UI can be exercised
// and photographed against invented drives without any real capture; nothing in
// the serving path uses it. The returned store is sealed exactly like Build's:
// sorted, viewed and locked against external access.
func BuildSynthetic(ctx context.Context, fill func(Appenders) error) (*DB, error) {
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		return nil, fmt.Errorf("open duckdb: %w", err)
	}
	sdb := sql.OpenDB(connector)
	fail := func(err error) (*DB, error) {
		sdb.Close()
		return nil, err
	}

	if _, err := sdb.ExecContext(ctx, schemaSQL); err != nil {
		return fail(fmt.Errorf("schema: %w", err))
	}

	conn, err := sdb.Conn(ctx)
	if err != nil {
		return fail(err)
	}
	err = conn.Raw(func(dc any) error {
		dconn, ok := dc.(driver.Conn)
		if !ok {
			return fmt.Errorf("unexpected driver connection %T", dc)
		}
		apps := Appenders{}
		for _, t := range bundleTables {
			a, err := duckdb.NewAppenderFromConn(dconn, "", t)
			if err != nil {
				return fmt.Errorf("appender %s: %w", t, err)
			}
			apps[t] = a
		}
		if err := fill(apps); err != nil {
			return err
		}
		for t, a := range apps {
			if err := a.Close(); err != nil {
				return fmt.Errorf("flush %s: %w", t, err)
			}
		}
		return nil
	})
	conn.Close()
	if err != nil {
		return fail(err)
	}

	for _, t := range sampleTables {
		q := fmt.Sprintf("CREATE OR REPLACE TABLE %[1]s AS SELECT * FROM %[1]s ORDER BY vehicle_id, boot_id, mono_ms, seq", t)
		if _, err := sdb.ExecContext(ctx, q); err != nil {
			return fail(fmt.Errorf("sort %s: %w", t, err))
		}
	}
	if _, err := sdb.ExecContext(ctx, viewsSQL); err != nil {
		return fail(fmt.Errorf("views: %w", err))
	}
	for _, p := range []string{"SET enable_external_access = false", "SET lock_configuration = true"} {
		if _, err := sdb.ExecContext(ctx, p); err != nil {
			return fail(fmt.Errorf("%s: %w", p, err))
		}
	}
	return &DB{db: sdb}, nil
}
