package tsdb

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Result is a query's output, shaped for JSON.
type Result struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	ElapsedUS int64    `json:"elapsed_us"`
	Truncated bool     `json:"truncated,omitempty"`
}

// ErrNotReadOnly means the statement was refused before it reached the engine.
var ErrNotReadOnly = errors.New("only read-only statements are accepted")

// mutating matches the words that begin or smuggle in a statement that changes
// state. It is the second of two layers: queries also run inside a transaction that is
// always rolled back (the driver has no read-only mode, but DuckDB DDL and DML
// are transactional, so a write that slipped past is undone), and the engine is
// locked against external access. This one is
// deliberately crude — a false positive costs the caller a rephrased query, and
// a false negative is caught by the layers behind it.
var mutating = regexp.MustCompile(`(?i)\b(insert|update|delete|drop|create|alter|copy|attach|detach|install|load|export|import|call|set|reset|pragma|truncate|vacuum|checkpoint)\b`)

// checkReadOnly refuses anything that is not a single read statement.
func checkReadOnly(q string) error {
	q = strings.TrimSpace(q)
	q = strings.TrimSuffix(q, ";")
	if q == "" {
		return errors.New("empty query")
	}
	if strings.Contains(q, ";") {
		return fmt.Errorf("%w: one statement per request", ErrNotReadOnly)
	}
	first := strings.ToLower(strings.Fields(q)[0])
	switch first {
	case "select", "with", "from", "describe", "show", "explain", "summarize":
	default:
		return fmt.Errorf("%w: %q", ErrNotReadOnly, first)
	}
	if m := mutating.FindString(q); m != "" {
		return fmt.Errorf("%w: found %q", ErrNotReadOnly, m)
	}
	return nil
}

// Query runs one read-only statement and returns at most maxRows rows.
func (d *DB) Query(ctx context.Context, q string, maxRows int) (*Result, error) {
	if err := checkReadOnly(q); err != nil {
		return nil, err
	}

	started := time.Now()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	res := &Result{Columns: cols, Rows: [][]any{}}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}

	for rows.Next() {
		if maxRows > 0 && len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out := make([]any, len(vals))
		for i, v := range vals {
			out[i] = jsonable(v)
		}
		res.Rows = append(res.Rows, out)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	res.ElapsedUS = time.Since(started).Microseconds()
	return res, nil
}

// jsonable maps the engine's value types onto things encoding/json renders
// faithfully. A 128-bit integer becomes a string rather than a float that would
// quietly lose its low digits.
func jsonable(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case *big.Int:
		return x.String()
	case []byte:
		return fmt.Sprintf("%x", x)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case fmt.Stringer:
		return x.String()
	default:
		return v
	}
}
