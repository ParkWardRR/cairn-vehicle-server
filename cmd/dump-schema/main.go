// Command dump-schema starts the real store, lets it build its native schema, and writes
// that schema as the store/v1 schema.json.
//
//	dump-schema                    # writes ./schema.json
//	dump-schema -o -               # writes to standard output
//	dump-schema -o path/schema.json
//
// "Real" means the production code path: tsdb.BuildSynthetic creates the schema and views
// exactly as cairn-tsdb does and seals the database the same way; only the rows are
// missing. The output is the store's own answer (Capabilities reads the live catalogue),
// not a copy of what a test expects, which is what makes comparing it with the pinned
// contracts/store/v1/schema.json meaningful. See internal/storeschema.
//
// It needs cgo, like everything that links DuckDB.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/storeschema"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/tsdb"
)

func main() {
	out := flag.String("o", "schema.json", "where to write the schema (- for standard output)")
	flag.Parse()
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "dump-schema:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	ctx := context.Background()
	db, err := tsdb.BuildSynthetic(ctx, func(tsdb.Appenders) error { return nil })
	if err != nil {
		return err
	}
	defer db.Close()

	caps, err := db.Capabilities(ctx)
	if err != nil {
		return err
	}
	b, err := storeschema.Marshal(storeschema.FromCapabilities(caps))
	if err != nil {
		return err
	}
	if out == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(out, b, 0o644)
}
