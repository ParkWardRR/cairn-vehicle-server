package tsdb

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// Generation has to be inert without a module set, and this is the non-circular half of
// proving it: the rendering is structurally the core's and nothing else.
//
// There was a whole-text golden here during the refactor -- buildViewsSQL(nil) asserted
// byte for byte against the views as they stood before -- and it did its job: it held
// through a 222-line rewrite of this file by another change and showed the refactor was
// inert. It is not kept, because it was a copy of all 27 KB of the views, so every edit
// anywhere in them forced a regeneration, and a golden regenerated without thought proves
// nothing. The property worth keeping permanently is below, plus the row-level comparison
// in TestAModuleMetricDoesNotDisturbTheCoreReadings.
func TestNoModuleSetRendersOnlyTheCoreMetrics(t *testing.T) {
	got, err := buildViewsSQL(nil)
	if err != nil {
		t.Fatalf("buildViewsSQL(nil): %v", err)
	}
	if strings.Contains(got, "/*CAIRN:") {
		t.Error("a substitution marker survived rendering")
	}
	if !strings.Contains(got, coreMetricArms) {
		t.Error("the core's metric arms are not in the rendering verbatim")
	}
	// Exactly the four, and in order: the key list is what v_tune_effect cross-joins, so a
	// fifth would silently add a row per tune and a missing one would drop a column of the
	// health page.
	want := "('boost_psi'), ('lambda'), ('ltft_pct'), ('stft_pct')"
	if !strings.Contains(got, want) {
		t.Errorf("the metric-key list is not %q", want)
	}
	// Counted inside v_metric_samples, not across the file: the views hold other UNION ALLs
	// (v_boot_start, v_gnss_sources, the trip sessionisation) and counting those made this
	// assertion fail for a reason that had nothing to do with modules.
	body := metricSamplesBody(t, got)
	if n, want := strings.Count(body, "UNION ALL"), strings.Count(coreMetricArms, "UNION ALL"); n != want {
		t.Errorf("v_metric_samples has %d UNION ALLs, the core arms have %d: an arm was appended "+
			"with no module set", n, want)
	}
}

// metricSamplesBody is the text of the v_metric_samples statement in a rendering.
func metricSamplesBody(t *testing.T, sql string) string {
	t.Helper()
	const head = "CREATE VIEW v_metric_samples AS"
	i := strings.Index(sql, head)
	if i < 0 {
		t.Fatal("the rendering has no v_metric_samples")
	}
	rest := sql[i+len(head):]
	j := strings.Index(rest, ";")
	if j < 0 {
		t.Fatal("v_metric_samples is unterminated")
	}
	return rest[:j]
}

func metricMod(id string, ms ...modules.Metric) *modules.Module {
	return &modules.Module{Manifest: modules.Manifest{
		Schema: modules.ManifestSchema, ID: id, Version: 1, Name: id, Status: "derived",
		Sources: []string{"a fixture"}, Metrics: ms,
	}}
}

// A module metric becomes an arm of v_metric_samples and a key in v_tune_effect, and the
// core's four are still there -- which is the property that matters, because a module set
// holding only `boost` must not make the fuel trims vanish.
func TestAModuleMetricIsAppendedAndTheCoreFourSurvive(t *testing.T) {
	m := metricMod("boost", modules.Metric{
		Key: "peak_kpa", Label: "Peak manifold", Unit: "kPa", Sample: "boot",
		SourceView: "boost", SourceColumn: "map_kpa",
	})
	got, err := buildViewsSQL([]*modules.Module{m})
	if err != nil {
		t.Fatalf("buildViewsSQL: %v", err)
	}
	for _, k := range append(coreMetricKeys, "peak_kpa") {
		if !strings.Contains(got, "('"+k+"')") {
			t.Errorf("v_tune_effect's key list is missing %q", k)
		}
	}
	if !strings.Contains(got, "'peak_kpa', median(x.map_kpa)") {
		t.Errorf("the module's arm is not in v_metric_samples:\n%s", got)
	}
}

// Rows, not only text: the core's readings must be unchanged by the presence of a module,
// and the module's must appear. This is the half a string comparison cannot prove.
func TestAModuleMetricDoesNotDisturbTheCoreReadings(t *testing.T) {
	core := metricRows(t, nil)
	with := metricRows(t, []*modules.Module{metricMod("extra", modules.Metric{
		Key: "peak_kpa", Label: "Peak manifold", Unit: "kPa", Sample: "boot",
		SourceView: "boost", SourceColumn: "map_kpa",
	})})

	// Guard the guard: comparing an empty core with an empty core would pass, so the
	// fixture has to actually produce every core metric -- both sample kinds, per-pull and
	// per-boot -- or this test proves nothing.
	for _, k := range coreMetricKeys {
		if core[k] == 0 {
			t.Fatalf("the fixture produced no %q rows, so this test would pass vacuously; got %v",
				k, core)
		}
	}

	for k, v := range core {
		if with[k] != v {
			t.Errorf("core metric %q changed when a module was added: %v -> %v", k, v, with[k])
		}
	}
	if _, ok := with["peak_kpa"]; !ok {
		t.Errorf("the module's metric produced no rows; got keys %v", keysOf(with))
	}
	if len(with) != len(core)+1 {
		t.Errorf("expected exactly one new metric, got keys %v (core had %v)", keysOf(with), keysOf(core))
	}
}

// metricRows builds a store with the given modules over a fixture and returns the row count
// per metric in v_metric_samples.
func metricRows(t *testing.T, mods []*modules.Module) map[string]int {
	t.Helper()
	db := deriveDB(t)
	ctx := context.Background()

	// Enough rows in one boot for the thin-sample floor to be met, so the per-boot medians
	// are present and a change to them would show.
	// observed_at matters: v_boot_start reads it from boost and obd, and every metric arm
	// joins through that view, so a fixture without it produces no rows at all.
	for i := range thinSampleFloor + 2 {
		_, err := db.ExecContext(ctx,
			`INSERT INTO boost (vehicle_id, boot_id, mono_ms, seq, observed_at, map_kpa, baro_kpa,
			                    lambda_e4, boost_psi, lambda_ratio, ltft_pct, stft_pct)
			 VALUES ('v', 'b', ?, ?, TIMESTAMP '2026-01-01 00:00:00' + INTERVAL 1 SECOND * ?,
			         200, 100, 9800, 14.5, 0.98, 3, -2)`,
			i*100, i, i)
		if err != nil {
			t.Fatal(err)
		}
	}
	// A rising-RPM run at wide-open throttle, so v_pulls detects one pull and the two
	// per-pull core metrics have something to report.
	for i := range 6 {
		_, err := db.ExecContext(ctx,
			`INSERT INTO obd (vehicle_id, boot_id, mono_ms, seq, observed_at, rpm, throttle_pct, speed_kph)
			 VALUES ('v', 'b', ?, ?, TIMESTAMP '2026-01-01 00:00:00' + INTERVAL 1 SECOND * ?, ?, 85, 60)`,
			i*200, i, i, 2000+i*600)
		if err != nil {
			t.Fatal(err)
		}
	}

	views, err := buildViewsSQL(mods)
	if err != nil {
		t.Fatalf("buildViewsSQL: %v", err)
	}
	if _, err := db.ExecContext(ctx, views); err != nil {
		t.Fatalf("views: %v", err)
	}
	return countByMetric(t, db)
}

func countByMetric(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	rows, err := db.QueryContext(context.Background(),
		`SELECT metric, count(*) FROM v_metric_samples GROUP BY metric`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		out[k] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func keysOf(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The refusals. Each has to be able to fail, and a collision in particular has to be
// refused rather than resolved, because resolving it would put a takeover rule in the
// server that module/v1 never agreed to.
func TestAModuleMetricIsRefusedWhen(t *testing.T) {
	for _, c := range []struct {
		name string
		m    modules.Metric
		want string
	}{{
		name: "its key is one the core already contributes",
		m:    modules.Metric{Key: "ltft_pct", Sample: "boot", SourceView: "boost", SourceColumn: "ltft_pct"},
		want: "already contributed by the logging core",
	}, {
		name: "its sample kind is not in the enum",
		m:    modules.Metric{Key: "x", Sample: "hourly", SourceView: "boost", SourceColumn: "map_kpa"},
		want: "is not one of sample, pull, boot, trip",
	}, {
		name: "its source view is not an identifier",
		m:    modules.Metric{Key: "x", Sample: "boot", SourceView: "boost; DROP TABLE obd", SourceColumn: "map_kpa"},
		want: "source_view",
	}, {
		name: "its source column is not an identifier",
		m:    modules.Metric{Key: "x", Sample: "boot", SourceView: "boost", SourceColumn: "map_kpa) --"},
		want: "source_column",
	}, {
		name: "its key is not an identifier",
		m:    modules.Metric{Key: "x'); --", Sample: "boot", SourceView: "boost", SourceColumn: "map_kpa"},
		want: "key is not a lowercase identifier",
	}} {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildViewsSQL([]*modules.Module{metricMod("m", c.m)})
			if err == nil {
				t.Fatalf("accepted %+v", c.m)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
		})
	}
}

// Two modules claiming one key is the same refusal, naming the other module.
func TestTwoModulesCannotContributeTheSameMetric(t *testing.T) {
	a := metricMod("aaa", modules.Metric{Key: "shared", Sample: "boot", SourceView: "boost", SourceColumn: "map_kpa"})
	b := metricMod("bbb", modules.Metric{Key: "shared", Sample: "boot", SourceView: "boost", SourceColumn: "map_kpa"})
	_, err := buildViewsSQL([]*modules.Module{b, a})
	if err == nil {
		t.Fatal("two modules both contributed the metric `shared`")
	}
	if !strings.Contains(err.Error(), "module aaa") || !strings.Contains(err.Error(), "bbb") {
		t.Errorf("error should name both modules, got %q", err)
	}
}

// The rendering must not depend on the order the modules were loaded in, or the same set
// would produce different SQL on two machines.
func TestRenderingDoesNotDependOnModuleOrder(t *testing.T) {
	a := metricMod("aaa", modules.Metric{Key: "a_metric", Sample: "boot", SourceView: "boost", SourceColumn: "map_kpa"})
	b := metricMod("bbb", modules.Metric{Key: "b_metric", Sample: "pull", SourceView: "v_pulls", SourceColumn: "avg_lambda"})
	one, err := buildViewsSQL([]*modules.Module{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, err := buildViewsSQL([]*modules.Module{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Error("the rendered SQL depends on the order the module set was listed in")
	}
}
