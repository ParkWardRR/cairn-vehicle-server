package tsdb

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/modules"
)

// Module metrics: the `metrics[]` of contracts/module/v1 §5, which is what lets the generic
// machinery — v_metric_samples, v_tune_effect, v_health_stats, the trip-insight list —
// treat a module's readings like any other's.
//
// Before this, the machinery was generic wrapped around a hard-coded list: the four arms of
// v_metric_samples and the `VALUES ('boost_psi'), ('lambda'), ('ltft_pct'), ('stft_pct')`
// in v_tune_effect. That literal is what a module contributes.
//
// **The core's four are grandfathered and this is append-only.** A module adds arms; it does
// not replace one. The reasoning is module/v1 §4's, one level up: a module set holding only
// `boost` must not make the two fuel trims vanish, because they belong to `fuel-mixture`,
// which is not written yet. Replacing a core metric is a *takeover*, the same question §4
// answered for columns and has not answered for metrics or views, so a collision is refused
// rather than resolved by whichever rule the server happens to implement.
//
// coreMetricKeys are therefore fixed, and in the order the arms appear.
var coreMetricKeys = []string{"boost_psi", "lambda", "ltft_pct", "stft_pct"}

// The markers buildViewsSQL substitutes in viewsTemplate.
const (
	markerArms = "/*CAIRN:METRIC_ARMS*/"
	markerKeys = "/*CAIRN:METRIC_KEYS*/"
)

// thinSampleFloor is how many readings a boot needs before its median counts as an
// observation. It lives here and not in a manifest on purpose: "a thin sample is not a
// verdict" is one of internal/insight's three rules and belongs to the core, so a module
// cannot lower the bar for its own metric.
const thinSampleFloor = 20

// buildViewsSQL renders the analysis views for a module set. With no module set it is the
// core's text, unchanged.
func buildViewsSQL(mods []*modules.Module) (string, error) {
	arms, keys, err := metricArms(mods)
	if err != nil {
		return "", err
	}
	list := make([]string, 0, len(keys))
	for _, k := range keys {
		list = append(list, "('"+k+"')")
	}
	out := strings.Replace(viewsTemplate, markerArms, arms, 1)
	out = strings.Replace(out, markerKeys, strings.Join(list, ", "), 1)
	if strings.Contains(out, "/*CAIRN:") {
		return "", fmt.Errorf("a substitution marker survived rendering: viewsTemplate and " +
			"buildViewsSQL have drifted")
	}
	return out, nil
}

// metricArms returns the body of v_metric_samples and the metric keys in it: the core's,
// then each module's in module id order.
func metricArms(mods []*modules.Module) (arms string, keys []string, err error) {
	arms = coreMetricArms
	keys = append(keys, coreMetricKeys...)

	seen := map[string]string{}
	for _, k := range coreMetricKeys {
		seen[k] = "the logging core"
	}

	for _, m := range sortedByID(mods) {
		for _, mt := range m.Manifest.Metrics {
			if owner, taken := seen[mt.Key]; taken {
				return "", nil, fmt.Errorf("module %s: metric %q is already contributed by %s: "+
					"taking a metric over is a different thing from adding one, and module/v1 "+
					"does not yet say how, so it is refused rather than guessed", m.ID(), mt.Key, owner)
			}
			arm, err := metricArm(mt)
			if err != nil {
				return "", nil, fmt.Errorf("module %s: metric %q: %w", m.ID(), mt.Key, err)
			}
			arms += "\nUNION ALL\n" + arm
			keys = append(keys, mt.Key)
			seen[mt.Key] = "module " + m.ID()
		}
	}
	return arms, keys, nil
}

// metricArm renders one metric as a SELECT over the view it names.
//
// `sample` is a closed enum, and that is the whole reason this can be generated: it decides
// what one observation is, so the shape of the SQL follows from it rather than from SQL a
// module wrote. A module says where to read and what one reading means; the core decides
// how to count, which is what keeps "enough observations to judge" comparable across
// modules.
func metricArm(m modules.Metric) (string, error) {
	if !identRe.MatchString(m.Key) {
		return "", fmt.Errorf("key is not a lowercase identifier")
	}
	if !identRe.MatchString(m.SourceView) {
		return "", fmt.Errorf("source_view %q is not a lowercase identifier", m.SourceView)
	}
	if !identRe.MatchString(m.SourceColumn) {
		return "", fmt.Errorf("source_column %q is not a lowercase identifier", m.SourceColumn)
	}

	switch m.Sample {
	// One observation per row of the source view, stamped with its boot's start. Used for
	// anything already reduced to one number per event -- a pull's peak boost, say.
	case "pull", "sample", "trip":
		return fmt.Sprintf(
			`SELECT x.vehicle_id, x.boot_id, '%[1]s', x.%[2]s, s.started_at
FROM %[3]s x JOIN v_boot_start s ON s.vehicle_id = x.vehicle_id AND s.boot_id = x.boot_id
WHERE x.%[2]s IS NOT NULL`, m.Key, m.SourceColumn, m.SourceView), nil

	// One observation per boot: the median over the boot, kept only when the boot holds
	// enough readings, so one long drive does not outweigh ten short ones and a drive that
	// barely started counts for nothing.
	case "boot":
		return fmt.Sprintf(
			`SELECT x.vehicle_id, x.boot_id, '%[1]s', median(x.%[2]s), s.started_at
FROM %[3]s x JOIN v_boot_start s ON s.vehicle_id = x.vehicle_id AND s.boot_id = x.boot_id
WHERE x.%[2]s IS NOT NULL
GROUP BY x.vehicle_id, x.boot_id, s.started_at
HAVING count(*) >= %[4]d`, m.Key, m.SourceColumn, m.SourceView, thinSampleFloor), nil
	}
	// The enum is closed in the schema, so reaching here means the manifest validator and
	// this switch have drifted. Refuse rather than silently contribute nothing.
	return "", fmt.Errorf("sample %q is not one of sample, pull, boot, trip", m.Sample)
}

// sortedByID copies and sorts, so the generated SQL does not depend on directory order.
func sortedByID(mods []*modules.Module) []*modules.Module {
	out := append([]*modules.Module(nil), mods...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
