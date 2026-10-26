package tsdb

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// A cold start at home: earlier drives' learning scans placed the home access points from
// the fixes beside them; this boot's first scans have no fix and are placed by those.
func TestWifiAccessPointsAreLearnedAndPlaceUnfixedScans(t *testing.T) {
	db := emptyDB(t)
	exec := func(q string) {
		t.Helper()
		if _, err := db.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	const homeLat, homeLon = 34.0280, -118.4527
	scan := func(boot string, mono, seq int, flags int, aps ...string) {
		exec(fmt.Sprintf(`INSERT INTO wifi_scan (vehicle_id, boot_id, mono_ms, seq, flags, scan_ms, ap_count) VALUES ('v','%s',%d,%d,%d,2000,%d)`, boot, mono, seq, flags, len(aps)/2))
		for i := 0; i+1 < len(aps); i += 2 {
			exec(fmt.Sprintf(`INSERT INTO wifi_ap_obs (vehicle_id, boot_id, mono_ms, seq, bssid, rssi_dbm, channel) VALUES ('v','%s',%d,%d,'%s',%s,6)`, boot, mono, seq, aps[i], aps[i+1]))
		}
	}
	fix := func(boot string, mono, seq int, lat, lon, speed float64) {
		exec(fmt.Sprintf(`INSERT INTO position (vehicle_id, boot_id, mono_ms, seq, lat, lon, fix_type, speed_mps, sats_used) VALUES ('v','%s',%d,%d,%f,%f,3,%f,12)`, boot, mono, seq, lat, lon, speed))
	}
	// Boot A: parked at home with a fix, three learning scans hear the two home APs. A
	// third AP is heard once only; a fourth (a bus) is heard 2 km apart.
	for i := 0; i < 3; i++ {
		m := 10000 + i*60000
		fix("A", m-500, i, homeLat+0.00002*float64(i), homeLon, 0)
		scan("A", m, 100+i, 1, "88:dc:97:07:b8:db", "-50", "88:dc:97:07:b8:dc", "-60")
	}
	scan("A", 70000, 200, 1, "aa:aa:aa:00:00:01", "-70")
	fix("A", 300000, 10, homeLat, homeLon, 0)
	scan("A", 300400, 300, 1, "bb:bb:bb:00:00:02", "-65")
	fix("A", 400000, 11, homeLat+0.02, homeLon, 0)
	scan("A", 400400, 301, 1, "bb:bb:bb:00:00:02", "-65")

	// Boot B: cold start, no fix for minutes, scans hear the home APs; then a fix arrives
	// and a scan beside it is not "unfixed".
	scan("B", 5000, 1, 2, "88:dc:97:07:b8:db", "-55", "88:dc:97:07:b8:dc", "-62")
	scan("B", 15000, 2, 2, "cc:cc:cc:00:00:03", "-80")
	fix("B", 600000, 1, homeLat+0.0005, homeLon, 12)
	scan("B", 601000, 3, 3, "88:dc:97:07:b8:db", "-90")

	res, err := db.Query(context.Background(), `SELECT bssid, observations, spread_m FROM v_wifi_ap_learned WHERE vehicle_id = 'v' ORDER BY bssid`, 0)
	if err != nil {
		t.Fatal(err)
	}
	learned := map[string]bool{}
	for _, r := range res.Rows {
		learned[r[0].(string)] = true
	}
	if !learned["88:dc:97:07:b8:db"] || !learned["88:dc:97:07:b8:dc"] {
		t.Errorf("home access points not learned: %v", res.Rows)
	}
	if learned["aa:aa:aa:00:00:01"] {
		t.Error("an access point seen once was learned")
	}
	if learned["bb:bb:bb:00:00:02"] {
		t.Error("an access point seen 2 km apart was learned as a place")
	}

	res, err = db.Query(context.Background(), `SELECT boot_id, seq, est_lat, est_lon, est_accuracy_m, est_aps FROM v_wifi_scan_unfixed ORDER BY boot_id, seq`, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]any{}
	for _, r := range res.Rows {
		got[fmt.Sprintf("%v/%v", r[0], r[1])] = r
	}
	r, ok := got["B/1"]
	if !ok || r[2] == nil {
		t.Fatalf("the cold-start scan was not estimated: %v", res.Rows)
	}
	dLat := (r[2].(float64) - homeLat) * 111320
	dLon := (r[3].(float64) - homeLon) * 111320 * math.Cos(homeLat*math.Pi/180)
	if d := math.Hypot(dLat, dLon); d > 10 {
		t.Errorf("cold-start estimate %.1f m from home, want within 10", d)
	}
	if r[5] != int32(2) {
		t.Errorf("est_aps = %v, want 2", r[5])
	}
	if r2, ok := got["B/2"]; !ok || r2[2] != nil {
		t.Errorf("a scan of unknown access points: %v, want listed with no estimate", r2)
	}
	if _, ok := got["B/3"]; ok {
		t.Error("a scan 1 s after a trusted fix was listed as unfixed")
	}
}

// Decoded scans reach both tables, one row per scan and one per access point.
func TestWifiScansLoadFromABundle(t *testing.T) {
	opts := testbundle.Default()
	opts.WifiScans = 3
	b, err := testbundle.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	sd := t.TempDir()
	writeSD(t, sd, b, "b1")
	db := buildFromSD(t, sd)
	if !db.Report.OK() {
		t.Fatalf("did not reproduce: %v", db.Report.Problems)
	}
	res, err := db.Query(context.Background(), `SELECT (SELECT count(*) FROM wifi_scan), (SELECT count(*) FROM wifi_ap_obs),
		(SELECT max(ap_count) FROM wifi_scan), (SELECT count(DISTINCT bssid) FROM wifi_ap_obs)`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Rows[0]; r[0] != int64(3) || r[1] != int64(6) || r[3] != int64(2) {
		t.Errorf("scans, access-point rows, max count, distinct = %v; want 3, 6, 2, 2", r)
	}
	if db.Report.Bundles[0].Warnings != nil {
		t.Errorf("warnings: %v", db.Report.Bundles[0].Warnings)
	}
}
