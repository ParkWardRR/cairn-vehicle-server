package tsdb

import (
	"context"
	"testing"
)

func TestOBDSpeed255AtZeroRPMIsUnavailable(t *testing.T) {
	db := emptyDB(t)
	for _, q := range []string{
		`INSERT INTO obd (vehicle_id, content_root, boot_id, mono_ms, seq, speed_kph, rpm) VALUES
			('v','r','b',1,1,255,0), ('v','r','b',2,2,255,2400), ('v','r','b',3,3,80,0), ('v','r','b',4,4,255,NULL)`,
	} {
		if _, err := db.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	report := &Report{}
	if err := clearUnavailableOBDSpeed(context.Background(), db.db, report); err != nil {
		t.Fatal(err)
	}
	res, err := db.Query(context.Background(), `SELECT seq, speed_kph FROM obd ORDER BY seq`, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []any{nil, int16(255), int16(80), int16(255)}
	for i, row := range res.Rows {
		if row[1] != want[i] {
			t.Errorf("seq %v: speed %v (%T), want %v", row[0], row[1], row[1], want[i])
		}
	}
	if len(report.Notes) != 1 {
		t.Errorf("notes = %q, want one", report.Notes)
	}
}
