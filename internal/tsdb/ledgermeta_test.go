package tsdb

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
)

func TestLedgerMetaReportsPathSizeDurationAndTime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	book, err := ledger.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC).UnixMilli()
	add := func(e ledger.Entry) {
		t.Helper()
		if err := book.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	// A relayed bundle, offered twice (a cut-off session retried) and committed 90 s after
	// the first offer.
	add(ledger.Entry{UTCMS: t0, Event: ledger.EventOffered, ContentRoot: "aa", Path: ledger.PathBLERelay})
	add(ledger.Entry{UTCMS: t0 + 40_000, Event: ledger.EventOffered, ContentRoot: "aa", Path: ledger.PathBLERelay})
	add(ledger.Entry{UTCMS: t0 + 90_000, Event: ledger.EventCommitted, ContentRoot: "aa", Bytes: 2048, Path: ledger.PathBLERelay})
	// A bundle whose path is only on its offer.
	add(ledger.Entry{UTCMS: t0, Event: ledger.EventOffered, ContentRoot: "bb", Path: ledger.PathLTE})
	add(ledger.Entry{UTCMS: t0 + 1000, Event: ledger.EventCommitted, ContentRoot: "bb", Bytes: 10})
	// A bundle written before paths were recorded, and one committed with no offer logged.
	add(ledger.Entry{UTCMS: t0, Event: ledger.EventOffered, ContentRoot: "cc"})
	add(ledger.Entry{UTCMS: t0 + 5, Event: ledger.EventCommitted, ContentRoot: "cc", Bytes: 7})
	add(ledger.Entry{UTCMS: t0, Event: ledger.EventCommitted, ContentRoot: "dd", Bytes: 7, Path: ledger.PathWiFiDirect})
	// A refusal is not a commit.
	add(ledger.Entry{UTCMS: t0, Event: ledger.EventOfferRejected, ContentRoot: "ee", Reason: "no", Path: ledger.PathLTE})
	book.Close()

	m, notes, err := ledgerMeta(dir)
	if err != nil || len(notes) != 0 {
		t.Fatalf("err = %v, notes = %v", err, notes)
	}
	a := m["aa"]
	if a.Path != "ble-relay" || a.SizeBytes != 2048 || a.DurationMS != 90_000 ||
		!a.ReceivedAt.Equal(time.UnixMilli(t0+90_000)) {
		t.Fatalf("aa = %+v: duration runs from the first offer", a)
	}
	if m["bb"].Path != "lte" {
		t.Fatalf("bb path = %q, want it taken from the offer", m["bb"].Path)
	}
	if m["cc"].Path != "" {
		t.Fatalf("cc path = %q: an unrecorded path stays unknown, it is not guessed", m["cc"].Path)
	}
	if d := m["dd"]; d.Path != "wifi-direct" || d.DurationMS != 0 {
		t.Fatalf("dd = %+v", d)
	}
	if _, ok := m["ee"]; ok {
		t.Fatal("a rejected offer is not a received bundle")
	}
}

func TestLedgerMetaWithNoLedgerIsEmptyNotAnError(t *testing.T) {
	m, notes, err := ledgerMeta(filepath.Join(t.TempDir(), "nope"))
	if err != nil || len(m) != 0 || len(notes) != 0 {
		t.Fatalf("got %v %v %v", m, notes, err)
	}
}

// A damaged line costs the entries after it, and the store says so rather than failing.
func TestLedgerMetaKeepsWhatItCouldReadFromADamagedLedger(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ledger")
	book, _ := ledger.Open(dir)
	t0 := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC).UnixMilli()
	book.Append(ledger.Entry{UTCMS: t0, Event: ledger.EventCommitted, ContentRoot: "aa", Bytes: 5, Path: ledger.PathBLERelay})
	book.Close()
	f, _ := os.OpenFile(filepath.Join(dir, "2026-10-05.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("{not json\n")
	f.Close()

	m, notes, err := ledgerMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m["aa"].Path != "ble-relay" || len(notes) != 1 {
		t.Fatalf("m = %+v, notes = %v", m, notes)
	}
}

func TestMetaColumnsAreNullWhenUnknown(t *testing.T) {
	if metaPath(nil) != nil || metaSize(nil) != nil || metaDuration(nil) != nil || metaReceived(nil) != nil {
		t.Fatal("no ledger record must reach the store as four NULLs")
	}
	if metaPath(&BundleMeta{}) != nil {
		t.Fatal("an empty path is NULL, not an empty string")
	}
	// A bundle with a size but no commit time has no duration either.
	if metaDuration(&BundleMeta{SizeBytes: 5}) != nil {
		t.Fatal("duration without a commit time must be NULL")
	}
}
