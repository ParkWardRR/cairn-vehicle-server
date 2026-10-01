package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

// Every rejection must carry a reason. Enforced in Append rather than trusted
// to call sites, because the entries that need a reason are written on error
// paths where it is easiest to forget — and a refusal without a reason is the
// one entry nobody can act on.
func TestRejectionsRequireAReason(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer l.Close()

	for _, ev := range []Event{
		EventOfferRejected, EventChunkRejected, EventCommitFailed,
		EventDecodeFailed, EventQuotaRefused, EventDeviceUnknown,
	} {
		if err := l.Append(Entry{Event: ev}); err == nil {
			t.Errorf("%s was accepted with no reason", ev)
		}
		if err := l.Append(Entry{Event: ev, Reason: "because"}); err != nil {
			t.Errorf("%s with a reason was refused: %v", ev, err)
		}
	}

	// A success needs no reason.
	if err := l.Append(Entry{Event: EventCommitted}); err != nil {
		t.Errorf("a success entry was refused: %v", err)
	}
}

func TestAppendAndReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	want := []Entry{
		{Event: EventOffered, BundleID: "aa", ContentRoot: "bb", Bytes: 100},
		{Event: EventQuotaRefused, DeviceID: "cc", Reason: "over allowance"},
		{Event: EventCommitted, BundleID: "aa"},
	}
	for _, e := range want {
		if err := l.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	l.Close()

	// Re-opened, so this reads from disk rather than memory.
	l2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()

	got, err := l2.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("read %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Event != want[i].Event {
			t.Errorf("entry %d event = %s, want %s", i, got[i].Event, want[i].Event)
		}
		if got[i].Reason != want[i].Reason {
			t.Errorf("entry %d reason = %q, want %q", i, got[i].Reason, want[i].Reason)
		}
		if got[i].UTCMS == 0 {
			t.Errorf("entry %d has no timestamp", i)
		}
	}
}

// An appended entry must survive a crash, because the entry most likely to be
// lost is the one explaining the crash.
func TestAppendIsDurableImmediately(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if err := l.Append(Entry{Event: EventOffered, BundleID: "zz"}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	// Read through a second handle without closing the first: the bytes must
	// already be on disk.
	l2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, err := l2.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 || got[0].BundleID != "zz" {
		t.Errorf("entry was not durable before close: %+v", got)
	}

	l.Close()
	l2.Close()
}

// A malformed line is reported rather than skipped: a quietly incomplete ledger
// is worse than one that admits it is damaged.
func TestReadReportsMalformedLines(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir)
	if err := l.Append(Entry{Event: EventOffered}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	l.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	path := filepath.Join(dir, entries[0].Name())
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f.WriteString("{not json\n")
	f.Close()

	l2, _ := Open(dir)
	defer l2.Close()
	if _, err := l2.Read(); err == nil {
		t.Error("a malformed line was silently skipped")
	}
}
