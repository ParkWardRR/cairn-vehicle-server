package outbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func newQueue(t *testing.T) (*Queue, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "outbox")
	q, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return q, dir
}

func entry(n int) Entry {
	return Entry{
		BundleID:    fmt.Sprintf("bundle-%04d", n),
		DeviceID:    "device-0001",
		ContentRoot: fmt.Sprintf("root-%04d", n),
		BytesStored: int64(n) * 1024,
	}
}

func TestAppendAndPending(t *testing.T) {
	q, _ := newQueue(t)

	for i := 0; i < 5; i++ {
		if err := q.Append(entry(i)); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}

	pending, err := q.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 5 {
		t.Fatalf("%d pending, want 5", len(pending))
	}

	// Sequence numbers are assigned by the queue, ascending from zero.
	for i, e := range pending {
		if e.Seq != uint64(i) {
			t.Errorf("entry %d has Seq %d, want %d", i, e.Seq, i)
		}
		if e.EnqueuedAt.IsZero() {
			t.Errorf("entry %d has no enqueue time", i)
		}
	}
}

func TestAckRemovesFromPending(t *testing.T) {
	q, _ := newQueue(t)

	for i := 0; i < 4; i++ {
		if err := q.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}

	if err := q.Ack(1); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	pending, err := q.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("%d pending after one ack, want 3", len(pending))
	}
	for _, e := range pending {
		if e.Seq == 1 {
			t.Error("an acknowledged entry is still pending")
		}
	}

	// The total is unchanged: acking does not rewrite the log.
	total, err := q.Len()
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 {
		t.Errorf("Len = %d, want 4 — acking must not mutate the log", total)
	}
}

// A worker that crashes after finishing but before acking must be able to
// repeat the ack safely.
func TestAckIsIdempotent(t *testing.T) {
	q, _ := newQueue(t)
	if err := q.Append(entry(0)); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := q.Ack(0); err != nil {
			t.Fatalf("Ack attempt %d: %v", i, err)
		}
	}

	count, err := q.PendingCount()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("PendingCount = %d, want 0", count)
	}
}

// Unacknowledged work must be redelivered after a restart. A worker crash costs
// a repeat, never a lost job — which is why decode work has to be idempotent.
func TestPendingSurvivesRestart(t *testing.T) {
	q, dir := newQueue(t)

	for i := 0; i < 3; i++ {
		if err := q.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Ack(0); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	pending, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Fatalf("%d pending after restart, want 2", len(pending))
	}
	if pending[0].Seq != 1 {
		t.Errorf("first pending Seq = %d, want 1", pending[0].Seq)
	}
}

// Sequence numbers must keep ascending across a restart, or a new entry could
// collide with an old acknowledgement marker and appear already done.
func TestSequenceContinuesAcrossRestart(t *testing.T) {
	q, dir := newQueue(t)

	for i := 0; i < 3; i++ {
		if err := q.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reopened.Append(entry(99)); err != nil {
		t.Fatal(err)
	}

	all, err := reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	last := all[len(all)-1]
	if last.Seq != 3 {
		t.Errorf("new entry after restart has Seq %d, want 3", last.Seq)
	}
}

// An append cut short by a crash never completed its fsync, so no caller was
// ever told the entry existed. Dropping the torn line is correct; treating it
// as valid would hand a worker a malformed job, and refusing to start would be
// worse than either.
func TestTornFinalLineIsDropped(t *testing.T) {
	q, dir := newQueue(t)

	for i := 0; i < 2; i++ {
		if err := q.Append(entry(i)); err != nil {
			t.Fatal(err)
		}
	}

	// Simulate a crash mid-append.
	logPath := filepath.Join(dir, "entries.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	truncated := append(data, []byte(`{"seq":2,"bundle_id":"bundle-00`)...)
	if err := os.WriteFile(logPath, truncated, 0o600); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("a torn final line must not prevent startup: %v", err)
	}
	pending, err := reopened.Pending()
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(pending) != 2 {
		t.Errorf("%d pending, want 2 — the torn line should be dropped", len(pending))
	}

	// And the queue must remain usable.
	if err := reopened.Append(entry(3)); err != nil {
		t.Fatalf("Append after a torn line: %v", err)
	}
}

func TestGet(t *testing.T) {
	q, _ := newQueue(t)
	if err := q.Append(entry(7)); err != nil {
		t.Fatal(err)
	}

	got, err := q.Get(0)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.BundleID != "bundle-0007" {
		t.Errorf("BundleID = %q, want bundle-0007", got.BundleID)
	}

	if _, err := q.Get(999); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

func TestEmptyQueue(t *testing.T) {
	q, _ := newQueue(t)

	pending, err := q.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("%d pending in a fresh queue, want 0", len(pending))
	}

	count, err := q.Len()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("Len = %d, want 0", count)
	}
}
