package counters

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

const dev = "8777228e000000000000000000000001"

func open(t *testing.T) (*Guard, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "counters.json")
	g, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return g, path
}

func TestFirstBundleIsNew(t *testing.T) {
	g, _ := open(t)
	v, gap, err := g.Check(dev, 1, "aa")
	if v != New || gap != 0 || err != nil {
		t.Fatalf("Check = %v, %d, %v", v, gap, err)
	}
}

func TestZeroCounterRefused(t *testing.T) {
	g, _ := open(t)
	if _, _, err := g.Check(dev, 0, "aa"); !errors.Is(err, ErrZeroCounter) {
		t.Fatalf("Check(0): %v", err)
	}
	if err := g.Record(dev, 0, "aa"); !errors.Is(err, ErrZeroCounter) {
		t.Fatalf("Record(0): %v", err)
	}
}

func TestSameContentIsADuplicate(t *testing.T) {
	g, _ := open(t)
	if err := g.Record(dev, 1, "aa"); err != nil {
		t.Fatal(err)
	}
	v, _, err := g.Check(dev, 1, "aa")
	if v != Duplicate || err != nil {
		t.Fatalf("restored-card re-upload: %v, %v", v, err)
	}
	// Recording the pair again is idempotent.
	if err := g.Record(dev, 1, "aa"); err != nil {
		t.Fatalf("re-record: %v", err)
	}
}

// A genuine device never seals two different bundles with one counter. This is
// what a cloned device, a forged bundle or a reflashed unit looks like.
func TestSameCounterDifferentContentConflicts(t *testing.T) {
	g, _ := open(t)
	if err := g.Record(dev, 5, "aa"); err != nil {
		t.Fatal(err)
	}

	v, _, err := g.Check(dev, 5, "bb")
	if v != Conflict || !errors.Is(err, ErrCounterConflict) {
		t.Fatalf("Check = %v, %v", v, err)
	}
	if err := g.Record(dev, 5, "bb"); !errors.Is(err, ErrCounterConflict) {
		t.Fatalf("Record must refuse too, or two racing offers could both win: %v", err)
	}
}

func TestOlderUnseenCounterIsNewNotAReplay(t *testing.T) {
	g, _ := open(t)
	for _, c := range []uint64{1, 2, 5} {
		if err := g.Record(dev, c, "r"+string(rune('0'+c))); err != nil {
			t.Fatal(err)
		}
	}
	// 3 and 4 arrive late, out of order: legitimate backlog.
	v, gap, err := g.Check(dev, 3, "r3")
	if v != New || gap != 0 || err != nil {
		t.Fatalf("late bundle: %v, gap %d, %v", v, gap, err)
	}
}

func TestGapsAreReportedNotRefused(t *testing.T) {
	g, _ := open(t)
	if err := g.Record(dev, 1, "a"); err != nil {
		t.Fatal(err)
	}

	v, gap, err := g.Check(dev, 4, "d")
	if v != New || gap != 2 || err != nil {
		t.Fatalf("jump: %v, gap %d, %v", v, gap, err)
	}
	if err := g.Record(dev, 4, "d"); err != nil {
		t.Fatal(err)
	}
	if got, want := g.Missing(dev), []uint64{2, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Missing = %v, want %v", got, want)
	}
	if err := g.Record(dev, 2, "b"); err != nil {
		t.Fatal(err)
	}
	if got, want := g.Missing(dev), []uint64{3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Missing after backfill = %v, want %v", got, want)
	}
}

func TestDevicesAreIndependent(t *testing.T) {
	g, _ := open(t)
	other := "8777228e000000000000000000000002"
	if err := g.Record(dev, 1, "aa"); err != nil {
		t.Fatal(err)
	}
	v, _, err := g.Check(other, 1, "bb")
	if v != New || err != nil {
		t.Fatalf("counter 1 on another device: %v, %v", v, err)
	}
}

func TestResumeRaisesTheFloor(t *testing.T) {
	g, _ := open(t)
	for _, c := range []uint64{1, 3} {
		if err := g.Record(dev, c, "r"+string(rune('0'+c))); err != nil {
			t.Fatal(err)
		}
	}
	// 2 is genuinely missing before the re-enrolment.
	if m := g.Missing(dev); !reflect.DeepEqual(m, []uint64{2}) {
		t.Fatalf("Missing before resume = %v", m)
	}

	hw, err := g.Resume(dev)
	if err != nil || hw != 3 {
		t.Fatalf("Resume = %d, %v", hw, err)
	}
	// Everything below the new floor is no longer reported as missing: the
	// device was re-keyed and will not resend it.
	if m := g.Missing(dev); len(m) != 0 {
		t.Fatalf("Missing after resume = %v", m)
	}
}

func TestSurvivesRestart(t *testing.T) {
	g, path := open(t)
	if err := g.Record(dev, 7, "aa"); err != nil {
		t.Fatal(err)
	}
	g2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _, _ := g2.Check(dev, 7, "bb"); v != Conflict {
		t.Fatalf("after restart: %v, want Conflict", v)
	}
	if g2.HighWater(dev) != 7 {
		t.Fatalf("high water = %d", g2.HighWater(dev))
	}
}
