package audit

import (
	"testing"
	"time"
)

func TestRecentReadsOnlyTheWindowNewestFirstAndSkips(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	base := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		day   int // days before base
		route string
	}{{3, "old"}, {1, "yesterday"}, {0, "GET /v1/health"}, {0, "today-a"}, {0, "today-b"}} {
		at := base.AddDate(0, 0, -c.day)
		l.SetClock(func() time.Time { return at })
		if err := l.Append(Entry{Time: at, ActorType: ActorApp, Route: c.route, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	l.SetClock(func() time.Time { return base })

	skipHealth := func(e Entry) bool { return e.Route == "GET /v1/health" }
	got, err := l.Recent(2, 0, skipHealth)
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, e := range got {
		routes = append(routes, e.Route)
	}
	want := []string{"today-b", "today-a", "yesterday"}
	if len(routes) != len(want) {
		t.Fatalf("got %v, want %v (the 3-day-old entry is outside a 2-day window)", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("got %v, want %v", routes, want)
		}
	}

	limited, _ := l.Recent(7, 2, skipHealth)
	if len(limited) != 2 || limited[0].Route != "today-b" {
		t.Fatalf("limit 2 returned %v", limited)
	}
	if empty, err := (&Log{dir: t.TempDir(), now: func() time.Time { return base }}).Recent(3, 10, nil); err != nil || len(empty) != 0 {
		t.Fatalf("an empty directory: %v %v", empty, err)
	}
}
