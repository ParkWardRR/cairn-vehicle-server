// Command cairn-tsdb-demo serves a synthetic store over cairn-tsdb's HTTP API.
//
//	cairn-tsdb-demo                  # listens on 127.0.0.1:8480
//	cairn-tsdb-demo -fetch           # refresh routes.json from the public OSRM demo server
//
// It exists so the web UI can be run and photographed (see docs/screenshots)
// without a real capture. Everything here is invented: a fictional owner of a
// turbocharged car who lives in Carmel-by-the-Sea, California, and spends two
// weeks on errands in and around town. The roads are real, the drives are not.
// The device id and every hash are derived from fixed strings.
//
// The schema, views and read-only lockdown are the production ones
// (tsdb.BuildSynthetic); only the rows are made up.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"sort"
	"time"

	"github.com/ParkWardRR/Cairn/server/internal/tsdb"
)

//go:embed routes.json
var routesJSON []byte

// outing is one scheduled excursion: how many days ago, what local time (PDT)
// it set off, and which template.
type outing struct {
	daysAgo int
	hh, mm  int
	tmpl    string
	style   string // overrides the template's when set
}

var schedule = []outing{
	{0, 7, 15, "crossroads", ""},
	{0, 9, 15, "valley", ""},
	{1, 16, 40, "ptlobos", ""},
	{2, 17, 30, "town", ""},
	{3, 7, 45, "seventeen", ""},
	{4, 18, 5, "crossroads", ""},
	{5, 10, 20, "mission", ""},
	{6, 10, 0, "valley", "brisk"},
	{8, 12, 10, "town", ""},
	{9, 8, 30, "ptlobos", ""},
	{10, 17, 50, "crossroads", ""},
	{11, 16, 0, "seventeen", ""},
	{13, 9, 40, "mission", ""},
}

const pdt = -7 * time.Hour

func main() {
	var (
		addr    = flag.String("addr", "127.0.0.1:8480", "listen address")
		fetch   = flag.Bool("fetch", false, "refresh routes.json from OSRM and exit")
		seed    = flag.Uint64("seed", 7, "random seed")
		verbose = flag.Bool("v", false, "print one line per generated boot")
	)
	flag.Parse()

	if *fetch {
		if err := fetchRoutes("routes.json"); err != nil {
			log.Fatal(err)
		}
		return
	}

	var routes map[string]route
	if err := json.Unmarshal(routesJSON, &routes); err != nil {
		log.Fatalf("routes.json: %v", err)
	}

	db, err := tsdb.BuildSynthetic(context.Background(), func(apps tsdb.Appenders) error {
		return generate(apps, routes, rand.New(rand.NewPCG(*seed, 1)), *verbose)
	})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("POST /query", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64<<10)
		n, _ := r.Body.Read(buf)
		res, err := db.Query(r.Context(), string(buf[:n]), 500000)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	})
	log.Printf("synthetic store ready on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

type boot struct {
	when   time.Time // local-clock-corrected UTC start
	tmpl   *template
	rt     route
	style  string
	home   bool // finishes at home
	origin string
}

func generate(apps tsdb.Appenders, routes map[string]route, rng *rand.Rand, verbose bool) error {
	now := time.Now().UTC()
	today := time.Date(now.Add(pdt).Year(), now.Add(pdt).Month(), now.Add(pdt).Day(), 0, 0, 0, 0, time.UTC)

	var boots []boot
	for _, o := range schedule {
		t := templates[o.tmpl]
		rt, ok := routes[o.tmpl]
		if !ok {
			return fmt.Errorf("no route for %s; run with -fetch", o.tmpl)
		}
		style := t.style
		if o.style != "" {
			style = o.style
		}
		out := today.AddDate(0, 0, -o.daysAgo).Add(time.Duration(o.hh)*time.Hour + time.Duration(o.mm)*time.Minute - pdt)
		if t.roundTrip {
			// Duration is unknown until simulated; estimate from distance.
			km := routeKm(rt)
			outDur := time.Duration(km/45*3600) * time.Second
			dwell := time.Duration(t.dwellMin[0]+rng.IntN(t.dwellMin[1]-t.dwellMin[0]+1)) * time.Minute
			boots = append(boots,
				boot{when: out, tmpl: t, rt: rt, style: style},
				boot{when: out.Add(outDur + dwell), tmpl: t, rt: reverse(rt), style: style, home: true})
		} else {
			boots = append(boots, boot{when: out, tmpl: t, rt: rt, style: style, home: true})
		}
	}
	sort.Slice(boots, func(i, j int) bool { return boots[i].when.Before(boots[j].when) })

	// Anything that would start after "now" slides back a day.
	for i := range boots {
		if boots[i].when.After(now.Add(-20 * time.Minute)) {
			boots[i].when = boots[i].when.Add(-24 * time.Hour)
		}
	}
	sort.Slice(boots, func(i, j int) bool { return boots[i].when.Before(boots[j].when) })

	deviceID := hexOf("cairn-demo-device")[:16]
	sd := 29400
	var prevEnd time.Time
	for i, b := range boots {
		cold := prevEnd.IsZero() || b.when.Sub(prevEnd) > 4*time.Hour
		coolStart := 78 + rng.Float64()*10
		ttff := 5 + rng.Float64()*14
		idle := 6 + rng.Float64()*16
		if cold {
			coolStart = 15 + rng.Float64()*6
			ttff = 24 + rng.Float64()*40
			idle = 22 + rng.Float64()*45
		} else if b.when.Sub(prevEnd) > 40*time.Minute {
			coolStart = 55 + rng.Float64()*15
			ttff = 10 + rng.Float64()*18
		}
		hour := float64((b.when.Add(pdt)).Hour()) + 0.5
		ambient := 13 + 8*math.Max(0, math.Sin((hour-6)/12*math.Pi))
		day := float64(b.when.Unix()) / 86400
		origin := "server"
		if i >= len(boots)-3 {
			origin = "sd"
		}
		bootID := hexOf("boot", i, b.when.Unix())[:32]
		sd -= 8 + rng.IntN(22)
		info, err := simulate(apps, rng, b.rt, b.tmpl, b.style, tripOpts{
			start: b.when, coolStartC: coolStart, ambientC: ambient, ttffS: ttff, idleS: idle,
			ltftBase: math.Round(2.6 + 1.2*math.Sin(day/5)), endsAtHome: b.home, origin: origin,
			sdFreeMiB: sd, deviceTempC: 24 + ambient/2, gap: rng.Float64() < 0.07,
		}, bootID)
		if err != nil {
			return err
		}
		prevEnd = info.endWall
		if verbose {
			fmt.Printf("%s  %-10s %-8s %5.1f min  obd=%d pos=%d\n",
				b.when.Add(pdt).Format("Mon Jan _2 15:04"), b.tmpl.name, b.style,
				float64(info.durationMS)/60000, info.counts.obd, info.counts.pos)
		}
		c := info.counts
		if err := apps.Append("bundles", info.root, info.bundleID, deviceID, info.bootID, info.origin,
			int32(1), hexOf("digest", info.root), true, int32(3+rng.IntN(9)),
			c.pos, c.imu, c.obd, c.boost, c.status, c.trans, c.gap, int32(0), ""); err != nil {
			return err
		}
	}
	return nil
}

func routeKm(rt route) float64 {
	var m float64
	for i := 1; i < len(rt.Coords); i++ {
		dx := (rt.Coords[i][0] - rt.Coords[i-1][0]) * math.Cos(rt.Coords[i][1]*math.Pi/180) * 111320
		dy := (rt.Coords[i][1] - rt.Coords[i-1][1]) * 110540
		m += math.Hypot(dx, dy)
	}
	return m / 1000
}
