package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// place is a named point with a rough altitude. The altitude only shapes the
// synthetic elevation profile; OSRM snaps the coordinates to the nearest road.
type place struct {
	lat, lon float64
	altM     float64
}

// The scenario is a fictional owner who lives in Carmel-by-the-Sea, Monterey
// County, California and stays within a few miles of home: downtown, the beach,
// the Mission, Crossroads, Point Lobos, Pebble Beach and Carmel Valley Road.
// Every coordinate is a public landmark; none of it is anyone's real address.
var places = map[string]place{
	"home":       {36.5611, -121.9163, 55},
	"oceanave":   {36.5553, -121.9227, 30},
	"beach":      {36.5547, -121.9300, 3},
	"mission":    {36.5399, -121.9199, 20},
	"riverbeach": {36.5361, -121.9300, 3},
	"crossroads": {36.5398, -121.9101, 30},
	"ptlobos":    {36.5214, -121.9383, 20},
	"pebble":     {36.5675, -121.9500, 80},
	"spanish":    {36.6120, -121.9490, 10},
	"quail":      {36.5446, -121.8905, 60},
	"valleyrd":   {36.5300, -121.8570, 90},
}

// template is one kind of outing. A round trip becomes two boots: the car is
// parked for a while at the far end, so the dongle sleeps and wakes again.
type template struct {
	name      string
	via       []string
	style     string // calm | brisk | spirited
	roundTrip bool
	ripple    float64 // extra altitude wobble, metres
	dwellMin  [2]int  // minutes parked at the far end
}

var templates = map[string]*template{
	"town":       {name: "town", via: []string{"home", "oceanave", "beach", "mission"}, style: "calm", roundTrip: true, dwellMin: [2]int{40, 90}},
	"mission":    {name: "mission", via: []string{"home", "mission", "riverbeach"}, style: "calm", roundTrip: true, dwellMin: [2]int{45, 80}},
	"crossroads": {name: "crossroads", via: []string{"home", "crossroads"}, style: "calm", roundTrip: true, dwellMin: [2]int{25, 55}},
	"ptlobos":    {name: "ptlobos", via: []string{"home", "ptlobos"}, style: "calm", roundTrip: true, dwellMin: [2]int{70, 120}},
	"seventeen":  {name: "seventeen", via: []string{"home", "pebble", "spanish", "home"}, style: "brisk", ripple: 6},
	"valley":     {name: "valley", via: []string{"home", "quail", "valleyrd"}, style: "spirited", roundTrip: true, ripple: 8, dwellMin: [2]int{40, 75}},
}

// route is a road-following polyline with the router's free-flow speed for each
// segment, which stands in for the posted limit.
type route struct {
	Coords [][2]float64 `json:"coords"` // lon, lat
	Speeds []float64    `json:"speeds"` // m/s, one per segment (len(Coords)-1)
}

// fetchRoutes asks the public OSRM demo server for each template's geometry.
// It runs only on -fetch; the result is committed as routes.json so the demo
// build is offline and repeatable.
func fetchRoutes(path string) error {
	out := map[string]route{}
	for name, t := range templates {
		var parts []string
		for _, v := range t.via {
			p := places[v]
			parts = append(parts, fmt.Sprintf("%.5f,%.5f", p.lon, p.lat))
		}
		u := "https://router.project-osrm.org/route/v1/driving/" + strings.Join(parts, ";") +
			"?" + url.Values{
			"overview": {"full"}, "geometries": {"geojson"}, "annotations": {"speed,distance"}, "continue_straight": {"true"},
		}.Encode()

		var body []byte
		var err error
		for try := 0; try < 4; try++ {
			body, err = get(u)
			if err == nil {
				break
			}
			time.Sleep(time.Duration(try+1) * 2 * time.Second)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}

		var resp struct {
			Code   string `json:"code"`
			Routes []struct {
				Distance float64 `json:"distance"`
				Geometry struct {
					Coordinates [][2]float64 `json:"coordinates"`
				} `json:"geometry"`
				Legs []struct {
					Annotation struct {
						Speed []float64 `json:"speed"`
					} `json:"annotation"`
				} `json:"legs"`
			} `json:"routes"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if resp.Code != "Ok" || len(resp.Routes) == 0 {
			return fmt.Errorf("%s: osrm said %q", name, resp.Code)
		}
		r := resp.Routes[0]
		var speeds []float64
		for _, l := range r.Legs {
			speeds = append(speeds, l.Annotation.Speed...)
		}
		coords := r.Geometry.Coordinates
		// The annotation is per graph edge, the geometry per vertex; they line
		// up one to one on a full overview. If they ever do not, fall back to a
		// flat speed rather than mis-assign limits.
		if len(speeds) != len(coords)-1 {
			fmt.Fprintf(os.Stderr, "%s: %d speeds for %d segments; using a flat 15 m/s\n", name, len(speeds), len(coords)-1)
			speeds = make([]float64, len(coords)-1)
			for i := range speeds {
				speeds[i] = 15
			}
		}
		out[name] = route{Coords: coords, Speeds: speeds}
		fmt.Fprintf(os.Stderr, "%-10s %6.1f km, %d points\n", name, r.Distance/1000, len(coords))
		time.Sleep(1200 * time.Millisecond) // the demo server is shared; be polite
	}

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func get(u string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http %d: %.120s", resp.StatusCode, b)
	}
	return b, nil
}
