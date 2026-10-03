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

// The scenario is a fictional owner who lives in Carmel-by-the-Sea, California
// and drives around the Monterey Peninsula and up and down Highway 1. Every
// coordinate is a public landmark; none of it is anyone's real address.
var places = map[string]place{
	"home":       {36.5589, -121.9205, 62},
	"crossroads": {36.5398, -121.9101, 30},
	"office":     {36.5981, -121.8946, 40},
	"cannery":    {36.6152, -121.8993, 5},
	"wharf":      {36.6033, -121.8933, 3},
	"lighthouse": {36.6384, -121.9334, 10},
	"spanish":    {36.6120, -121.9490, 10},
	"pebble":     {36.5675, -121.9500, 80},
	"ptlobos":    {36.5214, -121.9383, 20},
	"village":    {36.4796, -121.7289, 120},
	"lagunaseca": {36.5840, -121.7540, 190},
	"salinas":    {36.6743, -121.6560, 17},
	"garrapata":  {36.4465, -121.9230, 50},
	"bixby":      {36.3715, -121.9019, 75},
	"nepenthe":   {36.2706, -121.8076, 270},
	"pfeiffer":   {36.2495, -121.7878, 60},
}

// template is one kind of outing. A round trip becomes two boots: the car is
// parked for a while at the far end, so the dongle sleeps and wakes again.
type template struct {
	name      string
	via       []string
	style     string // calm | brisk | spirited
	roundTrip bool
	ripple    float64 // extra altitude wobble, metres, for coastal-cliff roads
	dwellMin  [2]int  // minutes parked at the far end
}

var templates = map[string]*template{
	"commute":    {name: "commute", via: []string{"home", "office"}, style: "calm", roundTrip: true, dwellMin: [2]int{480, 540}},
	"crossroads": {name: "crossroads", via: []string{"home", "crossroads"}, style: "calm", roundTrip: true, dwellMin: [2]int{25, 55}},
	"cannery":    {name: "cannery", via: []string{"home", "cannery", "wharf"}, style: "calm", roundTrip: true, dwellMin: [2]int{60, 100}},
	"ptlobos":    {name: "ptlobos", via: []string{"home", "ptlobos"}, style: "calm", roundTrip: true, dwellMin: [2]int{70, 120}},
	"seventeen":  {name: "seventeen", via: []string{"home", "pebble", "spanish", "lighthouse", "home"}, style: "calm"},
	"pgrove":     {name: "pgrove", via: []string{"home", "lighthouse", "wharf", "home"}, style: "brisk"},
	"valley":     {name: "valley", via: []string{"home", "village"}, style: "spirited", roundTrip: true, dwellMin: [2]int{45, 80}},
	"salinas":    {name: "salinas", via: []string{"home", "lagunaseca", "salinas"}, style: "brisk", roundTrip: true, dwellMin: [2]int{60, 150}},
	"garrapata":  {name: "garrapata", via: []string{"home", "garrapata"}, style: "brisk", roundTrip: true, ripple: 18, dwellMin: [2]int{40, 70}},
	"bixby":      {name: "bixby", via: []string{"home", "bixby", "nepenthe"}, style: "spirited", roundTrip: true, ripple: 30, dwellMin: [2]int{45, 90}},
	"pfeiffer":   {name: "pfeiffer", via: []string{"home", "bixby", "nepenthe", "pfeiffer"}, style: "brisk", roundTrip: true, ripple: 30, dwellMin: [2]int{60, 110}},
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
