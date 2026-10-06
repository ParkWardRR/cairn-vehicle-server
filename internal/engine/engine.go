// Package engine holds the per-engine analysis profiles: the labels, ranges and warning
// limits a dashboard needs to say whether a reading is normal for the car that made it.
//
// This is not the firmware's engine profile. That one (engines/*.yaml in the firmware
// repository, cairn.engine/v1-draft) says how to read an ECU: PIDs, formulas, cadence,
// sleep behaviour. This one says what the readings mean once they are in the store. The two
// share an engine id (bmw-n20) and nothing else, and the analysis half has no contract yet:
// the schema id is cairn.engine-analysis/v0 so no profile can be mistaken for a released
// one, and the shape is the one the web layer asked for (cairn-vehicle-server#22) so the
// two can be agreed before contracts/engine/v1 settles it.
//
// Two rules carried over from the firmware profiles:
//
//   - A profile states only what was established. A stub names the engine and claims no
//     limit; a limit that is null means "none known", never "none". The B58 profile is a
//     stub because nothing in the project documents B58 limits.
//   - Every limit comes from somewhere written down. The N20 numbers are the ones the web
//     dashboard hard-coded before it read them from here (status "derived").
//
// A vehicle whose engine code matches no profile gets none: the API says null, and the
// reader falls back to Generic, which carries only what holds for every engine.
package engine

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Schema is the profile schema id.
const Schema = "cairn.engine-analysis/v0"

// Signal is one measured quantity and what is normal for it.
type Signal struct {
	Key   string  `json:"key"`
	Label string  `json:"label"`
	Unit  string  `json:"unit"`
	Min   float64 `json:"min"`
	Max   float64 `json:"max"`
	// WarnLow and WarnHigh bound the normal band. Null means no limit is known on that
	// side, so a reading is never flagged for it.
	WarnLow  *float64 `json:"warn_low"`
	WarnHigh *float64 `json:"warn_high"`
	// CheckLow and CheckHigh are the further limits past which a reading is worth having
	// looked at, rather than watched. Optional.
	CheckLow  *float64 `json:"check_low,omitempty"`
	CheckHigh *float64 `json:"check_high,omitempty"`
}

// Profile is one engine's analysis profile.
type Profile struct {
	Schema     string             `json:"schema,omitempty"`
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Status     string             `json:"status"` // stub | derived | verified
	Codes      []string           `json:"codes,omitempty"`
	Sources    []string           `json:"sources,omitempty"`
	Signals    []Signal           `json:"signals"`
	Thresholds map[string]float64 `json:"thresholds"`
}

// Signal returns the named signal.
func (p *Profile) Signal(key string) (Signal, bool) {
	if p == nil {
		return Signal{}, false
	}
	for _, s := range p.Signals {
		if s.Key == key {
			return s, true
		}
	}
	return Signal{}, false
}

// Threshold returns a named threshold, or def when the profile states none.
func (p *Profile) Threshold(name string, def float64) float64 {
	if p != nil {
		if v, ok := p.Thresholds[name]; ok {
			return v
		}
	}
	return def
}

// Validate refuses a profile that states something impossible, so a typo in an
// operator's file fails at load rather than as a misleading health sentence.
func (p *Profile) Validate() error {
	if p.Schema != "" && p.Schema != Schema {
		return fmt.Errorf("schema %q is not %q", p.Schema, Schema)
	}
	if p.ID == "" || strings.ToLower(p.ID) != p.ID || strings.ContainsAny(p.ID, " /\\") {
		return fmt.Errorf("id %q must be lowercase with no spaces or slashes", p.ID)
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("a profile needs a name")
	}
	switch p.Status {
	case "stub", "derived", "verified":
	default:
		return fmt.Errorf("status %q is not stub, derived or verified", p.Status)
	}
	seen := map[string]bool{}
	for _, s := range p.Signals {
		if s.Key == "" || seen[s.Key] {
			return fmt.Errorf("signal key %q is empty or repeated", s.Key)
		}
		seen[s.Key] = true
		if s.Min >= s.Max {
			return fmt.Errorf("signal %s: min %v is not below max %v", s.Key, s.Min, s.Max)
		}
		if s.WarnLow != nil && s.WarnHigh != nil && *s.WarnLow >= *s.WarnHigh {
			return fmt.Errorf("signal %s: warn_low %v is not below warn_high %v", s.Key, *s.WarnLow, *s.WarnHigh)
		}
		if s.CheckHigh != nil && s.WarnHigh != nil && *s.CheckHigh < *s.WarnHigh {
			return fmt.Errorf("signal %s: check_high %v is below warn_high %v", s.Key, *s.CheckHigh, *s.WarnHigh)
		}
		if s.CheckLow != nil && s.WarnLow != nil && *s.CheckLow > *s.WarnLow {
			return fmt.Errorf("signal %s: check_low %v is above warn_low %v", s.Key, *s.CheckLow, *s.WarnLow)
		}
	}
	if p.Status == "stub" {
		for _, s := range p.Signals {
			if s.WarnLow != nil || s.WarnHigh != nil || s.CheckLow != nil || s.CheckHigh != nil {
				return fmt.Errorf("a stub claims no limit, but signal %s states one", s.Key)
			}
		}
		if len(p.Thresholds) > 0 {
			return errors.New("a stub claims no thresholds")
		}
	}
	return nil
}

//go:embed profiles/*.json
var builtin embed.FS

// Catalog is the set of profiles known to this server.
type Catalog struct {
	byID   map[string]*Profile
	byCode map[string]*Profile
}

// Builtin returns the catalog compiled into the binary.
func Builtin() (*Catalog, error) {
	return load(nil)
}

// Load returns the built-in catalog plus every *.json profile in dir, which wins on an
// id clash: an operator who has measured their own engine's limits replaces the shipped
// ones. An empty dir is the built-in catalog.
func Load(dir string) (*Catalog, error) {
	if dir == "" {
		return load(nil)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read engine profiles: %w", err)
	}
	var extra []namedBytes
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		extra = append(extra, namedBytes{e.Name(), b})
	}
	return load(extra)
}

type namedBytes struct {
	name string
	data []byte
}

func load(extra []namedBytes) (*Catalog, error) {
	var all []namedBytes
	entries, err := builtin.ReadDir("profiles")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := builtin.ReadFile("profiles/" + e.Name())
		if err != nil {
			return nil, err
		}
		all = append(all, namedBytes{e.Name(), b})
	}
	all = append(all, extra...)

	c := &Catalog{byID: map[string]*Profile{}, byCode: map[string]*Profile{}}
	for _, f := range all {
		var p Profile
		dec := json.NewDecoder(strings.NewReader(string(f.data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&p); err != nil {
			return nil, fmt.Errorf("engine profile %s: %w", f.name, err)
		}
		if err := p.Validate(); err != nil {
			return nil, fmt.Errorf("engine profile %s: %w", f.name, err)
		}
		if p.Thresholds == nil {
			p.Thresholds = map[string]float64{}
		}
		c.byID[p.ID] = &p
	}
	ids := make([]string, 0, len(c.byID))
	for id := range c.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		p := c.byID[id]
		for _, code := range p.Codes {
			key := normalize(code)
			if other, ok := c.byCode[key]; ok && other.ID != p.ID {
				return nil, fmt.Errorf("engine code %s is claimed by both %s and %s", code, other.ID, p.ID)
			}
			c.byCode[key] = p
		}
	}
	return c, nil
}

func normalize(code string) string { return strings.ToUpper(strings.TrimSpace(code)) }

// For returns the profile for a vehicle's engine code, or nil when none matches. The
// engine code is a free-text label (it may be "N20", "n20 " or "B58"), so matching is on
// the trimmed, upper-cased code only: a code that merely contains a known one is not a
// match.
func (c *Catalog) For(engineCode string) *Profile {
	if c == nil || strings.TrimSpace(engineCode) == "" {
		return nil
	}
	p := c.byCode[normalize(engineCode)]
	if p == nil {
		return nil
	}
	return p.clone()
}

// clone copies the slices and the map too, so a caller holding a returned profile cannot
// edit the catalog's.
func (p *Profile) clone() *Profile {
	cp := *p
	cp.Codes = append([]string(nil), p.Codes...)
	cp.Sources = append([]string(nil), p.Sources...)
	cp.Signals = append([]Signal(nil), p.Signals...)
	cp.Thresholds = make(map[string]float64, len(p.Thresholds))
	for k, v := range p.Thresholds {
		cp.Thresholds[k] = v
	}
	return &cp
}

// IDs lists the profile ids, sorted.
func (c *Catalog) IDs() []string {
	ids := make([]string, 0, len(c.byID))
	for id := range c.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Generic is what every engine shares and nothing more: the ECU's own fuel-trim range
// and a band any engine's trims should stay inside. It is used to summarise a vehicle
// whose engine has no profile, and is never presented as that engine's profile.
func Generic() *Profile {
	f := func(v float64) *float64 { return &v }
	return &Profile{
		ID: "generic", Name: "Generic engine", Status: "derived",
		Signals: []Signal{
			{Key: "ltft_pct", Label: "Long-term fuel trim", Unit: "%", Min: -25, Max: 25,
				WarnLow: f(-10), WarnHigh: f(10), CheckLow: f(-20), CheckHigh: f(20)},
			{Key: "stft_pct", Label: "Short-term fuel trim", Unit: "%", Min: -25, Max: 25},
		},
		Thresholds: map[string]float64{"ltft_drift_watch_pct": 3, "ltft_drift_check_pct": 6},
	}
}

// View is the profile as the API shows it: what a reader needs to label, range and judge a
// reading. The provenance (codes, sources) stays in the file it was loaded from.
type View struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Status     string             `json:"status"`
	Signals    []Signal           `json:"signals"`
	Thresholds map[string]float64 `json:"thresholds"`
}

// View returns the API shape of the profile, or nil for no profile.
func (p *Profile) View() *View {
	if p == nil {
		return nil
	}
	c := p.clone()
	return &View{ID: c.ID, Name: c.Name, Status: c.Status, Signals: c.Signals, Thresholds: c.Thresholds}
}
