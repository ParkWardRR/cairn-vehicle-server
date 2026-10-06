package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinProfilesLoadAndMatchByCode(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	n20 := c.For("N20")
	if n20 == nil || n20.ID != "bmw-n20" || n20.Status != "derived" {
		t.Fatalf("N20 profile = %+v", n20)
	}
	if p := c.For(" n26 "); p == nil || p.ID != "bmw-n20" {
		t.Fatal("codes match after trimming and case folding")
	}
	b58 := c.For("B58")
	if b58 == nil || b58.ID != "bmw-b58" || b58.Status != "stub" {
		t.Fatalf("B58 profile = %+v", b58)
	}
	if c.For("") != nil || c.For("S55") != nil || c.For("N2") != nil {
		t.Fatal("an unknown or partial code matches nothing")
	}
}

// The web dashboard carried these N20 numbers as literals; the profile has to say the same
// thing or moving to it silently changes what the owner is warned about.
func TestN20CarriesTheLimitsTheDashboardHardCoded(t *testing.T) {
	c, _ := Builtin()
	p := c.For("N20")
	boost, _ := p.Signal("boost_psi")
	if boost.WarnHigh == nil || *boost.WarnHigh != 20 || p.Threshold("pull_boost_note_psi", 0) != 18 {
		t.Fatalf("boost limits: %+v", boost)
	}
	lt, _ := p.Signal("ltft_pct")
	if *lt.WarnHigh != 10 || *lt.CheckHigh != 20 || *lt.WarnLow != -10 || *lt.CheckLow != -20 {
		t.Fatalf("ltft limits: %+v", lt)
	}
	lam, _ := p.Signal("lambda")
	if *lam.WarnHigh != 1.1 || p.Threshold("pull_lambda_rich", 0) != 0.9 {
		t.Fatalf("lambda limits: %+v", lam)
	}
}

// The B58 profile must not borrow the N20's numbers: the firmware's own B58 profile is a
// stub that claims nothing, and so is this one.
func TestB58ClaimsNoLimit(t *testing.T) {
	c, _ := Builtin()
	p := c.For("B58")
	if len(p.Signals) == 0 {
		t.Fatal("a stub still names its signals, so the UI can label them")
	}
	for _, s := range p.Signals {
		if s.WarnLow != nil || s.WarnHigh != nil || s.CheckLow != nil || s.CheckHigh != nil {
			t.Fatalf("%s states a limit on a stub", s.Key)
		}
	}
	if len(p.Thresholds) != 0 {
		t.Fatalf("thresholds on a stub: %v", p.Thresholds)
	}
}

func TestValidateRefusesWhatCannotBeTrue(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	good := func() Profile {
		return Profile{ID: "x", Name: "X", Status: "derived",
			Signals: []Signal{{Key: "boost_psi", Min: 0, Max: 30, WarnHigh: f(20)}}}
	}
	for name, mutate := range map[string]func(*Profile){
		"empty id":         func(p *Profile) { p.ID = "" },
		"uppercase id":     func(p *Profile) { p.ID = "BMW" },
		"path in id":       func(p *Profile) { p.ID = "a/b" },
		"no name":          func(p *Profile) { p.Name = " " },
		"unknown status":   func(p *Profile) { p.Status = "guess" },
		"repeated signal":  func(p *Profile) { p.Signals = append(p.Signals, p.Signals[0]) },
		"empty range":      func(p *Profile) { p.Signals[0].Max = 0 },
		"inverted warn":    func(p *Profile) { p.Signals[0].WarnLow = f(25) },
		"check under warn": func(p *Profile) { p.Signals[0].CheckHigh = f(10) },
		"stub with limit":  func(p *Profile) { p.Status = "stub" },
		"foreign schema":   func(p *Profile) { p.Schema = "cairn.engine/v1-draft" },
	} {
		p := good()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := good()
	if err := p.Validate(); err != nil {
		t.Fatalf("the baseline is valid: %v", err)
	}
}

func TestLoadDirOverridesAndRefusesUnknownFields(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("mine.json", `{"id":"bmw-n20","name":"My N20","status":"verified","codes":["N20"],
		"signals":[{"key":"boost_psi","label":"Boost","unit":"psi","min":0,"max":30,"warn_low":null,"warn_high":24}],
		"thresholds":{}}`)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p := c.For("N20"); p.Name != "My N20" || p.Status != "verified" {
		t.Fatalf("the operator's profile should win: %+v", p)
	}

	write("typo.json", `{"id":"s55","name":"S55","status":"derived","signalz":[]}`)
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "typo.json") {
		t.Fatalf("an unknown field is refused and names the file: %v", err)
	}
}

func TestTwoProfilesCannotClaimOneCode(t *testing.T) {
	dir := t.TempDir()
	body := `{"id":"other","name":"Other","status":"derived","codes":["B58"],"signals":[],"thresholds":{}}`
	if err := os.WriteFile(filepath.Join(dir, "o.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil || !strings.Contains(err.Error(), "B58") {
		t.Fatalf("expected a clash on B58: %v", err)
	}
}

func TestForReturnsACopy(t *testing.T) {
	c, _ := Builtin()
	c.For("N20").Thresholds["pull_boost_note_psi"] = 99
	if c.For("N20").Threshold("pull_boost_note_psi", 0) != 18 {
		t.Fatal("a caller must not be able to edit the catalog through a returned profile")
	}
}
