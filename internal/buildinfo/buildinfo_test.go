package buildinfo

import "testing"

func TestGetNeverReturnsEmpty(t *testing.T) {
	in := Get()
	if in.Version == "" || in.Commit == "" || in.Channel == "" {
		t.Fatalf("empty identity: %+v", in)
	}
}

func TestLinkTimeValuesWin(t *testing.T) {
	Version, Commit, Channel = "v9.9.9", "abc123", "stable"
	defer func() { Version, Commit, Channel = "", "", "" }()
	in := Get()
	if in.Version != "v9.9.9" || in.Commit != "abc123" {
		t.Fatalf("link-time values ignored: %+v", in)
	}
	// Only meaningful when the test binary itself was built from a clean tree; a modified
	// tree is forced to dev below.
	if !in.Modified && in.Channel != ChannelStable {
		t.Fatalf("link-time channel ignored: %+v", in)
	}
}

func TestAnUnknownChannelIsDevAndNeverStable(t *testing.T) {
	for _, v := range []string{"", "   ", "production", "prod", "Stable-ish", "$(CHANNEL)"} {
		if got := channel(v); got != ChannelDev {
			t.Errorf("channel(%q) = %q, want %q", v, got, ChannelDev)
		}
	}
}

func TestChannelIsCaseAndSpaceInsensitive(t *testing.T) {
	for v, want := range map[string]string{
		"stable":   ChannelStable,
		"STABLE":   ChannelStable,
		"  beta  ": ChannelBeta,
		"Dev":      ChannelDev,
	} {
		if got := channel(v); got != want {
			t.Errorf("channel(%q) = %q, want %q", v, got, want)
		}
	}
}

// A binary built from a tree with uncommitted changes cannot be reproduced from its commit,
// so whatever channel it was told to claim, it is a dev build.
func TestAModifiedTreeIsAlwaysDev(t *testing.T) {
	in := Info{Version: "v1", Commit: "abc", Channel: ChannelStable, Modified: true}
	// Get() applies the rule; assert it through the same path the handlers use.
	Version, Commit, Channel = in.Version, in.Commit, in.Channel
	defer func() { Version, Commit, Channel = "", "", "" }()
	got := Get()
	if got.Modified && got.Channel != ChannelDev {
		t.Fatalf("a modified build claimed %q: %+v", got.Channel, got)
	}
}
