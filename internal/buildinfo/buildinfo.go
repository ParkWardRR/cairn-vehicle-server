// Package buildinfo answers "which build is this?" for the health endpoints.
//
// Version, Commit and Channel are set at link time by the Makefile
// (-X .../internal/buildinfo.Version=...). A binary built without them, say with a
// plain `go build`, falls back to what the Go toolchain stamped into it, so the answer
// is still a commit and never an empty string.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Set by -ldflags. Empty means "ask the toolchain".
var (
	Version string
	Commit  string
	Channel string
)

// The release channels, defined for the whole project in the front door's
// docs/release-process.md: dev is a working tree with no promise, beta is a tagged
// pre-release carrying every feature including the unproven ones, and stable is a tagged
// release carrying only what has been proven.
const (
	ChannelDev    = "dev"
	ChannelBeta   = "beta"
	ChannelStable = "stable"
)

// Info is the build identity reported by /healthz.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	// Channel is dev, beta or stable.
	Channel string `json:"channel"`
	// Modified is true when the tree the binary was built from had uncommitted changes,
	// so a commit hash alone cannot reproduce it.
	Modified bool `json:"modified,omitempty"`
}

// Get returns this binary's identity.
func Get() Info {
	in := Info{Version: Version, Commit: Commit, Channel: channel(Channel)}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if in.Commit == "" {
					in.Commit = s.Value
				}
			case "vcs.modified":
				in.Modified = s.Value == "true"
			}
		}
	}
	if in.Version == "" {
		in.Version = "dev"
	}
	if in.Commit == "" {
		in.Commit = "unknown"
	}
	// A build from a modified tree is a dev build whatever it was told to call itself: the
	// channel is a claim about what the source was, and that source is not recoverable.
	if in.Modified {
		in.Channel = ChannelDev
	}
	return in
}

// channel normalises what -ldflags passed. An absent or unrecognised value is dev and
// never stable: a build that cannot say what it is has not earned the word that carries a
// promise.
func channel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case ChannelStable:
		return ChannelStable
	case ChannelBeta:
		return ChannelBeta
	default:
		return ChannelDev
	}
}
