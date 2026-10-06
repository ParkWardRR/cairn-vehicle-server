// Package buildinfo answers "which build is this?" for the health endpoints.
//
// Version and Commit are set at link time by the Makefile
// (-X .../internal/buildinfo.Version=...). A binary built without them, say with a
// plain `go build`, falls back to what the Go toolchain stamped into it, so the answer
// is still a commit and never an empty string.
package buildinfo

import "runtime/debug"

// Set by -ldflags. Empty means "ask the toolchain".
var (
	Version string
	Commit  string
)

// Info is the build identity reported by /healthz.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	// Modified is true when the tree the binary was built from had uncommitted changes,
	// so a commit hash alone cannot reproduce it.
	Modified bool `json:"modified,omitempty"`
}

// Get returns this binary's identity.
func Get() Info {
	in := Info{Version: Version, Commit: Commit}
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
	return in
}
