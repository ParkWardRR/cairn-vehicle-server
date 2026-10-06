// Package contracts finds the Cairn Vehicle Data Protocols directory: the specs and
// vectors that the firmware, server, web layer and phone app agree on.
//
// The directory is NOT part of this repository once the project is split; it is fetched
// at a pinned version (see docs/contracts.md). Everything that reads a vector goes
// through here, so there is one definition of where they are.
//
// Resolution order:
//
//  1. $CAIRN_CONTRACTS, the contracts directory itself (the one containing format/,
//     sync/, store/), never a checkout root. This is the override for changing a
//     contract and its implementation together.
//  2. the nearest ancestor of the working directory that has contracts/format
//     (the front door, or the monorepo before the split);
//  3. the nearest ancestor that has .contracts/contracts/format (a fetched copy).
package contracts

import (
	"os"
	"path/filepath"
)

// EnvVar names the override.
const EnvVar = "CAIRN_CONTRACTS"

// Dir returns the contracts directory. If none is found it returns the path where a
// fetched copy would be, so the error a caller then gets ("no such file") names a path
// a human can act on.
func Dir() string {
	if d := os.Getenv(EnvVar); d != "" {
		return d
	}
	wd, err := os.Getwd()
	if err != nil {
		return filepath.Join(".contracts", "contracts")
	}
	for dir := wd; ; dir = filepath.Dir(dir) {
		for _, rel := range []string{"contracts", filepath.Join(".contracts", "contracts")} {
			if st, err := os.Stat(filepath.Join(dir, rel, "format")); err == nil && st.IsDir() {
				return filepath.Join(dir, rel)
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return filepath.Join(wd, ".contracts", "contracts")
}

// Path joins elements onto the contracts directory.
func Path(elem ...string) string {
	return filepath.Join(append([]string{Dir()}, elem...)...)
}

// Vectors returns the directory holding a protocol's vectors, e.g. Vectors("format","v3").
func Vectors(protocol, version string) string {
	return Path(protocol, version, "vectors")
}
