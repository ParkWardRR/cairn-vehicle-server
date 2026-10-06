// Command cairn-ledger reads the bundle lifecycle ledger.
//
// Answers "what happened to this bundle, and why" without reconstructing it
// from logs. The entries that matter most are the refusals: those are the cases
// where the device is still holding data it could not deliver, and the reason
// is the difference between an unenrolled device, a quota, a bad signature and
// a self-contradictory manifest — which look identical from the device's side.
//
//	cairn-ledger /var/lib/cairn/ledger
//	cairn-ledger -bundle <hex> /var/lib/cairn/ledger
//	cairn-ledger -problems /var/lib/cairn/ledger
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/ledger"
)

func main() {
	var (
		bundle   = flag.String("bundle", "", "only entries for this bundle id or content root")
		device   = flag.String("device", "", "only entries for this device id")
		problems = flag.Bool("problems", false, "only refusals and failures")
		asJSON   = flag.Bool("json", false, "emit JSON")
		summary  = flag.Bool("summary", false, "tally events instead of listing them")
	)
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <ledger-dir>\n",
			filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}

	book, err := ledger.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer book.Close()

	entries, readErr := book.Read()
	// A read error still returns the entries it managed to parse. Reporting
	// both is the honest outcome: the ledger is damaged *and* here is what
	// survived, rather than discarding good entries because of a bad one.
	if readErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", readErr)
	}

	entries = filter(entries, *bundle, *device, *problems)

	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case *summary:
		printSummary(entries)
	default:
		printEntries(entries)
	}

	if readErr != nil {
		os.Exit(1)
	}
}

func isProblem(e ledger.Entry) bool {
	switch e.Event {
	case ledger.EventOfferRejected, ledger.EventChunkRejected,
		ledger.EventCommitFailed, ledger.EventDecodeFailed,
		ledger.EventQuotaRefused, ledger.EventDeviceUnknown:
		return true
	}
	return false
}

func filter(in []ledger.Entry, bundle, device string, problemsOnly bool) []ledger.Entry {
	bundle = strings.ToLower(bundle)
	device = strings.ToLower(device)

	var out []ledger.Entry
	for _, e := range in {
		if problemsOnly && !isProblem(e) {
			continue
		}
		// Matching either identifier, because an operator has whichever one the
		// device or the card happened to show them.
		if bundle != "" && !strings.EqualFold(e.BundleID, bundle) &&
			!strings.EqualFold(e.ContentRoot, bundle) {
			continue
		}
		if device != "" && !strings.EqualFold(e.DeviceID, device) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func printEntries(entries []ledger.Entry) {
	if len(entries) == 0 {
		fmt.Println("no matching entries")
		return
	}

	for _, e := range entries {
		when := time.UnixMilli(e.UTCMS).UTC().Format("2006-01-02 15:04:05")

		fmt.Printf("%s  %-16s", when, e.Event)
		if e.BundleID != "" {
			fmt.Printf("  bundle %s", short(e.BundleID))
		}
		if e.DeviceID != "" {
			fmt.Printf("  device %s", short(e.DeviceID))
		}
		if e.Bytes > 0 {
			fmt.Printf("  %d bytes", e.Bytes)
		}
		fmt.Println()

		if e.Reason != "" {
			fmt.Printf("    %s\n", e.Reason)
		}
	}

	fmt.Printf("\n%d entrie(s)\n", len(entries))
}

func printSummary(entries []ledger.Entry) {
	counts := map[ledger.Event]int{}
	for _, e := range entries {
		counts[e.Event]++
	}

	names := make([]string, 0, len(counts))
	for k := range counts {
		names = append(names, string(k))
	}
	sort.Strings(names)

	for _, n := range names {
		fmt.Printf("%-18s %d\n", n, counts[ledger.Event(n)])
	}

	// Call out refusals separately: a tally where they are mixed in with
	// successes is easy to read past.
	problems := 0
	for _, e := range entries {
		if isProblem(e) {
			problems++
		}
	}
	fmt.Printf("\n%d entrie(s), %d refusal(s) or failure(s)\n", len(entries), problems)
}

func short(hexID string) string {
	if len(hexID) <= 12 {
		return hexID
	}
	return hexID[:12] + ".."
}
