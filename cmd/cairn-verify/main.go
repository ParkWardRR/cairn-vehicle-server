// Command cairn-verify checks bundles straight off an SD card, with no server.
//
// This answers the question that is otherwise ambiguous after a drive: did the
// firmware write correct data? A failed sync could mean a bad bundle, a refused
// enrolment, a wrong receipt key or no network, and those look similar from the
// device's logs. Verifying the card separates "the device recorded this
// correctly" from "the upload worked", which are different problems with
// different fixes.
//
// It deliberately reuses server/format — the reference implementation the
// specification is written against — rather than reimplementing the checks. A
// verifier with its own idea of the format would be a third opinion to
// reconcile, not an oracle.
//
//	cairn-verify /Volumes/CARD/cairn                 whole card
//	cairn-verify /Volumes/CARD/cairn/bundles/01J...  one bundle
//	cairn-verify -device-key <hex> ...               also verify signatures
//	cairn-verify -json ...                           machine-readable
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ParkWardRR/Cairn/server/format"
)

func main() {
	var (
		deviceKeyHex = flag.String("device-key", "",
			"hex Ed25519 device public key, to verify manifest signatures "+
				"(the manifest carries only a truncated key id, so the key "+
				"must be supplied)")
		serverKeyHex = flag.String("server-key", "",
			"hex Ed25519 server receipt key, to verify any receipts found")
		asJSON  = flag.Bool("json", false, "emit JSON instead of a report")
		verbose = flag.Bool("v", false, "list every segment and record tally")
	)
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] <card-dir|bundle-dir>\n",
			filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(2)
	}

	opts := options{verbose: *verbose}

	if *deviceKeyHex != "" {
		k, err := parseKey(*deviceKeyHex)
		if err != nil {
			fatal("device-key: %v", err)
		}
		opts.deviceKey = k
	}
	if *serverKeyHex != "" {
		k, err := parseKey(*serverKeyHex)
		if err != nil {
			fatal("server-key: %v", err)
		}
		opts.serverKey = k
	}

	target := flag.Arg(0)
	bundles, receiptDir, err := discover(target)
	if err != nil {
		fatal("%v", err)
	}
	if len(bundles) == 0 {
		fatal("no bundles found under %s\n"+
			"       expected either a bundle directory containing manifest.cbor,\n"+
			"       or a card root containing bundles/ and/or capture/", target)
	}
	opts.receiptDir = receiptDir

	results := make([]bundleResult, 0, len(bundles))
	for _, b := range bundles {
		results = append(results, verifyBundle(b, opts))
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fatal("encode: %v", err)
		}
	} else {
		report(results, opts)
	}

	for _, r := range results {
		if len(r.Problems) > 0 {
			os.Exit(1)
		}
	}
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+f+"\n", a...)
	os.Exit(2)
}

func parseKey(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d bytes of hex, got %d",
			ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

type options struct {
	deviceKey  ed25519.PublicKey
	serverKey  ed25519.PublicKey
	receiptDir string
	verbose    bool
}

// discoveredBundle is a directory to check, and whether it was sealed.
type discoveredBundle struct {
	dir    string
	sealed bool
}

// discover accepts either a single bundle directory or a card root. Being
// lenient here matters: an operator pulls a card and runs this on whatever path
// is convenient, and guessing wrong should not look like "no data".
func discover(target string) ([]discoveredBundle, string, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, "", err
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("%s is not a directory", target)
	}

	// A bundle directory, named directly.
	if _, err := os.Stat(filepath.Join(target, "manifest.cbor")); err == nil {
		return []discoveredBundle{{dir: target, sealed: true}}, "", nil
	}

	var out []discoveredBundle

	// A card root, or the bundles/ directory itself.
	for _, sub := range []string{"bundles", "capture", "."} {
		base := filepath.Join(target, sub)
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(base, e.Name())
			if _, err := os.Stat(filepath.Join(dir, "manifest.cbor")); err != nil {
				// An unsealed capture has no manifest. Still worth scanning:
				// its segments are where an interrupted drive's data lives.
				if hasSegments(dir) {
					out = append(out, discoveredBundle{dir: dir, sealed: false})
				}
				continue
			}
			out = append(out, discoveredBundle{dir: dir, sealed: true})
		}
		if len(out) > 0 && sub != "." {
			continue
		}
	}

	receiptDir := filepath.Join(target, "receipts")
	if _, err := os.Stat(receiptDir); err != nil {
		receiptDir = ""
	}

	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	return out, receiptDir, nil
}

func hasSegments(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".seg") {
			return true
		}
	}
	return false
}

// ── results ─────────────────────────────────────────────────────────────────

type segmentResult struct {
	Name               string         `json:"name"`
	Stop               string         `json:"stop"`
	StopDetail         string         `json:"stop_detail,omitempty"`
	Frames             int            `json:"frames"`
	FirstSeq           uint32         `json:"first_seq"`
	LastSeq            uint32         `json:"last_seq"`
	DiscardedTailBytes uint32         `json:"discarded_tail_bytes"`
	UnknownTypes       int            `json:"unknown_type_count"`
	RecordCounts       map[string]int `json:"record_counts,omitempty"`
}

type bundleResult struct {
	Dir    string `json:"dir"`
	Sealed bool   `json:"sealed"`

	BundleID    string `json:"bundle_id,omitempty"`
	DeviceID    string `json:"device_id,omitempty"`
	DeviceKeyID string `json:"device_key_id,omitempty"`
	Firmware    string `json:"firmware_version,omitempty"`
	ContentRoot string `json:"content_root,omitempty"`

	RecoveryState      string `json:"recovery_state,omitempty"`
	DiscardedTailBytes uint32 `json:"manifest_discarded_tail_bytes,omitempty"`

	CaptureSegments []segmentResult `json:"capture_segments,omitempty"`
	JournalSegment  *segmentResult  `json:"journal_segment,omitempty"`

	Checks   []string `json:"checks"`
	Problems []string `json:"problems,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

func (r *bundleResult) pass(f string, a ...any) {
	r.Checks = append(r.Checks, fmt.Sprintf(f, a...))
}

func (r *bundleResult) fail(f string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(f, a...))
}

func (r *bundleResult) note(f string, a ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(f, a...))
}

// ── verification ────────────────────────────────────────────────────────────

func verifyBundle(b discoveredBundle, opts options) bundleResult {
	res := bundleResult{Dir: b.dir, Sealed: b.sealed}

	segs, journal := segmentNames(b.dir)
	if len(segs) == 0 && journal == "" {
		res.fail("no .seg files — there is no captured data here")
		return res
	}

	// Scan first, so an unsealed capture still gets a verdict. The scan is the
	// only check that works without a manifest, and it is the one that says
	// whether the data is readable at all.
	scanState := format.ScanState{}
	scannedCounts := map[format.RecordType]int{}
	var scannedFrames int
	var firstSeq, lastSeq uint32
	var haveSeq bool
	var totalDiscarded uint32

	for _, name := range segs {
		sr, err := scanFile(filepath.Join(b.dir, name), scanState)
		if err != nil {
			// A header error means the segment is unusable. It is still not
			// worthless: the server's salvage path may recover records, so this
			// is reported rather than treated as empty.
			res.fail("%s is unreadable: %v", name, err)
			continue
		}

		res.CaptureSegments = append(res.CaptureSegments, summarize(name, sr))

		for rt, n := range sr.RecordCounts {
			scannedCounts[rt] += n
		}
		scannedFrames += len(sr.Frames)
		totalDiscarded += sr.DiscardedTailBytes

		if len(sr.Frames) > 0 {
			if !haveSeq {
				firstSeq = sr.Frames[0].Seq
				haveSeq = true
			}
			lastSeq = sr.Frames[len(sr.Frames)-1].Seq
		}
		scanState = sr.Next
	}

	if journal != "" {
		// The journal has its own chain, so it starts from the zero state. A
		// shared state here would report a spurious chain break.
		sr, err := scanFile(filepath.Join(b.dir, journal), format.ScanState{})
		if err != nil {
			res.fail("%s is unreadable: %v", journal, err)
		} else {
			s := summarize(journal, sr)
			res.JournalSegment = &s
		}
	}

	if totalDiscarded > 0 {
		res.note("%d bytes were discarded as incomplete tails across %d segment(s)",
			totalDiscarded, len(segs))
	}

	if !b.sealed {
		res.note("unsealed capture: no manifest, so content root and signature " +
			"cannot be checked. This is the open bundle the device is still " +
			"writing to, or one interrupted before sealing.")
		return res
	}

	// ── the manifest ────────────────────────────────────────────────────────

	encoded, err := os.ReadFile(filepath.Join(b.dir, "manifest.cbor"))
	if err != nil {
		res.fail("cannot read manifest.cbor: %v", err)
		return res
	}

	m, err := format.ParseManifest(encoded)
	if err != nil {
		res.fail("manifest does not parse: %v", err)
		return res
	}
	res.pass("manifest parses as canonical deterministic CBOR")

	res.BundleID = hex.EncodeToString(m.BundleID[:])
	res.DeviceID = hex.EncodeToString(m.DeviceID[:])
	res.DeviceKeyID = hex.EncodeToString(m.DeviceKeyID[:])
	res.Firmware = m.FirmwareVersion
	res.ContentRoot = hex.EncodeToString(m.ContentRoot[:])
	res.RecoveryState = m.RecoveryState.String()
	res.DiscardedTailBytes = m.DiscardedTailBytes

	// Re-encoding must reproduce the file byte-for-byte. If it does not, the
	// signature covers bytes nobody can reproduce, so it could never be
	// re-verified after a round trip.
	reencoded, err := m.MarshalCBOR()
	if err != nil {
		res.fail("manifest will not re-encode: %v", err)
	} else if string(reencoded) != string(encoded) {
		res.fail("manifest is not canonical: re-encoding gives %d bytes vs %d "+
			"on disk, so the signed bytes are not reproducible",
			len(reencoded), len(encoded))
	} else {
		res.pass("re-encoding reproduces manifest.cbor byte-for-byte")
	}

	// ── members on disk ─────────────────────────────────────────────────────

	memberOK := true
	for _, mem := range m.Members {
		path := filepath.Join(b.dir, mem.Name)
		data, err := os.ReadFile(path)
		if err != nil {
			res.fail("member %s named by the manifest is missing: %v", mem.Name, err)
			memberOK = false
			continue
		}
		if uint64(len(data)) != mem.Length {
			res.fail("member %s is %d bytes on disk but the manifest says %d",
				mem.Name, len(data), mem.Length)
			memberOK = false
			continue
		}
		sum := sha256.Sum256(data)
		if sum != mem.SHA256 {
			res.fail("member %s does not match its manifest digest "+
				"(on disk %s, manifest %s)", mem.Name,
				hex.EncodeToString(sum[:8]), hex.EncodeToString(mem.SHA256[:8]))
			memberOK = false
		}
	}
	if memberOK {
		res.pass("all %d member(s) present, correct length and matching digest",
			len(m.Members))
	}

	if err := m.VerifyContentRoot(); err != nil {
		res.fail("content root does not match the members it names: %v", err)
	} else {
		res.pass("content root recomputes from the members")
	}

	// ── chunk descriptors ───────────────────────────────────────────────────
	//
	// Chunks and members partition the same bytes, so the two must agree. A
	// mismatch means the manifest is internally inconsistent whatever its
	// signature says, and the server checks this before committing.

	var chunkBytes, memberBytes uint64
	for i, c := range m.ChunkDescriptors {
		chunkBytes += uint64(c.ByteLength)
		if c.Index != uint32(i) {
			res.fail("chunk %d declares index %d; indices are positional", i, c.Index)
		}
	}
	for _, mem := range m.Members {
		memberBytes += mem.Length
	}
	if chunkBytes != memberBytes {
		res.fail("chunks cover %d bytes but members total %d — the manifest "+
			"describes two different streams", chunkBytes, memberBytes)
	} else if len(m.ChunkDescriptors) > 0 {
		res.pass("%d chunk(s) cover exactly the %d bytes the members total",
			len(m.ChunkDescriptors), memberBytes)
	}

	// ── manifest against the data ───────────────────────────────────────────
	//
	// The most valuable cross-check here, because nothing else catches it: the
	// manifest is a claim about the segments, and a firmware bug could make it
	// a false one while every signature still verified.

	if haveSeq {
		if m.FirstSeq != firstSeq || m.LastSeq != lastSeq {
			res.fail("manifest claims seq %d..%d but the segments hold %d..%d",
				m.FirstSeq, m.LastSeq, firstSeq, lastSeq)
		} else {
			res.pass("manifest's seq range %d..%d matches the segments",
				m.FirstSeq, m.LastSeq)
		}
	}

	countsOK := true
	for rt, want := range m.RecordCounts {
		if got := scannedCounts[rt]; uint32(got) != want {
			res.fail("manifest counts %d %s record(s) but the segments hold %d",
				want, rt, got)
			countsOK = false
		}
	}
	for rt, got := range scannedCounts {
		if _, named := m.RecordCounts[rt]; !named && got > 0 {
			res.fail("segments hold %d %s record(s) the manifest does not count",
				got, rt)
			countsOK = false
		}
	}
	if countsOK && len(m.RecordCounts) > 0 {
		res.pass("record counts match the segments exactly")
	}

	if m.DiscardedTailBytes != totalDiscarded {
		// Not a failure on its own: a tail discarded during an earlier boot is
		// truncated away, so the scan cannot see it any more. Worth surfacing
		// because the two numbers mean different things.
		res.note("manifest reports %d discarded tail bytes; this scan found %d "+
			"still visible (earlier boots truncate what they discard)",
			m.DiscardedTailBytes, totalDiscarded)
	}

	// ── signature ───────────────────────────────────────────────────────────

	sig, sigErr := os.ReadFile(filepath.Join(b.dir, "manifest.sig"))
	switch {
	case sigErr != nil:
		res.fail("cannot read manifest.sig: %v", sigErr)
	case len(sig) != ed25519.SignatureSize:
		res.fail("manifest.sig is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	case opts.deviceKey == nil:
		res.note("manifest signature not checked: pass -device-key with the " +
			"device's public key. The manifest carries only a truncated key id, " +
			"so the key cannot be recovered from the bundle.")
	default:
		if want := format.DeviceKeyID(opts.deviceKey); want != m.DeviceKeyID {
			res.fail("the supplied key has id %s but the manifest names %s — "+
				"this is a different device's key",
				hex.EncodeToString(want[:]), hex.EncodeToString(m.DeviceKeyID[:]))
		} else if _, err := format.VerifyManifest(encoded, sig, opts.deviceKey); err != nil {
			res.fail("manifest signature does not verify: %v", err)
		} else {
			res.pass("manifest signature verifies against the supplied device key")
		}
	}

	// ── receipt, if one is on the card ──────────────────────────────────────

	if opts.receiptDir != "" {
		checkReceipt(&res, m, opts)
	}

	return res
}

// checkReceipt verifies any receipt stored alongside the bundle. A receipt here
// is what authorized, or would authorize, deleting this data — so it is worth
// knowing whether it actually covers this bundle.
func checkReceipt(res *bundleResult, m *format.Manifest, opts options) {
	// The device names receipts by the bundle's ULID directory name.
	name := filepath.Base(res.Dir) + ".cbor"
	path := filepath.Join(opts.receiptDir, name)

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		res.note("no receipt on the card for this bundle: it has not been " +
			"acknowledged by a server yet, so nothing may prune it")
		return
	}
	if err != nil {
		res.fail("cannot read receipt %s: %v", name, err)
		return
	}

	r, err := format.ParseReceipt(raw)
	if err != nil {
		res.fail("receipt %s does not parse: %v", name, err)
		return
	}

	if opts.serverKey == nil {
		res.note("a receipt is present but not checked: pass -server-key to " +
			"verify it (cairn-server -print-receipt-key)")
		return
	}

	if err := r.VerifyAcknowledges(opts.serverKey, m.ContentRoot); err != nil {
		res.fail("receipt does not acknowledge this bundle under the supplied "+
			"server key: %v", err)
		return
	}
	res.pass("receipt verifies and acknowledges this content root")
}

// ── segment helpers ─────────────────────────────────────────────────────────

func segmentNames(dir string) (capture []string, journal string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, ""
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".seg") {
			continue
		}
		if n == "journal.seg" {
			journal = n
			continue
		}
		capture = append(capture, n)
	}
	// Index order, which is also chain order. Scanning out of order would make
	// the continuity check meaningless.
	sort.Strings(capture)
	return capture, journal
}

func scanFile(path string, state format.ScanState) (*format.ScanResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return format.ScanSegment(b, state)
}

func summarize(name string, sr *format.ScanResult) segmentResult {
	out := segmentResult{
		Name:               name,
		Stop:               sr.Stop.String(),
		StopDetail:         sr.StopDetail,
		Frames:             len(sr.Frames),
		DiscardedTailBytes: sr.DiscardedTailBytes,
		UnknownTypes:       sr.UnknownTypeCount,
		RecordCounts:       map[string]int{},
	}
	if len(sr.Frames) > 0 {
		out.FirstSeq = sr.Frames[0].Seq
		out.LastSeq = sr.Frames[len(sr.Frames)-1].Seq
	}
	for rt, n := range sr.RecordCounts {
		out.RecordCounts[rt.String()] = n
	}
	return out
}

// ── reporting ───────────────────────────────────────────────────────────────

func report(results []bundleResult, opts options) {
	var bad int

	for i, r := range results {
		if i > 0 {
			fmt.Println()
		}

		status := "OK"
		if len(r.Problems) > 0 {
			status = "FAILED"
			bad++
		}
		if !r.Sealed {
			status += " (unsealed)"
		}

		fmt.Printf("%s  %s\n", status, r.Dir)

		if r.BundleID != "" {
			fmt.Printf("  bundle       %s\n", r.BundleID)
			fmt.Printf("  device       %s  firmware %s\n", r.DeviceID, r.Firmware)
			fmt.Printf("  content root %s\n", r.ContentRoot)
			fmt.Printf("  recovery     %s", r.RecoveryState)
			if r.DiscardedTailBytes > 0 {
				fmt.Printf(", %d byte(s) discarded", r.DiscardedTailBytes)
			}
			fmt.Println()
		}

		for _, s := range r.CaptureSegments {
			fmt.Printf("  %-20s %-13s %5d frame(s)  seq %d..%d",
				s.Name, s.Stop, s.Frames, s.FirstSeq, s.LastSeq)
			if s.DiscardedTailBytes > 0 {
				fmt.Printf("  %d byte tail discarded", s.DiscardedTailBytes)
			}
			fmt.Println()
			if opts.verbose {
				printCounts(s.RecordCounts)
			}
		}
		if r.JournalSegment != nil {
			s := r.JournalSegment
			fmt.Printf("  %-20s %-13s %5d frame(s)  seq %d..%d  (own chain)\n",
				s.Name, s.Stop, s.Frames, s.FirstSeq, s.LastSeq)
			if opts.verbose {
				printCounts(s.RecordCounts)
			}
		}

		for _, c := range r.Checks {
			fmt.Printf("  pass  %s\n", c)
		}
		for _, n := range r.Notes {
			fmt.Printf("  note  %s\n", n)
		}
		for _, p := range r.Problems {
			fmt.Printf("  FAIL  %s\n", p)
		}
	}

	fmt.Printf("\n%d bundle(s) checked, %d with problems\n", len(results), bad)
}

func printCounts(counts map[string]int) {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("      %-18s %d\n", k, counts[k])
	}
}
