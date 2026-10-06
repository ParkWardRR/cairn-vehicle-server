package offloadclient_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/contracts"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

// Golden vectors for the BLE offload protocol: what a phone writes and exactly
// what the dongle answers, byte for byte, produced by the firmware's own protocol
// module (offload-sim) over a deterministic sealed bundle.
//
// They exist for the iOS app (and anything else that speaks to the dongle): replay
// the writes, compare the dongle's bytes. They are generated from the firmware,
// not hand-written, so they cannot drift from it; this test fails if they do.
//
//	go test ./internal/offloadclient -run Vectors -update-vectors
var updateVectors = flag.Bool("update-vectors", false, "rewrite contracts/ble/v1/vectors/offload/vectors.json")

type event struct {
	T   string `json:"t"` // control_write, data_write, mtu, indication, notification
	Hex string `json:"hex"`
	Why string `json:"why,omitempty"`
}

type scenario struct {
	Name   string  `json:"name"`
	Doc    string  `json:"doc"`
	Trip   bool    `json:"trip_active,omitempty"`
	NoKey  bool    `json:"no_pinned_key,omitempty"`
	Events []event `json:"events"`
}

type vectorFile struct {
	Version   int        `json:"version"`
	Spec      string     `json:"spec"`
	MTU       int        `json:"att_mtu"`
	Notes     []string   `json:"notes"`
	Bundle    vecBundle  `json:"bundle"`
	Scenarios []scenario `json:"scenarios"`
}

type vecBundle struct {
	ID               string `json:"bundle_id"`
	StreamBytes      uint64 `json:"stream_bytes"`
	ManifestLen      int    `json:"manifest_len"`
	ChunkCount       int    `json:"chunk_count"`
	Member0Length    uint64 `json:"first_member_length"`
	StreamSHA256     string `json:"stream_sha256"`
	StreamPrefixHex  string `json:"stream_first_64_bytes_hex"`
	ReceiptPublicKey string `json:"receipt_public_key_hex"`
	Receipt          string `json:"genuine_receipt_hex"`
	WrongKeyReceipt  string `json:"wrong_key_receipt_hex"`
}

// session drives offload-sim at the raw record level and records every event.
type session struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	events chan event
	rec    []event
}

func newSession(t *testing.T, card, pinned, trip string) *session {
	t.Helper()
	args := []string{card, pinned}
	if trip != "" {
		args = append(args, trip)
	}
	cmd := exec.Command(simPath(t), args...)
	in, err := cmd.StdinPipe()
	must(t, err)
	out, err := cmd.StdoutPipe()
	must(t, err)
	must(t, cmd.Start())
	s := &session{t: t, cmd: cmd, in: in, events: make(chan event, 4096)}
	go func() {
		var h [3]byte
		for {
			if _, err := io.ReadFull(out, h[:]); err != nil {
				return
			}
			buf := make([]byte, int(h[1])|int(h[2])<<8)
			if _, err := io.ReadFull(out, buf); err != nil {
				return
			}
			kind := map[byte]string{'I': "indication", 'N': "notification"}[h[0]]
			s.events <- event{T: kind, Hex: hex.EncodeToString(buf)}
		}
	}()
	t.Cleanup(func() { s.send('Q', nil); in.Close(); _ = cmd.Wait() })
	return s
}

func (s *session) send(kind byte, b []byte) {
	rec := append([]byte{kind, byte(len(b)), byte(len(b) >> 8)}, b...)
	_, _ = s.in.Write(rec)
}

// do sends the given inputs back to back (so the dongle sees them together, which
// is what makes a BUSY reproducible) and records everything until it goes quiet.
func (s *session) do(inputs ...event) []event {
	var wire []byte
	for _, in := range inputs {
		b, _ := hex.DecodeString(in.Hex)
		kind := map[string]byte{"control_write": 'C', "data_write": 'D', "mtu": 'M'}[in.T]
		wire = append(wire, append([]byte{kind, byte(len(b)), byte(len(b) >> 8)}, b...)...)
		s.rec = append(s.rec, in)
	}
	_, err := s.in.Write(wire)
	must(s.t, err)
	for {
		select {
		case e := <-s.events:
			s.rec = append(s.rec, e)
		case <-time.After(150 * time.Millisecond):
			out := s.rec
			s.rec = nil
			return out
		}
	}
}

func ctl(op, rid byte, payload ...byte) event {
	return event{T: "control_write", Hex: hex.EncodeToString(append([]byte{op, rid}, payload...))}
}

func le(n uint64, size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(n >> (8 * i))
	}
	return b
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	o := testbundle.Default()
	o.ChunkSize = 4096
	o.GNSSSamples = 120
	o.DeviceCounter = 1
	b, err := testbundle.Build(o)
	must(t, err)

	card := t.TempDir()
	putOnCard(t, card, b)
	id := b.Manifest.BundleID[:]

	// A receipt for this bundle, signed by a fixed test server key, so it is
	// deterministic. (A real receipt has a random id; the dongle does not care.)
	seed := []byte("cairn-vector-server-key-seed!!!!")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	mkReceipt := func(p ed25519.PrivateKey, root [32]byte) []byte {
		r := &format.Receipt{
			ReceiptVersion: format.ReceiptVersion, ReceiptID: [16]byte{1, 2, 3},
			DeviceID: b.Manifest.DeviceID, BundleID: b.Manifest.BundleID, ContentRoot: root,
			ServerIngestUTCMS: 1760000000000, ServerKeyID: format.DeviceKeyID(p.Public().(ed25519.PublicKey)),
			IngestSchemaVersion: 1, StoredObjectIDs: nil, SignatureAlgorithm: format.SignatureAlgorithmEd25519,
		}
		enc, err := r.Sign(p)
		must(t, err)
		return enc
	}
	good := mkReceipt(priv, b.Manifest.ContentRoot)
	otherSeed := []byte("cairn-vector-other-key-seed!!!!!")
	wrong := mkReceipt(ed25519.NewKeyFromSeed(otherSeed), b.Manifest.ContentRoot)

	sum := hashHex(b.Stream)
	vf := vectorFile{
		Version: 1, Spec: "contracts/ble/v1/offload.md", MTU: 247,
		Notes: []string{
			"All frames are hex. Control writes go to OFFLOAD_CONTROL; the dongle's indications come back on it. Data notifications come on OFFLOAD_DATA; receipt frames are written to it.",
			"Every scenario starts a fresh dongle with the bundle above on its card and the MTU already negotiated to att_mtu (an `mtu` event is shown where a scenario changes it).",
			"Events are in the order the dongle produced them. A phone should produce exactly the control_write and data_write bytes shown and parse every indication and notification.",
			"The dongle's receipt key is receipt_public_key_hex unless a scenario says no_pinned_key.",
			"These were produced by the firmware's own protocol module, not by hand. go test ./internal/offloadclient -run Vectors fails if they drift.",
		},
		Bundle: vecBundle{
			ID: hex.EncodeToString(id), StreamBytes: uint64(len(b.Stream)), ManifestLen: len(b.ManifestBytes),
			ChunkCount: len(b.Chunks), Member0Length: b.Manifest.Members[0].Length, StreamSHA256: sum,
			StreamPrefixHex: hex.EncodeToString(b.Stream[:64]), ReceiptPublicKey: hex.EncodeToString(pub),
			Receipt: hex.EncodeToString(good), WrongKeyReceipt: hex.EncodeToString(wrong),
		},
	}

	pinned := hex.EncodeToString(pub)
	run := func(name, doc string, trip, nokey bool, f func(s *session) []event) {
		key := pinned
		if nokey {
			key = "none"
		}
		tripFile := ""
		if trip {
			tripFile = filepath.Join(t.TempDir(), "trip")
			must(t, os.WriteFile(tripFile, nil, 0o644))
		}
		cardCopy := t.TempDir()
		copyTree(t, card, cardCopy)
		s := newSession(t, cardCopy, key, tripFile)
		ev := s.do(event{T: "mtu", Hex: "f700", Why: "ATT MTU 247"})
		ev = append(ev, f(s)...)
		vf.Scenarios = append(vf.Scenarios, scenario{Name: name, Doc: doc, Trip: trip, NoKey: nokey, Events: ev})
	}

	m0 := b.Manifest.Members[0].Length
	run("list", "LIST page 0: total 1, one 29-byte entry.", false, false,
		func(s *session) []event { return s.do(ctl(0x01, 1, 0, 0)) })
	run("get_manifest", "GET_MANIFEST: response, then manifest.cbor||manifest.sig as seq-numbered notifications, then the 0x86 done indication (bytes_sent, CRC-32).", false, false,
		func(s *session) []event { return s.do(ctl(0x02, 2, id...)) })
	run("read_across_member_boundary", "READ 100 bytes straddling the end of the first member: the bundle byte stream is the members concatenated.", false, false,
		func(s *session) []event { return s.do(ctl(0x03, 3, cat(id, le(m0-50, 8), le(100, 4))...)) })
	run("read_first_bytes", "READ the first 40 bytes: one notification, seq 0.", false, false,
		func(s *session) []event { return s.do(ctl(0x03, 4, cat(id, le(0, 8), le(40, 4))...)) })
	run("read_bad_arguments", "READ refused with BAD_ARGUMENT: offset at the end, zero length, over the 64 KiB cap, a range past the end, and an offset that would wrap.", false, false,
		func(s *session) []event {
			total := uint64(len(b.Stream))
			var out []event
			out = append(out, s.do(ctl(0x03, 5, cat(id, le(total, 8), le(1, 4))...))...)
			out = append(out, s.do(ctl(0x03, 6, cat(id, le(0, 8), le(0, 4))...))...)
			out = append(out, s.do(ctl(0x03, 7, cat(id, le(0, 8), le(65537, 4))...))...)
			out = append(out, s.do(ctl(0x03, 8, cat(id, le(total-1, 8), le(2, 4))...))...)
			out = append(out, s.do(ctl(0x03, 9, cat(id, le(^uint64(0)-5, 8), le(100, 4))...))...)
			return out
		})
	run("unknown_bundle", "Every operation on a bundle id the dongle does not hold answers UNKNOWN_BUNDLE.", false, false,
		func(s *session) []event {
			ghost := append([]byte(nil), id...)
			ghost[15] ^= 0x55
			var out []event
			out = append(out, s.do(ctl(0x02, 10, ghost...))...)
			out = append(out, s.do(ctl(0x03, 11, cat(ghost, le(0, 8), le(10, 4))...))...)
			out = append(out, s.do(ctl(0x04, 12, cat(ghost, le(100, 2))...))...)
			return out
		})
	run("busy_then_abort", "A request while a READ is in progress is answered BUSY; ABORT is always honoured and frees the dongle. The first notifications of the READ are shown, then it is aborted.", false, false,
		func(s *session) []event {
			return s.do(ctl(0x03, 13, cat(id, le(0, 8), le(uint64(len(b.Stream))>>1, 4))...), ctl(0x01, 14, 0, 0), ctl(0x05, 15))
		})
	run("abort_when_idle", "ABORT with nothing in progress answers NO_TRANSFER.", false, false,
		func(s *session) []event { return s.do(ctl(0x05, 16)) })
	run("trip_active", "While a trip is in progress LIST, GET_MANIFEST, READ and PUT_RECEIPT are all refused with TRIP_ACTIVE; ABORT still answers.", true, false,
		func(s *session) []event {
			var out []event
			out = append(out, s.do(ctl(0x01, 17, 0, 0))...)
			out = append(out, s.do(ctl(0x02, 18, id...))...)
			out = append(out, s.do(ctl(0x03, 19, cat(id, le(0, 8), le(10, 4))...))...)
			out = append(out, s.do(ctl(0x04, 20, cat(id, le(100, 2))...))...)
			out = append(out, s.do(ctl(0x05, 21))...)
			return out
		})
	run("mtu_too_small", "At the default ATT MTU of 23 the dongle refuses everything with IO_ERROR rather than half working; negotiate a larger MTU first.", false, false,
		func(s *session) []event {
			out := s.do(event{T: "mtu", Hex: "1700", Why: "ATT MTU 23"})
			return append(out, s.do(ctl(0x01, 22, 0, 0))...)
		})

	putReceipt := func(rid byte, r []byte, piece int) func(s *session) []event {
		return func(s *session) []event {
			out := s.do(ctl(0x04, rid, cat(id, le(uint64(len(r)), 2))...))
			var frames []event
			for seq, at := 0, 0; at < len(r); seq++ {
				n := min(piece, len(r)-at)
				frames = append(frames, event{T: "data_write", Hex: hex.EncodeToString(cat(le(uint64(seq), 2), r[at:at+n]))})
				at += n
			}
			return append(out, s.do(frames...)...)
		}
	}
	run("put_receipt_genuine", "PUT_RECEIPT with a receipt signed by the pinned key naming this bundle: ready, receipt frames, then 0x84 outcome 0 (pruned). The bundle is gone afterwards.", false, false, putReceipt(23, good, 200))
	run("put_receipt_wrong_key", "A receipt signed by a different key: outcome 2 (rejected: signature). Nothing is stored or deleted.", false, false, putReceipt(24, wrong, 200))
	run("put_receipt_no_pinned_key", "A dongle with no key pinned cannot verify: outcome 4. Nothing is stored or deleted. The bundle is safe on the server but stays on the card.", false, true, putReceipt(25, good, 200))
	run("put_receipt_bad_length", "A receipt length of 0 or over 1024 is refused up front with BAD_RECEIPT_LENGTH.", false, false,
		func(s *session) []event {
			out := s.do(ctl(0x04, 26, cat(id, le(0, 2))...))
			return append(out, s.do(ctl(0x04, 27, cat(id, le(1025, 2))...))...)
		})
	run("put_receipt_out_of_order", "A receipt frame with the wrong sequence number ends the upload with BAD_ARGUMENT and no outcome byte. Nothing is stored or deleted.", false, false,
		func(s *session) []event {
			out := s.do(ctl(0x04, 28, cat(id, le(uint64(len(good)), 2))...))
			return append(out, s.do(event{T: "data_write", Hex: hex.EncodeToString(cat(le(1, 2), good[:50]))})...)
		})

	sort.SliceStable(vf.Scenarios, func(i, j int) bool { return false })
	return vf
}

func hashHex(b []byte) string {
	return hex.EncodeToString(sumSHA256(b))
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	cmd := exec.Command("cp", "-R", from+"/.", to)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cp: %v %s", err, out)
	}
}

func TestVectorsAreGeneratedFromTheFirmwareAndHaveNotDrifted(t *testing.T) {
	got, err := json.MarshalIndent(buildVectors(t), "", "  ")
	must(t, err)
	got = append(got, '\n')

	path := contracts.Path("ble", "v1", "vectors", "offload", "vectors.json")
	if *updateVectors {
		must(t, os.MkdirAll(filepath.Dir(path), 0o755))
		must(t, os.WriteFile(path, got, 0o644))
		t.Logf("wrote %s (%d bytes)", path, len(got))
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v: generate them with -update-vectors", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("contracts/ble/v1/vectors/offload/vectors.json differs from what the firmware produces now.\nIf the protocol changed on purpose, regenerate with:\n  go test ./internal/offloadclient -run Vectors -update-vectors\nand tell the iOS app, which replays them.")
	}
}
