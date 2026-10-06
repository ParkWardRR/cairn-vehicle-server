package offloadclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/audit"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/cas"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/intake"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/offloadclient"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/outbox"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/receipts"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/syncapi"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

// These tests run THREE real implementations against each other with no radio:
//
//   - this package's phone client,
//   - the firmware's protocol module (lib/cairn_offload), compiled for the host as
//     offload-sim and run as a subprocess over a pipe, on a real sealed-bundle
//     directory,
//   - the server's relay, over HTTP with real per-request signatures and the real
//     intake service.
//
// Only the BLE link itself is simulated. The simulator is built from the firmware
// repository (`make -C test/host offload-sim` there): point CAIRN_OFFLOAD_SIM at
// the binary. The tests skip, loudly, if it is not set.

func simPath(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("CAIRN_OFFLOAD_SIM"); p != "" {
		return p
	}
	t.Skip("CAIRN_OFFLOAD_SIM is not set: build the firmware repository's `make -C test/host offload-sim` and point it at the binary")
	return ""
}

// ─── the server ─────────────────────────────────────────────────────────────

type stack struct {
	t        *testing.T
	ts       *httptest.Server
	receipts *receipts.Store
	clients  *clients.Registry
	vehicle  string
}

func newStack(t *testing.T) *stack {
	t.Helper()
	root := t.TempDir()

	store, err := cas.Open(filepath.Join(root, "cas"))
	must(t, err)
	rec, err := receipts.Open(receipts.Config{Dir: filepath.Join(root, "receipts"), KeyPath: filepath.Join(root, "keys", "receipt.seed")})
	must(t, err)
	dev, err := devices.Open(filepath.Join(root, "devices.json"))
	must(t, err)
	ob, err := outbox.Open(filepath.Join(root, "outbox"))
	must(t, err)
	regs, err := testbundle.OpenRegistries(root)
	must(t, err)
	svc, err := intake.New(intake.Config{CAS: store, Receipts: rec, Registry: dev, Outbox: ob, OfferDir: filepath.Join(root, "offers"),
		Vehicles: regs.Vehicles, Counters: regs.Counters, Keys: regs.Keys})
	must(t, err)
	pub, _ := testbundle.DeviceKey()
	_, err = dev.Enroll(testbundle.DeviceID(), "test-recorder", pub, 0)
	must(t, err)

	appDir := t.TempDir()
	paths := syncapi.DataPaths(appDir)
	vr, err := vehicles.Open(paths.Vehicles, paths.VehicleKey)
	must(t, err)
	cr, err := clients.Open(paths.Clients)
	must(t, err)
	st, err := syncapi.OpenStore(paths.SyncDir)
	must(t, err)
	al, err := audit.Open(paths.AuditDir)
	must(t, err)
	t.Cleanup(func() { st.Close(); al.Close() })

	api, err := syncapi.New(syncapi.Config{
		Clients: cr, Vehicles: vr, Devices: dev, Store: st, Audit: al,
		Classifier: &syncapi.Classifier{LAN: syncapi.DefaultLAN(), Tailnet: syncapi.DefaultTailnet()},
		InstanceID: "00112233445566778899aabbccddeeff", AckPath: filepath.Join(paths.SyncDir, "acks.json"),
		Intake: svc,
	})
	must(t, err)
	ts := httptest.NewServer(api.Routes())
	t.Cleanup(ts.Close)

	v := testbundle.VehicleID()
	return &stack{t: t, ts: ts, receipts: rec, clients: cr, vehicle: hex.EncodeToString(v[:])}
}

// enrol runs the real invitation flow over HTTP and returns a relay for that phone.
func (s *stack) enrol(scope ...string) *offloadclient.HTTPRelay {
	s.t.Helper()
	code, _, err := s.clients.CreateInvite(clients.InviteSpec{Role: clients.RoleUser, Vehicles: scope, Name: "test phone", CreatedBy: "test"})
	must(s.t, err)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(s.t, err)
	pubHex := clients.PublicKeyHex(&key.PublicKey)
	sum := sha256.Sum256(clients.EnrollProofMessage(code, pubHex))
	proof, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	must(s.t, err)
	body, _ := json.Marshal(map[string]string{"code": code, "name": "test phone", "public_key": pubHex, "proof": base64.StdEncoding.EncodeToString(proof)})
	resp, err := http.Post(s.ts.URL+"/v1/enroll/app", "application/json", bytes.NewReader(body))
	must(s.t, err)
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
	}
	must(s.t, json.NewDecoder(resp.Body).Decode(&out))
	if resp.StatusCode != http.StatusCreated {
		s.t.Fatalf("enrol: %d", resp.StatusCode)
	}
	return &offloadclient.HTTPRelay{BaseURL: s.ts.URL, ClientID: out.ClientID, Key: key}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ─── the dongle ─────────────────────────────────────────────────────────────

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ulid is the firmware's bundle directory name: 128 bits as 26 base32 characters.
func ulid(id [16]byte) string {
	out := make([]byte, 26)
	for i := 0; i < 26; i++ {
		v := 0
		for b := 0; b < 5; b++ {
			pos := i*5 - 2 + b
			bit := 0
			if pos >= 0 && pos < 128 {
				bit = int(id[pos/8]>>(7-uint(pos%8))) & 1
			}
			v = v<<1 | bit
		}
		out[i] = crockford[v&31]
	}
	return string(out)
}

// putOnCard lays a sealed bundle out exactly as the firmware does.
func putOnCard(t *testing.T, card string, b *testbundle.Bundle) string {
	t.Helper()
	dir := filepath.Join(card, "cairn", "bundles", ulid(b.Manifest.BundleID))
	must(t, os.MkdirAll(dir, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "manifest.cbor"), b.ManifestBytes, 0o644))
	must(t, os.WriteFile(filepath.Join(dir, "manifest.sig"), b.Signature, 0o644))
	for name, data := range b.Members() {
		must(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
	}
	return dir
}

type faults struct {
	dropNote int // drop the Nth notification once (1-based); 0 = never
	flipNote int // flip a bit in the Nth notification once
}

type dongle struct {
	t      *testing.T
	cmd    *exec.Cmd
	in     io.WriteCloser
	mu     sync.Mutex
	client *offloadclient.Client
	notes  int
	faults faults
	fired  map[int]bool
}

func startDongle(t *testing.T, card, pinned, tripFile string, f faults) *dongle {
	t.Helper()
	args := []string{card, pinned}
	if tripFile != "" {
		args = append(args, tripFile)
	}
	cmd := exec.Command(simPath(t), args...)
	in, err := cmd.StdinPipe()
	must(t, err)
	out, err := cmd.StdoutPipe()
	must(t, err)
	cmd.Stderr = os.Stderr
	must(t, cmd.Start())

	d := &dongle{t: t, cmd: cmd, in: in, faults: f, fired: map[int]bool{}}
	d.client = offloadclient.New(d)
	d.client.ControlTimeout = 5 * time.Second
	d.client.StreamTimeout = 10 * time.Second
	d.client.ReadPiece = 7000 // several reads per chunk, so boundaries are crossed

	go func() {
		var h [3]byte
		for {
			if _, err := io.ReadFull(out, h[:]); err != nil {
				return
			}
			n := int(h[1]) | int(h[2])<<8
			buf := make([]byte, n)
			if _, err := io.ReadFull(out, buf); err != nil {
				return
			}
			switch h[0] {
			case 'I':
				d.client.OnControl(buf)
			case 'N':
				d.mu.Lock()
				d.notes++
				k := d.notes
				drop := d.faults.dropNote == k && !d.fired[k]
				flip := d.faults.flipNote == k && !d.fired[k]
				if drop || flip {
					d.fired[k] = true
				}
				d.mu.Unlock()
				if drop {
					continue // a notification the radio lost
				}
				if flip && len(buf) > 3 {
					buf[3] ^= 0x40 // a bit flipped in flight
				}
				d.client.OnData(buf)
			}
		}
	}()
	t.Cleanup(func() { d.write('Q', nil); d.in.Close(); _ = d.cmd.Wait() })
	d.write('M', []byte{247, 0})
	return d
}

func (d *dongle) write(kind byte, b []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	rec := append([]byte{kind, byte(len(b)), byte(len(b) >> 8)}, b...)
	_, err := d.in.Write(rec)
	return err
}
func (d *dongle) WriteControl(b []byte) error { return d.write('C', b) }
func (d *dongle) WriteData(b []byte) error    { return d.write('D', b) }
func (d *dongle) MTU() int                    { return 247 }

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func newBundle(t *testing.T, counter uint64, samples int) *testbundle.Bundle {
	t.Helper()
	o := testbundle.Default()
	o.ChunkSize = 9000
	o.GNSSSamples = samples
	o.DeviceCounter = counter
	b, err := testbundle.Build(o)
	must(t, err)
	if len(b.Chunks) < 2 {
		t.Fatalf("test bundle has %d chunk(s); want several so chunk and READ boundaries are crossed", len(b.Chunks))
	}
	return b
}

func logf(t *testing.T) func(string, ...any) {
	return func(f string, a ...any) { t.Logf(f, a...) }
}

// ─── tests ──────────────────────────────────────────────────────────────────

func TestEndToEndABundleTravelsFromTheCardToTheServerAndIsPruned(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 300)
	dir := putOnCard(t, card, b)
	pub := hex.EncodeToString(s.receipts.PublicKey())

	d := startDongle(t, card, pub, "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err != nil {
		t.Fatalf("results: %+v", res)
	}
	if res[0].Outcome != offloadclient.OutcomePruned {
		t.Fatalf("outcome = %v, want pruned", res[0].Outcome)
	}
	if res[0].Chunks != len(b.Chunks) {
		t.Fatalf("uploaded %d chunks, want %d", res[0].Chunks, len(b.Chunks))
	}

	// What matters is on disk: the server holds a receipt for exactly this
	// content, and the dongle's card no longer holds the bundle.
	if _, _, err := s.receipts.Lookup(b.Manifest.ContentRoot); err != nil {
		t.Fatalf("the server has no receipt for the bundle: %v", err)
	}
	if exists(dir) {
		t.Fatal("the bundle is still on the dongle's card after a verified receipt")
	}
	if !exists(filepath.Join(card, "cairn", "receipts", ulid(b.Manifest.BundleID)+".cbor")) {
		t.Fatal("the dongle did not keep the verified receipt")
	}

	// A second run has nothing to do.
	res, err = d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 0 {
		t.Fatalf("a second run found %d bundle(s)", len(res))
	}
}

func TestEndToEndSeveralBundlesAreEachPrunedAndNothingElseIs(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(s.vehicle)
	card := t.TempDir()
	var bs []*testbundle.Bundle
	for i := uint64(1); i <= 3; i++ {
		b := newBundle(t, i, 200+int(i)*40)
		putOnCard(t, card, b)
		bs = append(bs, b)
	}
	d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 3 {
		t.Fatalf("got %d results, want 3", len(res))
	}
	for i, r := range res {
		if r.Err != nil || r.Outcome != offloadclient.OutcomePruned {
			t.Fatalf("bundle %d: %+v", i, r)
		}
	}
	for _, b := range bs {
		if exists(filepath.Join(card, "cairn", "bundles", ulid(b.Manifest.BundleID))) {
			t.Fatalf("bundle %x survived", b.Manifest.BundleID)
		}
		if _, _, err := s.receipts.Lookup(b.Manifest.ContentRoot); err != nil {
			t.Fatalf("no server receipt for %x", b.Manifest.BundleID)
		}
	}
}

func TestEndToEndALostOrCorruptedNotificationIsDetectedAndReRead(t *testing.T) {
	for name, f := range map[string]faults{
		"a lost notification":       {dropNote: 12},
		"a bit flipped in flight":   {flipNote: 12},
		"a loss on the first frame": {dropNote: 1},
	} {
		t.Run(name, func(t *testing.T) {
			s := newStack(t)
			phone := s.enrol(clients.ScopeAll)
			card := t.TempDir()
			b := newBundle(t, 1, 300)
			dir := putOnCard(t, card, b)
			d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), "", f)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			res, err := d.client.Offload(ctx, phone, logf(t))
			must(t, err)
			if len(res) != 1 || res[0].Err != nil || res[0].Outcome != offloadclient.OutcomePruned {
				t.Fatalf("the fault was not recovered from: %+v", res)
			}
			if exists(dir) {
				t.Fatal("bundle not pruned")
			}
			// The server got the bundle intact: it verified every chunk hash itself.
			if _, _, err := s.receipts.Lookup(b.Manifest.ContentRoot); err != nil {
				t.Fatal("no receipt")
			}
		})
	}
}

func TestEndToEndADongleWithoutAPinnedKeyKeepsEverything(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 250)
	dir := putOnCard(t, card, b)
	d := startDongle(t, card, "none", "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err != nil || res[0].Outcome != offloadclient.OutcomeNoKey {
		t.Fatalf("results: %+v", res)
	}
	// The data is safe on the server, but the dongle could not verify the receipt,
	// so it must not delete or store anything.
	if _, _, err := s.receipts.Lookup(b.Manifest.ContentRoot); err != nil {
		t.Fatal("the server should hold the bundle")
	}
	if !exists(dir) {
		t.Fatal("A DONGLE WITH NO PINNED KEY DELETED A BUNDLE")
	}
	if exists(filepath.Join(card, "cairn", "receipts", ulid(b.Manifest.BundleID)+".cbor")) {
		t.Fatal("an unverifiable receipt was stored")
	}
}

func TestEndToEndAReceiptFromTheWrongServerDeletesNothing(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 250)
	dir := putOnCard(t, card, b)

	// The dongle pins a different server's key: the real server's receipt is a
	// forgery as far as it can tell.
	otherPub := bytes.Repeat([]byte{0x42}, 32)
	d := startDongle(t, card, hex.EncodeToString(otherPub), "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("a rejected receipt should surface as an error: %+v", res)
	}
	if res[0].Outcome != offloadclient.OutcomeBadSig {
		t.Fatalf("outcome = %v, want a bad-signature rejection", res[0].Outcome)
	}
	if !exists(dir) {
		t.Fatal("A RECEIPT THE DONGLE COULD NOT VERIFY DELETED A BUNDLE")
	}
}

func TestEndToEndNothingMovesWhileATripIsInProgress(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 250)
	dir := putOnCard(t, card, b)
	trip := filepath.Join(t.TempDir(), "trip")
	must(t, os.WriteFile(trip, nil, 0o644))

	d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), trip, faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := d.client.Offload(ctx, phone, logf(t))
	if !errors.Is(err, offloadclient.ErrTripActive) {
		t.Fatalf("err = %v, want ErrTripActive", err)
	}
	if !exists(dir) {
		t.Fatal("the bundle moved during a trip")
	}
	if _, _, lerr := s.receipts.Lookup(b.Manifest.ContentRoot); lerr == nil {
		t.Fatal("the server received a bundle during a trip")
	}

	// The drive ends: the same phone, the same dongle, now it works.
	must(t, os.Remove(trip))
	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err != nil || res[0].Outcome != offloadclient.OutcomePruned {
		t.Fatalf("after the trip: %+v", res)
	}
}

func TestEndToEndAPhoneOutsideTheVehicleScopeCannotRelayAndNothingIsLost(t *testing.T) {
	s := newStack(t)
	stranger := s.enrol("ffffffffffffffffffffffffffffffff")
	card := t.TempDir()
	b := newBundle(t, 1, 250)
	dir := putOnCard(t, card, b)
	d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, stranger, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("results: %+v", res)
	}
	var re *offloadclient.RelayError
	if !errors.As(res[0].Err, &re) || re.Status != http.StatusForbidden || re.Code != "scope" || !re.Permanent() {
		t.Fatalf("err = %v, want a permanent 403 scope refusal", res[0].Err)
	}
	if !exists(dir) {
		t.Fatal("a refused bundle left the dongle")
	}
	if _, _, lerr := s.receipts.Lookup(b.Manifest.ContentRoot); lerr == nil {
		t.Fatal("the server accepted a bundle from an out-of-scope phone")
	}
}

// The relay, not the phone, decides what the server will hold: a phone that
// uploads bytes that do not match the signed manifest gets no receipt, so the
// dongle keeps the bundle.
func TestEndToEndAPhoneThatCorruptsWhatItUploadsGetsNoReceipt(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 250)
	dir := putOnCard(t, card, b)
	d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, &corrupting{HTTPRelay: phone}, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("a corrupted upload should fail: %+v", res)
	}
	if !exists(dir) {
		t.Fatal("the dongle deleted a bundle the server never received intact")
	}
	if _, _, lerr := s.receipts.Lookup(b.Manifest.ContentRoot); lerr == nil {
		t.Fatal("a receipt was issued for data that was never delivered")
	}
}

type corrupting struct{ *offloadclient.HTTPRelay }

func (c *corrupting) PutChunk(ctx context.Context, id, digest string, data []byte) error {
	bad := append([]byte(nil), data...)
	bad[len(bad)/2] ^= 1
	return c.HTTPRelay.PutChunk(ctx, id, digest, bad)
}

var _ = binary.LittleEndian

// Bit rot on the card. The dongle streams the damaged bytes faithfully, so the
// BLE length and CRC are fine; only the manifest's chunk digest can show they are
// not what was sealed. The phone must catch it BEFORE uploading, and the damaged
// bundle must stay where it is: an intact copy is worth more than a receipt.
func TestEndToEndAnUnreadableOrDamagedCardIsCaughtBeforeUpload(t *testing.T) {
	s := newStack(t)
	phone := s.enrol(clients.ScopeAll)
	card := t.TempDir()
	b := newBundle(t, 1, 300)
	dir := putOnCard(t, card, b)

	// Flip one byte in the middle of the first member.
	var first string
	for name := range b.Members() {
		if first == "" || name < first {
			first = name
		}
	}
	p := filepath.Join(dir, first)
	data, err := os.ReadFile(p)
	must(t, err)
	data[len(data)/2] ^= 0x01
	must(t, os.WriteFile(p, data, 0o644))

	d := startDongle(t, card, hex.EncodeToString(s.receipts.PublicKey()), "", faults{})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := d.client.Offload(ctx, phone, logf(t))
	must(t, err)
	if len(res) != 1 || res[0].Err == nil {
		t.Fatalf("a damaged card should fail the bundle: %+v", res)
	}
	if !bytes.Contains([]byte(res[0].Err.Error()), []byte("does not hash")) {
		t.Fatalf("err = %v, want the digest mismatch to be what stopped it", res[0].Err)
	}
	if !exists(dir) {
		t.Fatal("a damaged bundle was removed from the card")
	}
	if _, _, lerr := s.receipts.Lookup(b.Manifest.ContentRoot); lerr == nil {
		t.Fatal("a receipt exists for a bundle that was never delivered intact")
	}
}

func sumSHA256(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
