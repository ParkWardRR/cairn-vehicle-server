//go:build darwin

// Command cairn-phone is a stand-in for the Cairn iPhone app, for the one job
// the dongle now depends on: pulling sealed bundles off it over BLE and carrying
// them to the server. It is a reference for the iOS app as much as a tool: the
// same enrolment, the same per-request signatures, the same BLE offload loop.
//
//	cairn-phone enrol   --server https://cairn.example.lan:8444 --code <invitation>
//	cairn-phone offload
//
// State (the app key, client id and the server's pinned key) is kept in
// ~/.cairn/phone.json, mode 0600. The key never leaves it.
//
// macOS only: it uses CoreBluetooth through tinygo.org/x/bluetooth. The first BLE
// access to the dongle makes macOS ask for the pairing passkey.

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/offloadclient"
	"tinygo.org/x/bluetooth"
)

const (
	serviceUUID = "A8E30000-4F5B-11EF-A017-325096B39F47"
	controlUUID = "A8E30030-4F5B-11EF-A017-325096B39F47"
	dataUUID    = "A8E30031-4F5B-11EF-A017-325096B39F47"
	versionUUID = "A8E300F0-4F5B-11EF-A017-325096B39F47"
	capOffload  = 0x04
)

type config struct {
	Server   string `json:"server"`
	ClientID string `json:"client_id"`
	KeyHex   string `json:"key_hex"` // the P-256 private scalar, 32 bytes
	SPKIPin  string `json:"spki_pin"`
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "cairn-phone: "+f+"\n", a...)
	os.Exit(1)
}

func configPath(p string) string {
	if p != "" {
		return p
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".cairn", "phone.json")
}

func loadConfig(path string) (*config, *ecdsa.PrivateKey) {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal("not enrolled (%v): run `cairn-phone enrol` first", err)
	}
	var c config
	if err := json.Unmarshal(b, &c); err != nil {
		fatal("%s: %v", path, err)
	}
	raw, err := hex.DecodeString(c.KeyHex)
	if err != nil || len(raw) != 32 {
		fatal("%s has a bad key", path)
	}
	return &c, keyFromScalar(raw)
}

func keyFromScalar(d []byte) *ecdsa.PrivateKey {
	k := new(ecdsa.PrivateKey)
	k.Curve = elliptic.P256()
	k.D = new(big.Int).SetBytes(d)
	k.PublicKey.X, k.PublicKey.Y = k.Curve.ScalarBaseMult(d)
	return k
}

// ─── enrol ──────────────────────────────────────────────────────────────────

func enrol(args []string) {
	fs := flag.NewFlagSet("enrol", flag.ExitOnError)
	server := fs.String("server", "", "app API base URL, e.g. https://cairn.example.lan:8444")
	code := fs.String("code", "", "the invitation code from `cairn-admin client invite`")
	name := fs.String("name", "cairn-phone (Mac)", "a name for this installation")
	cfgPath := fs.String("config", "", "where to keep state (default ~/.cairn/phone.json)")
	fs.Parse(args)
	if *server == "" || *code == "" {
		fatal("--server and --code are required")
	}

	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(*code))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatal("%v", err)
	}
	pubHex := clients.PublicKeyHex(&key.PublicKey)
	sum := sha256.Sum256(clients.EnrollProofMessage(norm, pubHex))
	proof, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		fatal("%v", err)
	}

	// Trust on first use: the server's key is pinned from this first connection,
	// then checked against what the server itself reports in the enrolment response.
	var seen string
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // pinned below, after enrolment answers
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) > 0 {
				if c, err := x509.ParseCertificate(raw[0]); err == nil {
					s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
					seen = hex.EncodeToString(s[:])
				}
			}
			return nil
		},
	}}}
	body, _ := json.Marshal(map[string]string{"code": norm, "name": *name, "public_key": pubHex, "proof": base64.StdEncoding.EncodeToString(proof)})
	resp, err := hc.Post(strings.TrimRight(*server, "/")+"/v1/enroll/app", "application/json", strings.NewReader(string(body)))
	if err != nil {
		fatal("enrol: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID       string `json:"client_id"`
		Role           string `json:"role"`
		ServerIdentity struct {
			SPKI string `json:"spki_sha256"`
		} `json:"server_identity"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		fatal("the server refused enrolment: %d %s (codes are single use and expire in 10 minutes)", resp.StatusCode, out.Error)
	}
	if out.ServerIdentity.SPKI != "" && seen != "" && !strings.EqualFold(out.ServerIdentity.SPKI, seen) {
		fatal("the key the server presented (%s) differs from the one it reports (%s): not saving", seen, out.ServerIdentity.SPKI)
	}
	pin := out.ServerIdentity.SPKI
	if pin == "" {
		pin = seen
	}

	path := configPath(*cfgPath)
	cfg := config{Server: *server, ClientID: out.ClientID, KeyHex: fmt.Sprintf("%064x", key.D), SPKIPin: pin}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		fatal("%v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		fatal("%v", err)
	}
	fmt.Printf("enrolled as client %s (%s); pinned the server key %s…\nstate saved to %s\n", out.ClientID, out.Role, pin[:12], path)
}

// ─── BLE ────────────────────────────────────────────────────────────────────

type bleTransport struct {
	control, data bluetooth.DeviceCharacteristic
	mtu           int
}

func (b *bleTransport) WriteControl(p []byte) error { _, err := b.control.Write(p); return err }
func (b *bleTransport) WriteData(p []byte) error {
	_, err := b.data.WriteWithoutResponse(p)
	return err
}
func (b *bleTransport) MTU() int { return b.mtu }

func connect(timeout time.Duration, wantName string) (*offloadclient.Client, func(), error) {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, nil, fmt.Errorf("bluetooth: %w (allow Bluetooth for this terminal in System Settings)", err)
	}
	svc, _ := bluetooth.ParseUUID(serviceUUID)

	fmt.Printf("scanning for a Cairn dongle (up to %s)…\n", timeout)
	found := make(chan bluetooth.ScanResult, 1)
	go func() {
		_ = adapter.Scan(func(a *bluetooth.Adapter, r bluetooth.ScanResult) {
			// RSSI 127 is CoreBluetooth's "no reading": a peripheral remembered from an earlier
			// scan, not one heard now. Connecting to it never reaches the radio.
			if r.RSSI == 127 || r.RSSI == 0 {
				return
			}
			if r.HasServiceUUID(svc) || (wantName != "" && r.LocalName() == wantName) {
				select {
				case found <- r:
					_ = a.StopScan()
				default:
				}
			}
		})
	}()
	var res bluetooth.ScanResult
	select {
	case res = <-found:
	case <-time.After(timeout):
		_ = adapter.StopScan()
		return nil, nil, errors.New("no Cairn dongle found: is it powered and awake? (it sleeps when parked for a while)")
	}
	fmt.Printf("found %q (rssi %d); connecting…\n", res.LocalName(), res.RSSI)

	// At a weak signal (the dongle is often heard at -85 dBm or worse) CoreBluetooth can report
	// a connection that never completed; tinygo then returns a Device with no peripheral and
	// DiscoverServices dereferences nil. Treat that as a failed attempt and try again.
	var dev bluetooth.Device
	var services []bluetooth.DeviceService
	var err error
	connected := false
	for attempt := 1; attempt <= 4 && !connected; attempt++ {
		if attempt > 1 {
			fmt.Printf("connection attempt %d of 4…\n", attempt)
			time.Sleep(time.Second)
		}
		dev, err = adapter.Connect(res.Address, bluetooth.ConnectionParams{})
		if err != nil {
			fmt.Printf("  connect failed: %v\n", err)
			continue
		}
		services, err = discoverServices(dev, svc)
		if err != nil || len(services) == 0 {
			fmt.Printf("  the link did not hold during service discovery: %v\n", err)
			safeDisconnect(dev)
			continue
		}
		connected = true
	}
	if !connected {
		return nil, nil, errors.New("could not hold a connection to the dongle (signal too weak? move it within about a metre of the Mac, off the USB 3 hub)")
	}
	cleanup := func() { safeDisconnect(dev) }
	ctlU, _ := bluetooth.ParseUUID(controlUUID)
	datU, _ := bluetooth.ParseUUID(dataUUID)
	verU, _ := bluetooth.ParseUUID(versionUUID)

	// Touching an encrypted characteristic is what makes macOS pair; this is where
	// the passkey prompt appears the first time.
	fmt.Println("reading the dongle's capabilities (macOS may ask for the pairing passkey)…")
	chars, err := services[0].DiscoverCharacteristics([]bluetooth.UUID{ctlU, datU, verU})
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("characteristics: %w", err)
	}
	var tr bleTransport
	var ver bluetooth.DeviceCharacteristic
	have := 0
	for _, c := range chars {
		switch c.UUID() {
		case ctlU:
			tr.control = c
			have |= 1
		case datU:
			tr.data = c
			have |= 2
		case verU:
			ver = c
			have |= 4
		}
	}
	if have&4 == 0 {
		cleanup()
		return nil, nil, errors.New("this dongle has no PROTOCOL_VERSION characteristic")
	}
	buf := make([]byte, 4)
	n, err := ver.Read(buf)
	if err != nil || n < 2 {
		cleanup()
		return nil, nil, fmt.Errorf("reading the protocol version (pairing failed?): %v", err)
	}
	if buf[1]&capOffload == 0 || have&3 != 3 {
		cleanup()
		return nil, nil, fmt.Errorf("this firmware does not support bundle offload (version %d, capabilities %#x)", buf[0], buf[1])
	}

	if w, err := tr.control.GetMTU(); err == nil && w > 0 {
		tr.mtu = int(w) + 3
	} else {
		tr.mtu = 23
	}
	fmt.Printf("paired; ATT MTU %d\n", tr.mtu)

	cl := offloadclient.New(&tr)
	if err := tr.control.EnableNotifications(cl.OnControl); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("subscribe to indications: %w", err)
	}
	if err := tr.data.EnableNotifications(cl.OnData); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("subscribe to data: %w", err)
	}
	return cl, cleanup, nil
}

func offload(args []string) {
	fs := flag.NewFlagSet("offload", flag.ExitOnError)
	cfgPath := fs.String("config", "", "state file (default ~/.cairn/phone.json)")
	scan := fs.Duration("scan", 45*time.Second, "how long to look for the dongle")
	name := fs.String("name", "Cairn", "advertised name to accept as well as the service UUID")
	piece := fs.Int("piece", 16384, "bytes per READ (smaller loses less to a dropped notification)")
	fs.Parse(args)

	cfg, key := loadConfig(configPath(*cfgPath))
	relay := &offloadclient.HTTPRelay{BaseURL: cfg.Server, ClientID: cfg.ClientID, Key: key, SPKIPin: cfg.SPKIPin}

	cl, cleanup, err := connect(*scan, *name)
	if err != nil {
		fatal("%v", err)
	}
	defer cleanup()
	cl.ReadPiece = *piece

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	start := time.Now()
	results, err := cl.Offload(ctx, relay, func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) })
	if errors.Is(err, offloadclient.ErrTripActive) {
		fmt.Println("the dongle is capturing a trip; try again after the drive (it seals the trip a few minutes after you park)")
		return
	}
	if err != nil {
		fatal("%v", err)
	}

	bytesTotal, bad := 0, 0
	for _, r := range results {
		bytesTotal += r.Bytes
		if r.Err != nil {
			bad++
			var re *offloadclient.RelayError
			note := ""
			if errors.As(r.Err, &re) && re.Permanent() {
				note = " (refused: the bundle stays on the dongle)"
			}
			fmt.Printf("  %s: FAILED: %v%s\n", r.BundleID[:8], r.Err, note)
		}
	}
	fmt.Printf("done: %d bundle(s), %d byte(s) in %s, %d failed\n", len(results), bytesTotal, time.Since(start).Round(time.Millisecond), bad)
	if bad > 0 {
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: cairn-phone enrol|offload [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enrol", "enroll":
		enrol(os.Args[2:])
	case "offload":
		offload(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: cairn-phone enrol|offload [flags]")
		os.Exit(2)
	}
}

// discoverServices is DiscoverServices that reports a link which never really came up as an
// error instead of a nil-pointer panic inside the Bluetooth library.
func discoverServices(dev bluetooth.Device, svc bluetooth.UUID) (services []bluetooth.DeviceService, err error) {
	defer func() {
		if r := recover(); r != nil {
			services, err = nil, fmt.Errorf("the connection did not complete (%v)", r)
		}
	}()
	return dev.DiscoverServices([]bluetooth.UUID{svc})
}

// safeDisconnect is Disconnect that tolerates a device whose connection never completed
// (tinygo's darwin Disconnect dereferences a nil peripheral).
func safeDisconnect(dev bluetooth.Device) {
	defer func() { _ = recover() }()
	_ = dev.Disconnect()
}
