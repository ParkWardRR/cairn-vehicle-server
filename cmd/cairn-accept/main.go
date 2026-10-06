// Command cairn-accept runs the app-API acceptance checks against a RUNNING server:
// the authenticated sync API (#1), the authenticated snapshot (#3) and the bundle
// relay (#4), over the real listener rather than in-process.
//
//	cairn-accept -server https://cairn.example.lan:8444 -code <invitation> -vehicle <id>
//	cairn-accept -server ... -state ~/.cairn/accept.json -vehicle <id> -relay -receipt-key <hex>
//
// The first run enrols with -code and keeps the app key in -state (mode 0600). It
// writes real, small records (a maintenance event, a synthetic bundle), so point it
// at a scratch vehicle: the invitation should be scoped to that one vehicle.
//
// -relay needs the synthetic recorder the tests use to exist on the server (the
// device key and storage root are fixed); `cairn-accept -print-synthetic` prints the
// cairn-server and cairn-admin commands that create it. The relay check is the one
// that writes into the bundle store, so run it against a scratch instance unless a
// synthetic bundle in the real store is acceptable.
package main

import (
	"bytes"
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
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/offloadclient"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/syncapi"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/testbundle"
)

type state struct {
	Server   string `json:"server"`
	ClientID string `json:"client_id"`
	KeyHex   string `json:"key_hex"`
	SPKIPin  string `json:"spki_pin"`
}

var failed int

func check(name string, ok bool, detail string, args ...any) {
	if ok {
		fmt.Printf("  PASS  %s\n", name)
		return
	}
	failed++
	fmt.Printf("  FAIL  %s: %s\n", name, fmt.Sprintf(detail, args...))
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "cairn-accept: "+f+"\n", a...)
	os.Exit(2)
}

func main() {
	var (
		server   = flag.String("server", "", "app API base URL")
		code     = flag.String("code", "", "invitation code (first run only)")
		statePth = flag.String("state", filepath.Join(os.Getenv("HOME"), ".cairn", "accept.json"), "where the enrolled client is kept")
		vehicle  = flag.String("vehicle", "", "32-hex vehicle id this client is scoped to")
		other    = flag.String("other-vehicle", "404142434445464748494a4b4c4d4e4f", "a vehicle id outside the client's scope")
		relay    = flag.Bool("relay", false, "also run a synthetic bundle through the relay")
		rcptKey  = flag.String("receipt-key", "", "server receipt public key (hex), to verify the relayed receipt")
		snapshot = flag.Bool("snapshot", true, "check the authenticated snapshot")
		printSyn = flag.Bool("print-synthetic", false, "print the commands that create the synthetic recorder and exit")
		counter  = flag.Uint64("counter", uint64(time.Now().Unix()), "device counter for the synthetic bundle (must increase)")
	)
	flag.Parse()
	if *printSyn {
		printSynthetic()
		return
	}
	if *server == "" || *vehicle == "" {
		die("-server and -vehicle are required")
	}
	base := strings.TrimRight(*server, "/")

	st, key := loadOrEnrol(base, *code, *statePth)
	hc := pinnedClient(st.SPKIPin)
	rl := &offloadclient.HTTPRelay{BaseURL: base, ClientID: st.ClientID, Key: key, SPKIPin: st.SPKIPin, HTTP: hc}

	fmt.Println("health and the unauthenticated surface")
	status, body := get(hc, base+"/v1/health", nil)
	var h struct {
		Status string `json:"status"`
		Build  struct {
			Version, Commit string
		} `json:"build"`
	}
	_ = json.Unmarshal(body, &h)
	check("/v1/health is ok and names the build", status == 200 && h.Status == "ok" && h.Build.Commit != "", "%d %s", status, body)
	for _, p := range []string{"/v1/snapshot?format=tar&vehicle=" + *vehicle, "/v1/sync/pull", "/v1/relay/bundles/x/receipt"} {
		s, b := get(hc, base+p, nil)
		check("unauthenticated "+strings.SplitN(p, "?", 2)[0]+" is the uniform 401", s == 401 && errCode(b) == "unauthenticated", "%d %s", s, b)
	}
	s, b := do(hc, "POST", base+"/v1/relay/bundles/offer", []byte("x"), map[string]string{"Authorization": "Bearer nope"})
	check("an unknown bearer token is the uniform 401", s == 401 && errCode(b) == "unauthenticated", "%d %s", s, b)

	signed := func(method, uri string, body []byte, hdr map[string]string) (int, []byte, http.Header) {
		nonce, _ := syncapi.NewNonce()
		auth, err := syncapi.AuthorizationHeader(key, st.ClientID, method, uri, body, time.Now(), nonce)
		if err != nil {
			die("%v", err)
		}
		h := map[string]string{"Authorization": auth}
		for k, v := range hdr {
			h[k] = v
		}
		return doH(hc, method, base+uri, body, h)
	}

	fmt.Println("signed sync (#1)")
	opID := uuidV7ish()
	payload := []byte(`{"kind":"acceptance","odometer_km":1}`)
	canon, err := syncapi.Canonicalize(payload)
	if err != nil {
		die("%v", err)
	}
	op := fmt.Sprintf(`{"operations":[{"operation_id":%q,"client_id":%q,"vehicle_id":%q,"kind":"maintenance_event","created_at":%q,"payload_version":1,"payload":%s,"content_hash":%q}]}`,
		opID, st.ClientID, *vehicle, time.Now().UTC().Format(time.RFC3339), canon, syncapi.ContentHash(canon))
	s, b, _ = signed("POST", "/v1/sync/push", []byte(op), nil)
	check("push is accepted", s == 200 && bytes.Contains(b, []byte(`"accepted"`)), "%d %s", s, b)
	s, b, _ = signed("POST", "/v1/sync/push", []byte(op), nil)
	check("the same push again is a duplicate, not a second record", s == 200 && bytes.Contains(b, []byte(`"duplicate"`)), "%d %s", s, b)
	s, b, _ = signed("GET", "/v1/sync/pull?limit=500", nil, nil)
	var pull struct {
		Changes []struct {
			Operation struct {
				ID string `json:"operation_id"`
			} `json:"operation"`
		} `json:"changes"`
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(b, &pull)
	seen := false
	for _, c := range pull.Changes {
		seen = seen || c.Operation.ID == opID
	}
	check("pull returns the pushed operation", s == 200 && seen, "%d (%d changes) %.200s", s, len(pull.Changes), b)
	if pull.Cursor != "" {
		ack, _ := json.Marshal(map[string]string{"cursor": pull.Cursor})
		s, b, _ = signed("POST", "/v1/sync/ack", ack, nil)
		check("ack of the pulled cursor is accepted", s == 200, "%d %s", s, b)
	}
	s, b, _ = signed("GET", "/v1/sync/pull?cursor=bm90LWEtY3Vyc29y", nil, nil)
	check("a bad cursor is refused", s == 400, "%d %s", s, b)
	push2 := strings.Replace(op, `"vehicle_id":"`+*vehicle+`"`, `"vehicle_id":"`+*other+`"`, 1)
	push2 = strings.Replace(push2, opID, uuidV7ish(), 1)
	s, b, _ = signed("POST", "/v1/sync/push", []byte(push2), nil)
	check("a push for a vehicle outside the scope is rejected", s == 200 && !bytes.Contains(b, []byte(`"accepted"`)) || s == 403, "%d %s", s, b)

	fmt.Println("tokens and signed-only routes")
	s, b, _ = signed("POST", "/v1/auth/token", nil, nil)
	var tok struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(b, &tok)
	check("a signed request mints a bearer token", s == 200 && tok.Token != "", "%d %s", s, b)
	if tok.Token != "" {
		s, b = do(hc, "GET", base+"/v1/sync/pull?limit=1", nil, map[string]string{"Authorization": "Bearer " + tok.Token})
		check("the token authenticates a pull", s == 200, "%d %s", s, b)
		s, b = do(hc, "POST", base+"/v1/auth/token", nil, map[string]string{"Authorization": "Bearer " + tok.Token})
		check("a token on a signed-only route is 401 signature_required", s == 401 && errCode(b) == "signature_required", "%d %s", s, b)
	}

	if *snapshot {
		fmt.Println("authenticated snapshot (#3)")
		s, b, _ = signed("GET", "/v1/snapshot?format=tar", nil, nil)
		check("a scoped client must name a vehicle", s == 403 && errCode(b) == "vehicle_required", "%d %s", s, b)
		s, b, _ = signed("GET", "/v1/snapshot?format=tar&vehicle="+*other, nil, nil)
		check("another vehicle is outside the scope", s == 403 && errCode(b) == "scope", "%d %s", s, b)
		uri := "/v1/snapshot?format=tar&vehicle=" + *vehicle
		s, b, hdr := signed("GET", uri, nil, nil)
		etag := hdr.Get("ETag")
		check("the client's own vehicle returns a snapshot", s == 200 && len(b) > 0, "%d (%d bytes) %.120s", s, len(b), b)
		check("the snapshot carries an ETag", etag != "", "no ETag header")
		if etag != "" {
			s, _, _ = signed("GET", uri, nil, map[string]string{"If-None-Match": etag})
			check("If-None-Match with that ETag is 304", s == 304, "%d", s)
		}
	}

	if *relay {
		fmt.Println("bundle relay (#4)")
		runRelay(rl, *counter, *rcptKey, signed)
	}

	if failed > 0 {
		fmt.Printf("\n%d check(s) FAILED\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nall checks passed")
}

func runRelay(rl *offloadclient.HTTPRelay, counter uint64, receiptKeyHex string, signed func(string, string, []byte, map[string]string) (int, []byte, http.Header)) {
	o := testbundle.Default()
	o.ChunkSize = 256
	o.DeviceCounter = counter
	b, err := testbundle.Build(o)
	if err != nil {
		die("build bundle: %v", err)
	}
	ctx := context.Background()
	offer, err := rl.Offer(ctx, b.ManifestBytes, b.Signature)
	if err != nil {
		check("offer is accepted", false, "%v", err)
		return
	}
	check("offer names every chunk of a fresh bundle", len(offer.MissingChunks) == len(b.Chunks) && !offer.ReceiptAvailable, "%+v", offer)
	for _, m := range offer.MissingChunks {
		part := b.Stream[m.Offset : m.Offset+uint64(m.Length)]
		if err := rl.PutChunk(ctx, offer.BundleID, m.SHA256, part); err != nil {
			check(fmt.Sprintf("chunk %d is accepted", m.Index), false, "%v", err)
			return
		}
	}
	// A wrong chunk must be refused and must not yield a receipt.
	if len(offer.MissingChunks) > 0 {
		bad := append([]byte(nil), b.Stream[:int(offer.MissingChunks[0].Length)]...)
		bad[0] ^= 0xff
		err := rl.PutChunk(ctx, offer.BundleID, offer.MissingChunks[0].SHA256, bad)
		re, _ := err.(*offloadclient.RelayError)
		check("a chunk with flipped bytes is refused 409", re != nil && re.Status == 409, "%v", err)
	}
	receipt, err := rl.Commit(ctx, offer.BundleID)
	if err != nil {
		check("commit returns a receipt", false, "%v", err)
		return
	}
	check("commit returns a receipt", len(receipt) > 0, "empty")
	if receiptKeyHex != "" {
		pub, err := hex.DecodeString(receiptKeyHex)
		if err != nil || len(pub) != 32 {
			die("-receipt-key must be 64 hex characters")
		}
		parsed, err := format.ParseReceipt(receipt)
		if err == nil {
			err = parsed.VerifyAcknowledges(pub, b.Manifest.ContentRoot)
		}
		check("the receipt verifies against the server's key and names this bundle", err == nil, "%v", err)
	}
	s, again, _ := signed("GET", "/v1/relay/bundles/"+offer.BundleID+"/receipt", nil, nil)
	check("the receipt can be fetched again, byte-identical", s == 200 && bytes.Equal(again, receipt), "%d", s)
	re, err := rl.Offer(ctx, b.ManifestBytes, b.Signature)
	check("re-offering a delivered bundle says a receipt exists", err == nil && re.ReceiptAvailable && len(re.MissingChunks) == 0, "%v %+v", err, re)
}

func printSynthetic() {
	pub, _ := testbundle.DeviceKey()
	root := testbundle.RootKey()
	dev, veh, asg := testbundle.DeviceID(), testbundle.VehicleID(), testbundle.AssignmentID()
	fmt.Printf(`# the synthetic recorder the relay check carries bundles for
cairn-server -data DIR -keystore-master MASTER \
  -enroll %x -enroll-key %x -enroll-root %x -enroll-name synthetic-recorder
cairn-admin -data DIR vehicle add --name acceptance --id %x
cairn-admin -data DIR assign --assignment-id %x %x %x
`, dev, []byte(pub), root[:], veh, asg, dev, veh)
}

// ─── state and enrolment ────────────────────────────────────────────────────

func loadOrEnrol(base, code, path string) (*state, *ecdsa.PrivateKey) {
	if b, err := os.ReadFile(path); err == nil && code == "" {
		var st state
		if err := json.Unmarshal(b, &st); err != nil {
			die("%s: %v", path, err)
		}
		raw, err := hex.DecodeString(st.KeyHex)
		if err != nil || len(raw) != 32 {
			die("%s has a bad key", path)
		}
		return &st, keyFromScalar(raw)
	}
	if code == "" {
		die("not enrolled: pass -code <invitation>")
	}
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(code))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		die("%v", err)
	}
	pubHex := clients.PublicKeyHex(&key.PublicKey)
	sum := sha256.Sum256(clients.EnrollProofMessage(norm, pubHex))
	proof, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		die("%v", err)
	}
	// Trust on first use, as the app does: the pin is whatever key the server
	// presented, cross-checked against what its enrolment response reports.
	hc, seen := tofuClient()
	body, _ := json.Marshal(map[string]string{"code": norm, "name": "cairn-accept", "public_key": pubHex, "proof": base64.StdEncoding.EncodeToString(proof)})
	resp, err := hc.Post(base+"/v1/enroll/app", "application/json", bytes.NewReader(body))
	if err != nil {
		die("enrol: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID       string `json:"client_id"`
		ServerIdentity struct {
			SPKI string `json:"spki_sha256"`
		} `json:"server_identity"`
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != http.StatusCreated {
		die("enrolment refused: %d %s", resp.StatusCode, out.Error)
	}
	pin := out.ServerIdentity.SPKI
	if pin == "" {
		pin = *seen
	}
	if *seen != "" && !strings.EqualFold(pin, *seen) {
		die("the server presented a key that differs from the one it reports")
	}
	st := &state{Server: base, ClientID: out.ClientID, KeyHex: fmt.Sprintf("%064x", key.D), SPKIPin: pin}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		die("%v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		die("%v", err)
	}
	fmt.Printf("enrolled as client %s; state in %s\n", out.ClientID, path)
	return st, key
}

func keyFromScalar(d []byte) *ecdsa.PrivateKey {
	k := new(ecdsa.PrivateKey)
	k.Curve = elliptic.P256()
	k.D = new(big.Int).SetBytes(d)
	k.PublicKey.X, k.PublicKey.Y = k.Curve.ScalarBaseMult(d)
	return k
}

// ─── http helpers ───────────────────────────────────────────────────────────

func get(hc *http.Client, url string, h map[string]string) (int, []byte) {
	return do(hc, "GET", url, nil, h)
}

func do(hc *http.Client, method, url string, body []byte, h map[string]string) (int, []byte) {
	s, b, _ := doH(hc, method, url, body, h)
	return s, b
}

func doH(hc *http.Client, method, url string, body []byte, h map[string]string) (int, []byte, http.Header) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		die("%v", err)
	}
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		die("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func errCode(b []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	return e.Error
}

// uuidV7ish returns a version-7-shaped UUID: the time in the first 48 bits, random
// after, so operation ids are unique per run.
func uuidV7ish() string {
	var u [16]byte
	_, _ = rand.Read(u[:])
	ms := uint64(time.Now().UnixMilli())
	for i := 0; i < 6; i++ {
		u[i] = byte(ms >> (8 * (5 - i)))
	}
	u[6] = 0x70 | u[6]&0x0f
	u[8] = 0x80 | u[8]&0x3f
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// pinnedClient trusts exactly the server key pinned at enrolment; an empty pin uses
// the system trust store.
func pinnedClient(pin string) *http.Client {
	tr := &http.Transport{}
	if pin != "" {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // the pin below is the verification
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return fmt.Errorf("no server certificate")
				}
				c, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
				if !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
					return fmt.Errorf("the server's key does not match the pin")
				}
				return nil
			},
		}
	}
	return &http.Client{Transport: tr, Timeout: 2 * time.Minute}
}

// tofuClient accepts any certificate and reports the key it saw, for first use.
func tofuClient() (*http.Client, *string) {
	seen := new(string)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // pinned after enrolment answers
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) > 0 {
				if c, err := x509.ParseCertificate(raw[0]); err == nil {
					sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
					*seen = hex.EncodeToString(sum[:])
				}
			}
			return nil
		},
	}}}, seen
}
