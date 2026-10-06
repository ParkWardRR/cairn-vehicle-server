package syncapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ParkWardRR/Cairn/server/internal/clients"
)

// Pinned signing and enrolment vectors for the iOS app and any other client:
// fixtures/app-sync-v1/vectors.json.
//
// ECDSA is randomised, so a signature cannot be reproduced, only verified. The
// fixture therefore carries one genuine signature per case, made once with the
// public test key below. What this test pins is everything deterministic (the
// exact signing string, the body hash, the header layout) and that each committed
// signature VERIFIES over it with the server's own verification code. A client
// that builds the same string and verifies the same signature agrees with the
// server; one that cannot reproduce the string does not.
//
//	go test ./internal/syncapi -run Vectors -update-vectors   (after a deliberate change)
var updateVectors = flag.Bool("update-vectors", false, "rewrite fixtures/app-sync-v1/vectors.json")

// A public test key. It is committed to a public repository and protects nothing.
const vectorScalarHex = "11065c969d488e9a896d78d3fcc6d3b831da4d22df873d6f3668b4c55b28b889"

type signCase struct {
	Name          string `json:"name"`
	Doc           string `json:"doc"`
	Method        string `json:"method"`
	Target        string `json:"request_target"`
	BodyHex       string `json:"body_hex"`
	BodyText      string `json:"body_text,omitempty"`
	TS            string `json:"ts"`
	Nonce         string `json:"nonce"`
	BodySHA256    string `json:"body_sha256"`
	SigningString string `json:"signing_string"`
	SignatureB64  string `json:"signature_der_base64"`
	Header        string `json:"authorization_header"`
}

type enrolCase struct {
	Doc          string `json:"doc"`
	Code         string `json:"code"`
	PublicKeyHex string `json:"public_key_hex"`
	Message      string `json:"proof_message"`
	ProofB64     string `json:"proof_der_base64"`
}

type appVectors struct {
	Version   int        `json:"version"`
	Spec      string     `json:"spec"`
	Notes     []string   `json:"notes"`
	Key       vectorKey  `json:"test_key"`
	Signing   []signCase `json:"signing"`
	Enrolment enrolCase  `json:"enrolment"`
}

type vectorKey struct {
	PrivateScalarHex string `json:"private_scalar_hex"`
	PublicKeyHex     string `json:"public_key_x963_hex"`
	ClientID         string `json:"client_id"`
}

func testKey() *ecdsa.PrivateKey {
	d, _ := hex.DecodeString(vectorScalarHex)
	k := new(ecdsa.PrivateKey)
	k.Curve = elliptic.P256()
	k.D = new(big.Int).SetBytes(d)
	k.PublicKey.X, k.PublicKey.Y = k.Curve.ScalarBaseMult(d)
	return k
}

func buildSignCase(key *ecdsa.PrivateKey, name, doc, method, target string, body []byte, bodyText, ts, nonce string) signCase {
	hash := BodyHashHex(body)
	str := SigningString(method, target, ts, nonce, hash, vectorClientID)
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum([]byte(str)))
	if err != nil {
		panic(err)
	}
	b64 := base64.StdEncoding.EncodeToString(sig)
	return signCase{
		Name: name, Doc: doc, Method: method, Target: target, BodyHex: hex.EncodeToString(body), BodyText: bodyText,
		TS: ts, Nonce: nonce, BodySHA256: hash, SigningString: str, SignatureB64: b64,
		Header: SigScheme + ` client="` + vectorClientID + `",ts="` + ts + `",nonce="` + nonce + `",sig="` + b64 + `"`,
	}
}

func generateAppVectors() appVectors {
	key := testKey()
	pub := clients.PublicKeyHex(&key.PublicKey)
	v := appVectors{
		Version: 1, Spec: "docs/app-sync-protocol.md section 2",
		Notes: []string{
			"ECDSA is randomised: signatures cannot be reproduced, only verified. Build the signing_string yourself from the other fields and check it equals the one given; then verify signature_der_base64 over SHA-256(signing_string) with test_key.public_key_x963_hex. Do both: agreeing on the string and on verification is what proves compatibility with the server.",
			"signature_der_base64 is the ASN.1 DER ECDSA-P256-SHA256 signature, standard base64 with padding. CryptoKit: signature.derRepresentation.",
			"signing_string lines are separated by a single LF with no trailing newline: CAIRN-SIG-V1, METHOD, request target exactly as sent (path plus ?query, not re-encoded), ts, nonce, lowercase hex SHA-256 of the body (of the empty string when there is none), client id.",
			"The test key is public and protects nothing.",
		},
		Key: vectorKey{PrivateScalarHex: vectorScalarHex, PublicKeyHex: pub, ClientID: vectorClientID},
	}
	v.Signing = []signCase{
		buildSignCase(key, "post_with_json_body", "A POST carrying a JSON body: the body hash is of the exact bytes sent.",
			"POST", "/v1/sync/ack", []byte(`{"cursor":"AAAA"}`), `{"cursor":"AAAA"}`, "1790000000", "00112233445566778899aabbccddeeff"),
		buildSignCase(key, "get_with_query_and_no_body", "A GET with a query string and no body: the target includes the query exactly as sent, and the body hash is that of the empty string (e3b0c442...).",
			"GET", "/v1/sync/pull?cursor=AAAA&limit=100", nil, "", "1790000060", "ffeeddccbbaa99887766554433221100"),
		buildSignCase(key, "post_with_empty_body", "A POST with no body (token minting): same empty-body hash.",
			"POST", "/v1/auth/token", nil, "", "1790000120", "0123456789abcdef0123456789abcdef"),
		buildSignCase(key, "put_with_binary_body", "A PUT carrying binary bytes (a relay chunk): the hash covers raw bytes, not any text form.",
			"PUT", "/v1/relay/bundles/0190a1b2c3d47e5f8a6b7c8d9e0f1a2b/chunks/"+hex.EncodeToString(sum([]byte{0, 1, 2, 3, 255, 254})),
			[]byte{0, 1, 2, 3, 255, 254}, "", "1790000180", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
	}

	code := "ee026e944c7a389c6f803600648b75aa"
	msg := clients.EnrollProofMessage(code, pub)
	proof, err := ecdsa.SignASN1(rand.Reader, key, sum(msg))
	if err != nil {
		panic(err)
	}
	v.Enrolment = enrolCase{
		Doc:  "The enrolment proof: a signature, by the key being enrolled, over `CAIRN-ENROLL-V1\\n<code: 32 lowercase hex, dashes removed>\\n<public key, lowercase hex>` with single LFs and no trailing newline. POST /v1/enroll/app {code, name, public_key, proof}.",
		Code: code, PublicKeyHex: pub, Message: string(msg), ProofB64: base64.StdEncoding.EncodeToString(proof),
	}
	return v
}

func TestAppSyncVectorsAreStableAndVerify(t *testing.T) {
	path, _ := filepath.Abs("../../../fixtures/app-sync-v1/vectors.json")
	if *updateVectors {
		b, err := json.MarshalIndent(generateAppVectors(), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v: generate with -update-vectors", err)
	}
	var v appVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := clients.ParsePublicKey(v.Key.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := clients.PublicKeyHex(&testKey().PublicKey); got != v.Key.PublicKeyHex {
		t.Fatalf("the test key's public half changed: %s", got)
	}
	if len(v.Signing) < 3 {
		t.Fatalf("only %d signing vectors; the app asked for at least 3", len(v.Signing))
	}

	for _, c := range v.Signing {
		body, _ := hex.DecodeString(c.BodyHex)
		if got := BodyHashHex(body); got != c.BodySHA256 {
			t.Errorf("%s: body hash %s, fixture %s", c.Name, got, c.BodySHA256)
		}
		str := SigningString(c.Method, c.Target, c.TS, c.Nonce, c.BodySHA256, v.Key.ClientID)
		if str != c.SigningString {
			t.Errorf("%s: the signing string the server builds differs from the fixture:\n%q\n%q", c.Name, str, c.SigningString)
		}
		sig, err := base64.StdEncoding.DecodeString(c.SignatureB64)
		if err != nil {
			t.Fatal(err)
		}
		if !clients.VerifyDER(pub, []byte(str), sig) {
			t.Errorf("%s: the committed signature does not verify over the signing string", c.Name)
		}
		if want := SigScheme + ` client="` + v.Key.ClientID + `",ts="` + c.TS + `",nonce="` + c.Nonce + `",sig="` + c.SignatureB64 + `"`; c.Header != want {
			t.Errorf("%s: authorization header layout drifted", c.Name)
		}
		// And the real pipeline accepts it: parse the header the way the server does.
		params := parseParams(c.Header[len(SigScheme)+1:])
		if params["client"] != v.Key.ClientID || params["ts"] != c.TS || params["nonce"] != c.Nonce || params["sig"] != c.SignatureB64 {
			t.Errorf("%s: the server's header parser reads %v", c.Name, params)
		}
	}

	proof, _ := base64.StdEncoding.DecodeString(v.Enrolment.ProofB64)
	msg := clients.EnrollProofMessage(v.Enrolment.Code, v.Enrolment.PublicKeyHex)
	if string(msg) != v.Enrolment.Message {
		t.Errorf("enrolment proof message drifted: %q", msg)
	}
	if !clients.VerifyDER(pub, msg, proof) {
		t.Error("the committed enrolment proof does not verify")
	}
}
