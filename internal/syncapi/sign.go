package syncapi

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

// SigScheme is the Authorization scheme for per-request signatures.
const SigScheme = "Cairn-Sig"

// sigDomain prefixes every signed string. It binds a signature to this
// protocol and version, so the same key signing something else (an enrolment
// proof, a future protocol) can never produce a valid request signature.
const sigDomain = "CAIRN-SIG-V1"

// SigningString builds the exact byte string a request signature covers.
//
//	CAIRN-SIG-V1 \n METHOD \n path?query \n ts \n nonce \n hex(sha256(body)) \n client_id
//
// Every element that gives a request its meaning is in it: the method and the
// request target (so a signature for GET /v1/sync/pull cannot be replayed as a
// POST to something else), the body hash (so the body cannot be swapped), the
// timestamp and nonce (so it cannot be replayed), and the client ID (so a
// signature is bound to the identity it claims). The path is the request target
// *as received* — not re-encoded — because any normalisation step is a place
// two implementations disagree and a valid request fails.
func SigningString(method, requestURI, ts, nonce, bodyHashHex, clientID string) string {
	return sigDomain + "\n" + method + "\n" + requestURI + "\n" + ts + "\n" + nonce + "\n" + bodyHashHex + "\n" + clientID
}

// BodyHashHex is the hex SHA-256 of a request body (of the empty string for a
// request with none).
func BodyHashHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// NewNonce returns 128 random bits as 32 lowercase hex characters.
func NewNonce() (string, error) {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(n[:]), nil
}

// AuthorizationHeader signs a request and returns the Authorization header
// value. The server never calls it; it is the reference implementation the
// tests and the documented test vector are generated from, and what a Go
// client would use.
func AuthorizationHeader(key *ecdsa.PrivateKey, clientID, method, requestURI string, body []byte, ts time.Time, nonce string) (string, error) {
	tsText := strconv.FormatInt(ts.Unix(), 10)
	msg := SigningString(method, requestURI, tsText, nonce, BodyHashHex(body), clientID)
	sum := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	return fmt.Sprintf(`%s client="%s",ts="%s",nonce="%s",sig="%s"`,
		SigScheme, clientID, tsText, nonce, base64.StdEncoding.EncodeToString(sig)), nil
}
