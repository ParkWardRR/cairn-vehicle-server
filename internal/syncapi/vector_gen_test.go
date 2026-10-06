package syncapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
)

// TestGenerateVector prints a fresh test vector. Run it by hand when the
// protocol version changes:
//
//	CAIRN_PRINT_VECTOR=1 go test ./internal/syncapi -run TestGenerateVector -v
func TestGenerateVector(t *testing.T) {
	if os.Getenv("CAIRN_PRINT_VECTOR") == "" {
		t.Skip("set CAIRN_PRINT_VECTOR=1 to print a vector")
	}
	d := new(big.Int).SetBytes(sha256Sum("cairn app-sync test vector -- PUBLIC TEST KEY"))
	key := new(ecdsa.PrivateKey)
	key.D = d
	key.PublicKey.Curve = elliptic.P256()
	key.PublicKey.X, key.PublicKey.Y = elliptic.P256().ScalarBaseMult(d.Bytes())

	clientID := "0190a1b2c3d47e5f8a6b7c8d9e0f1a2b"
	body := []byte(`{"cursor":"AAAA"}`)
	msg := SigningString("POST", "/v1/sync/ack", "1790000000", "00112233445566778899aabbccddeeff", BodyHashHex(body), clientID)
	sum := sha256.Sum256([]byte(msg))
	sig, _ := ecdsa.SignASN1(rand.Reader, key, sum[:])

	fmt.Printf("private scalar (hex): %x\npublic key (X9.63 hex): %s\nbody: %s\n", d.Bytes(), clients.PublicKeyHex(&key.PublicKey), body)
	fmt.Printf("signing string:\n%q\nsignature (DER, base64): %s\n", msg, base64.StdEncoding.EncodeToString(sig))
}

func sha256Sum(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
