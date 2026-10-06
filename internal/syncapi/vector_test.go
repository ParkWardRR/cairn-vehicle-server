package syncapi

import (
	"testing"

	"github.com/ParkWardRR/Cairn/server/internal/clients"
)

// The vector published in contracts/sync/v1/spec.md. If this fails the
// document is lying to the iOS client's author, so change both together.
const (
	vectorPublicKey = "049865616d17bd8336564c615ad4076c347938be436834bae774437ab3530e216b21025bb8042070ee6c9276fa4dd857e2525a8a2915aba1e45761cedfd8aada39"
	vectorClientID  = "0190a1b2c3d47e5f8a6b7c8d9e0f1a2b"
	vectorBody      = `{"cursor":"AAAA"}`
	vectorSigning   = "CAIRN-SIG-V1\nPOST\n/v1/sync/ack\n1790000000\n00112233445566778899aabbccddeeff\n264ef7813246976045be09d319d4cecdbb620331ca551f04d0e8e07f25946468\n0190a1b2c3d47e5f8a6b7c8d9e0f1a2b"
	vectorSig       = "MEUCIDZQYt9QDF5PJ43nMAA9D5/HNm+d+QwpABTSQyLdxMVdAiEAjMSDavgvRW6dg2vGSPelsKCoBezOsZMvDuC770JXZ+0="
)

func TestPublishedVectorStillHolds(t *testing.T) {
	got := SigningString("POST", "/v1/sync/ack", "1790000000", "00112233445566778899aabbccddeeff",
		BodyHashHex([]byte(vectorBody)), vectorClientID)
	if got != vectorSigning {
		t.Fatalf("signing string drifted from the documented vector:\n got %q\nwant %q", got, vectorSigning)
	}

	pub, err := clients.ParsePublicKey(vectorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := clients.DecodeSignature(vectorSig)
	if err != nil {
		t.Fatal(err)
	}
	if !clients.VerifyDER(pub, []byte(vectorSigning), sig) {
		t.Fatal("the documented signature no longer verifies")
	}
}

// The canonical-JSON content hash is the other thing two languages must agree
// on byte for byte.
func TestCanonicalPayloadVector(t *testing.T) {
	in := `{ "target": "trip-1", "fields": { "title": "Café run / 5°C", "odometer_km": 45210 } }`
	canon, err := Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"fields":{"odometer_km":45210,"title":"Café run / 5°C"},"target":"trip-1"}`
	if string(canon) != want {
		t.Fatalf("canonical form:\n got %s\nwant %s", canon, want)
	}
	const wantHash = "bfb34ea202550b8fb7c04570f8426f1a27d058069d39b2513f4861bc9c882028"
	if h := ContentHash(canon); h != wantHash {
		t.Fatalf("content hash = %s, want %s", h, wantHash)
	}
}
