package enroll

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The negative vectors (contracts/enrolment/v1/vectors/negative.json) are written
// by cmd/mkvectors, not by this package: Go reading what Go wrote proves
// determinism, not correctness, so what this test adds is that the acceptance path
// refuses every one of them, for the stated reason, and that a refusal leaves no
// state behind.

var negativePath = filepath.Join(filepath.Dir(vectorPath), "negative.json")

type negativeFile struct {
	Vectors []struct {
		Name               string `json:"name"`
		Blob               string `json:"blob"`
		BlobText           string `json:"blob_text"`
		ServerPrivateKey   string `json:"server_private_key"`
		ConfirmFingerprint string `json:"confirm_fingerprint"`
		Error              string `json:"error"`
	} `json:"vectors"`
	Sequences []struct {
		Name  string `json:"name"`
		Steps []struct {
			Action              string `json:"action"`
			Blob                string `json:"blob"`
			ConfirmFingerprint  string `json:"confirm_fingerprint"`
			DeviceID            string `json:"device_id"`
			KeyVersion          uint32 `json:"key_version"`
			Error               string `json:"error"`
			RootAlreadyEscrowed *bool  `json:"root_already_escrowed"`
		} `json:"steps"`
	} `json:"sequences"`
	ServerPrivateKey string `json:"server_private_key"`
}

// refusalClass names an Enroll error in the vocabulary of negative.json.
func refusalClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrMalformed):
		return "malformed"
	case errors.Is(err, ErrBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrUnseal):
		return "unseal"
	case errors.Is(err, ErrFingerprintMismatch):
		return "fingerprint_mismatch"
	case errors.Is(err, ErrFingerprintRequired):
		return "fingerprint_required"
	case errors.Is(err, ErrRootMismatch):
		return "root_mismatch"
	case errors.Is(err, ErrKeyChanged):
		return "key_changed"
	case errors.Is(err, ErrRootShredded):
		return "root_shredded"
	case errors.Is(err, ErrRevokedDevice):
		return "revoked_device"
	case strings.Contains(err.Error(), "fingerprint must be"):
		return "fingerprint_invalid"
	}
	return "other: " + err.Error()
}

func serverFromHex(t *testing.T, s string) *ecdh.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func loadNegatives(t *testing.T) *negativeFile {
	t.Helper()
	raw, err := os.ReadFile(negativePath)
	if err != nil {
		t.Skipf("enrolment negative vectors not found (%v); they arrive with the contracts release "+
			"that adds them, or generate them with: go run ./cmd/mkvectors (CAIRN_CONTRACTS set)", err)
	}
	var f negativeFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Vectors) == 0 || len(f.Sequences) == 0 {
		t.Fatal("negative.json has no vectors or no sequences")
	}
	return &f
}

func TestNegativeVectors(t *testing.T) {
	f := loadNegatives(t)
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var blob []byte
			var err error
			if v.BlobText != "" {
				blob, err = DecodeText(v.BlobText)
			} else {
				blob, err = hex.DecodeString(v.Blob)
			}
			if err != nil {
				if got := refusalClass(err); got != v.Error {
					t.Fatalf("refused as %q (%v), want %q", got, err, v.Error)
				}
				return
			}

			e := newEnv(t, serverFromHex(t, v.ServerPrivateKey))
			_, err = Enroll(Request{Blob: blob, ConfirmFingerprint: v.ConfirmFingerprint}, e.deps)
			if err == nil {
				t.Fatalf("a blob the vector says is %q was enrolled", v.Error)
			}
			if got := refusalClass(err); got != v.Error {
				t.Fatalf("refused as %q (%v), want %q", got, err, v.Error)
			}
			if len(e.deps.Registry.List()) != 0 {
				t.Fatal("a refused enrolment registered a device")
			}
		})
	}
}

func TestNegativeSequences(t *testing.T) {
	f := loadNegatives(t)
	for _, s := range f.Sequences {
		t.Run(s.Name, func(t *testing.T) {
			e := newEnv(t, serverFromHex(t, f.ServerPrivateKey))
			for i, step := range s.Steps {
				switch step.Action {
				case "enrol":
					blob, err := hex.DecodeString(step.Blob)
					if err != nil {
						t.Fatal(err)
					}
					res, err := Enroll(Request{Blob: blob, ConfirmFingerprint: step.ConfirmFingerprint}, e.deps)
					if got := refusalClass(err); got != step.Error {
						t.Fatalf("step %d: refused as %q (%v), want %q", i, got, err, step.Error)
					}
					if err == nil && step.RootAlreadyEscrowed != nil && res.RootAlreadyEscrowed != *step.RootAlreadyEscrowed {
						t.Fatalf("step %d: root_already_escrowed = %v, want %v", i, res.RootAlreadyEscrowed, *step.RootAlreadyEscrowed)
					}
				case "destroy_key":
					if err := e.deps.Keys.Destroy(step.DeviceID, step.KeyVersion); err != nil {
						t.Fatalf("step %d: %v", i, err)
					}
				case "revoke":
					id, err := hex.DecodeString(step.DeviceID)
					if err != nil || len(id) != 16 {
						t.Fatalf("step %d: bad device_id", i)
					}
					if err := e.deps.Registry.Revoke([16]byte(id), "negative vector"); err != nil {
						t.Fatalf("step %d: %v", i, err)
					}
				default:
					t.Fatalf("step %d: unknown action %q", i, step.Action)
				}
			}
		})
	}
}
