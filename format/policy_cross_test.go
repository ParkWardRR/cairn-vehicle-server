package format

import (
	"os"
	"path/filepath"
	"testing"
)

// The committed policy vector is now the cross-implementation check, so this
// file only guards the strictness rules.
//
// It used to carry a hex array captured from the C encoder. That was weaker
// than it looked: a snapshot pasted into a test file is a claim about what the
// other implementation did once, where a committed vector is an input both
// implementations run. fixtures/format-v2/policy-snapshot/policy.cbor is that
// input, and TestConformanceVectors checks this implementation against it.

// Trailing bytes and unknown keys are both refused, because reporting a partial
// policy as a complete one is worse than reporting none.
func TestParsePolicySnapshotRejectsMalformed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorDir, "policy-snapshot", "policy.cbor"))
	if err != nil {
		t.Skipf("vectors not generated (%v); run: go run ./cmd/mkvectors -out ../fixtures/format-v2", err)
	}

	if _, err := ParsePolicySnapshot(raw); err != nil {
		t.Fatalf("the committed vector should parse: %v", err)
	}

	withTrailing := append(append([]byte{}, raw...), 0x00)
	if _, err := ParsePolicySnapshot(withTrailing); err == nil {
		t.Error("a trailing byte was accepted")
	}

	if _, err := ParsePolicySnapshot(raw[:len(raw)-2]); err == nil {
		t.Error("a truncated snapshot was accepted")
	}

	// The map still claims its full field count but uses a key this build does
	// not define, which means the policy is only partly understood.
	unknown := append([]byte{}, raw...)
	unknown[1] = 99
	if _, err := ParsePolicySnapshot(unknown); err == nil {
		t.Error("an unknown key was accepted")
	}
}
