package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

// Domain separation tags. A leaf must never be reinterpretable as an internal
// node, and an empty tree must not be confusable with either.
const (
	domainLeaf     byte = 0x00
	domainInternal byte = 0x01
	domainEmpty    byte = 0x02
)

// LeafHash returns SHA256(0x00 || d).
func LeafHash(d []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{domainLeaf})
	h.Write(d)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// internalHash returns SHA256(0x01 || l || r).
func internalHash(l, r [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{domainInternal})
	h.Write(l[:])
	h.Write(r[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot builds the binary Merkle root over an ordered leaf list.
//
// When a level has an odd node count the final node is promoted unchanged to
// the next level. It is deliberately not duplicated: duplicating the last node
// admits two distinct leaf lists that produce the same root.
//
// The empty tree has root SHA256(0x02).
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256([]byte{domainEmpty})
	}

	level := make([][32]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, internalHash(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			// Promote, do not duplicate.
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

// Member is one file in a bundle. manifest.cbor and manifest.sig are not
// members: the content root is an input to the manifest, so it cannot cover it.
type Member struct {
	Name   string
	Length uint64
	SHA256 [32]byte
}

// memberLeafInput returns u16le(len(name)) || name || sha256(contents).
func memberLeafInput(m Member) []byte {
	buf := make([]byte, 0, 2+len(m.Name)+32)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(m.Name)))
	buf = append(buf, m.Name...)
	buf = append(buf, m.SHA256[:]...)
	return buf
}

// ContentRoot computes the bundle's content identity: a Merkle root over one
// leaf per member, with members sorted by raw name bytes ascending.
//
// Identity is defined over members rather than over an archive's bytes so that
// it stays independent of archive framing. Hashing a tar stream would make
// identity depend on mtime, uid and padding, so repacking identical data would
// yield a different identity.
//
// The input slice is not modified.
func ContentRoot(members []Member) ([32]byte, error) {
	if err := validateMembers(members); err != nil {
		return [32]byte{}, err
	}

	sorted := make([]Member, len(members))
	copy(sorted, members)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	leaves := make([][32]byte, len(sorted))
	for i, m := range sorted {
		leaves[i] = LeafHash(memberLeafInput(m))
	}
	return MerkleRoot(leaves), nil
}

func validateMembers(members []Member) error {
	seen := make(map[string]struct{}, len(members))
	for _, m := range members {
		if m.Name == "" {
			return fmt.Errorf("member with empty name")
		}
		if len(m.Name) > 0xFFFF {
			return fmt.Errorf("member name exceeds 65535 bytes: %q", m.Name)
		}
		if _, dup := seen[m.Name]; dup {
			return fmt.Errorf("duplicate member name %q", m.Name)
		}
		seen[m.Name] = struct{}{}
	}
	return nil
}

// SortMembers orders members canonically, by raw name bytes ascending. Callers
// building a manifest must store members in this order.
func SortMembers(members []Member) {
	sort.Slice(members, func(i, j int) bool {
		return bytes.Compare([]byte(members[i].Name), []byte(members[j].Name)) < 0
	})
}
