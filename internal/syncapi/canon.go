package syncapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

// Canonical payload form
//
// An operation's content_hash is the SHA-256 of its payload in a canonical
// encoding, so the server can tell "the same operation retried" from "a
// different operation reusing an id", and so a payload mangled in transit is
// caught before it becomes a permanent record.
//
// The encoding is chosen to be trivial to reproduce byte-for-byte in Swift
// without a library. General-purpose canonical JSON (RFC 8785) is mostly about
// number formatting, and number formatting is where two languages disagree. So
// the problem is removed instead of solved: payloads may not contain
// non-integer numbers. A decimal quantity is sent as a string ("12.34") or as a
// scaled integer (cents, millimetres, tenths of a litre), which also happens to
// be the right way to store money and odometer readings anyway.
//
// The rules:
//
//   - no insignificant whitespace;
//   - object keys sorted by their UTF-8 bytes, ascending, no duplicates;
//   - strings in UTF-8, with only '"', '\' and code points below U+0020
//     escaped. '"' and '\' use \" and \; control characters use \u00xx with
//     lowercase hex. Nothing else is escaped, so '/', '<', '&' and non-ASCII
//     text appear literally;
//   - numbers are integers without exponent, leading zeros or "-0", within
//     +/-(2^53 - 1), so every JSON implementation reads them exactly;
//   - true, false and null as written.

const (
	// maxPayloadDepth bounds nesting so a hostile payload cannot exhaust the
	// stack of the recursive canonicaliser.
	maxPayloadDepth = 12

	maxSafeInt = 1<<53 - 1
)

// Canonicalize re-encodes raw JSON in the canonical form.
func Canonicalize(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	out, err := canonValue(dec, 0)
	if err != nil {
		return nil, err
	}
	// Anything after the first value (a second document, stray bytes) would be
	// hashed by the client and silently dropped by us; refuse it.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	return out, nil
}

// ContentHash is the hex SHA-256 of a payload's canonical form.
func ContentHash(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func canonValue(dec *json.Decoder, depth int) ([]byte, error) {
	if depth > maxPayloadDepth {
		return nil, errors.New("payload is nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			type member struct {
				key string
				val []byte
			}
			var members []member
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("invalid JSON: %w", err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if seen[key] {
					// Two values for one key parse differently in different
					// languages, so the "same" payload would hash two ways.
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = true
				val, err := canonValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				members = append(members, member{key, val})
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			sort.Slice(members, func(i, j int) bool { return members[i].key < members[j].key })

			var b bytes.Buffer
			b.WriteByte('{')
			for i, m := range members {
				if i > 0 {
					b.WriteByte(',')
				}
				b.Write(quote(m.key))
				b.WriteByte(':')
				b.Write(m.val)
			}
			b.WriteByte('}')
			return b.Bytes(), nil

		case '[':
			var b bytes.Buffer
			b.WriteByte('[')
			first := true
			for dec.More() {
				val, err := canonValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				if !first {
					b.WriteByte(',')
				}
				first = false
				b.Write(val)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, fmt.Errorf("invalid JSON: %w", err)
			}
			b.WriteByte(']')
			return b.Bytes(), nil
		}
		return nil, errors.New("unexpected delimiter")

	case string:
		return quote(t), nil

	case json.Number:
		return canonNumber(t.String())

	case bool:
		if t {
			return []byte("true"), nil
		}
		return []byte("false"), nil

	case nil:
		return []byte("null"), nil
	}
	return nil, errors.New("unsupported JSON token")
}

func canonNumber(s string) ([]byte, error) {
	digits := s
	if len(digits) > 0 && digits[0] == '-' {
		digits = digits[1:]
	}
	if digits == "" {
		return nil, fmt.Errorf("invalid number %q", s)
	}
	for _, c := range []byte(digits) {
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("number %q is not an integer; send decimals as strings or scaled integers", s)
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return nil, fmt.Errorf("number %q has a leading zero", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n > maxSafeInt || n < -maxSafeInt {
		return nil, fmt.Errorf("number %q is outside +/-(2^53-1)", s)
	}
	if n == 0 && s != "0" {
		return nil, errors.New("negative zero is not allowed")
	}
	return []byte(s), nil
}

const hexDigits = "0123456789abcdef"

func quote(s string) []byte {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b = append(b, '\\', '"')
		case c == '\\':
			b = append(b, '\\', '\\')
		case c < 0x20:
			b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}
