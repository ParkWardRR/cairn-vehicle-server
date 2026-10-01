// Package format is the reference implementation of Cairn bundle format v2.
//
// The normative specification is docs/bundle-format-v2.md. Where this package
// and that document disagree, the document is correct and this package has a
// bug. The conformance vectors in fixtures/format-v2/ are the executable form
// of the specification; the firmware (C) and emulator (Rust) implementations
// must produce byte-identical output and identical parse verdicts.
//
// Three identifiers appear throughout and are deliberately distinct:
//
//   - BundleID    a ULID, assigned at bundle open. Operational handle for
//     retries, receipts, support and log correlation.
//   - ContentRoot a Merkle root over bundle members. Identity of the data,
//     used for deduplication, idempotency and the signed
//     commitment. Identical data always yields an identical root.
//   - transfer hash  SHA-256 of a transferred byte stream. Transport integrity
//     only; never an identity.
package format

// FormatVersion is the segment and manifest format version this package
// implements. There is no v1 read path.
const FormatVersion uint16 = 2
