// Package format is the reference implementation of Cairn bundle format v3.
//
// The normative specification is docs/bundle-format-v3.md. Where this package
// and that document disagree, the document is correct and this package has a
// bug. The conformance vectors in fixtures/format-v3/ are the executable form
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
//
// The SD card is never a security boundary. Every frame payload is encrypted
// (XChaCha20-Poly1305) under a per-segment key derived from a device root the
// server holds in escrow, and every frame authenticates the segment header that
// binds it to a device, vehicle, assignment and bundle counter. Because the
// frame CRC, the prev_crc32 chain and the Merkle root are all computed over
// ciphertext, structural verification needs no key at all; only reading the
// records does.
package format

// FormatVersion is the segment and manifest format version this package
// implements. There is no v1 or v2 read path: v3 replaces them outright.
const FormatVersion uint16 = 3
