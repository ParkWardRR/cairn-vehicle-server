package format

import "hash/crc32"

// CRC32 computes the frame and header checksum defined in the specification:
// CRC-32 with the reflected IEEE/zlib polynomial 0xEDB88320.
//
// The specification deliberately uses CRC-32 rather than CRC32C/Castagnoli.
// CRC32C offers no meaningful error-detection advantage at the frame sizes
// involved, and CRC-32 is available in ESP32 ROM as esp_rom_crc32_le, so the
// most constrained of the three implementations gets an optimized routine for
// free.
//
// The device-side equivalent of this function is a plain
//
//	esp_rom_crc32_le(0, buf, len)
//
// which looks too simple for an API documented as carrying a `~` at both ends.
// It is correct because CRC-32/ISO-HDLC's init and xorout are both 0xffffffff,
// and those cancel the two inversions exactly; esp_rom_crc.h's CRC-16/X25
// example reduces the same way. Writing it as ~esp_rom_crc32_le(~0u, ...)
// instead — as this comment previously recommended — applies the inversions but
// drops the xorout and returns the raw shift register, which is internally
// consistent on the device and therefore invisible to it.
//
// On amd64 and arm64 crc32.ChecksumIEEE dispatches to a carry-less multiply
// implementation (PCLMULQDQ, PMULL) at run time, so this is already the
// hardware path; see bench_test.go for the measured throughput.
func CRC32(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}
