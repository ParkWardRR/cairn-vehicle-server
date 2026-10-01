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
// The ESP ROM routine uses an inverted convention; the device-side equivalent
// of this function is:
//
//	~esp_rom_crc32_le(~0u, buf, len)
func CRC32(b []byte) uint32 {
	return crc32.ChecksumIEEE(b)
}
