package format_test

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/ParkWardRR/Cairn/server/format"
)

// These benchmarks exist to answer a specific question with numbers rather than
// assertions: is this binary actually getting the CPU's hash and checksum
// acceleration, and does raising the compiler's instruction-set baseline change
// anything measurable?
//
// All three primitives reach hardware through the standard library:
//
//	CRC-32    hash/crc32 selects a PCLMULQDQ implementation on amd64
//	SHA-256   crypto/sha256 selects SHA-NI where the CPU reports it
//	Ed25519   no SIMD path exists in the standard library, by design
//
// None of that is affected by GOAMD64, which only governs the code the compiler
// generates for ordinary Go. Run with:
//
//	GOAMD64=v1 go test ./format -run '^$' -bench 'Hardware' -benchmem
//	GOAMD64=v3 go test ./format -run '^$' -bench 'Hardware' -benchmem
//
// and compare. Report throughput, not wall time: b.SetBytes makes the numbers
// comparable across input sizes.

// sizes span a frame payload, a segment, and a whole bundle's byte stream.
var sizes = []int{64, 4 << 10, 1 << 20}

func BenchmarkHardwareCRC32(b *testing.B) {
	for _, n := range sizes {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i)
		}

		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ResetTimer()

			var sink uint32
			for i := 0; i < b.N; i++ {
				sink = format.CRC32(buf)
			}
			_ = sink
		})
	}
}

func BenchmarkHardwareSHA256(b *testing.B) {
	for _, n := range sizes {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i)
		}

		b.Run(fmt.Sprintf("%dB", n), func(b *testing.B) {
			b.SetBytes(int64(n))
			b.ResetTimer()

			var sink [32]byte
			for i := 0; i < b.N; i++ {
				sink = sha256.Sum256(buf)
			}
			_ = sink
		})
	}
}

// BenchmarkHardwareMerkle is the shape the decoder actually hits: many small
// SHA-256 calls over 32-byte inputs rather than one large one. Per-call
// overhead dominates here, so it is the case least helped by acceleration and
// worth measuring separately from raw throughput.
func BenchmarkHardwareMerkle(b *testing.B) {
	for _, count := range []int{16, 1024} {
		leaves := make([][32]byte, count)
		for i := range leaves {
			leaves[i] = sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		}

		b.Run(fmt.Sprintf("%dleaves", count), func(b *testing.B) {
			b.SetBytes(int64(count) * 32)
			b.ResetTimer()

			var sink [32]byte
			for i := 0; i < b.N; i++ {
				sink = format.MerkleRoot(leaves)
			}
			_ = sink
		})
	}
}

// benchSegment builds a segment the way the device builds one.
func benchSegment(b *testing.B, frames int) ([]byte, *format.RootKeyProvider) {
	var deviceID [16]byte
	for i := range deviceID {
		deviceID[i] = byte(0x10 + i)
	}

	keys := &format.RootKeyProvider{Version: 1}
	for i := range keys.Root {
		keys.Root[i] = byte(i)
	}

	w, err := format.NewSegmentWriter(
		format.SegmentHeader{DeviceID: deviceID, StorageKeyVersion: 1}, format.ScanState{}, keys, nil)
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 32)
	for i := range payload {
		payload[i] = byte(i)
	}

	for i := 0; i < frames; i++ {
		if err := w.Append(format.RecordGNSSSample, 1, 0, uint32(i*200), payload); err != nil {
			b.Fatalf("append frame %d: %v", i, err)
		}
	}
	return w.Bytes(), keys
}

// BenchmarkHardwareScanSegment is the end-to-end per-frame path without a key:
// header CRC, body CRC and the chain check. This is the number that matters for
// structural verification, which needs no key and runs wherever the bytes are.
func BenchmarkHardwareScanSegment(b *testing.B) {
	const frames = 4096
	seg, _ := benchSegment(b, frames)

	b.SetBytes(int64(len(seg)))
	b.ReportMetric(float64(frames), "frames/op")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res, err := format.ScanSegment(seg, format.ScanState{}, nil)
		if err != nil {
			b.Fatalf("scan: %v", err)
		}
		if len(res.Frames) != frames {
			b.Fatalf("scanned %d frames, want %d", len(res.Frames), frames)
		}
	}
}

// BenchmarkKeyedScanSegment adds tag verification and decryption of every
// frame: the cost of reading the records, as ingest and decode pay it.
func BenchmarkKeyedScanSegment(b *testing.B) {
	const frames = 4096
	seg, keys := benchSegment(b, frames)

	b.SetBytes(int64(len(seg)))
	b.ReportMetric(float64(frames), "frames/op")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		res, err := format.ScanSegment(seg, format.ScanState{}, keys)
		if err != nil {
			b.Fatalf("scan: %v", err)
		}
		if len(res.Frames) != frames {
			b.Fatalf("scanned %d frames, want %d", len(res.Frames), frames)
		}
	}
}
