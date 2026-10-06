// Command cairn-signfw signs a firmware image for OTA.
//
// The update key is deliberately separate from the receipt key: the receipt key
// says "this data is safe to delete", the update key says "this code is safe to
// run". A server compromised enough to issue false receipts costs stored trips;
// one that could also sign firmware owns the device.
//
//	cairn-signfw -genkey -key update.seed
//	cairn-signfw -key update.seed -print-public
//	cairn-signfw -key update.seed -image firmware.bin -version cairn-v2.1.0 -out fw-v2.1.0
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/format"
)

func main() {
	var (
		keyPath = flag.String("key", "", "Ed25519 seed file for the update key")
		genKey  = flag.Bool("genkey", false, "create the seed file and exit")
		print   = flag.Bool("print-public", false,
			"print the update public key to pin in firmware, and exit")

		imagePath = flag.String("image", "", "firmware image to sign")
		version   = flag.String("version", "", "firmware version, e.g. cairn-v2.1.0")
		minVer    = flag.String("min-version", "",
			"refuse to install over firmware older than this")
		out = flag.String("out", "", "output prefix; writes <out>.cbor and <out>.sig")
	)
	flag.Parse()

	if err := run(*keyPath, *genKey, *print, *imagePath, *version, *minVer, *out); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(keyPath string, genKey, printPub bool, imagePath, version, minVer, out string) error {
	if keyPath == "" {
		return errors.New("-key is required")
	}

	if genKey {
		return generateKey(keyPath)
	}

	seed, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read update key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("update key is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	if printPub {
		// Key on stdout so it pipes; the guidance on stderr.
		fmt.Println(hex.EncodeToString(pub))
		fmt.Fprintln(os.Stderr,
			"pin this in firmware/cairn-v2/include/secrets.h as CAIRN_UPDATE_KEY_HEX")
		fmt.Fprintln(os.Stderr,
			"leaving it undefined disables OTA entirely, which is the correct "+
				"default: a device that cannot verify an update has no business "+
				"installing one")
		return nil
	}

	if imagePath == "" || version == "" || out == "" {
		return errors.New("-image, -version and -out are required to sign")
	}

	image, err := os.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("read image: %w", err)
	}
	if len(image) == 0 {
		return errors.New("image is empty")
	}

	sum := sha256.Sum256(image)

	desc := format.UpdateDescriptor{
		DescriptorVersion:  format.UpdateDescriptorVersion,
		FirmwareVersion:    version,
		ImageSHA256:        sum,
		ImageLength:        uint32(len(image)),
		MinFirmwareVersion: minVer,
		BuildUTCMS:         uint64(time.Now().UnixMilli()),
		SignatureAlgorithm: format.SignatureAlgorithmEd25519,
	}

	encoded, sig, err := desc.Sign(priv)
	if err != nil {
		return fmt.Errorf("sign descriptor: %w", err)
	}

	// Verify what was just produced before writing it. A descriptor that does
	// not verify here will not verify on the device either, and finding out now
	// costs nothing — whereas shipping one means a device that refuses to
	// update for a reason it cannot explain.
	if _, err := format.VerifyUpdateDescriptor(encoded, sig, pub); err != nil {
		return fmt.Errorf("freshly signed descriptor does not verify: %w", err)
	}

	descPath := out + ".cbor"
	sigPath := out + ".sig"

	if err := writeNew(descPath, encoded); err != nil {
		return err
	}
	if err := writeNew(sigPath, sig); err != nil {
		return err
	}

	fmt.Printf("signed %s (%d bytes)\n", filepath.Base(imagePath), len(image))
	fmt.Printf("  version      %s\n", version)
	if minVer != "" {
		fmt.Printf("  min version  %s\n", minVer)
	}
	fmt.Printf("  image sha256 %s\n", hex.EncodeToString(sum[:]))
	fmt.Printf("  descriptor   %s (%d bytes)\n", descPath, len(encoded))
	fmt.Printf("  signature    %s\n", sigPath)
	fmt.Printf("\nServe the image at its hash, alongside the descriptor:\n")
	fmt.Printf("  %s -> %s\n", hex.EncodeToString(sum[:]), imagePath)

	return nil
}

func generateKey(path string) error {
	// Refuse to overwrite: replacing an update key silently would strand every
	// device that pinned the old one, with no way to deliver a fix.
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite an update "+
			"key that devices may already have pinned", path)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	seed := priv.Seed()
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	fmt.Printf("update key written to %s\n", path)
	fmt.Printf("public key: %s\n", hex.EncodeToString(pub))
	fmt.Fprintln(os.Stderr,
		"\nback this up. Losing it means no further updates can be signed for "+
			"devices that pinned it, and the only remedy is reflashing each one "+
			"over serial.")
	return nil
}

func writeNew(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
