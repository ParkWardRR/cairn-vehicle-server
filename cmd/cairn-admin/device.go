package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/devices"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/enroll"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/keystore"
)

func deviceCmd(dataDir, master string, args []string) error {
	if len(args) == 0 {
		return errors.New("device: expected enroll or list")
	}
	switch args[0] {
	case "list":
		reg, err := devices.Open(filepath.Join(dataDir, "devices.json"))
		if err != nil {
			return err
		}
		for _, d := range reg.List() {
			status := "active"
			if d.Revoked {
				status = "REVOKED: " + d.RevokedReason
			}
			fmt.Printf("%s  %-20s key=%s  %s\n", d.DeviceID, d.Name, d.KeyIDHex, status)
		}
		return nil
	case "enroll":
		return deviceEnroll(dataDir, master, args[1:])
	}
	return fmt.Errorf("device: unknown subcommand %q", args[0])
}

// deviceEnroll turns a dongle's sealed enrolment blob into an enrolled device
// with an escrowed storage root.
//
// There is deliberately no flag that skips the fingerprint: approving "whatever
// arrived" would make this a way to enrol any key someone can get onto a
// clipboard. The operator reads the 8-hex FINGERPRINT off the dongle's console
// and types it here.
func deviceEnroll(dataDir, master string, args []string) error {
	fs := flag.NewFlagSet("device enroll", flag.ExitOnError)
	blob := fs.String("blob", "", "the dongle's ENROLL-BLOB line, or its bare base64")
	fp := fs.String("confirm-fingerprint", "", "the 8-hex FINGERPRINT the dongle printed (required)")
	name := fs.String("name", "", "friendly name")
	allowKey := fs.Bool("allow-key-change", false, "accept a different signing key for an already-enrolled device id")
	reinstate := fs.Bool("reinstate", false, "re-admit a revoked device")
	_ = fs.Parse(args)

	if *blob == "" {
		return errors.New("--blob is required")
	}
	raw, err := enroll.DecodeText(*blob)
	if err != nil {
		return err
	}

	if master == "" {
		master = filepath.Join(dataDir, "keys", "keystore.master")
	}
	// Refuse to create a master key here. Opening the keystore would mint a
	// fresh one if the file were missing, and escrowing a root under a key that
	// is not the server's real one would "work" and then fail to decrypt later.
	if _, err := os.Stat(master); err != nil {
		return fmt.Errorf("keystore master key %s: %w (pass --keystore-master, never create a new one by accident)", master, err)
	}

	ks, err := keystore.Open(filepath.Join(dataDir, "keystore.json"), master)
	if err != nil {
		return err
	}
	reg, err := devices.Open(filepath.Join(dataDir, "devices.json"))
	if err != nil {
		return err
	}
	guard, err := counters.Open(filepath.Join(dataDir, "counters.json"))
	if err != nil {
		return err
	}
	key, err := enroll.LoadServerKey(enroll.ServerKeyPath(dataDir), ks)
	if err != nil {
		return err
	}

	res, err := enroll.Enroll(enroll.Request{
		Blob: raw, ConfirmFingerprint: *fp, Name: *name, AllowKeyChange: *allowKey, Reinstate: *reinstate,
	}, enroll.Deps{Registry: reg, Keys: ks, Counters: guard, ServerKey: key})
	if err != nil {
		return err
	}

	again := ""
	if res.RootAlreadyEscrowed {
		again = " (this exact root was already escrowed: a harmless repeat)"
	}
	// Machine-readable lines first: cairn-provision parses these.
	fmt.Printf("device_id %s\n", res.DeviceID)
	fmt.Printf("fingerprint %s\n", res.Fingerprint)
	fmt.Printf("key_version %d\n", res.KeyVersion)
	fmt.Printf("counter_floor %d\n", res.CounterFloor)
	fmt.Printf("enrolled %s (%s), key ID %s, storage root escrowed as version %d%s\n",
		res.DeviceID, res.Name, res.KeyIDHex, res.KeyVersion, again)
	fmt.Println("next: assign it to a vehicle (cairn-admin assign) — bundles from an unassigned device are refused")
	return nil
}
