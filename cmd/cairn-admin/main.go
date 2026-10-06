// Command cairn-admin manages vehicles, device assignments and app clients.
//
// It edits the same files the running cairn-server reads, so every change is
// effective immediately with no restart — which is the point for revocation: a
// lost phone is an action, not a maintenance window. It needs no network.
//
//	cairn-admin [-data DIR] vehicle add|list|archive|reveal-vin
//	cairn-admin [-data DIR] assign <device-id> <vehicle-id>
//	cairn-admin [-data DIR] unassign <device-id>
//	cairn-admin [-data DIR] assignments [device-id]
//	cairn-admin [-data DIR] counters <device-id>
//	cairn-admin [-data DIR] client invite|list|revoke
//
// Device enrolment, including escrowing its storage root, stays on
// `cairn-server -enroll`, because it must happen with the keystore's master key.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/clients"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/counters"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/syncapi"
	"github.com/ParkWardRR/cairn-vehicle-server/internal/vehicles"
)

func main() {
	dataDir := flag.String("data", "/var/lib/cairn", "cairn-server data directory")
	master := flag.String("keystore-master", "",
		"keystore master key file (needed by `device enroll`; default <data>/keys/keystore.master)")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	if err := run(*dataDir, *master, args); err != nil {
		fmt.Fprintln(os.Stderr, "cairn-admin:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: cairn-admin [-data DIR] <command>

  vehicle add --name N [--year Y --make M --model M --engine E --vin V --id HEX]
  vehicle list
  vehicle archive <id>
  vehicle reveal-vin <id>
  assign [--assignment-id HEX] <device-id> <vehicle-id>
  unassign <device-id>
  assignments [device-id]
  counters <device-id>
  device enroll --blob B64 --confirm-fingerprint 8HEX [--name N] [--allow-key-change] [--reinstate]
  device list
  client invite [--role user|admin] [--vehicles id,id|*] [--name N] [--ttl 10m]
  client list
  client revoke <id> [reason]
`)
}

func run(dataDir, master string, args []string) error {
	paths := syncapi.DataPaths(dataDir)

	switch args[0] {
	case "vehicle":
		reg, err := vehicles.Open(paths.Vehicles, paths.VehicleKey)
		if err != nil {
			return err
		}
		return vehicleCmd(reg, args[1:])
	case "assign", "unassign", "assignments":
		reg, err := vehicles.Open(paths.Vehicles, paths.VehicleKey)
		if err != nil {
			return err
		}
		return assignCmd(reg, args)
	case "counters":
		return countersCmd(dataDir, args[1:])
	case "device":
		return deviceCmd(dataDir, master, args[1:])
	case "client":
		reg, err := clients.Open(paths.Clients)
		if err != nil {
			return err
		}
		return clientCmd(reg, args[1:])
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func vehicleCmd(reg *vehicles.Registry, args []string) error {
	if len(args) == 0 {
		return errors.New("vehicle: expected add, list, archive or reveal-vin")
	}
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("vehicle add", flag.ExitOnError)
		name := fs.String("name", "", "display name, e.g. \"2017 BMW M240i — B58\"")
		year := fs.Int("year", 0, "model year")
		make_ := fs.String("make", "", "make")
		model := fs.String("model", "", "model")
		engine := fs.String("engine", "", "engine family code (a label, not an identity)")
		vin := fs.String("vin", "", "17-character VIN (sealed at rest; only the last four stay readable)")
		id := fs.String("id", "", "32-hex vehicle ID (restore only; normally generated)")
		_ = fs.Parse(args[1:])
		v, err := reg.CreateVehicle(vehicles.NewVehicleSpec{
			ID: *id, DisplayName: *name, Year: *year, Make: *make_, Model: *model, EngineCode: *engine, VIN: *vin,
		})
		if err != nil {
			return err
		}
		fmt.Printf("created vehicle %s  %s\n", v.ID, v.DisplayName)
		return nil
	case "list":
		for _, v := range reg.Vehicles() {
			state := ""
			if v.Archived() {
				state = "  [archived]"
			}
			vin := ""
			if v.VINLast4 != "" {
				vin = "  VIN …" + v.VINLast4
			}
			fmt.Printf("%s  %-32s %s%s%s\n", v.ID, v.DisplayName, v.EngineCode, vin, state)
		}
		return nil
	case "archive":
		if len(args) != 2 {
			return errors.New("vehicle archive <id>")
		}
		if err := reg.Archive(args[1]); err != nil {
			return err
		}
		fmt.Println("archived", args[1], "- it accepts no new bundles and its recorder is free")
		return nil
	case "reveal-vin":
		if len(args) != 2 {
			return errors.New("vehicle reveal-vin <id>")
		}
		vin, err := reg.RevealVIN(args[1])
		if err != nil {
			return err
		}
		fmt.Println(vin)
		return nil
	}
	return fmt.Errorf("vehicle: unknown subcommand %q", args[0])
}

func assignCmd(reg *vehicles.Registry, args []string) error {
	switch args[0] {
	case "assign":
		// --assignment-id pins the assignment's ID (restore and test fixtures only;
		// normally it is generated).
		pinned := ""
		if len(args) >= 3 && args[1] == "--assignment-id" {
			pinned, args = args[2], append([]string{args[0]}, args[3:]...)
		}
		if len(args) != 3 {
			return errors.New("assign [--assignment-id HEX] <device-id> <vehicle-id>")
		}
		a, err := reg.AssignWithID(pinned, args[1], args[2], "cairn-admin")
		if err != nil {
			return err
		}
		fmt.Printf("assignment %s: device %s -> vehicle %s (#%d)\n", a.ID, a.DeviceID, a.VehicleID, a.Seq)
		fmt.Println("the device must be given this assignment ID before it seals bundles under it")
		return nil
	case "unassign":
		if len(args) != 2 {
			return errors.New("unassign <device-id>")
		}
		return reg.Unassign(args[1])
	case "assignments":
		dev := ""
		if len(args) > 1 {
			dev = args[1]
		}
		for _, a := range reg.Assignments(dev) {
			end := "open"
			if !a.Open() {
				end = "ended " + a.EndsAt.Format(time.RFC3339)
			}
			fmt.Printf("%s  device %s -> vehicle %s  #%d  %s  counters %d..%d\n",
				a.ID, a.DeviceID, a.VehicleID, a.Seq, end, a.FirstCounter, a.LastCounter)
		}
		return nil
	}
	return nil
}

func countersCmd(dataDir string, args []string) error {
	if len(args) != 1 {
		return errors.New("counters <device-id>")
	}
	g, err := counters.Open(dataDir + "/counters.json")
	if err != nil {
		return err
	}
	fmt.Printf("high-water counter: %d\n", g.HighWater(args[0]))
	if missing := g.Missing(args[0]); len(missing) > 0 {
		fmt.Printf("missing (sealed but never received): %v\n", missing)
	} else {
		fmt.Println("no missing counters")
	}
	return nil
}

func clientCmd(reg *clients.Registry, args []string) error {
	if len(args) == 0 {
		return errors.New("client: expected invite, list or revoke")
	}
	switch args[0] {
	case "invite":
		fs := flag.NewFlagSet("client invite", flag.ExitOnError)
		role := fs.String("role", "user", "user or admin")
		scope := fs.String("vehicles", "*", "comma-separated vehicle IDs, or * for all")
		name := fs.String("name", "", "label shown in listings")
		ttl := fs.Duration("ttl", 0, "lifetime (default 10m)")
		replaces := fs.String("replaces", "", "id of a client to revoke when this invitation is accepted (key rotation); role, vehicles and name default to that client's")
		_ = fs.Parse(args[1:])
		set := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if *replaces != "" {
			// Rotating a key should not quietly change what the phone may do, so the
			// defaults come from the client being replaced; a flag still overrides.
			old, err := reg.Get(*replaces)
			if err != nil {
				return err
			}
			if !set["role"] {
				*role = string(old.Role)
			}
			if !set["vehicles"] {
				*scope = strings.Join(old.Vehicles, ",")
			}
			if !set["name"] {
				*name = old.Name
			}
		}
		code, inv, err := reg.CreateInvite(clients.InviteSpec{
			Role: clients.Role(*role), Vehicles: strings.Split(*scope, ","), Name: *name,
			CreatedBy: "cairn-admin", TTL: *ttl, Replaces: *replaces,
		})
		if err != nil {
			return err
		}
		fmt.Printf("invitation code (shown once, single use, expires %s):\n\n    %s\n\n",
			inv.ExpiresAt.Format(time.RFC3339), clients.FormatCode(code))
		fmt.Printf("role %s, vehicles %s\n", inv.Role, strings.Join(inv.Vehicles, ","))
		if inv.Replaces != "" {
			fmt.Printf("accepting it revokes client %s in the same write\n", inv.Replaces)
		}
		return nil
	case "list":
		for _, c := range reg.List() {
			seen := "never"
			if !c.LastSeenAt.IsZero() {
				seen = c.LastSeenAt.Format(time.RFC3339) + " via " + c.LastTransport
			}
			extra := ""
			if c.Status == clients.StatusRevoked {
				extra = "  (" + c.RevokedReason + ")"
			}
			fmt.Printf("%s  %-18s %-5s %-8s key %s  last seen %s%s\n", c.ID, c.Name, c.Role, c.Status, c.KeyID, seen, extra)
		}
		return nil
	case "revoke":
		if len(args) < 2 {
			return errors.New("client revoke <id> [reason]")
		}
		reason := "revoked by operator"
		if len(args) > 2 {
			reason = strings.Join(args[2:], " ")
		}
		if err := reg.Revoke(args[1], reason); err != nil {
			return err
		}
		fmt.Println("revoked", args[1], "- effective on its next request; also remove it from the tailnet")
		return nil
	}
	return fmt.Errorf("client: unknown subcommand %q", args[0])
}
