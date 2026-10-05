// Command cairn-provision enrols a Cairn dongle with the server over USB and
// installs its vehicle assignment and counter floor.
//
//	cairn-provision --port /dev/cu.usbserial-10 --reset \
//	  --admin-cmd 'ssh user@host sudo -u cairn cairn-admin -data /var/lib/cairn -keystore-master /etc/cairn/keystore.master' \
//	  --vehicle <32hex> --name car
//
// The dongle holds no network credential, so nothing secret is provisioned: no
// Wi-Fi password, no client certificate, no private key. The device's storage
// root is sealed to the server's enrolment key on the device and never printed
// in the clear. See docs/device-provisioning.md.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"go.bug.st/serial"
)

type serialConn struct {
	port serial.Port
	r    *bufio.Reader
}

// Write paces the bytes. The firmware has a large receive buffer, but a
// microcontroller that is also writing a card and running a radio does not drain
// it instantly, and a dropped byte in a base64 credential is indistinguishable
// from a bad credential. Small chunks with a short gap cost a second or two per
// run and remove the failure mode.
func (s *serialConn) Write(b []byte) (int, error) {
	const chunk = 128
	total := 0
	for len(b) > 0 {
		n := min(chunk, len(b))
		w, err := s.port.Write(b[:n])
		total += w
		if err != nil {
			return total, err
		}
		b = b[n:]
		if len(b) > 0 {
			time.Sleep(8 * time.Millisecond)
		}
	}
	return total, nil
}

func (s *serialConn) ReadLine(deadline time.Time) (string, error) {
	// The serial library's read timeout is per call; poll in short slices so the
	// overall deadline holds.
	for {
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timed out waiting for the device")
		}
		line, err := s.r.ReadString('\n')
		if err == nil {
			return line, nil
		}
		if err != io.EOF && !isTimeout(err) {
			return "", err
		}
	}
}

func isTimeout(err error) bool { return err != nil && strings.Contains(err.Error(), "timeout") }

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cairn-provision: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	port := flag.String("port", "", "serial port, e.g. /dev/cu.usbserial-10")
	baud := flag.Int("baud", 115200, "baud rate")
	reset := flag.Bool("reset", false, "reset the board first (RTS pulse): a provisioned device only listens for 60 s after boot")
	admin := flag.String("admin-cmd", "", "shell prefix that runs cairn-admin on the server host (omit to skip server enrolment)")
	vehicle := flag.String("vehicle", "", "vehicle ID (32 hex) to assign the device to")
	assignment := flag.String("assignment", "", "existing assignment ID (32 hex); created if omitted and --vehicle is given")
	name := flag.String("name", "", "friendly device name for the server")
	expectID := flag.String("expect-device-id", "", "abort unless the device reports this id (from an independent record)")
	expectFP := flag.String("expect-fingerprint", "", "abort unless the device reports this fingerprint (from an independent record)")
	monitor := flag.Int("monitor", 0, "just print the console for this many seconds (with --reset: from boot) and exit; provisions nothing")
	yes := flag.Bool("yes", false, "do not prompt for confirmation (the fingerprint is still printed)")
	flag.Parse()

	if *port == "" {
		fatal("--port is required")
	}

	p := Plan{AdminCmd: *admin, Vehicle: strings.ToLower(*vehicle), Assignment: strings.ToLower(*assignment),
		Name: *name, ExpectDeviceID: *expectID, ExpectFingerprint: *expectFP,
		Log: func(f string, a ...any) { fmt.Printf("  "+f+"\n", a...) }}

	p.Confirm = func(id, fp string) (bool, error) {
		fmt.Printf("\nDevice %s\nFingerprint %s\n", id, fp)
		if *yes {
			return true, nil
		}
		fmt.Print("Is this the unit in front of you? Enroll it? [y/N] ")
		var ans string
		fmt.Scanln(&ans)
		return strings.EqualFold(strings.TrimSpace(ans), "y"), nil
	}

	sp, err := serial.Open(*port, &serial.Mode{BaudRate: *baud})
	if err != nil {
		fatal("open %s: %v", *port, err)
	}
	defer sp.Close()
	_ = sp.SetReadTimeout(500 * time.Millisecond)

	if *reset {
		// Auto-reset circuit: RTS drives EN, DTR drives GPIO0. Keep GPIO0 high
		// (normal boot) and pulse EN low.
		_ = sp.SetDTR(false)
		_ = sp.SetRTS(true)
		time.Sleep(120 * time.Millisecond)
		_ = sp.SetRTS(false)
		fmt.Println("reset sent")
		if *monitor == 0 {
			fmt.Println("waiting for the device to boot")
			time.Sleep(2500 * time.Millisecond)
		}
	}
	if *monitor == 0 {
		_ = sp.ResetInputBuffer() // monitoring wants the boot lines, provisioning does not
	}

	c := &serialConn{port: sp, r: bufio.NewReader(sp)}

	if *monitor > 0 {
		// The device never writes a credential to its console, so this is safe to
		// show; the non-printable bytes of the reset transient are dropped.
		end := time.Now().Add(time.Duration(*monitor) * time.Second)
		for time.Now().Before(end) {
			line, err := c.ReadLine(end)
			if err != nil {
				break
			}
			clean := strings.Map(func(r rune) rune {
				if r == '\t' || (r >= 0x20 && r < 0x7f) {
					return r
				}
				return -1
			}, line)
			if strings.TrimSpace(clean) != "" {
				fmt.Println(clean)
			}
		}
		return
	}
	if err := Run(c, p); err != nil {
		fatal("%v", err)
	}
	fmt.Println("done")
}
