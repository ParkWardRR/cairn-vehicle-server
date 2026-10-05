package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	devID   = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	devFP   = "5fd41190"
	vehID   = "606162636465666768696a6b6c6d6e6f"
	asgID   = "707172737475767778797a7b7c7d7e7f"
)

// fakeDevice speaks the console protocol the firmware speaks, including the
// log noise a real console carries between replies.
type fakeDevice struct {
	toHost   *io.PipeWriter
	fromHost *bufio.Reader
	hostR    *io.PipeReader

	mu       sync.Mutex
	received []string
	refuse   string // if set, BEGIN is refused with this reason
	bootAt   time.Time
	bootWait time.Duration
}

type pipeConn struct {
	w     io.Writer
	lines chan string
	d     *fakeDevice
}

func (p *pipeConn) Write(b []byte) (int, error) { return p.w.Write(b) }

// ReadLine takes lines from one long-lived reader. A reader goroutine per call
// would leave a stale one behind after every timeout, and that one would then
// swallow the next line meant for a later call.
func (p *pipeConn) ReadLine(deadline time.Time) (string, error) {
	select {
	case l, ok := <-p.lines:
		if !ok {
			return "", io.EOF
		}
		return l, nil
	case <-time.After(time.Until(deadline)):
		return "", errors.New("timed out waiting for the device")
	}
}

func newPair(refuse string, bootWait time.Duration) (*pipeConn, *fakeDevice) {
	hostToDevR, hostToDevW := io.Pipe()
	devToHostR, devToHostW := io.Pipe()
	d := &fakeDevice{toHost: devToHostW, fromHost: bufio.NewReader(hostToDevR), hostR: hostToDevR,
		refuse: refuse, bootAt: time.Now(), bootWait: bootWait}
	go d.run()
	lines := make(chan string, 64)
	go func() {
		r := bufio.NewReader(devToHostR)
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				close(lines)
				return
			}
			lines <- l
		}
	}()
	return &pipeConn{w: hostToDevW, lines: lines, d: d}, d
}

func (d *fakeDevice) say(s string) { fmt.Fprintf(d.toHost, "%s\n", s) }

func (d *fakeDevice) run() {
	d.say("I (123) BOOT some log line that is not a reply")
	for {
		line, err := d.fromHost.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		d.mu.Lock()
		d.received = append(d.received, line)
		d.mu.Unlock()

		d.say("[PROV] I log noise between replies")
		switch {
		case line == "CAIRN-PROV BEGIN":
			if time.Since(d.bootAt) < d.bootWait {
				continue // still booting: silence, like a real device
			}
			if d.refuse != "" {
				d.say("@prov ERR refused: " + d.refuse)
			} else {
				d.say("@prov PROV-READY " + devID + " " + devFP)
			}
		case line == "GET enroll_blob":
			d.say("@prov ENROLL-BLOB Q0VOUg==")
		default:
			d.say("@prov OK")
		}
	}
}

func (d *fakeDevice) lines() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.received...)
}

// fakeAdmin writes a script that behaves like cairn-admin for the two commands
// the tool issues, and records its environment and arguments.
func fakeAdmin(t *testing.T, floor int, enrolledID string) (prefix, record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(dir, "calls.log")
	script := filepath.Join(dir, "cairn-admin")
	body := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
case "$1" in
  device) echo "device_id %s"; echo "fingerprint %s"; echo "key_version 1"; echo "counter_floor %d"; echo "enrolled x";;
  assign) echo "assignment %s: device $2 -> vehicle $3 (#1)";;
esac
`, record, enrolledID, devFP, floor, asgID)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, record
}

func basePlan(prefix string) Plan {
	return Plan{
		AdminCmd: prefix, Vehicle: vehID,
		Confirm: func(string, string) (bool, error) { return true, nil },
		Timeout: 2 * time.Second, BeginRetry: 3 * time.Second,
	}
}

func TestFullFlowInstallsAssignmentAndFloorAndSendsNoCredentials(t *testing.T) {
	prefix, record := fakeAdmin(t, 7, devID)
	conn, dev := newPair("", 0)

	var logged strings.Builder
	p := basePlan(prefix)
	p.Log = func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) }

	if err := Run(conn, p); err != nil {
		t.Fatal(err)
	}

	got := dev.lines()
	want := []string{"CAIRN-PROV BEGIN", "GET enroll_blob"}
	for i, w := range want {
		if got[i] != w {
			t.Fatalf("line %d = %q, want %q", i, got[i], w)
		}
	}
	joined := strings.Join(got, "\n")
	for _, must := range []string{
		"SET assignment " + vehID + " " + asgID, "SET counter_floor 7", "COMMIT"} {
		if !strings.Contains(joined, must) {
			t.Fatalf("the device never received %q; got:\n%s", must, joined)
		}
	}
	// COMMIT is the last thing sent, after every value was staged.
	if got[len(got)-1] != "COMMIT" {
		t.Fatalf("tail of the conversation = %q", got[len(got)-2:])
	}

	// The server was asked to enrol, with the device's fingerprint, then to assign.
	rec, _ := os.ReadFile(record)
	if !strings.Contains(string(rec), "device enroll --blob Q0VOUg== --confirm-fingerprint "+devFP) {
		t.Fatalf("enrolment call wrong:\n%s", rec)
	}
	if !strings.Contains(string(rec), "assign "+devID+" "+vehID) {
		t.Fatalf("assignment call wrong:\n%s", rec)
	}

	// The dongle holds no network credential, so the tool must never send one:
	// no Wi-Fi, no client certificate, no private key. A regression that
	// re-added any of them would put a secret on the chip this change exists to
	// keep clean.
	for _, l := range got {
		for _, banned := range []string{"wifi_", "client_cert", "client_key", "PRIVATE KEY"} {
			if strings.Contains(l, banned) {
				t.Fatalf("the tool sent %q to the device", l)
			}
		}
	}
}

func TestMismatchedServerDeviceIsRefusedBeforeAnythingIsInstalled(t *testing.T) {
	prefix, _ := fakeAdmin(t, 1, "ffffffffffffffffffffffffffffffff") // server enrolled someone else
	conn, dev := newPair("", 0)
	err := Run(conn, basePlan(prefix))
	if err == nil || !strings.Contains(err.Error(), "enrolled device") {
		t.Fatalf("err = %v", err)
	}
	for _, l := range dev.lines() {
		if strings.HasPrefix(l, "SET ") || l == "COMMIT" {
			t.Fatalf("installed %q after the server disagreed about which device this is", l)
		}
	}
}

func TestDeclinedConfirmationEnrolsNothing(t *testing.T) {
	prefix, record := fakeAdmin(t, 1, devID)
	conn, dev := newPair("", 0)
	p := basePlan(prefix)
	p.Confirm = func(string, string) (bool, error) { return false, nil }
	if err := Run(conn, p); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(record); err == nil {
		t.Fatal("the server was called although the operator declined")
	}
	for _, l := range dev.lines() {
		if strings.HasPrefix(l, "SET ") || l == "COMMIT" {
			t.Fatalf("installed %q after a declined confirmation", l)
		}
	}
}

func TestRefusedSessionIsReportedNotRetriedForever(t *testing.T) {
	prefix, _ := fakeAdmin(t, 1, devID)
	conn, _ := newPair("a trip is active", 0)
	start := time.Now()
	err := Run(conn, basePlan(prefix))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("kept retrying a device that explicitly refused")
	}
}

func TestWaitsForADeviceThatIsStillBooting(t *testing.T) {
	prefix, _ := fakeAdmin(t, 1, devID)
	conn, _ := newPair("", 1200*time.Millisecond)
	if err := Run(conn, basePlan(prefix)); err != nil {
		t.Fatalf("a device that needed a moment to boot was given up on: %v", err)
	}
}

func TestSilentDeviceTimesOutWithAHelpfulMessage(t *testing.T) {
	conn, _ := newPair("", time.Hour)
	p := basePlan("")
	p.BeginRetry = 1500 * time.Millisecond
	err := Run(conn, p)
	if err == nil || !strings.Contains(err.Error(), "60 s after boot") {
		t.Fatalf("err = %v", err)
	}
}
