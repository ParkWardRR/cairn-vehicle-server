package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Plan is everything a provisioning run needs. The dongle holds no network
// credential (no Wi-Fi, no client certificate), so there is no secret in it:
// what is installed is the vehicle assignment and the counter floor.
type Plan struct {
	AdminCmd string // shell prefix that runs cairn-admin on the server host

	Vehicle    string // 32 hex; with no Assignment, one is created
	Assignment string // 32 hex

	// Garage is the cars the dongle moves between, each with the engine profile its
	// VIN will name. Each gets an open assignment (cairn-admin assign --keep, which
	// reuses one the device already holds), and the device is told all of them. With
	// a garage, Vehicle (optional) is the car the dongle is in now and must be one of
	// them: a plain assign would end the others.
	Garage []GarageCar

	Name string

	// ExpectDeviceID and ExpectFingerprint, when set, must match what the device
	// reports. They are the non-interactive form of the human check: values taken
	// from a source other than the console (a record made when the unit was first
	// enrolled) rather than from the channel being verified.
	ExpectDeviceID    string
	ExpectFingerprint string

	Confirm func(deviceID, fingerprint string) (bool, error)
	Log     func(format string, args ...any)

	// BeginRetry is how long to keep sending BEGIN: after a reset the device
	// needs a few seconds to boot before it is listening.
	BeginRetry time.Duration
	Timeout    time.Duration // per reply
}

// GarageCar is one car of a garage.
type GarageCar struct {
	Vehicle    string // 32 hex
	Engine     string // engine profile id, e.g. bmw-b58
	Assignment string // filled in from the server
}

var engineID = regexp.MustCompile(`^[a-z0-9-]{1,23}$`)

// ParseGarage reads "vehicle=engine,vehicle=engine".
func ParseGarage(s string) ([]GarageCar, error) {
	var out []GarageCar
	for _, part := range strings.Split(s, ",") {
		veh, eng, ok := strings.Cut(strings.TrimSpace(part), "=")
		veh, eng = strings.ToLower(veh), strings.ToLower(eng)
		if !ok || !hex32.MatchString(veh) || !engineID.MatchString(eng) {
			return nil, fmt.Errorf("garage entry %q: want <vehicle 32 hex>=<engine id>", part)
		}
		for _, g := range out {
			if g.Vehicle == veh {
				return nil, fmt.Errorf("garage names vehicle %s twice", veh)
			}
		}
		out = append(out, GarageCar{Vehicle: veh, Engine: eng})
	}
	if len(out) == 0 || len(out) > 4 {
		return nil, fmt.Errorf("a garage holds 1 to 4 cars, got %d", len(out))
	}
	return out, nil
}

// Conn is a line-oriented console.
type Conn interface {
	io.Writer
	ReadLine(deadline time.Time) (string, error)
}

// replyPrefix marks protocol replies. The console also carries the device's
// log, so anything without it is ignored.
const replyPrefix = "@prov "

var (
	hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex8  = regexp.MustCompile(`^[0-9a-f]{8}$`)
)

// expect reads until a protocol reply arrives and returns it without the prefix.
func expect(c Conn, timeout time.Duration) (string, error) {
	return expectReply(c, timeout, false)
}

// expectReply is expect with control over stale ready-replies.
//
// After a reset the tool sends BEGIN repeatedly until the device finishes
// booting, and a device that was only slow rather than deaf answers every one of
// them. Those late PROV-READY lines then arrive while the tool is waiting for the
// reply to something else, and must not be mistaken for it. Once a session is
// open they are skipped; only the BEGIN loop itself wants them.
func expectReply(c Conn, timeout time.Duration, wantReady bool) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		line, err := c.ReadLine(deadline)
		if err != nil {
			return "", err
		}
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), strings.TrimSpace(replyPrefix))
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if !wantReady && strings.HasPrefix(rest, "PROV-READY ") {
			continue
		}
		return rest, nil
	}
}

func send(c Conn, line string) error {
	_, err := io.WriteString(c, line+"\n")
	return err
}

// cmd sends a line and requires "OK".
func cmd(c Conn, timeout time.Duration, line, what string) error {
	if err := send(c, line); err != nil {
		return err
	}
	reply, err := expect(c, timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if reply != "OK" {
		return fmt.Errorf("%s: device said %q", what, reply)
	}
	return nil
}

// Run executes the provisioning flow.
func Run(c Conn, p Plan) error {
	if p.Log == nil {
		p.Log = func(string, ...any) {}
	}
	if p.Timeout == 0 {
		p.Timeout = 10 * time.Second
	}
	if p.BeginRetry == 0 {
		p.BeginRetry = 30 * time.Second
	}
	// 1. open a session, retrying while the device boots.
	var deviceID, fingerprint string
	begin := time.Now().Add(p.BeginRetry)
	for {
		if err := send(c, "CAIRN-PROV BEGIN"); err != nil {
			return err
		}
		reply, err := expectReply(c, 2*time.Second, true)
		if err == nil {
			if rest, ok := strings.CutPrefix(reply, "PROV-READY "); ok {
				f := strings.Fields(rest)
				if len(f) == 2 && hex32.MatchString(f[0]) && hex8.MatchString(f[1]) {
					deviceID, fingerprint = f[0], f[1]
					break
				}
				return fmt.Errorf("malformed PROV-READY: %q", reply)
			}
			if strings.HasPrefix(reply, "ERR refused") {
				return fmt.Errorf("the device refused to open a session: %s", reply)
			}
		}
		if time.Now().After(begin) {
			return errors.New("no PROV-READY from the device: is it powered, is the port right, " +
				"and was it reset within the last minute (a provisioned device only listens for 60 s after boot)?")
		}
	}
	p.Log("device %s, fingerprint %s", deviceID, fingerprint)
	if p.ExpectDeviceID != "" && !strings.EqualFold(p.ExpectDeviceID, deviceID) {
		_ = send(c, "CAIRN-PROV END")
		return fmt.Errorf("this is device %s, not the expected %s: nothing was enrolled", deviceID, p.ExpectDeviceID)
	}
	if p.ExpectFingerprint != "" && !strings.EqualFold(p.ExpectFingerprint, fingerprint) {
		_ = send(c, "CAIRN-PROV END")
		return fmt.Errorf("fingerprint %s does not match the expected %s: nothing was enrolled", fingerprint, p.ExpectFingerprint)
	}

	// 2. fetch the sealed enrolment blob.
	if err := send(c, "GET enroll_blob"); err != nil {
		return err
	}
	reply, err := expect(c, p.Timeout)
	if err != nil {
		return err
	}
	blob, ok := strings.CutPrefix(reply, "ENROLL-BLOB ")
	if !ok {
		return fmt.Errorf("the device could not produce an enrolment blob: %s", reply)
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(blob); err != nil {
		return fmt.Errorf("the device's enrolment blob is not valid base64: %w", err)
	}

	// 3. a human confirms that this is the unit in front of them.
	if p.Confirm != nil {
		yes, err := p.Confirm(deviceID, fingerprint)
		if err != nil {
			return err
		}
		if !yes {
			_ = send(c, "CAIRN-PROV END")
			return errors.New("not confirmed; nothing was enrolled")
		}
	}

	// 4. enrol on the server.
	floor := uint64(0)
	if p.AdminCmd != "" {
		out, err := runAdmin(p.AdminCmd, `device enroll --blob "$CAIRN_BLOB" --confirm-fingerprint "$CAIRN_FP"`+nameArg(p.Name),
			map[string]string{"CAIRN_BLOB": blob, "CAIRN_FP": fingerprint, "CAIRN_NAME": p.Name})
		if err != nil {
			return fmt.Errorf("server enrolment failed: %w", err)
		}
		kv := parseKV(out)
		if kv["device_id"] != deviceID {
			return fmt.Errorf("the server enrolled device %q but the console said %q", kv["device_id"], deviceID)
		}
		floor, err = strconv.ParseUint(kv["counter_floor"], 10, 64)
		if err != nil {
			return fmt.Errorf("the server did not return a counter floor: %q", kv["counter_floor"])
		}
		p.Log("enrolled on the server; counter floor %d", floor)

		for i := range p.Garage {
			g := &p.Garage[i]
			out, err := runAdmin(p.AdminCmd, `assign --keep "$CAIRN_DEV" "$CAIRN_VEH"`,
				map[string]string{"CAIRN_DEV": deviceID, "CAIRN_VEH": g.Vehicle})
			if err != nil {
				return fmt.Errorf("adding %s to the garage failed: %w", g.Vehicle, err)
			}
			m := regexp.MustCompile(`assignment ([0-9a-f]{32}):`).FindStringSubmatch(out)
			if m == nil {
				return fmt.Errorf("could not read the garage assignment id from: %s", strings.TrimSpace(out))
			}
			g.Assignment = m[1]
			p.Log("garage slot %d: vehicle %s, engine %s, assignment %s", i, g.Vehicle, g.Engine, g.Assignment)
			if g.Vehicle == p.Vehicle && p.Assignment == "" {
				p.Assignment = g.Assignment
			}
		}

		if p.Vehicle != "" && p.Assignment == "" {
			if len(p.Garage) > 0 {
				return fmt.Errorf("vehicle %s is not in the garage", p.Vehicle)
			}
			out, err := runAdmin(p.AdminCmd, `assign "$CAIRN_DEV" "$CAIRN_VEH"`,
				map[string]string{"CAIRN_DEV": deviceID, "CAIRN_VEH": p.Vehicle})
			if err != nil {
				return fmt.Errorf("creating the assignment failed: %w", err)
			}
			m := regexp.MustCompile(`assignment ([0-9a-f]{32}):`).FindStringSubmatch(out)
			if m == nil {
				return fmt.Errorf("could not read the new assignment id from: %s", strings.TrimSpace(out))
			}
			p.Assignment = m[1]
			p.Log("assignment %s", p.Assignment)
		}
	}

	// 5. install the garage, the assignment and the counter floor, then commit once.
	for i, g := range p.Garage {
		if !hex32.MatchString(g.Assignment) {
			return fmt.Errorf("garage slot %d has no assignment (is --admin-cmd set?)", i)
		}
		line := fmt.Sprintf("SET garage %d %s %s %s", i, g.Vehicle, g.Assignment, g.Engine)
		if err := cmd(c, p.Timeout, line, "garage"); err != nil {
			return err
		}
	}
	if p.Vehicle != "" && p.Assignment != "" {
		if !hex32.MatchString(p.Vehicle) || !hex32.MatchString(p.Assignment) {
			return errors.New("vehicle and assignment must be 32 lowercase hex characters")
		}
		if err := cmd(c, p.Timeout, "SET assignment "+p.Vehicle+" "+p.Assignment, "assignment"); err != nil {
			return err
		}
	}
	if floor > 0 {
		if err := cmd(c, p.Timeout, "SET counter_floor "+strconv.FormatUint(floor, 10), "counter_floor"); err != nil {
			return err
		}
	}
	// A successful COMMIT closes the session on the device, which stays silent
	// about lines sent outside one; sending END here would just time out.
	if err := cmd(c, p.Timeout, "COMMIT", "commit"); err != nil {
		return err
	}
	p.Log("committed")
	return nil
}

func nameArg(name string) string {
	if name == "" {
		return ""
	}
	return ` --name "$CAIRN_NAME"`
}

// runAdmin runs "<prefix> <args>" through sh with the values in the
// environment, so a base64 blob or a name is never interpolated into a command
// line the shell might re-parse.
func runAdmin(prefix, args string, env map[string]string) (string, error) {
	c := exec.Command("sh", "-c", prefix+" "+args)
	c.Env = os.Environ()
	for k, v := range env {
		c.Env = append(c.Env, k+"="+v)
	}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func parseKV(out string) map[string]string {
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " ")
		if ok && !strings.Contains(k, ":") {
			kv[k] = strings.TrimSpace(v)
		}
	}
	return kv
}
