// Package gnssassist fetches u-blox AssistNow Predictive Orbits for the dongle's
// receiver and serves them to the dongle.
//
// Why: measured 2026-10-25 from the dongle's card, a cold receiver in the M240i
// (OBD port low under the dash) saw no satellites for minutes, then three or
// four, and gave its first usable fix after 8.5 and 10.5 minutes, and after 30
// on 2026-10-24. What it lacks at power-up is orbits and time. AssistNow
// Predictive Orbits supplies the orbits; the dongle supplies the time.
//
// The flow, from the Thingstream AssistNow guides (read 2026-10-25):
//
//  1. Zero Touch Provisioning, once per receiver: POST the Device Profile's
//     token and the receiver's own UBX-SEC-UNIQID and UBX-MON-VER replies (whole
//     frames, continuous hex) to the profile's ZTP endpoint; the answer is a
//     chipcode, the service URL and the data types the profile allows.
//  2. GET <serviceUrl>?chipcode=..&gnss=..&data=uporb_N,ualm: a stream of
//     UBX-MGA-ANO (one per satellite per day) and UBX-MGA-*-ALM frames.
//  3. The device injects them, today's predictions only.
//
// The server does steps 1 and 2 so neither the token nor the chipcode ever
// reaches the dongle, and so the Evaluation profile's 300 requests a month are
// spent once a day by one process rather than by every reconnect. The dongle
// reports its receiver's identity and downloads the cached stream over its
// existing mTLS session.
//
// Secrets. The ZTP token and the chipcode are credentials. Neither is logged,
// put in an error, or returned to a device; the chipcode travels only in the
// query string of the AssistNow request, and Go's url.Error (which prints the
// whole URL) is rewritten before it can escape. Tests check all of this.
package gnssassist

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
)

// secret is a string that refuses to be printed.
type secret string

const redacted = "[redacted]"

func (s secret) String() string                { return redacted }
func (s secret) GoString() string              { return redacted }
func (s secret) LogValue() slog.Value          { return slog.StringValue(redacted) }
func (s secret) MarshalText() ([]byte, error)  { return []byte(redacted), nil }
func (s secret) Format(f fmt.State, verb rune) { _, _ = f.Write([]byte(redacted)) }
func (s secret) reveal() string                { return string(s) }
func (s secret) scrub(text string) string      { return scrub(text, string(s)) }
func scrub(text string, secrets ...string) string {
	for _, v := range secrets {
		if v != "" {
			text = strings.ReplaceAll(text, v, redacted)
		}
	}
	return text
}

// ZTP is the Device Profile credential, as installed at
// /etc/cairn/assistnow-ztp.json: {"endpoint": "...", "token": "..."}.
type ZTP struct {
	Endpoint string
	Token    secret
}

// ErrNoConfig means the credential file is absent: the feature is off.
var ErrNoConfig = errors.New("no AssistNow ZTP credential")

// LoadZTP reads the credential file. A missing file is ErrNoConfig, which the
// caller treats as "feature off"; any other problem is reported without the
// file's contents.
func LoadZTP(path string) (ZTP, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ZTP{}, ErrNoConfig
	}
	if err != nil {
		return ZTP{}, fmt.Errorf("read AssistNow ZTP credential: %w", err)
	}
	var raw struct {
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		// Not %w and not the decoder's message: a JSON syntax error quotes the
		// offending text, which could be the token.
		return ZTP{}, errors.New("AssistNow ZTP credential is not valid JSON")
	}
	if strings.TrimSpace(raw.Token) == "" {
		return ZTP{}, errors.New("AssistNow ZTP credential has no token")
	}
	if err := checkURL(raw.Endpoint); err != nil {
		return ZTP{}, fmt.Errorf("AssistNow ZTP endpoint: %w", err)
	}
	return ZTP{Endpoint: raw.Endpoint, Token: secret(strings.TrimSpace(raw.Token))}, nil
}

// checkURL insists on HTTPS, because the token and the chipcode ride in these
// requests. Plain HTTP is allowed only to a loopback host, which is what the
// tests' fakes are.
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("not an absolute URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("scheme %q: HTTPS is required", u.Scheme)
}
