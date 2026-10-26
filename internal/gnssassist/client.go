package gnssassist

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The two calls to u-blox. Both are small and both fail loudly but cleanly:
// every error that leaves this file has had the token and the chipcode scrubbed
// from it, and none carries a request URL.

// Credentials are what ZTP returns for one receiver.
type Credentials struct {
	Chipcode    secret   `json:"-"`
	ServiceURL  string   `json:"service_url"`
	AllowedData []string `json:"allowed_data"`
}

// credentialsFile is the on-disk form. The chipcode is a plain field here and
// nowhere else: the file is 0600 under the 0700 data directory.
type credentialsFile struct {
	UniqueID     string    `json:"unique_id"`
	Chipcode     string    `json:"chipcode"`
	ServiceURL   string    `json:"service_url"`
	AllowedData  []string  `json:"allowed_data"`
	RegisteredAt time.Time `json:"registered_at"`
	Receiver     string    `json:"receiver"`
}

// Response bodies are read to these limits and no further. ZTP answers with a
// few hundred bytes of JSON; Predictive Orbits for seven days of four
// constellations plus almanacs is ~77 KB (u-blox's own table: 84 bytes per
// ANO message, 31 GPS + 36 Galileo + 40 BeiDou + 20 GLONASS a day, almanacs
// 7.3 KB), and the guide's ceiling for the service is "~3 - 135 KBs".
const (
	maxZTPResponse   = 64 << 10
	maxOrbitResponse = 512 << 10
)

// httpError is a non-2xx answer, with a short scrubbed excerpt of its body.
type httpError struct {
	Op     string
	Status int
	Body   string
}

func (e *httpError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.Status, e.Body)
}

// excerpt keeps an error body readable in a log line and short, with secrets out.
func excerpt(body []byte, secrets ...string) string {
	s := strings.TrimSpace(string(body))
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = scrub(s, secrets...)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// cleanTransportError drops the URL from a client error. *url.Error prints
// `Get "https://...?chipcode=XXXX": dial tcp ...`, which is exactly the leak to
// prevent; what is left is the operation and the cause.
func cleanTransportError(op string, err error, secrets ...string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	msg := "request failed"
	if err != nil {
		msg = scrub(err.Error(), secrets...)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %s: %w", op, msg, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s: %s", op, msg)
}

// register performs ZTP for one receiver.
func register(ctx context.Context, hc *http.Client, cfg ZTP, id Identity) (Credentials, error) {
	const op = "AssistNow ZTP registration"
	body, err := json.Marshal(map[string]any{
		"token": cfg.Token.reveal(),
		"messages": map[string]string{
			// "the full receiver response messages as continuous hex strings"
			"UBX-SEC-UNIQID": strings.ToUpper(hex.EncodeToString(id.SecUniqID)),
			"UBX-MON-VER":    strings.ToUpper(hex.EncodeToString(id.MonVer)),
		},
	})
	if err != nil {
		return Credentials{}, fmt.Errorf("%s: encode request", op)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return Credentials{}, fmt.Errorf("%s: build request", op)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return Credentials{}, cleanTransportError(op, err, cfg.Token.reveal())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxZTPResponse+1))
	if err != nil {
		return Credentials{}, cleanTransportError(op, err, cfg.Token.reveal())
	}
	if resp.StatusCode/100 != 2 {
		return Credentials{}, &httpError{Op: op, Status: resp.StatusCode, Body: excerpt(raw, cfg.Token.reveal())}
	}
	if len(raw) > maxZTPResponse {
		return Credentials{}, fmt.Errorf("%s: response larger than %d bytes", op, maxZTPResponse)
	}
	var out struct {
		Chipcode    string   `json:"chipcode"`
		ServiceURL  string   `json:"serviceUrl"`
		AllowedData []string `json:"allowedData"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return Credentials{}, fmt.Errorf("%s: response is not the documented JSON", op)
	}
	if out.Chipcode == "" {
		return Credentials{}, fmt.Errorf("%s: response has no chipcode", op)
	}
	if err := checkURL(out.ServiceURL); err != nil {
		return Credentials{}, fmt.Errorf("%s: serviceUrl: %w", op, err)
	}
	return Credentials{Chipcode: secret(out.Chipcode), ServiceURL: out.ServiceURL, AllowedData: out.AllowedData}, nil
}

// Constellations requested. The receiver's model is not known yet (u-blox M9 on
// the vendor's page, M10 configuration packets in the vendor's driver): an M9
// tracks GPS, GLONASS, Galileo and BeiDou by default, an M10 GPS, Galileo,
// BeiDou and QZSS. Predictions for a system the receiver is not using are
// discarded by it, so asking for the four that have ANO costs ~1.7 KB a day of
// GLONASS that may be unused and nothing else. QZSS has no ANO.
const gnssList = "gps,gal,bds,glo"

// dataFor picks the request's data types from what the profile allows. Seven
// days, so a car parked for most of a week still starts with today's orbits;
// fourteen would not fit the device's 128 KiB bound. The almanac whenever it is
// allowed: it is what lets a cold receiver know which satellites to look for.
func dataFor(allowed []string) string {
	if len(allowed) == 0 {
		return "uporb_7,ualm"
	}
	has := map[string]bool{}
	for _, a := range allowed {
		has[strings.TrimSpace(a)] = true
	}
	var parts []string
	for _, p := range []string{"uporb_7", "uporb_3", "uporb_1", "uporb_14"} {
		if has[p] {
			parts = append(parts, p)
			break
		}
	}
	if has["ualm"] {
		parts = append(parts, "ualm")
	}
	return strings.Join(parts, ",")
}

// fetchOrbits downloads Predictive Orbits with one receiver's credentials.
func fetchOrbits(ctx context.Context, hc *http.Client, cred Credentials) ([]byte, string, error) {
	const op = "AssistNow Predictive Orbits"
	data := dataFor(cred.AllowedData)
	if !strings.Contains(data, "uporb_") {
		return nil, data, fmt.Errorf("%s: the profile allows no Predictive Orbits (allowedData %v)", op, cred.AllowedData)
	}
	u, err := url.Parse(cred.ServiceURL)
	if err != nil {
		return nil, data, fmt.Errorf("%s: bad service URL", op)
	}
	// Built by hand rather than with url.Values: the guide's rules are
	// key=value&key=value with commas between list items, and Encode would turn
	// each comma into %2C.
	u.RawQuery = "chipcode=" + url.QueryEscape(cred.Chipcode.reveal()) + "&gnss=" + gnssList + "&data=" + data
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, data, fmt.Errorf("%s: build request", op)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, data, cleanTransportError(op, err, cred.Chipcode.reveal())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOrbitResponse+1))
	if err != nil {
		return nil, data, cleanTransportError(op, err, cred.Chipcode.reveal())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, data, &httpError{Op: op, Status: resp.StatusCode, Body: excerpt(raw, cred.Chipcode.reveal())}
	}
	if len(raw) > maxOrbitResponse {
		return nil, data, fmt.Errorf("%s: response larger than %d bytes", op, maxOrbitResponse)
	}
	return raw, data, nil
}

// statusOf extracts the HTTP status from an error, or 0.
func statusOf(err error) int {
	var he *httpError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// nextUTCMidnight is when AssistNow's usage counters reset ("at 00.00 UTC of
// the day and/or month").
func nextUTCMidnight(now time.Time) time.Time {
	y, m, d := now.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Add(24 * time.Hour)
}
