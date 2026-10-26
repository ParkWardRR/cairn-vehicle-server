package gnssassist

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixtures. The token and chipcode are made-up values with the documented shapes
// (a 36-character UUID; a 28-character base64 string), chosen to be greppable.
const (
	testToken    = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	testChipcode = "Q0hJUENPREVURVNUMDEyMzQ1Njc="
	testDevice   = "00112233445566778899aabbccddeeff"
)

// secM10 is a version-2 UBX-SEC-UNIQID (6-byte id), the shape the service
// integration guide quotes; secM9 a version-1 one (5-byte id).
func secM10() []byte {
	return Encode(classSEC, idSECUNIQID, []byte{0x02, 0, 0, 0, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6})
}
func secM9() []byte {
	return Encode(classSEC, idSECUNIQID, []byte{0x01, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55})
}

func monVer(mod string) []byte {
	p := make([]byte, 40+30*2)
	copy(p[0:], "ROM SPG 5.10 (7b202e)")
	copy(p[30:], "000A0000")
	copy(p[40:], "PROTVER=34.10")
	copy(p[70:], "MOD="+mod)
	return Encode(classMON, idMONVER, p)
}

func ano(day time.Time, gnssID, svID byte) []byte {
	p := make([]byte, 76)
	p[2], p[3] = svID, gnssID
	p[4], p[5], p[6] = byte(day.Year()-2000), byte(day.Month()), byte(day.Day())
	return Encode(classMGA, idMGAANO, p)
}

func gpsAlm(sv byte) []byte {
	p := make([]byte, 36)
	p[0], p[2] = 0x02, sv
	return Encode(classMGA, 0x00, p)
}

func iniTime() []byte { return Encode(classMGA, idMGAINI, make([]byte, 24)) }

var day0 = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

// orbitStream is what the fake AssistNow serves: INI-TIME_UTC first (as the
// guide says it is when GLONASS/Galileo almanacs are asked for), almanacs, then
// seven days of predictions starting the day before "now".
func orbitStream() []byte {
	var b bytes.Buffer
	b.Write(iniTime())
	for sv := byte(1); sv <= 3; sv++ {
		b.Write(gpsAlm(sv))
	}
	for d := -1; d < 6; d++ {
		for sv := byte(1); sv <= 4; sv++ {
			b.Write(ano(day0.AddDate(0, 0, d), 0, sv))
		}
	}
	return b.Bytes()
}

// fakeUblox is ZTP and AssistNow in one httptest server.
type fakeUblox struct {
	t        *testing.T
	mu       sync.Mutex
	ztpCalls int
	getCalls int
	lastZTP  map[string]any
	lastGet  string
	ztpCode  int
	ztpBody  string
	getCode  int
	getBody  []byte
	srv      *httptest.Server
}

func newFake(t *testing.T) *fakeUblox {
	f := &fakeUblox{t: t, ztpCode: 200, getCode: 200, getBody: orbitStream()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /ztp/assistnow/credentials", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ztpCalls++
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("ZTP Content-Type %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		f.lastZTP = map[string]any{}
		_ = json.Unmarshal(body, &f.lastZTP)
		if f.ztpCode != 200 {
			w.WriteHeader(f.ztpCode)
			io.WriteString(w, f.ztpBody)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"chipcode":    testChipcode,
			"serviceUrl":  f.srv.URL + "/GetAssistNowData.ashx",
			"allowedData": []string{"ualm", "uporb_1", "uporb_3", "uporb_7", "uporb_14"},
		})
	})
	mux.HandleFunc("GET /GetAssistNowData.ashx", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.getCalls++
		f.lastGet = r.URL.RawQuery
		w.WriteHeader(f.getCode)
		w.Write(f.getBody)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newService(t *testing.T, f *fakeUblox, logs *bytes.Buffer) (*Service, *clock, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "gnss-assist")
	c := &clock{t: day0.Add(10 * time.Hour)}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(Config{
		Dir: dir,
		ZTP: ZTP{Endpoint: f.srv.URL + "/ztp/assistnow/credentials", Token: secret(testToken)},
		Log: log,
		Now: c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, c, dir
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func assertNoSecrets(t *testing.T, where, text string) {
	t.Helper()
	for _, sec := range []string{testToken, testChipcode} {
		if strings.Contains(text, sec) {
			t.Fatalf("%s contains a secret (%q):\n%s", where, sec[:6]+"...", text)
		}
	}
}

func TestParseIdentity(t *testing.T) {
	id, err := ParseIdentity(hexOf(secM10()), hexOf(monVer("NEO-M10S")))
	if err != nil {
		t.Fatal(err)
	}
	if id.UniqueID != "a1b2c3d4e5f6" {
		t.Errorf("M10 unique id %q", id.UniqueID)
	}
	if d := id.Describe(); !strings.Contains(d, "MOD=NEO-M10S") || !strings.Contains(d, "hw=000A0000") {
		t.Errorf("Describe() = %q", d)
	}
	id9, err := ParseIdentity(strings.ToUpper(hexOf(secM9())), hexOf(monVer("NEO-M9N")))
	if err != nil {
		t.Fatal(err)
	}
	if id9.UniqueID != "1122334455" {
		t.Errorf("M9 unique id %q", id9.UniqueID)
	}

	bad := secM10()
	bad[len(bad)-1] ^= 1
	for name, c := range map[string][2]string{
		"bad checksum":        {hexOf(bad), hexOf(monVer("x"))},
		"swapped":             {hexOf(monVer("x")), hexOf(secM10())},
		"the poll, not reply": {"B562270300002AA5", hexOf(monVer("x"))},
		"two frames":          {hexOf(append(secM10(), secM10()...)), hexOf(monVer("x"))},
		"not hex":             {"zz", hexOf(monVer("x"))},
		"short MON-VER":       {hexOf(secM10()), hexOf(Encode(classMON, idMONVER, make([]byte, 39)))},
	} {
		if _, err := ParseIdentity(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadZTP(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadZTP(filepath.Join(dir, "absent.json")); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("missing file: %v, want ErrNoConfig", err)
	}

	good := filepath.Join(dir, "ztp.json")
	os.WriteFile(good, []byte(`{"endpoint":"https://api.thingstream.io/ztp/assistnow/credentials","token":"`+testToken+`"}`), 0o600)
	z, err := LoadZTP(good)
	if err != nil {
		t.Fatal(err)
	}
	if z.Token.reveal() != testToken {
		t.Fatal("token not loaded")
	}
	// The token cannot be printed by accident, by any verb.
	for _, s := range []string{
		z.Token.String(), fmtAll(z), fmtAll(z.Token),
	} {
		assertNoSecrets(t, "formatted ZTP", s)
	}
	var logs bytes.Buffer
	slog.New(slog.NewTextHandler(&logs, nil)).Info("x", "ztp", z, "token", z.Token)
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("x", "ztp", z, "token", z.Token)
	assertNoSecrets(t, "slog of ZTP", logs.String())

	// A syntax error must not quote the file back (the token is in it).
	broken := filepath.Join(dir, "broken.json")
	os.WriteFile(broken, []byte(`{"endpoint":"https://x","token":"`+testToken+`"`), 0o600)
	if _, err := LoadZTP(broken); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatalf("broken file: %v", err)
	}

	plain := filepath.Join(dir, "plain.json")
	os.WriteFile(plain, []byte(`{"endpoint":"http://api.thingstream.io/ztp","token":"t"}`), 0o600)
	if _, err := LoadZTP(plain); err == nil {
		t.Fatal("a plain-HTTP endpoint off loopback was accepted")
	}
}

// The whole flow: report, register, download, serve, with every log line,
// error, state file and status line checked for the two secrets.
func TestRegisterFetchServe(t *testing.T) {
	f := newFake(t)
	var logs bytes.Buffer
	s, c, dir := newService(t, f, &logs)

	// No receiver yet: nothing to serve.
	if _, _, err := s.Data(testDevice); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("before any report: %v", err)
	}

	res, err := s.ReportReceiver(strings.ToUpper(testDevice), hexOf(secM10()), hexOf(monVer("NEO-M10S")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Registered || !res.Changed || res.UniqueID != "a1b2c3d4e5f6" {
		t.Fatalf("first report: %+v", res)
	}

	s.Tick(context.Background())

	// ZTP got the documented body.
	if f.ztpCalls != 1 {
		t.Fatalf("ZTP calls %d", f.ztpCalls)
	}
	if f.lastZTP["token"] != testToken {
		t.Errorf("ZTP token field %v", f.lastZTP["token"])
	}
	msgs, _ := f.lastZTP["messages"].(map[string]any)
	if msgs["UBX-SEC-UNIQID"] != strings.ToUpper(hexOf(secM10())) || msgs["UBX-MON-VER"] != strings.ToUpper(hexOf(monVer("NEO-M10S"))) {
		t.Errorf("ZTP messages %v", msgs)
	}

	// AssistNow got the documented query, commas literal.
	if f.getCalls != 1 {
		t.Fatalf("AssistNow calls %d", f.getCalls)
	}
	wantQ := "chipcode=" + strings.ReplaceAll(testChipcode, "=", "%3D") + "&gnss=gps,gal,bds,glo&data=uporb_7,ualm"
	if f.lastGet != wantQ {
		t.Errorf("query\n got %s\nwant %s", f.lastGet, wantQ)
	}

	// Stored with the chipcode only in the 0600 credentials file.
	uid := "a1b2c3d4e5f6"
	info, err := os.Stat(filepath.Join(dir, "receivers", uid, "credentials.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v %v", err, info)
	}
	if info, err := os.Stat(filepath.Join(dir, "receivers", uid, "orbits.ubx")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("orbits file: %v", err)
	}
	state, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	assertNoSecrets(t, "state.json", string(state))

	// Served: no INI, no prediction for yesterday, everything else in order.
	body, etag, err := s.Data(testDevice)
	if err != nil {
		t.Fatal(err)
	}
	frames, err := SplitFrames(body)
	if err != nil {
		t.Fatal(err)
	}
	sum := summarise(frames)
	if sum.ANO != 6*4 || sum.Almanac != 3 || !sum.FirstDay.Equal(day0) {
		t.Errorf("served %+v", sum)
	}
	for _, fr := range frames {
		if isINI(fr) {
			t.Fatal("served an MGA-INI frame: a stale time would be injected as current")
		}
	}
	if etag != ETag(body) || len(etag) != 66 {
		t.Errorf("etag %q", etag)
	}

	// The same report again changes nothing and calls nobody.
	res, _ = s.ReportReceiver(testDevice, hexOf(secM10()), hexOf(monVer("NEO-M10S")))
	if !res.Registered || res.Changed {
		t.Errorf("repeat report: %+v", res)
	}
	s.Tick(context.Background())
	if f.ztpCalls != 1 || f.getCalls != 1 {
		t.Errorf("a repeat report re-registered or re-fetched: %d %d", f.ztpCalls, f.getCalls)
	}

	// A day later the data is refreshed, once, and the served set moves on.
	c.add(RefreshEvery)
	s.Tick(context.Background())
	s.Tick(context.Background())
	if f.getCalls != 2 {
		t.Errorf("refresh calls %d, want 2", f.getCalls)
	}

	for _, line := range s.Status() {
		assertNoSecrets(t, "status", line)
	}
	assertNoSecrets(t, "logs", logs.String())
	if !strings.Contains(logs.String(), "AssistNow Predictive Orbits stored") {
		t.Errorf("no storage log line:\n%s", logs.String())
	}
}

// Every failure path, with the secrets planted where a careless error would
// pick them up: echoed in a response body, and in the request URL itself.
func TestFailuresKeepSecretsAndBounds(t *testing.T) {
	f := newFake(t)
	var logs bytes.Buffer
	s, c, _ := newService(t, f, &logs)

	// ZTP refuses and echoes the token back.
	f.ztpCode, f.ztpBody = 400, `{"error":"bad token `+testToken+`"}`
	s.ReportReceiver(testDevice, hexOf(secM10()), hexOf(monVer("x")))
	s.Tick(context.Background())
	if f.ztpCalls != 1 {
		t.Fatalf("ZTP calls %d", f.ztpCalls)
	}
	// Retried after an hour, not on the next tick.
	s.Tick(context.Background())
	if f.ztpCalls != 1 {
		t.Fatalf("retried at once: %d", f.ztpCalls)
	}
	c.add(retryAfter)
	s.Tick(context.Background())
	c.add(retryAfter)
	s.Tick(context.Background())
	c.add(retryAfter)
	s.Tick(context.Background())
	if f.ztpCalls != maxRegPerDay {
		t.Fatalf("registration attempts in a day %d, want the cap %d", f.ztpCalls, maxRegPerDay)
	}

	// Registration works; the download returns an error string with a 200.
	c.add(24 * time.Hour)
	f.ztpCode = 200
	f.getBody = []byte("chipcode " + testChipcode + " is not valid")
	s.Tick(context.Background())
	if f.getCalls != 1 {
		t.Fatalf("AssistNow calls %d", f.getCalls)
	}
	if _, _, err := s.Data(testDevice); !errors.Is(err, ErrNotAvailable) {
		t.Fatalf("a text body was stored as data: %v", err)
	}

	// Over the daily cap nothing more is asked.
	c.add(retryAfter)
	s.Tick(context.Background())
	c.add(retryAfter)
	s.Tick(context.Background())
	if f.getCalls != maxFetchPerDay {
		t.Fatalf("downloads in a day %d, want the cap %d", f.getCalls, maxFetchPerDay)
	}

	// 403 (usage limit) waits for UTC midnight.
	c.add(24 * time.Hour)
	f.getCode, f.getBody = 403, []byte("403003 Access is blocked - Predictive Orbits usage limit has been reached")
	s.Tick(context.Background())
	calls := f.getCalls
	c.add(2 * time.Hour)
	s.Tick(context.Background())
	if f.getCalls != calls {
		t.Fatal("a 403 was retried before midnight")
	}

	// A transport failure: *url.Error would print the whole URL, chipcode and all.
	f.srv.Close()
	c.add(24 * time.Hour)
	s.Tick(context.Background())

	for _, line := range s.Status() {
		assertNoSecrets(t, "status", line)
	}
	assertNoSecrets(t, "logs", logs.String())
	if os.Getenv("GNSS_DUMP") != "" {
		t.Log(logs.String())
	}
	if !strings.Contains(logs.String(), "AssistNow download failed") {
		t.Errorf("failures were not logged:\n%s", logs.String())
	}
}

func TestDirectErrorsAreClean(t *testing.T) {
	// fetchOrbits against a closed port: the error is the cause, not the URL.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, _, err := fetchOrbits(context.Background(), &http.Client{Timeout: time.Second},
		Credentials{Chipcode: secret(testChipcode), ServiceURL: url + "/x", AllowedData: []string{"uporb_7"}})
	if err == nil {
		t.Fatal("no error from a closed server")
	}
	assertNoSecrets(t, "transport error", err.Error())
	if strings.Contains(err.Error(), "chipcode=") {
		t.Fatalf("error carries the query: %v", err)
	}

	_, err = register(context.Background(), &http.Client{Timeout: time.Second},
		ZTP{Endpoint: url, Token: secret(testToken)}, Identity{SecUniqID: secM10(), MonVer: monVer("x")})
	if err == nil {
		t.Fatal("no error from a closed server")
	}
	assertNoSecrets(t, "ZTP transport error", err.Error())
}

func TestDataFor(t *testing.T) {
	for _, c := range []struct {
		allowed []string
		want    string
	}{
		{nil, "uporb_7,ualm"},
		{[]string{"ualm", "uporb_1", "uporb_3", "uporb_7", "uporb_14", "ulorb_l1"}, "uporb_7,ualm"},
		{[]string{"uporb_3"}, "uporb_3"},
		{[]string{"uporb_14", "ualm"}, "uporb_14,ualm"},
		{[]string{"ulorb_l1", "ualm"}, "ualm"},
	} {
		if got := dataFor(c.allowed); got != c.want {
			t.Errorf("dataFor(%v) = %q, want %q", c.allowed, got, c.want)
		}
	}
}

// The device bound: whole days come off the end until the body fits, and
// predictions for days before today never go.
func TestForDeviceBound(t *testing.T) {
	frames, err := SplitFrames(orbitStream())
	if err != nil {
		t.Fatal(err)
	}
	frames, dropped := cleanForCache(frames)
	if dropped != 1 {
		t.Fatalf("dropped %d INI frames, want 1", dropped)
	}
	all := forDevice(frames, day0, 1<<20)
	oneDay := 4 * len(ano(day0, 0, 1))
	capped := forDevice(frames, day0, len(all)-1)
	got, _ := SplitFrames(capped)
	sum := summarise(got)
	if len(capped) != len(all)-oneDay || !sum.LastDay.Equal(day0.AddDate(0, 0, 4)) || sum.Almanac != 3 {
		t.Errorf("capped: %d bytes (all %d, a day %d), %+v", len(capped), len(all), oneDay, sum)
	}
	// Ten days on, only almanacs remain.
	late, _ := SplitFrames(forDevice(frames, day0.AddDate(0, 0, 10), 1<<20))
	if s := summarise(late); s.ANO != 0 || s.Almanac != 3 {
		t.Errorf("late: %+v", s)
	}
}

func fmtAll(v any) string {
	b, _ := json.Marshal(v)
	return fmt.Sprintf("%v|%+v|%#v|%s|%q|", v, v, v, v, v) + string(b)
}
