package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/gnssassist"
)

// GNSS assistance for the dongle's receiver (format/v3 §6.4).
//
// Two routes, registered only when the server holds an AssistNow credential:
// the device reports which receiver it has, and downloads the Predictive
// Orbits the server keeps for that receiver. Neither carries a u-blox secret in
// either direction; the server holds the ZTP token and the chipcode.
//
// Both demand the mTLS client certificate and an enrolled, unrevoked device
// behind it. The bundle routes can lean on the manifest signature; these have
// no signed body, so the certificate is the whole of the authentication.

// GNSSAssist is the part of gnssassist.Service the handlers use.
type GNSSAssist interface {
	ReportReceiver(deviceHex, secHex, monHex string) (gnssassist.ReportResult, error)
	Data(deviceHex string) ([]byte, string, error)
}

// maxReceiverReport bounds the report body. MON-VER is 40 + 30n bytes with n a
// handful of extension strings, so the JSON is well under 2 KiB.
const maxReceiverReport = 4 << 10

type receiverReport struct {
	SecUniqID string `json:"sec_uniqid"`
	MonVer    string `json:"mon_ver"`
}

// deviceFromCert names the enrolled device on the other end of the connection.
func (s *Server) deviceFromCert(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("no client certificate presented")
	}
	cn := strings.ToLower(r.TLS.PeerCertificates[0].Subject.CommonName)
	id, err := parseID16(cn)
	if err != nil {
		return "", errors.New("client certificate does not name a device")
	}
	if s.registry == nil {
		return "", errors.New("no device registry")
	}
	if _, err := s.registry.Lookup(id); err != nil {
		return "", err
	}
	return cn, nil
}

func (s *Server) handleGNSSReceiver(w http.ResponseWriter, r *http.Request) {
	device, err := s.deviceFromCert(r)
	if err != nil {
		s.fail(w, r, http.StatusForbidden, "an enrolled device certificate is required", err)
		return
	}
	if s.limiter != nil && !s.limiter.Allow(device) {
		s.fail(w, r, http.StatusTooManyRequests, "rate limit exceeded", nil)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReceiverReport))
	if err != nil {
		s.fail(w, r, http.StatusRequestEntityTooLarge, "receiver report too large or unreadable", err)
		return
	}
	var rep receiverReport
	if err := json.Unmarshal(body, &rep); err != nil {
		s.fail(w, r, http.StatusBadRequest, "receiver report is not the documented JSON", nil)
		return
	}
	res, err := s.gnss.ReportReceiver(device, rep.SecUniqID, rep.MonVer)
	if errors.Is(err, gnssassist.ErrBadIdentity) {
		s.fail(w, r, http.StatusBadRequest, "receiver report is not two valid UBX replies", err)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "cannot record the receiver", err)
		return
	}
	// 202 while registration is still to happen: the data is not there yet,
	// and the device should not expect it in this session.
	code := http.StatusAccepted
	if res.Registered {
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"unique_id": res.UniqueID, "registered": res.Registered})
}

func (s *Server) handleGNSSAssist(w http.ResponseWriter, r *http.Request) {
	device, err := s.deviceFromCert(r)
	if err != nil {
		s.fail(w, r, http.StatusForbidden, "an enrolled device certificate is required", err)
		return
	}
	if s.limiter != nil && !s.limiter.Allow(device) {
		s.fail(w, r, http.StatusTooManyRequests, "rate limit exceeded", nil)
		return
	}
	body, etag, err := s.gnss.Data(device)
	if errors.Is(err, gnssassist.ErrNotAvailable) {
		s.fail(w, r, http.StatusNotFound, "no GNSS assistance data for this device yet", nil)
		return
	}
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "cannot read GNSS assistance data", err)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		s.log.Warn("writing GNSS assistance data failed", "error", err)
	}
}

// etagMatches implements If-None-Match's weak comparison (RFC 9110 §13.1.2):
// a list of tags, W/ ignored, or *.
func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimSpace(t)
		if t == "*" {
			return true
		}
		if strings.TrimPrefix(t, "W/") == etag {
			return true
		}
	}
	return false
}
