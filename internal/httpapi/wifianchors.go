package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/wifianchors"
)

// Wi-Fi anchors for the dongle (format/v3 §6.4): the access-point positions the
// store has learned for the cars this device is assigned to, so that at
// power-up it can locate itself from a Wi-Fi scan and give its GNSS receiver an
// initial-position hint.
//
// The route has no signed body, so the mTLS certificate is the whole of the
// authentication: it must name an enrolled, unrevoked device. A device only ever
// receives its own garage's anchors.

// WiFiAnchors is the part of wifianchors.Service the handler uses.
type WiFiAnchors interface {
	For(ctx context.Context, deviceHex string) (body []byte, count int, err error)
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

func (s *Server) handleWiFiAnchors(w http.ResponseWriter, r *http.Request) {
	device, err := s.deviceFromCert(r)
	if err != nil {
		s.fail(w, r, http.StatusForbidden, "an enrolled device certificate is required", err)
		return
	}
	if s.limiter != nil && !s.limiter.Allow(device) {
		s.fail(w, r, http.StatusTooManyRequests, "rate limit exceeded", nil)
		return
	}
	// The device gives this request a bounded slice of an upload session; a
	// store that has not answered in 15 s will not answer in time for it.
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	body, count, err := s.anchors.For(ctx, device)
	if err != nil {
		// 503, not 500: the device keeps the copy it has and asks again later.
		s.fail(w, r, http.StatusServiceUnavailable, "the learned access points cannot be read now", err)
		return
	}
	etag := wifianchors.ETag(body)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Cairn-Anchor-Count", strconv.Itoa(count))
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		s.log.Warn("writing Wi-Fi anchors failed", "error", err)
	}
}

// etagMatches implements If-None-Match's weak comparison (RFC 9110 §13.1.2):
// a list of tags, W/ ignored, or *.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
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
