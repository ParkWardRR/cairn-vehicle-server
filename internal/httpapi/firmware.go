package httpapi

import (
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Firmware serving for OTA (docs/ota.md).
//
// Deliberately dumb: it serves bytes that were signed offline by cairn-signfw
// and never signs anything itself. The update key does not live on the server,
// so a server compromise cannot produce firmware a device will accept — which
// is the entire reason that key is separate from the receipt key.

// handleFirmwareLatest serves the newest descriptor in the firmware directory,
// with its detached signature in a header.
//
// The signature is a header rather than part of the body because the body is
// exactly the bytes the signature covers. Wrapping them in an envelope would
// mean the device had to unwrap before verifying, which is the step where an
// implementation starts verifying something other than what it received.
func (s *Server) handleFirmwareLatest(w http.ResponseWriter, r *http.Request) {
	name, err := newestDescriptor(s.firmwareDir)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no firmware descriptor available", err)
		return
	}

	descriptor, err := os.ReadFile(filepath.Join(s.firmwareDir, name+".cbor"))
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "cannot read descriptor", err)
		return
	}
	signature, err := os.ReadFile(filepath.Join(s.firmwareDir, name+".sig"))
	if err != nil {
		// A descriptor without its signature is unusable, and serving it would
		// make the device fail verification for a reason that looks like
		// tampering. Refuse here instead.
		s.fail(w, r, http.StatusInternalServerError,
			"descriptor has no signature alongside it", err)
		return
	}

	w.Header().Set("Content-Type", ContentTypeCBOR)
	w.Header().Set(SignatureHeader, hex.EncodeToString(signature))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(descriptor); err != nil {
		s.log.Warn("writing firmware descriptor failed", "error", err)
	}
}

// handleFirmwareImage serves an image by its SHA-256.
//
// Addressed by hash rather than version for the same reason bundle chunks are:
// a hash cannot be ambiguous about which bytes it names, so there is no way for
// the device to receive a different image than the descriptor described.
func (s *Server) handleFirmwareImage(w http.ResponseWriter, r *http.Request) {
	digest, err := parseDigest(r.PathValue("digest"))
	if err != nil {
		s.fail(w, r, http.StatusBadRequest, "invalid image digest", err)
		return
	}

	hexDigest := hex.EncodeToString(digest[:])
	path := filepath.Join(s.firmwareDir, hexDigest+".bin")

	f, err := os.Open(path)
	if err != nil {
		s.fail(w, r, http.StatusNotFound, "no image with that digest", err)
		return
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "cannot stat image", err)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, hexDigest+".bin", info.ModTime(), f)
}

// newestDescriptor picks the lexicographically last descriptor.
//
// Ordering by name rather than mtime: a file copied onto the server gets a new
// mtime, so mtime would make "newest" depend on deployment order rather than on
// the version. The device re-checks the version against its own regardless, so
// this only decides which one is offered.
func newestDescriptor(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".cbor") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".cbor"))
	}
	if len(names) == 0 {
		return "", os.ErrNotExist
	}

	sort.Strings(names)
	return names[len(names)-1], nil
}
