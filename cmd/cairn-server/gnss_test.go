package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// -assistnow-ztp pointing at a file that is not there is "feature off", not a
// failure to start: the credential is installed separately from the unit.
func TestOpenGNSSAssist(t *testing.T) {
	dir := t.TempDir()
	var logs bytes.Buffer
	cfg := runConfig{dataDir: dir, log: slog.New(slog.NewTextHandler(&logs, nil))}

	if svc, err := openGNSSAssist(cfg); svc != nil || err != nil {
		t.Fatalf("no flag: %v %v", svc, err)
	}
	cfg.assistNowZTP = filepath.Join(dir, "absent.json")
	if svc, err := openGNSSAssist(cfg); svc != nil || err != nil {
		t.Fatalf("absent file: %v %v", svc, err)
	}

	const token = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	cfg.assistNowZTP = filepath.Join(dir, "assistnow-ztp.json")
	os.WriteFile(cfg.assistNowZTP, []byte(`{"endpoint":"https://api.thingstream.io/ztp/assistnow/credentials","token":"`+token+`"}`), 0o640)
	svc, err := openGNSSAssist(cfg)
	if err != nil || svc == nil {
		t.Fatalf("present file: %v %v", svc, err)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("the token was logged")
	}
	if info, err := os.Stat(filepath.Join(dir, "gnss-assist")); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory: %v %v", info, err)
	}
}
