package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ParkWardRR/cairn-vehicle-server/internal/gnssassist"
)

// openGNSSAssist starts GNSS assistance when -assistnow-ztp names a credential
// that exists. No flag, or no file, is "off" and not an error: the credential is
// installed separately (/etc/cairn/assistnow-ztp.json, 0640 root:cairn) and a
// server without it is a normal configuration.
func openGNSSAssist(cfg runConfig) (*gnssassist.Service, error) {
	if cfg.assistNowZTP == "" {
		return nil, nil
	}
	ztp, err := gnssassist.LoadZTP(cfg.assistNowZTP)
	if errors.Is(err, gnssassist.ErrNoConfig) {
		cfg.log.Info("GNSS assistance off: no AssistNow credential", "path", cfg.assistNowZTP)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	svc, err := gnssassist.New(gnssassist.Config{
		Dir: filepath.Join(cfg.dataDir, "gnss-assist"),
		ZTP: ztp,
		Log: cfg.log,
	})
	if err != nil {
		return nil, err
	}
	cfg.log.Info("GNSS assistance on", "ztp_endpoint", ztp.Endpoint, "state", filepath.Join(cfg.dataDir, "gnss-assist"))
	return svc, nil
}

// gnssAdmin runs -gnss-assist-status and -gnss-assist-register.
func gnssAdmin(cfg runConfig) error {
	if cfg.assistNowZTP == "" {
		return errors.New("GNSS assistance needs -assistnow-ztp")
	}
	svc, err := openGNSSAssist(cfg)
	if err != nil {
		return err
	}
	if svc == nil {
		return fmt.Errorf("no AssistNow credential at %s", cfg.assistNowZTP)
	}
	if cfg.gnssRegister != "" {
		sec, mon, ok := strings.Cut(cfg.gnssRegister, ",")
		if !ok {
			return errors.New("-gnss-assist-register wants SEC_UNIQID_HEX,MON_VER_HEX")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		uid, err := svc.RegisterNow(ctx, sec, mon)
		if err != nil {
			return fmt.Errorf("receiver %s: %w", uid, err)
		}
		fmt.Printf("registered receiver %s and stored its Predictive Orbits\n", uid)
	}
	for _, line := range svc.Status() {
		fmt.Println(line)
	}
	return nil
}
