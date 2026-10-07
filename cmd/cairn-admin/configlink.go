package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"rsc.io/qr"
)

// configureLink builds the cairn://configure link the phone app opens: the server
// URL(s), a single-use invitation code and the private CA certificate, so a tester
// scans one QR code instead of typing a URL, a code and installing a profile.
//
// The format is mirrored by CairnCore's ConfigureLink; change both together.
//
//	cairn://configure?v=1&url=<https lan url>&tailnet=<https url>&code=<code>&ca=<DER, base64url, unpadded>
func configureLink(serverURL, tailnetURL, code string, caPEM []byte) (string, error) {
	if err := requireHTTPS(serverURL); err != nil {
		return "", fmt.Errorf("--url: %w", err)
	}
	q := url.Values{}
	q.Set("v", "1")
	q.Set("url", serverURL)
	if tailnetURL != "" {
		if err := requireHTTPS(tailnetURL); err != nil {
			return "", fmt.Errorf("--tailnet-url: %w", err)
		}
		q.Set("tailnet", tailnetURL)
	}
	q.Set("code", code)
	if len(caPEM) > 0 {
		der, err := caDER(caPEM)
		if err != nil {
			return "", err
		}
		q.Set("ca", base64.RawURLEncoding.EncodeToString(der))
	}
	return "cairn://configure?" + q.Encode(), nil
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("must be an https:// URL with a host, e.g. https://cairn.example.lan:8444")
	}
	return nil
}

func caDER(caPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("CA file holds no PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("CA certificate is not a CA (basicConstraints CA:TRUE missing); refusing to embed it")
	}
	return block.Bytes, nil
}

// qrText renders the code with half-block characters, two module rows per text row,
// including the quiet zone. It sets its own black-on-white colours so the polarity is
// right on a dark or a light terminal theme.
func qrText(link string) (string, error) {
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return "", err
	}
	const quiet = 2
	dark := func(x, y int) bool {
		return x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y)
	}
	var b bytes.Buffer
	for y := -quiet; y < code.Size+quiet; y += 2 {
		b.WriteString("\x1b[30;107m")
		for x := -quiet; x < code.Size+quiet; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString("\x1b[0m\n")
	}
	return b.String(), nil
}

func qrPNG(link string) ([]byte, error) {
	code, err := qr.Encode(link, qr.L)
	if err != nil {
		return nil, err
	}
	code.Scale = 8
	return code.PNG(), nil
}
