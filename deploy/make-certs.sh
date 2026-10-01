#!/usr/bin/env bash
#
# Issue the mTLS chain for Cairn: a private CA, a server certificate, and one
# client certificate per device.
#
# Two details make this worth scripting rather than documenting:
#
#   1. The client certificate's CommonName must be the device id as 32 lowercase
#      hex characters. The server compares it against the device id inside the
#      signed manifest and refuses the upload if they differ — which surfaces as
#      an HTTP 403 that looks nothing like a certificate problem.
#   2. The CA has to be embedded in firmware as a C string literal. Converting a
#      PEM by hand is tedious and silently wrong if a newline is dropped, so this
#      emits the literal ready to paste.
#
# Usage:
#   ./make-certs.sh init   cairn.example.lan          # CA + server certificate
#   ./make-certs.sh device <32-hex-device-id>         # one client certificate
#   ./make-certs.sh ca-literal                        # CA as a C string literal
#
# The device id is printed by the firmware at every boot; see
# docs/v2-firmware-testing.md. Everything lands in ./certs, which should not be
# committed.

set -euo pipefail

CERT_DIR="${CERT_DIR:-./certs}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_LEAF="${DAYS_LEAF:-825}"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_ca() {
    [[ -f "$CERT_DIR/ca.pem" && -f "$CERT_DIR/ca-key.pem" ]] \
        || die "no CA found in $CERT_DIR — run '$0 init <hostname>' first"
}

cmd_init() {
    local host="${1:-}"
    [[ -n "$host" ]] || die "usage: $0 init <server-hostname>"

    mkdir -p "$CERT_DIR"

    if [[ -f "$CERT_DIR/ca.pem" ]]; then
        die "$CERT_DIR/ca.pem already exists — refusing to overwrite a CA that
       certificates may already chain to. Move it aside deliberately if you
       really mean to start over."
    fi

    # P-256 throughout: supported by mbedTLS on ESP32 and much cheaper than RSA
    # on a handshake the device performs on battery.
    #
    # -sha256 is explicit on every signing step and must stay. LibreSSL — which
    # is what /usr/bin/openssl is on macOS — defaults to SHA-1, and Go rejects
    # SHA-1 signatures outright: the server refuses the handshake with
    # "insecure algorithm ECDSA-SHA1" and sends the client an "unknown ca"
    # alert, which points at the wrong problem entirely.
    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/ca-key.pem"
    openssl req -new -x509 -sha256 \
        -key "$CERT_DIR/ca-key.pem" -out "$CERT_DIR/ca.pem" \
        -days "$DAYS_CA" -subj "/CN=Cairn Private CA" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    openssl ecparam -genkey -name prime256v1 -out "$CERT_DIR/server-key.pem"
    openssl req -new -sha256 \
        -key "$CERT_DIR/server-key.pem" -out "$CERT_DIR/server.csr" \
        -subj "/CN=$host"

    # A SAN is required: the ESP32 TLS stack validates the name against SAN and
    # ignores CommonName, so a server certificate without one fails to verify
    # for a reason the error message does not explain.
    openssl x509 -req -sha256 -in "$CERT_DIR/server.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$CERT_DIR/server.pem" -days "$DAYS_LEAF" \
        -extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$host")

    rm -f "$CERT_DIR/server.csr"

    cat <<EOF

CA and server certificate written to $CERT_DIR.

Run the server with:

  cairn-server -data /var/lib/cairn \\
    -addr :8443 \\
    -tls-cert $CERT_DIR/server.pem \\
    -tls-key $CERT_DIR/server-key.pem \\
    -tls-client-ca $CERT_DIR/ca.pem

Then embed the CA in firmware:

  $0 ca-literal

EOF
}

cmd_device() {
    local device_id="${1:-}"
    [[ -n "$device_id" ]] || die "usage: $0 device <32-hex-device-id>"

    # Checked here rather than left to the server, because the failure there is
    # a 403 long after the certificate was installed.
    [[ "$device_id" =~ ^[0-9a-fA-F]{32}$ ]] \
        || die "device id must be exactly 32 hex characters, got '${device_id}'
       The firmware prints it at boot as 'device_id <...>'."

    device_id="$(printf '%s' "$device_id" | tr '[:upper:]' '[:lower:]')"
    need_ca

    local out="$CERT_DIR/device-$device_id"
    mkdir -p "$out"

    openssl ecparam -genkey -name prime256v1 -out "$out/client.key"
    openssl req -new -sha256 \
        -key "$out/client.key" -out "$out/client.csr" \
        -subj "/CN=$device_id"
    openssl x509 -req -sha256 -in "$out/client.csr" \
        -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca-key.pem" \
        -CAcreateserial -out "$out/client.crt" -days "$DAYS_LEAF" \
        -extfile <(printf 'extendedKeyUsage=clientAuth\n')

    rm -f "$out/client.csr"

    local cn
    cn="$(openssl x509 -in "$out/client.crt" -noout -subject)"

    cat <<EOF

Client certificate written to $out
  $cn

Copy both files to the device's card:

  mkdir -p /Volumes/<card>/cairn/certs
  cp $out/client.crt $out/client.key /Volumes/<card>/cairn/certs/

The firmware reads them at boot and logs 'mTLS ready' once both are present.
EOF
}

# Emit the CA as a C string literal for secrets.h. Hand-converting a PEM is
# where a dropped newline turns into an unexplained handshake failure.
cmd_ca_literal() {
    need_ca

    echo "/* Paste into firmware/cairn-v2/include/secrets.h */"
    echo "#define CAIRN_SERVER_CA_PEM \\"
    sed -e 's/\r$//' -e 's/^/    "/' -e 's/$/\\n" \\/' "$CERT_DIR/ca.pem" \
        | sed '$ s/ \\$//'
}

case "${1:-}" in
    init)       shift; cmd_init "$@" ;;
    device)     shift; cmd_device "$@" ;;
    ca-literal) shift; cmd_ca_literal "$@" ;;
    *)
        cat >&2 <<EOF
usage:
  $0 init <server-hostname>     create the CA and the server certificate
  $0 device <32-hex-device-id>  create one client certificate
  $0 ca-literal                 print the CA as a C literal for secrets.h
EOF
        exit 2
        ;;
esac
