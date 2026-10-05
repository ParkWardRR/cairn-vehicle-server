# Deploying the ingest server

What is actually running, and why each piece is where it is. Current as of
2026-10-01, when the server first went up as a real service.

## The short version

```
device ──── mutual TLS, private CA ────► cairn-server :8443   (systemd, no proxy)
browser ─── Let's Encrypt via Caddy ───► web UI :443          (Caddy, DNS-01)
```

Two separate paths on purpose. The device path is deliberately not behind the
reverse proxy.

## Why Caddy does not front device ingest

This is the one design decision here worth reading before changing anything.

The ingest handler authenticates a device by reading the TLS client certificate
off the connection:

```go
certDevice := r.TLS.PeerCertificates[0].Subject.CommonName
```

It compares that CommonName to the device id inside the signed manifest and
refuses the upload if they differ, so possessing a card is not enough to upload
as a different device. `internal/httpapi/identity_test.go` exercises this over a
real TLS listener.

Terminate TLS in a proxy and `r.TLS` is nil by the time the handler runs. The
only way to recover the identity is for the proxy to forward it in a header that
the server then trusts — and anything that can reach the backend can set that
header. **A reverse proxy cannot sit in front of mutual TLS without dissolving
the mutual half.** So `cairn-server` terminates its own TLS.

There is a second, independent reason to keep ACME off that path: the device has
to be able to deliver a trip when the internet is down. A certificate that needs
renewing from Let's Encrypt makes trip delivery depend on the internet being up,
which is the opposite of what an offline-first device is for. The private CA
issues a 10-year root and 825-day leaves, entirely offline.

Caddy is still the right tool for the browser-facing UI, and uses the house
pattern there — Let's Encrypt over the Cloudflare DNS-01 challenge, so an
internal hostname gets a publicly trusted certificate without being publicly
reachable. See `deploy/caddy/Caddyfile`.

## The service

`deploy/systemd/cairn-server.service`, installed to
`/etc/systemd/system/`. It replaced a `systemd-run --user` transient unit used
during bring-up that did not survive a reboot.

- Runs as a dedicated `cairn` system user, not a login account. The directory it
  owns holds the receipt-signing seed, and that key is what authorizes a device
  to delete a trip from its card.
- `StateDirectory=cairn` owns `/var/lib/cairn` at 0700.
- Sandboxed fairly tightly — `ProtectSystem=strict`, `MemoryDenyWriteExecute`,
  `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_INET AF_INET6`.
  An ingest service parses attacker-supplied bytes for a living: a bundle
  arrives over the network and is scanned frame by frame.
- Flags come from `/etc/cairn/server.env` so changing transport does not mean
  editing a unit. `CAIRN_ARGS` is intentionally unquoted in `ExecStart`, because
  systemd word-splits a bare `$VAR`.

```bash
sudo systemctl status cairn-server
sudo journalctl -u cairn-server -f
```

The startup line states the security posture, and is worth reading rather than
assuming:

```
cairn ingest starting addr=:8443 tls=true client_auth=true \
  receipt_key_id=cde936abd43d9703 devices=1
```

## Certificates

`deploy/make-certs.sh` issues the chain. P-256 throughout, since mbedTLS on the
ESP32 supports it and it is far cheaper than RSA on a handshake the device
performs on battery.

```bash
./make-certs.sh init   cairn.alpina.casa   # CA + server certificate
./make-certs.sh device <32-hex-device-id>  # one client certificate
./make-certs.sh ca-literal                 # CA as a C string literal
```

Three details that each cause a failure pointing somewhere else:

- **The client CommonName must be the device id**, 32 lowercase hex. The server
  compares it to the signed manifest and returns 403 on a mismatch — which looks
  nothing like a certificate problem.
- **`-sha256` is explicit on every signing step.** LibreSSL, which is
  `/usr/bin/openssl` on macOS, defaults to SHA-1, and Go rejects SHA-1
  signatures outright: the handshake fails with `insecure algorithm ECDSA-SHA1`
  and the client sees an `unknown ca` alert, pointing at entirely the wrong
  thing.
- **A subjectAltName is required.** The ESP32 TLS stack validates the name
  against SAN and ignores CommonName. Note that LibreSSL cannot *read* SANs
  (`openssl x509 -ext` is OpenSSL-only), so verify with
  `openssl x509 -text | grep -A1 Alternative` or a cert that has one looks like
  one that does not.

The CA private key stays on the workstation. Only `ca.pem`, `server.pem` and
`server-key.pem` are copied to the host, into `/etc/cairn/certs` with the key at
0640 `root:cairn`. `deploy/certs/` is gitignored; this repository is public.

## Switching transport

`/etc/cairn/server.env` holds one active `CAIRN_ARGS` line.

Mutual TLS, the intended configuration:

```
CAIRN_ARGS=-addr :8443 -data /var/lib/cairn -tls-cert /etc/cairn/certs/server.pem -tls-key /etc/cairn/certs/server-key.pem -tls-client-ca /etc/cairn/certs/ca.pem
```

Plaintext, for a device that cannot speak mutual TLS yet:

```
CAIRN_ARGS=-dev -addr :8080 -data /var/lib/cairn
```

Then `sudo systemctl restart cairn-server`. A device needs two things before it
can use mutual TLS, and both require physical access to the hardware:
`CAIRN_SERVER_CA_PEM` compiled into firmware, and `client.crt` / `client.key` in
`/cairn/certs/` on its card.

Plaintext is not as alarming as it sounds, and is not an excuse either: a
receipt's Ed25519 signature is what authorizes deleting data, not the transport.
Plaintext changes who can read an upload, not whether a deletion is legitimate.

## The receipt key is a reflash-level dependency

`/var/lib/cairn/keys/receipt.seed` signs every receipt. The device pins the
corresponding public key in firmware and refuses to delete anything not signed
by it.

**Lose that seed and every device must be reflashed** to pin a new one. Back it
up. `-dev` no longer mints an ephemeral key when a seed exists — it used to, and
the result was a server issuing receipts under a key no device had pinned, with
nothing logging an error on either side.

```bash
cairn-server -data /var/lib/cairn -print-receipt-key
```

## Verifying it works

```bash
# Must be refused: no client certificate.
curl --cacert ca.pem https://cairn.alpina.casa:8443/api/v2/bundles/offer

# Must reach the handler, which then complains about the body rather than TLS.
curl --cacert ca.pem --cert client.crt --key client.key \
  -X POST https://cairn.alpina.casa:8443/api/v2/bundles/offer
# → 400 missing X-Cairn-Signature

# What the pipeline actually recorded. Three things to get right at once:
# the ledger directory is positional (-data is rejected), /var/lib/cairn is
# 0700 cairn so it needs sudo, and sudo's secure_path excludes /usr/local/bin
# so the binary needs its full path. Each of the three fails differently and
# none of them says "permissions".
sudo /usr/local/bin/cairn-ledger -summary  /var/lib/cairn/ledger
sudo /usr/local/bin/cairn-ledger -problems /var/lib/cairn/ledger
```

## Building

`server/Makefile` detects the host CPU and selects `GOAMD64=v3`, worth +15.7% on
segment scanning. It falls back to `v1` with a warning when AVX2, BMI2 and FMA
are not all present, because a `v3` binary on an older CPU dies with SIGILL at
startup rather than reporting anything useful.

```bash
cd server && make build     # ./bin/, then install to /usr/local/bin
make bench-isa              # re-derive the v1-vs-v3 table
```

To build on the host and install the binaries and systemd units in one step, use
`deploy/deploy-v3.sh <user@host>` (it also builds `cairn-tsdb`, which needs cgo, and
keeps the previous binaries as `<name>.prev`). The UI is deployed separately with
`deploy/deploy-ui.sh`.
