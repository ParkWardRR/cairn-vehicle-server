# Deploying the ingest server

> **Amended 2026-10-05.** The dongle no longer has Wi-Fi and does not use the
> `:8443` mTLS listener described here; the enrolled phone relays its bundles through
> the app API ([app-sync-protocol.md](https://github.com/ParkWardRR/cairn-driving-log-selfhosted/blob/main/contracts/sync/v1/spec.md) §13). This page describes
> the legacy device path, which stays deployed until the relay is proven on hardware
> and is then retired (Cairn #7). The current deployment is
> `deploy/deploy-v3.sh`; see also [tailscale-deployment.md](tailscale-deployment.md).

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
./make-certs.sh init   cairn.example.lan   # CA + server certificate
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
curl --cacert ca.pem https://cairn.example.lan:8443/api/v2/bundles/offer

# Must reach the handler, which then complains about the body rather than TLS.
curl --cacert ca.pem --cert client.crt --key client.key \
  -X POST https://cairn.example.lan:8443/api/v2/bundles/offer
# → 400 missing X-Cairn-Signature

# What the pipeline actually recorded. Three things to get right at once:
# the ledger directory is positional (-data is rejected), /var/lib/cairn is
# 0700 cairn so it needs sudo, and sudo's secure_path excludes /usr/local/bin
# so the binary needs its full path. Each of the three fails differently and
# none of them says "permissions".
sudo /usr/local/bin/cairn-ledger -summary  /var/lib/cairn/ledger
sudo /usr/local/bin/cairn-ledger -problems /var/lib/cairn/ledger
```

### The app API, over the real listener

`cairn-accept` runs the sync, snapshot and relay acceptance checks against a running
server. It writes real records (a maintenance event; with `-relay`, a synthetic bundle),
so give it an invitation scoped to a scratch vehicle:

```bash
sudo -u cairn /usr/local/bin/cairn-admin -data /var/lib/cairn vehicle add --name acceptance-test
sudo -u cairn /usr/local/bin/cairn-admin -data /var/lib/cairn client invite --vehicles <vehicle-id>
cairn-accept -server https://cairn.example.lan:8444 -code <invitation> -vehicle <vehicle-id>
# afterwards: client revoke <id>, vehicle archive <id>
```

The authenticated snapshot answers `503 no snapshot available` until `cairn-tsdb` holds
a bundle, so on a store with none the snapshot checks fail for that reason, not a bug.
`-relay` needs the synthetic recorder the tests use (`cairn-accept -print-synthetic`
prints the commands) and is best run against a scratch instance (`-dev`, its own `-data`
and `cairn-tsdb`), so no synthetic bundle reaches the real store.

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

## Is the stack healthy?

`deploy/healthcheck.sh` (installed as `/usr/local/bin/cairn-healthcheck`) checks the whole
stack from the host: the units (`cairn-server`, `cairn-tsdb`, `cairn-ui`, `caddy`,
`tailscaled`), the app API and tsdb endpoints, the dashboard *through the reverse proxy*,
`tailscaled`'s LocalAPI (the dashboard's tailnet identity depends on it), and the proxy's
certificate (fails under 14 days). It exits non-zero and names each failure. `deploy-v3.sh`
installs it with a systemd timer (`cairn-healthcheck.timer`, every 5 minutes), so a stack
that has quietly lost a link shows up in `systemctl --failed`, and runs it as the last step
of every deploy. Tailnet sign-in needs no `tailscale serve` config: the UI asks `tailscaled`
who owns the peer address behind Caddy (see the dashboard's `docs/auth.md`).

## Enrolling a phone with a QR code

`cairn-admin client invite --qr` prints the invitation as a QR code the phone's camera opens in
the Cairn app. One scan sets the server URL, trusts the private CA for the app's own connections,
and enrols the phone, so a tester never types a URL or installs a profile:

```bash
sudo -u cairn cairn-admin -data /var/lib/cairn client invite --name "Sam's iPhone" --ttl 30m \
    --qr --url https://cairn.example.lan:8444 [--tailnet-url https://cairn-host.example-tailnet.ts.net]
```

- `--url` is the app listener (`:8444`), not the web UI on `:443`. It can come from
  `$CAIRN_PUBLIC_URL`. `--ca` defaults to `/etc/cairn/certs/ca.pem` (the public certificate, no key).
- The same output holds a `cairn://configure?...` link to send by AirDrop or Messages when the
  camera is not handy, and `--qr-png FILE` writes the code as an image (mode 0600).
- The QR code carries the single-use invitation, so treat it like the code: short `--ttl`, show it
  only to the person enrolling. The CA certificate in it is public.
- The link format is mirrored by `ConfigureLink` in cairn-ios-companion-app and `buildPhoneLink` in
  the web dashboard; change all three together.

### From the web UI

The dashboard's **Add a phone** page makes the same QR code after a passkey check. It asks the
loopback local API (`POST /v1/local/clients/invite`, a *user* invitation of at most an hour, never
an admin one), which needs the shared write token:

```bash
openssl rand -hex 32 | sudo install -m 0640 -o root -g cairn /dev/stdin /etc/cairn/local-write-token
# add to CAIRN_ARGS in /etc/cairn/server.env, next to -app-local-addr:
#   -app-local-token-file /etc/cairn/local-write-token
sudo systemctl restart cairn-server
```

and in the UI's `/etc/cairn/ui.env`: `NUXT_CAIRN_LOCAL_TOKEN_FILE=/etc/cairn/local-write-token`,
`NUXT_PHONE_SETUP_URL=https://cairn.example.lan:8444` and `NUXT_PHONE_SETUP_CA_FILE=/etc/cairn/certs/ca.pem`
(`NUXT_PHONE_SETUP_TAILNET_URL` is optional). The UI reads the token from the file on each use, so the
secret lives in one place.

## Snapshot before a risky deploy

```bash
deploy/deploy-v3.sh <user@host> --snapshot          # snapshot, restore-test, then install
deploy/snapshot.sh <user@host> --stop-services      # just the snapshot; prints its directory
deploy/restore-test.sh <user@host> <snapshot-dir>   # restore it somewhere harmless and boot it
```

`snapshot.sh` is a **cold** copy: it stops `cairn-server` for the few seconds the copy takes
and starts it again afterwards, whatever happens (the store, `cairn-tsdb`, writes nothing
durable and stays up). That is why it refuses to run while the unit is active unless you
pass `--stop-services`, and always refuses while some other `cairn-server` process is using
the data directory. `deploy-v3.sh --snapshot` passes the flag for you (the deploy restarts
the service anyway), and cannot be combined with `--build-only`. The default is
`/var/backups/cairn-v3/cairn-<UTC time>/`, mode 0700, root only:

| file | holds |
|------|-------|
| `data.tar.gz` | `/var/lib/cairn`: every store the server writes (listed in [retention-and-backup.md](retention-and-backup.md)) |
| `tsdb-sd.tar.gz` | `/var/lib/cairn-tsdb/sd`, the card mirror |
| `config.tar.gz` | `/etc/cairn` (certificates, `server.env`) **without** the master key |
| `units.tar.gz` | `cairn-*.service` and drop-ins from `/etc/systemd/system` |
| `bin.tar.gz` | the installed `cairn-*` binaries and their `.prev` |
| `keystore.master` | the keystore master key, kept apart so the archives can travel without it |
| `MANIFEST` | archive hashes, a hash of every stored file, per-store file counts, binary hashes |

`restore-test.sh` restores into a scratch directory and boots the snapshot's **own** binaries
over the snapshot's own data and key, on spare loopback ports (`--ports`, default 19600-19603).
It passes only if every archive matches the manifest; every restored file matches the hash it
had when it was snapshotted; the key, config and binaries needed to run are present; the
restored `cairn-server` and `cairn-tsdb` come up; the server serves the receipt key held in the
snapshot (a server that quietly minted a new one would look healthy and refuse every device);
and the restored stack answers like the live one: the vehicle list, the app instance id, what
the store loaded, and `v_vehicles`. The live endpoints come from the snapshotted `server.env`
(`--live-tsdb`, `--live-local`, `--live-serve` override; `--no-live` skips the comparison).
Run it right after the snapshot: a trip that lands in between is a real difference. It never
writes to the live data or services. The restored server runs with `-dev`, so the TLS
certificates are checked for presence, not exercised.

The web layer's own stores (`/var/lib/cairn-ui`) are snapshotted by that repository's
`deploy-ui.sh --snapshot`. Old snapshots are not pruned; delete them by hand.

`tests/snapshot-restore.sh` runs all of this end to end against a scratch stack (no systemd,
no real data directory) and is what to run after changing either script.
