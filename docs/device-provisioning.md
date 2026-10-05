# Device enrolment and provisioning

How a Cairn dongle gets its server-side identity, its storage root escrowed and its
vehicle, over the USB console, with nothing secret on the SD card, nothing secret in
the clear on any wire, and **no network credential of any kind on the device**.

The dongle has no Wi-Fi and no TLS client: sealed bundles leave it over BLE, carried
by the enrolled phone ([ble-offload.md](ble-offload.md)). So there is no SSID, no
password, no client certificate and no transport private key to provision. What is
provisioned is small and none of it is a secret the chip must keep.

Context: [trust-model-v3.md](trust-model-v3.md) §3.3 and §4.1. Code:
`firmware/cairn-v2/lib/cairn_prov`, `firmware/cairn-v2/src/prov_console.cpp`,
`server/internal/enroll`, `server/cmd/cairn-admin` (`device enroll`),
`server/cmd/cairn-provision`. Public test vectors: `fixtures/enroll-v1/`.

## What gets provisioned

| Item | Where it ends up | Why |
|---|---|---|
| Storage root `K_root` | Generated **on the device**; sealed to the server and escrowed there. Never leaves the device in the clear | The server must decode; nobody else may |
| Vehicle and assignment ids | Device NVS | Every segment and manifest carries them |
| Counter floor | Device NVS (the counter only ever rises) | A re-enrolled unit must resume above every counter already spent |

Compiled in, deliberately: the server's **enrolment public key** (to seal the root),
the server's **receipt public key** (to authorise deleting a bundle) and the BLE
passkey. Trust anchors, not secrets; one read from the card could be swapped by
anyone holding the card.

**Earlier firmware** kept a Wi-Fi password and a client certificate and private key in
NVS. This firmware erases them at boot (`cairn_prov_erase_legacy_credentials`) and
refuses to accept them again, so a dongle that was provisioned the old way is cleaned
by simply flashing the new build.

NVS is plain until flash encryption and NVS encryption arrive together in
ROADMAP Phase 24. Until then the device protects the **card**, not the **chip**:
someone who dumps the chip's flash can read the storage root. That is the reason a
network private key must not also live there, and no longer does.

## The sealed enrolment blob

Printed by the device on request (`GET enroll_blob`). 225 bytes, little-endian,
shown as base64:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `CENR` |
| 4 | 1 | version = 1 |
| 5 | 16 | `device_id` |
| 21 | 32 | device Ed25519 public key |
| 53 | 4 | `storage_key_version` |
| 57 | 32 | ephemeral X25519 public key |
| 89 | 24 | XChaCha20-Poly1305 nonce |
| 113 | 32 | ciphertext of `K_root` |
| 145 | 16 | Poly1305 tag |
| 161 | 64 | Ed25519 signature by the device key over bytes `[0, 161)` |

```text
shared = X25519(eph_priv, server_enrol_pub)
key    = HKDF-SHA256(ikm = shared, salt = eph_pub ‖ server_enrol_pub,
                     info = "cairn/enroll-seal/v1", L = 32)
ct‖tag = XChaCha20-Poly1305(key, nonce, K_root, aad = bytes [0, 113))
```

- The **AAD** covers every header field, so identity, key and key version cannot
  be edited without failing the tag.
- The **signature** is proof of possession: whoever produced the blob holds the
  device's signing key, so a blob cannot enrol someone else's public key.
- The ephemeral key and nonce come from the hardware RNG. The device **refuses**
  to produce a blob while the pinned server key is the all-zero placeholder:
  sealing to a key nobody holds would "succeed" and lose the root.
- The server's enrolment private key is wrapped under the keystore master key
  (`<data>/keys/enroll.x25519`). A blob is not secret (it crosses a console, ssh
  and logs), so the key that opens it must be protected exactly like the roots it
  unlocks.
- The C implementation and the Go reference produce **byte-identical** blobs from
  the same inputs; `fixtures/enroll-v1/vectors.json` pins that and both test
  suites check it.

### The fingerprint

`FINGERPRINT` is the first 4 bytes of SHA-256(device public key), 8 hex
characters: the same value as the first half of the device key id. It is a
**mix-up check**, "the blob I am approving came from the unit on my bench", not
authentication of the channel. `cairn-admin device enroll` **requires**
`--confirm-fingerprint`; there is no approve-whatever-arrived mode. For the check
to mean anything the value should come from somewhere other than the console it
guards: a record made when the unit was first enrolled, or the label on a unit
you provisioned yourself. `cairn-provision` accepts `--expect-device-id` and
`--expect-fingerprint` for exactly that, so a non-interactive run is still a
checked one.

## The console protocol

Line-oriented ASCII at 115200 baud. Host commands, device replies prefixed
`@prov ` (the console also carries the device's log, so a bare `OK` would be
ambiguous):

| Host | Device |
|---|---|
| `CAIRN-PROV BEGIN` | `@prov PROV-READY <device_id hex> <fingerprint>` or `@prov ERR refused: …` |
| `GET enroll_blob` | `@prov ENROLL-BLOB <base64>` or `@prov ERR …` |
| `SET assignment <vehicle32hex> <assignment32hex>` | `OK` (both non-zero) |
| `SET counter_floor <n>` | `OK` (decimal u64; only raises) |
| `COMMIT` | `OK`, or `ERR <reason>` (staged values kept; re-send) |
| `CAIRN-PROV END` | `OK` |

`SET wifi_ssid`, `SET wifi_pass`, `SET client_cert` and `SET client_key` no longer
exist and are answered `ERR unknown field`. A host script written for the old
firmware therefore **cannot** put a private key on a current dongle, which is the
point; a host test asserts it.

A successful `COMMIT` closes the session; the device stays silent about lines
sent outside one.

**Rules.**

- **Never during a trip**: whenever the controller is past Idle.
- An **unassigned** device accepts a session at any time (nothing to protect).
- An **assigned** device accepts one only in the first **60 s after boot**, so
  an unattended unit cannot be re-provisioned by someone who plugs in later.
  `cairn-provision --reset` pulses the board's reset line and then begins.
- A session idles out after **30 s** and its staged values are scrubbed.
- The assignment and the counter floor are idempotent and the floor only rises, so
  a `COMMIT` that reports failure is safe to simply send again.
- **No secret is ever echoed or logged.** The log records events and field
  *names* only. A host test sends a canary through every path and asserts it
  appears in no reply and no log line, raw or base64.

## Operator procedure

All values are placeholders. Run on the workstation the dongle is plugged into.

1. **Pin the server's enrolment key in firmware** (once per server):
   ```sh
   ssh <user>@<host> sudo -u cairn cairn-server -data /var/lib/cairn \
       -keystore-master /etc/cairn/keystore.master -print-enroll-key
   ```
   Put the printed hex in the gitignored `firmware/cairn-v2/include/secrets.h` as
   `CAIRN_SERVER_ENROLL_PUBKEY_HEX`, build and flash. The same file holds the
   server's receipt public key and the BLE passkey; it holds nothing else.
2. **Create the vehicle** (once per car):
   ```sh
   cairn-admin -data /var/lib/cairn vehicle add --name "<display name>" --engine <code>
   ```
3. **Provision**:
   ```sh
   cairn-provision --port /dev/cu.usbserial-<n> --reset \
     --expect-device-id <32hex> --expect-fingerprint <8hex> \
     --admin-cmd 'ssh <user>@<host> sudo -u cairn /usr/local/bin/cairn-admin -data /var/lib/cairn -keystore-master /etc/cairn/keystore.master' \
     --vehicle <vehicle id> --name <name>
   ```
   The tool fetches the blob, shows the fingerprint, enrols on the server
   (`cairn-admin device enroll --blob … --confirm-fingerprint …`), creates an
   assignment if needed, installs it with the counter floor, and commits. There is
   no certificate to issue and no Wi-Fi to configure.
4. **Check** with `cairn-provision --port … --reset --monitor 12`: the boot log
   should say `an assignment is installed`.
5. **Pair the phone** (BLE passkey) and let the app offload; see
   [ble-offload.md](ble-offload.md).

`cairn-admin device enroll` refuses, before writing anything: a blob whose
signature does not verify, a fingerprint that does not match, a device id
already enrolled with a **different** signing key (pass `--allow-key-change`
only if the unit was deliberately re-keyed), a **different root** for a key
version already escrowed (a wiped NVS or a clone claiming the id), a revoked
device (`--reinstate`), and a crypto-shredded key version.

## Residual risk

Physical access to the USB port is the trust boundary until flash encryption and
secure boot exist (ROADMAP Phase 24). Someone with the cable and the 60-second
window can replace the assignment; the rules above narrow that, they do not remove
it. What stays true regardless: they cannot read the root (it is never printed in
the clear), cannot enrol a key without the server operator confirming a
fingerprint, and a stolen unit is stopped by revoking it on the server. And there
is no network secret on the chip to steal.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `ERR refused: … window … closed` | An assigned unit is past its 60 s; use `--reset` |
| `ERR unknown field` for `wifi_*` / `client_*` | A stale host tool. Those fields were removed on purpose |
| `no server enrolment key is pinned` | `CAIRN_SERVER_ENROLL_PUBKEY_HEX` is still all zeros in `secrets.h` |
| `a DIFFERENT storage root is already escrowed` | The device's NVS was erased and it generated a new root. Decide whether that is intended; if so, escrow a new key version, do not overwrite |
| `SD mount failed … GO_IDLE_STATE failed` | No card in the dongle. Provisioning does not need it; capture does |
| Boot log: `erased Wi-Fi and client-certificate material left in NVS` | Expected once, on the first boot after upgrading from firmware that had Wi-Fi |
