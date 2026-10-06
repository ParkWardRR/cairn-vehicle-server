# Device enrolment and provisioning

How a Cairn dongle gets its server-side identity, its storage root escrowed and its
vehicle, over the USB console, with nothing secret on the SD card, nothing secret in
the clear on any wire, and **no network credential of any kind on the device**.

The dongle has no Wi-Fi and no TLS client: sealed bundles leave it over BLE, carried
by the enrolled phone ([ble-offload.md](https://github.com/ParkWardRR/cairn-driving-log-selfhosted/blob/main/contracts/ble/v1/offload.md)). So there is no SSID, no
password, no client certificate and no transport private key to provision. What is
provisioned is small and none of it is a secret the chip must keep.

Context: [trust-model-v3.md](https://github.com/ParkWardRR/cairn-driving-log-selfhosted/blob/main/docs/trust-model-v3.md) §3.3 and §4.1. Code:
`firmware/cairn-v2/lib/cairn_prov`, `firmware/cairn-v2/src/prov_console.cpp`,
`server/internal/enroll`, `server/cmd/cairn-admin` (`device enroll`),
`server/cmd/cairn-provision`. Public test vectors: `contracts/enrolment/v1/vectors/`.

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

**Limit, measured on the car's dongle.** Erasing an NVS entry only marks it deleted;
the bytes stay in flash until NVS recycles that page. The boot-time scrub forces a
lot of recycling, and it overwrote the old **private key and certificate** (large
blobs, mostly-deleted pages), but a **Wi-Fi password** the Wi-Fi stack had saved in
its own NVS namespace survived in a page that also holds live entries. So the
guarantee is: no key or certificate remains, and the old credentials are no longer
used or reachable through any API; a password may remain readable to someone who
dumps the chip's flash, until flash encryption exists (Phase 24). If a unit that ran
earlier firmware is ever lost, change the Wi-Fi password.

NVS is plain until flash encryption and NVS encryption arrive together in
ROADMAP Phase 24. Until then the device protects the **card**, not the **chip**:
someone who dumps the chip's flash can read the storage root. That is the reason a
network private key must not also live there, and no longer does.

## The wire format

The sealed blob, its fingerprint and the console protocol are specified in
[contracts/enrolment/v1/spec.md](https://github.com/ParkWardRR/cairn-driving-log-selfhosted/blob/main/contracts/enrolment/v1/spec.md). In short: the device
seals its storage root to the server's enrolment key, signs the result, and prints it on
request; the operator's workstation relays it to `cairn-admin device enroll`, which refuses
anything it cannot verify, then installs the vehicle assignment and counter floor over the
console. `cairn-provision` does the whole sequence and requires the device's fingerprint to be
confirmed against a record made somewhere other than the console it guards.

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
   [ble-offload.md](https://github.com/ParkWardRR/cairn-driving-log-selfhosted/blob/main/contracts/ble/v1/offload.md).

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
