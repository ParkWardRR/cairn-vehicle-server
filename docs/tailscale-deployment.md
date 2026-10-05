# Tailscale deployment

Remote access for the iOS app, with no public exposure. Read
[trust-model-v3.md](trust-model-v3.md) §1 first: **Tailscale here is
reachability, not authorization.** The app still needs its own enrolled
identity, and the dongle never touches the Tailnet.

All hostnames below are placeholders (`cairn-host`, `example-tailnet`). Real
values belong in your own notes and the gitignored deployment env, not in this
repository.

## Topology

```text
iPhone ── LAN Wi-Fi ───────────► https://cairn.example.lan:8444        (cairn-server, app listener)
   └──── Tailscale ──► tailscaled on the host
                         └─ tailscale serve (TLS terminated here)
                              └─► http://127.0.0.1:8445               (cairn-server, loopback listener)

Dongle ── BLE ──► iPhone ──(either path above)──► relay endpoints on the app listener
```

The dongle has no Wi-Fi: the phone carries its bundles ([ble-offload.md](ble-offload.md)),
so the Tailnet path above also carries trip uploads. The legacy `:8443` device listener
is no longer used by any dongle and is retired once the relay is proven (Cairn #7).

The two app URLs are *one logical account* in the app, not two databases.

## Install on the host, not in a container

`tailscaled` runs on the Cairn host. Do **not** put it in the application
container or pass its auth key through Compose: the key would then live in an
image layer, a compose file or an environment dump.

```bash
# host
sudo tailscale up --advertise-tags=tag:cairn-server --ssh=false
```

- Use a **one-time, tagged, pre-authorised** auth key if you script it, and
  keep it out of Git and images. An interactive `tailscale up` needs none.
- Tagged nodes have key expiry disabled by default; that is appropriate for a
  server and it is exactly why the tag's ACL must be tight.
- Leave **device approval** on for the tailnet so an unexpected node cannot
  join silently.
- No subnet router unless you actually need one. No Tailscale SSH on this host
  unless you have a specific need, and then restricted to your identity.

## Publish only the app listener

Bind Cairn's tailnet-facing listener to **loopback** (`-app-serve-addr`, plain HTTP, accepted
only on loopback) and let Serve front it. It is the same API instance as the LAN listener
(`-app-addr`), so both routes share one sync log, cursor and set of clients:

```bash
cairn-server ... \
  -app-addr :8444 \
  -app-serve-addr 127.0.0.1:8445 \
  -trust-tailscale-serve

sudo tailscale serve --bg --https=443 http://127.0.0.1:8445
tailscale serve status        # confirm it is Serve, not Funnel
```

(Check the flag syntax against the installed `tailscale` version; it has
changed between releases.)

- **Never** run `tailscale funnel` for Cairn. The app listener rejects any
  request carrying the Funnel header as a backstop, but the control is not
  turning it on. `tailscale serve status` must not show "Funnel on".
- Do not publish the device listener (`:8443`), PostgreSQL, MQTT, `cairn-tsdb`
  or any admin endpoint to the Tailnet. The dongle does not need it.
- `-trust-tailscale-serve` makes Cairn honour the `Tailscale-User-Login` /
  `Tailscale-User-Name` headers that Serve injects, **only** when the TCP peer
  is loopback. From any other peer they are ignored, so a LAN client cannot
  spoof a Tailnet identity.

## ACL policy

Allow only your phone to reach only the app port on the server tag:

```jsonc
{
  "tagOwners": { "tag:cairn-server": ["autogroup:admin"] },
  "grants": [
    {
      "src": ["you@example.com"],           // your user; or tag your phone
      "dst": ["tag:cairn-server"],
      "ip":  ["tcp:443"]
    }
  ],
  "ssh": []                                  // no Tailscale SSH
}
```

Optionally add `-require-tailnet-identity -tailnet-allow-login you@example.com`
so tailnet-class requests must carry your Serve-injected identity as well as a
valid app signature. That is defence in depth: three independent checks (ACL,
Tailnet login, enrolled app key) must all agree.

## DNS and TLS

- Use the MagicDNS name (`cairn-host.example-tailnet.ts.net`); do not point an
  arbitrary public DNS record at a Tailnet address.
- Serve obtains a certificate for that name. The app trusts the normal chain
  **and** pins the server's SPKI hash returned at enrolment; a Tailnet peer is
  not trusted blindly.

## Verifying it

```bash
# From the phone's tailnet address only:
curl -s https://cairn-host.example-tailnet.ts.net/v1/health       # 200, tiny JSON
# Unsigned API call must fail:
curl -si https://cairn-host.example-tailnet.ts.net/v1/sync/pull   # 401
# From the open internet (cellular, not on Tailnet): must not connect at all.
```

## Reliability caveat

iOS does not keep a VPN up in every background state. Sync is designed as a
durable outbox with resumable background transfers: it completes when the app
next runs and a route exists. Tailscale is a route preference, never a
dependency for correctness.

## Operations

- Revoke a lost phone with `cairn-admin client revoke <id>`; it takes effect on
  the next request. Also remove it from the Tailnet.
- Rotate the server's auth key and review the ACL when the set of devices
  changes. Review `tailscale serve status` after any host change.
