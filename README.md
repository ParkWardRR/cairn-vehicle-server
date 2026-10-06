# Cairn vehicle server

The self-hosted server of the [Cairn driving log](https://github.com/ParkWardRR/Cairn):
it receives encrypted trip bundles from the enrolled phone, verifies and decodes them, keeps the
record, and answers the phone and the web dashboard. Written in Go; runs on one small machine.

The dongle has no network of its own. Bundles reach this server over BLE through the phone, which
only relays them: it cannot read them, and the server issues a signed receipt that the dongle checks
before it deletes anything. See the front door for the whole system.

| Part | What it does |
|---|---|
| `cmd/cairn-server` | ingest, the app API and the phone relay |
| `cmd/cairn-tsdb` | in-memory DuckDB store the dashboard queries (loopback only) |
| `cmd/cairn-admin` | devices, vehicles, assignments, enrolment, clients |
| `cmd/cairn-provision` | one-time dongle provisioning over USB |
| `cmd/cairn-verify`, `cairn-ledger`, `cairn-signfw` | offline verification, the audit ledger, firmware signing |
| `cmd/mkvectors` | generates the conformance vectors (into the contracts, see below) |
| `format/` | the reference implementation of the bundle format |
| `deploy/` | systemd units, migrations, `deploy-v3.sh` |

## Contracts

The wire and file formats this server implements are specified, with test vectors, in
[Cairn Vehicle Data Protocols](https://github.com/ParkWardRR/Cairn/tree/main/contracts). They are not
copied here: `contracts.lock` pins a release by tag **and** commit, and `scripts/fetch-contracts.sh`
fetches it into `.contracts/` and checks both. To change a contract and its implementation together, point
`CAIRN_CONTRACTS` at a local checkout (`CAIRN_CONTRACTS=../Cairn/contracts`); release builds refuse that.

## Build and test

```sh
scripts/fetch-contracts.sh
go build ./... && go vet ./... && go test ./...
```

The decode-pipeline tests need PostgreSQL with PostGIS (`CAIRN_TEST_DSN`); `tests/ci/postgis.sh start`
starts a throwaway one. The offload end-to-end tests need the firmware's protocol simulator
(`CAIRN_OFFLOAD_SIM`, built in the firmware repository) and skip loudly without it.

## Deploy

`deploy/deploy-v3.sh <user@host>` builds on the target host and installs the units; `--build-only` stops
after the build. No host name is stored in this repository. Read `docs/deploying.md` first.

## Related repositories

- [cairn-driving-log-selfhosted](https://github.com/ParkWardRR/Cairn): the front door, system docs and the contracts
- [cairn-vehicle-web-dashboard](https://github.com/ParkWardRR/cairn-vehicle-web-dashboard): the web dashboard
- [cairn-esp32-device-firmware](https://github.com/ParkWardRR/cairn-esp32-device-firmware): the dongle firmware
- [cairn-ios-companion-app](https://github.com/ParkWardRR/cairn-companion-ios-esp32-obd2-gps-ble): the iPhone app

History before the split is preserved here; see [MIGRATION.md](MIGRATION.md).

## License

Blue Oak Model License 1.0.0, see [LICENSE](LICENSE).
