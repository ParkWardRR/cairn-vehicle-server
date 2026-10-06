#!/usr/bin/env bash
# Interop: this server against the firmware's own code, built from a PINNED firmware
# revision, so a break on either side is caught by the repository whose change caused it.
#
#   tests/interop/run.sh                    the firmware commit pinned in interop.lock
#   INTEROP_FIRMWARE_DIR=<checkout> tests/interop/run.sh
#                                           a local firmware checkout (the firmware repo's
#                                           scheduled run uses this against the server's main)
#
# Three things run, none of them mocks:
#
#   1. the offload end-to-end tests: the PHONE client, the firmware's OWN protocol module
#      (compiled for the host as offload-sim) and this server's relay, all real, only the
#      BLE link simulated. They skip when the simulator is absent, so this asserts that
#      they did not skip;
#   2. the emulator's protocol fault-matrix rows against a running server: torn uploads,
#      replays, reordering, forged receipts;
#   3. the emulator's own local durability rows are NOT here: they need no server and run in
#      the firmware repository.
#
# Needs Go, a C compiler, make, Rust (cargo) and git. Nothing is installed or published.
set -euo pipefail

cd "$(dirname "$0")/../.."
ROOT="$PWD"
WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# this server's own pinned contracts (the offload tests compare against its vectors)
scripts/fetch-contracts.sh >/dev/null

# ─── the firmware, pinned ────────────────────────────────────────────────────
if [ -n "${INTEROP_FIRMWARE_DIR:-}" ]; then
  FW="$(cd "$INTEROP_FIRMWARE_DIR" && pwd)"
  echo "==> firmware from $FW (override)"
else
  field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" interop.lock | head -1; }
  repo="$(field repo)"; commit="$(field commit)"
  [ -n "$repo" ] && [ -n "$commit" ] || { echo "interop.lock has no repo or commit" >&2; exit 1; }
  FW="$ROOT/.interop/firmware"
  if [ ! -d "$FW/.git" ] || [ "$(git -C "$FW" rev-parse HEAD)" != "$commit" ]; then
    echo "==> fetching the firmware at $commit"
    rm -rf "$FW"; mkdir -p "$FW"
    git -C "$FW" init -q
    git -C "$FW" fetch -q --depth 1 "$repo" "$commit"
    git -C "$FW" checkout -q FETCH_HEAD
  fi
  [ "$(git -C "$FW" rev-parse HEAD)" = "$commit" ] || { echo "fetched the wrong firmware commit" >&2; exit 1; }
  echo "==> firmware pinned at $commit"
fi

# the firmware resolves its own pinned contracts
"$FW/scripts/fetch-contracts.sh" >/dev/null

# ─── 1. the offload end-to-end tests, for real ───────────────────────────────
echo "==> building the firmware protocol simulator"
make -C "$FW/test/host" offload-sim >/dev/null
SIM="$FW/test/host/build/offload-sim"
[ -x "$SIM" ] || { echo "offload-sim was not built" >&2; exit 1; }

echo "==> offload end-to-end (phone client, firmware module, server relay)"
out="$(CAIRN_OFFLOAD_SIM="$SIM" go test ./internal/offloadclient -count=1 -v 2>&1)" || { echo "$out" | tail -30; exit 1; }
echo "$out" | tail -3
if echo "$out" | grep -q -- '--- SKIP'; then
  echo "an offload test skipped, so it proved nothing:" >&2
  echo "$out" | grep -- '--- SKIP' >&2
  exit 1
fi

# ─── 2. the emulator's protocol rows against a running server ────────────────
echo "==> building the emulator and the server"
( cd "$FW/emulator" && cargo build --release -q )
EMU="$FW/emulator/target/release/cairn-emulator"
go build -o "$WORK/cairn-server" ./cmd/cairn-server
go build -o "$WORK/cairn-admin" ./cmd/cairn-admin

# v3 intake needs, for every device: an escrowed storage root, a vehicle, and an assignment
# of the device to it. These are the emulator's PUBLIC test values (its default root and a
# fixed pair of ids); they protect nothing.
DATA="$WORK/data"; mkdir -p "$DATA"
ROOT_HEX=636169726e2d656d756c61746f722d7075626c69632d746573742d726f6f7421
VEHICLE=606162636465666768696a6b6c6d6e6f
ASSIGNMENT=707172737475767778797a7b7c7d7e7f
MASTER="$WORK/keystore.master"
PORT="${INTEROP_PORT:-18700}"

# A persistent receipt key: an ephemeral one would invalidate every receipt on restart.
"$WORK/cairn-server" -data "$DATA" -keystore-master "$MASTER" \
  -enroll 101112131415161718191a1b1c1d1e1f \
  -enroll-key 9f8d4bbc0bf6feeabbabe4d2aff165db4f77fc4b6d46619818af409ddab507bf \
  -enroll-root "$ROOT_HEX" \
  -enroll-name interop-device
"$WORK/cairn-admin" -data "$DATA" vehicle add --id "$VEHICLE" --name "interop car"
"$WORK/cairn-admin" -data "$DATA" assign --assignment-id "$ASSIGNMENT" \
  101112131415161718191a1b1c1d1e1f "$VEHICLE"

"$WORK/cairn-server" -data "$DATA" -addr "127.0.0.1:$PORT" -dev \
  -keystore-master "$MASTER" -receipt-key "$DATA/receipt.seed" >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  curl -sf "http://127.0.0.1:$PORT/api/v2/health" >/dev/null && break
  sleep 0.2
done
curl -sf "http://127.0.0.1:$PORT/api/v2/health" >/dev/null || { echo "the server did not start:" >&2; tail -20 "$WORK/server.log" >&2; exit 1; }

echo "==> emulator protocol rows against the running server"
"$EMU" fault-matrix --work-dir "$WORK/fault-matrix-net" \
  --root-key "$ROOT_HEX" --vehicle-id "$VEHICLE" --assignment-id "$ASSIGNMENT" \
  --server "http://127.0.0.1:$PORT" --verbose

echo "==> the C writer's bundles against this server's verifier (fw #8)"
# The offload and emulator rows above never see bytes the firmware's C format code wrote, so a
# wrong CRC polynomial or frame layout there would pass them. This seals bundles with the real C
# writer and judges them with cairn-verify, then proves the check can fail: four mutations of a
# copy of the C sources must each be rejected.
"$FW/scripts/interop-writer.sh" --server "$ROOT" --mutation-check

echo "==> emulator as the phone against the relay (fw #12)"
# The real path: dongle -> BLE -> phone -> /v1/relay/bundles/*. Builds this checkout into its own
# temporary directory and runs the relay rows plus the rows only the relay has, then proves the
# run can fail (wrong pinned receipt key, revoked phone). Without this gate the relay path is
# provable only by hand, which is how a chain ends up never having carried a trip.
# Its own server, on its own ports: the one above is still running on $PORT.
INTEROP_PORT=$((PORT + 10)) INTEROP_APP_PORT=$((PORT + 11)) \
  "$FW/scripts/relay-interop.sh" --server "$ROOT" --selftest

echo "==> interop passed"
