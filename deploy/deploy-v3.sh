#!/usr/bin/env bash
# Deploy the v3 server stack to the Cairn host.
#
#   deploy/deploy-v3.sh <user@host> [--reset-v2-data] [--build-only]
#
# --build-only syncs and builds on the host, then stops: nothing is installed and
# nothing is restarted, so it is safe to run against a host that is serving.
#
# Builds ON the host (cairn-tsdb links DuckDB through cgo, which does not cross-
# compile from a Mac), from a source rsync rather than a git pull, so it deploys
# exactly the tree on this machine and publishes nothing. Never put real host
# names in this file: pass them on the command line.
#
# What it does, in order, stopping at the first failure:
#   1. rsync this repository (and deploy/) to ~/cairn-v3 on the host
#   2. build with nice and -p 4 (the host is shared with the runner and the
#      database; an uncapped build has wedged it before)
#   3. install the binaries, keeping the previous ones as <name>.prev
#   4. install the systemd units from deploy/systemd
#   5. refuse to restart unless /etc/cairn/server.env and the keystore master key
#      are in place (they are host-specific and are never overwritten here)
#   6. optionally archive v2 data (--reset-v2-data): moves, never deletes, and
#      KEEPS keys/ — the receipt seed is pinned in the dongle's firmware, and
#      losing it means reflashing every device
#   7. restart and wait for health
set -euo pipefail

HOST="${1:?usage: deploy-v3.sh <user@host> [--reset-v2-data] [--build-only]}"
shift
RESET=0; BUILD_ONLY=0
for a in "$@"; do
  case "$a" in
    --reset-v2-data) RESET=1 ;;
    --build-only) BUILD_ONLY=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA=/var/lib/cairn
BINS="cairn-server cairn-admin cairn-verify cairn-ledger cairn-signfw"

echo "==> syncing source"
ssh "$HOST" "mkdir -p ~/cairn-v3/server ~/cairn-v3/deploy"
rsync -az --delete --exclude node_modules --exclude .git --exclude 'bin/' \
  --exclude deploy --exclude .contracts \
  "$ROOT/" "$HOST:cairn-v3/server/"
rsync -az --delete "$ROOT/deploy/" "$HOST:cairn-v3/deploy/"

echo "==> building on the host (nice, -p 4)"
# The source is rsynced without .git, so the host cannot work out the build identity
# (/healthz) itself; it is taken from this checkout and passed in.
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
ssh "$HOST" "cd ~/cairn-v3/server && nice -n 10 make build BINDIR=bin GOFLAGS=-p=4 VERSION='$VERSION' COMMIT='$COMMIT' && nice -n 10 make build-tsdb BINDIR=bin GOFLAGS=-p=4 VERSION='$VERSION' COMMIT='$COMMIT'"

if [ "$BUILD_ONLY" = 1 ]; then
  echo "==> built; --build-only, so nothing was installed or restarted"
  exit 0
fi

echo "==> installing binaries"
ssh "$HOST" "cd ~/cairn-v3/server/bin && for b in $BINS cairn-tsdb; do
  test -x \$b || { echo missing \$b; exit 1; }
  if test -e /usr/local/bin/\$b; then sudo cp -p /usr/local/bin/\$b /usr/local/bin/\$b.prev; fi
  sudo install -m 0755 \$b /usr/local/bin/\$b
done"

echo "==> installing systemd units"
ssh "$HOST" 'cd ~/cairn-v3/deploy/systemd && for u in cairn-server.service cairn-tsdb.service; do
  sudo install -m 0644 $u /etc/systemd/system/$u
done && sudo systemctl daemon-reload'

echo "==> checking host-specific configuration"
ssh "$HOST" 'set -e
sudo test -s /etc/cairn/keystore.master || { echo "MISSING /etc/cairn/keystore.master (see deploy/systemd/cairn-server.service)"; exit 1; }
sudo grep -q "^CAIRN_ARGS=" /etc/cairn/server.env || { echo "server.env has no CAIRN_ARGS"; exit 1; }'

if [ "$RESET" = 1 ]; then
  echo "==> archiving v2 data (keys/ stays)"
  ssh "$HOST" "set -e
  sudo systemctl stop cairn-tsdb cairn-server
  A=/var/lib/cairn-archive-v2-\$(date +%Y%m%d-%H%M%S)
  sudo mkdir -p \$A
  for d in cas offers outbox receipts ledger devices.json; do
    sudo test -e $DATA/\$d && sudo mv $DATA/\$d \$A/ || true
  done
  sudo test -d /var/lib/cairn-tsdb/sd && sudo mv /var/lib/cairn-tsdb/sd \$A/tsdb-sd || true
  echo archived to \$A"
fi

echo "==> restarting"
ssh "$HOST" 'sudo systemctl restart cairn-server && sleep 2 && sudo systemctl restart cairn-tsdb && sleep 3
systemctl is-active cairn-server cairn-tsdb
journalctl -u cairn-server -n 6 --no-pager | tail -6'
echo "==> done. Next: seed vehicles and enrol devices (docs/device-provisioning.md)"
