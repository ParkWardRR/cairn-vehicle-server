#!/usr/bin/env bash
# Deploy the v3 server stack to the Cairn host.
#
#   deploy/deploy-v3.sh <user@host> [--channel beta|stable] [--reset-v2-data] [--build-only] [--snapshot]
#
# --channel names the release channel this deploy is: beta or stable. It changes two
# things. The binaries are stamped with it, so /healthz says which channel is serving;
# and the source is a clean export of HEAD rather than the working tree, with a dirty
# tree refused outright. Without --channel the deploy is a dev deploy of the working
# tree, which is what it has always been and is right for iterating.
#
# A release that cannot be reproduced is not one. See the front door's
# docs/release-process.md.
#
# --build-only syncs and builds on the host, then stops: nothing is installed and
# nothing is restarted, so it is safe to run against a host that is serving.
#
# --snapshot takes a cold snapshot of the host's state before anything is installed
# (deploy/snapshot.sh: cairn-server is stopped for the few seconds the copy takes), prints
# its path, and restore-tests it (deploy/restore-test.sh); a snapshot that does not restore
# and boot stops the deploy. It cannot be combined with --build-only, which promises not to
# stop anything.
#
# Builds ON the host (cairn-tsdb links DuckDB through cgo, which does not cross-
# compile from a Mac), from a source rsync rather than a git pull, so it deploys
# exactly the tree on this machine and publishes nothing. Never put real host
# names in this file: pass them on the command line.
#
# What it does, in order, stopping at the first failure:
#   0. with --channel: refuse a dirty tree, and export HEAD to a temporary directory
#   1. rsync this repository (and deploy/) to ~/cairn-v3 on the host
#   2. build with nice and -p 4 (the host is shared with the runner and the
#      database; an uncapped build has wedged it before)
#   3. install the binaries, keeping the previous ones as <name>.prev
#   3b. with --snapshot: snapshot and restore-test the state as it is now
#   4. install the systemd units from deploy/systemd
#   5. refuse to restart unless /etc/cairn/server.env and the keystore master key
#      are in place (they are host-specific and are never overwritten here)
#   6. optionally archive v2 data (--reset-v2-data): moves, never deletes, and
#      KEEPS keys/ — the receipt seed is pinned in the dongle's firmware, and
#      losing it means reflashing every device
#   7. restart and wait for health
set -euo pipefail

HOST="${1:?usage: deploy-v3.sh <user@host> [--channel beta|stable] [--reset-v2-data] [--build-only] [--snapshot]}"
shift
RESET=0; BUILD_ONLY=0; SNAPSHOT=0; CHANNEL=dev
while [ $# -gt 0 ]; do
  case "$1" in
    --reset-v2-data) RESET=1 ;;
    --build-only) BUILD_ONLY=1 ;;
    --snapshot) SNAPSHOT=1 ;;
    --channel)
      CHANNEL="${2:?--channel needs a value: beta or stable}"
      shift
      case "$CHANNEL" in
        beta|stable) ;;
        dev) echo "dev is the default; --channel dev is the same as passing nothing" >&2 ;;
        *) echo "channel must be beta or stable, not '$CHANNEL'" >&2; exit 2 ;;
      esac
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$SNAPSHOT" = 1 ] && [ "$BUILD_ONLY" = 1 ] && { echo "--snapshot stops cairn-server for the copy; --build-only promises to stop nothing" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA=/var/lib/cairn
BINS="cairn-server cairn-admin cairn-verify cairn-ledger cairn-signfw"

# What gets rsynced. A dev deploy sends the working tree, which is the point of a dev
# deploy. A channel deploy sends a clean export of HEAD, so the commit on /healthz
# describes what is running.
SRC="$ROOT"
if [ "$CHANNEL" != dev ]; then
  if [ -n "$(git -C "$ROOT" status --porcelain)" ]; then
    echo "Refusing a $CHANNEL deploy from a dirty tree: /healthz would name a commit that is not what ran." >&2
    git -C "$ROOT" status --short >&2
    exit 1
  fi
  SRC="$(mktemp -d)"
  trap 'rm -rf "$SRC"' EXIT
  git -C "$ROOT" archive HEAD | tar -x -C "$SRC"
  echo "==> $CHANNEL deploy from a clean export of $(git -C "$ROOT" rev-parse --short HEAD)"
fi

echo "==> syncing source"
ssh "$HOST" "mkdir -p ~/cairn-v3/server ~/cairn-v3/deploy"
rsync -az --delete --exclude node_modules --exclude .git --exclude 'bin/' \
  --exclude deploy --exclude .contracts \
  "$SRC/" "$HOST:cairn-v3/server/"
rsync -az --delete "$ROOT/deploy/" "$HOST:cairn-v3/deploy/"

echo "==> building on the host (nice, -p 4)"
# The source is rsynced without .git, so the host cannot work out the build identity
# (/healthz) itself; it is taken from this checkout and passed in.
VERSION="$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
ssh "$HOST" "cd ~/cairn-v3/server && nice -n 10 make build BINDIR=bin GOFLAGS=-p=4 VERSION='$VERSION' COMMIT='$COMMIT' CHANNEL='$CHANNEL' && nice -n 10 make build-tsdb BINDIR=bin GOFLAGS=-p=4 VERSION='$VERSION' COMMIT='$COMMIT' CHANNEL='$CHANNEL'"

if [ "$BUILD_ONLY" = 1 ]; then
  echo "==> built; --build-only, so nothing was installed or restarted"
  exit 0
fi

if [ "$SNAPSHOT" = 1 ]; then
  # Here, after the build: a build that fails costs nothing, and a snapshot is only worth
  # taking when the install that follows is going to happen. --stop-services is the explicit
  # consent snapshot.sh requires to stop the live unit; passing --snapshot is that consent.
  echo "==> snapshotting the host's state (cairn-server is stopped for the copy)"
  SNAP="$("$ROOT/deploy/snapshot.sh" "$HOST" --stop-services | tail -1)"
  echo "    snapshot: $SNAP (on $HOST)"
  echo "==> restore-testing the snapshot"
  "$ROOT/deploy/restore-test.sh" "$HOST" "$SNAP" || {
    echo "==> Refusing to deploy: the snapshot did not restore cleanly. Nothing was installed." >&2
    exit 1
  }
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
done
# The stack health check and its timer (a failing run shows in `systemctl --failed`).
sudo install -m 0755 ~/cairn-v3/deploy/healthcheck.sh /usr/local/bin/cairn-healthcheck
for u in cairn-healthcheck.service cairn-healthcheck.timer; do
  sudo install -m 0644 $u /etc/systemd/system/$u
done && sudo systemctl daemon-reload && sudo systemctl enable --now cairn-healthcheck.timer'

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
echo "==> health check (units, endpoints, proxy, certificate)"
# The services were just restarted: allow a few seconds for them to answer before failing.
ssh "$HOST" 'for i in 1 2 3 4 5 6; do /usr/local/bin/cairn-healthcheck --quiet && exit 0; sleep 5; done
echo "unhealthy after the deploy:" >&2; /usr/local/bin/cairn-healthcheck >&2; exit 1' || {
  echo "==> The deploy installed, but the stack is not healthy. Previous binaries are kept as <name>.prev." >&2
  exit 1
}
echo "==> done. Next: seed vehicles and enrol devices (docs/device-provisioning.md)"
