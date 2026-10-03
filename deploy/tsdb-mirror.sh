#!/bin/sh
# Mirror an SD card's sealed v2 bundles to the host running cairn-tsdb, then
# rebuild the store.
#
#   deploy/tsdb-mirror.sh <host> [card-cairn-dir]
#   deploy/tsdb-mirror.sh cairn.example.lan /Volumes/CAIRN/cairn
#
# Additive on purpose. A bundle the device later prunes (after a receipt) stays
# in the mirror, so the analytical store keeps data the card no longer holds.
#
# Only bundles/ is copied. The card's trips/ directories are v1, which is dead and
# is never read, and capture/ is a bundle still being written, which is not
# sealed and so not yet a bundle.
set -eu

host=${1:?usage: tsdb-mirror.sh <host> [card-cairn-dir]}
card=${2:-/Volumes/CAIRN/cairn}
dest=/var/lib/cairn-tsdb/sd/bundles

[ -d "$card/bundles" ] || { echo "no bundles/ under $card" >&2; exit 1; }

n=$(find "$card/bundles" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
echo "mirroring $n bundle(s) from $card to $host:$dest"

# Run the remote rsync as the service user so the files arrive owned by it and
# the hardened unit can read them; no copy is left readable by anyone else.
rsync -a --exclude '._*' --rsync-path='sudo -u cairn rsync' \
    "$card/bundles/" "$host:$dest/"

# With -watch the service would notice on its own within a couple of intervals;
# asking directly makes the script's answer immediate. A build that did not
# reproduce comes back as a 409 and fails the script, which is the point.
ssh "$host" 'curl -fsS -X POST localhost:8480/reload >/dev/null && curl -fsS localhost:8480/metrics' |
    grep -E '^cairn_tsdb_(bundles|bundles_reproduced|problems) '
