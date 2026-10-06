#!/usr/bin/env bash
# Cold snapshot of the v3 server's state on its host: the rollback point to take before a
# deploy that could go wrong. Adapted from the front door's cutover snapshot.
#
#   deploy/snapshot.sh <user@host|local> [--stop-services] [options]
#
# Prints the snapshot directory as its last line (everything else goes to stderr), so
# `SNAP="$(deploy/snapshot.sh host --stop-services | tail -1)"` works. Run
# deploy/restore-test.sh on the result: a snapshot you have not restored is a hope.
#
# "local" runs on this machine (needs read access to the data directory, so usually sudo);
# anything else is an ssh target, and the script is piped to `sudo bash` there. Never put
# real host names in this file: pass them on the command line.
#
# COLD means the writer is stopped for the few seconds the copy takes. The server's JSON
# stores, ledger and sync log are single-writer files with no snapshot primitive, so a copy
# taken while it runs can tear (docs/retention-and-backup.md says which stores tolerate it
# and which do not). Consequently this REFUSES to run while the unit, or any cairn-server
# process on this data directory, is live, unless you pass --stop-services: that stops the
# unit for the copy and starts it again afterwards, whatever happens. A cairn-server process
# that is not a unit cannot be stopped from here and is always refused.
#
# What it captures, into <dest>/cairn-<UTC time>/ (0700, root): the data directory, the
# tsdb SD mirror, the config (certificates, server.env) and systemd unit overrides, and the
# cairn binaries with their .prev. The keystore master key is deliberately NOT inside any
# archive: it is stored beside them as keystore.master so the archives can be copied
# elsewhere without carrying the key to every escrowed storage root.
#
# The web layer's own stores are snapshotted by the web repository's deploy-ui.sh --snapshot.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: snapshot.sh <user@host|local> [--stop-services] [options]
options:
  --stop-services   stop the unit for the copy (and restart it); required if it is active
  --dest DIR        parent directory for snapshots          (default /var/backups/cairn-v3)
  --data DIR        server data directory                    (default /var/lib/cairn)
  --tsdb-sd DIR     tsdb SD-card mirror                      (default /var/lib/cairn-tsdb/sd)
  --etc DIR         config and certificates                  (default /etc/cairn)
  --bin DIR         installed binaries                       (default /usr/local/bin)
  --systemd DIR     unit files and drop-ins                  (default /etc/systemd/system)
  --unit NAME       the unit that writes the data directory  (default cairn-server; "none" if no
                    unit manages this directory, e.g. a scratch copy)
EOF
}

# ---- on the operator's machine: pick the host and hand over -------------------------------
if [ "${1:-}" != --on-host ]; then
  HOST="${1:-}"
  case "$HOST" in ''|-h|--help) usage; exit 2 ;; -*) usage; exit 2 ;; esac
  shift
  if [ "$HOST" = local ]; then exec bash "$0" --on-host "$@"; fi
  # %q so an option value with a space survives the remote shell
  # shellcheck disable=SC2046
  exec ssh "$HOST" "sudo -n bash -s -- --on-host $(printf '%q ' "$@")" < "$0"
fi
shift

# ---- on the host ---------------------------------------------------------------------------
STOP=0
DEST=/var/backups/cairn-v3
DATA=/var/lib/cairn
SD=/var/lib/cairn-tsdb/sd
ETC=/etc/cairn
BIN=/usr/local/bin
SYSTEMD=/etc/systemd/system
UNIT=cairn-server
while [ $# -gt 0 ]; do
  case "$1" in
    --stop-services) STOP=1 ;;
    --dest) DEST="${2:?--dest needs a value}"; shift ;;
    --data) DATA="${2:?--data needs a value}"; shift ;;
    --tsdb-sd) SD="${2:?--tsdb-sd needs a value}"; shift ;;
    --etc) ETC="${2:?--etc needs a value}"; shift ;;
    --bin) BIN="${2:?--bin needs a value}"; shift ;;
    --systemd) SYSTEMD="${2:?--systemd needs a value}"; shift ;;
    --unit) UNIT="${2:?--unit needs a value}"; shift ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

log() { echo "==> $*" >&2; }
die() { echo "snapshot: $*" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then SHA=(sha256sum); else SHA=(shasum -a 256); fi
sha() { "${SHA[@]}" "$@"; }

[ -d "$DATA" ] || die "no data directory at $DATA"
[ -s "$ETC/keystore.master" ] || die "no $ETC/keystore.master: a snapshot without the master key cannot be restored"
ls "$BIN"/cairn-server >/dev/null 2>&1 || die "no $BIN/cairn-server: the restore test boots the snapshot's own binaries, so there is nothing to snapshot yet"

# ---- refuse to copy a store something is writing -------------------------------------------
unit_active=0
if [ "$UNIT" != none ] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$UNIT" 2>/dev/null; then
  unit_active=1
fi
if [ "$unit_active" = 1 ] && [ "$STOP" = 0 ]; then
  die "$UNIT is running and would be writing while this copies it. Re-run with --stop-services to stop it for the copy (it is restarted afterwards), or stop it yourself first."
fi
# A process that is not the unit (a hand-started server) cannot be stopped from here.
if command -v pgrep >/dev/null 2>&1 && [ "$unit_active" = 0 ] &&
   pgrep -f "cairn-server .*-data $DATA( |\$)" >/dev/null 2>&1; then
  die "a cairn-server process is using $DATA and is not the $UNIT unit; stop it first"
fi

umask 077
ts="$(date -u +%Y%m%dT%H%M%SZ)"
snap="$DEST/cairn-$ts"
mkdir -p "$DEST" && chmod 0700 "$DEST"
mkdir "$snap"

stopped=0
restart() {
  if [ "$stopped" = 1 ]; then
    stopped=0
    log "starting $UNIT again"
    systemctl start "$UNIT" || echo "snapshot: FAILED to start $UNIT again; start it by hand" >&2
  fi
}
trap restart EXIT
trap 'exit 130' INT TERM

if [ "$unit_active" = 1 ]; then
  log "stopping $UNIT for the copy"
  stopped=1
  systemctl stop "$UNIT"
fi

# ---- the copy, while nothing writes --------------------------------------------------------
# tree DIGEST: the hash of every file's hash, so restore-test.sh can prove the files that
# come out are the files that went in, not merely that the archive is intact.
tree() { ( cd "$1" && find . -type f -print0 | sort -z | xargs -0 -n 64 "${SHA[@]}" | sha | cut -d' ' -f1 ); }
nfiles() { find "$1" -type f | wc -l | tr -d ' '; }

log "archiving $DATA"
tar -C "$DATA" -czpf "$snap/data.tar.gz" .
data_tree="$(tree "$DATA")"; data_n="$(nfiles "$DATA")"
declare -a counts=()
for e in "$DATA"/*; do
  [ -e "$e" ] || continue
  counts+=("count $(basename "$e") $(nfiles "$e")")
done

sd_tree=""; sd_n=0
if [ -d "$SD" ]; then
  log "archiving $SD"
  tar -C "$SD" -czpf "$snap/tsdb-sd.tar.gz" .
  sd_tree="$(tree "$SD")"; sd_n="$(nfiles "$SD")"
fi

log "archiving $ETC (without the master key)"
tar -C "$ETC" --exclude ./keystore.master -czpf "$snap/config.tar.gz" .
install -m 0600 "$ETC/keystore.master" "$snap/keystore.master"

units=()
for f in "$SYSTEMD"/cairn-*.service "$SYSTEMD"/cairn-*.service.d; do [ -e "$f" ] && units+=("$(basename "$f")"); done
if [ ${#units[@]} -gt 0 ]; then
  tar -C "$SYSTEMD" -czpf "$snap/units.tar.gz" "${units[@]}"
fi

bins=()
for f in "$BIN"/cairn-*; do [ -f "$f" ] && bins+=("$(basename "$f")"); done
tar -C "$BIN" -czpf "$snap/bin.tar.gz" "${bins[@]}"

# the data is on disk; let the service resume before the (slower, read-only) bookkeeping
restart

# ---- manifest ------------------------------------------------------------------------------
{
  echo "cairn-snapshot 1"
  echo "info taken $ts (UTC)"
  echo "info host $(hostname -s 2>/dev/null || hostname)"
  echo "info kernel $(uname -sr)"
  echo "info unit $UNIT stopped for the copy: $([ "$unit_active" = 1 ] && echo yes || echo no)"
  echo "info data $DATA"
  for a in data tsdb-sd config units bin; do
    [ -f "$snap/$a.tar.gz" ] && echo "archive $(sha "$snap/$a.tar.gz" | cut -d' ' -f1) $a.tar.gz"
  done
  echo "archive $(sha "$snap/keystore.master" | cut -d' ' -f1) keystore.master"
  echo "tree data.tar.gz $data_tree $data_n"
  [ -n "$sd_tree" ] && echo "tree tsdb-sd.tar.gz $sd_tree $sd_n"
  printf '%s\n' "${counts[@]}"
  for b in "${bins[@]}"; do echo "bin $(sha "$BIN/$b" | cut -d' ' -f1) $b"; done
} > "$snap/MANIFEST"
chmod 0600 "$snap"/*

log "snapshot written: $(du -sh "$snap" | cut -f1)"
echo "$snap"
