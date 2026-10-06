#!/usr/bin/env bash
# Restores a snapshot (deploy/snapshot.sh) into a scratch directory and BOOTS it: the
# snapshot's own cairn-tsdb and cairn-server binaries over the snapshot's own data and
# master key, on spare loopback ports. It then asks the restored stack the questions the
# live one answers and requires the same answers. The live services and their data are
# never touched: nothing here writes outside the scratch directory, and the live side is
# only read over HTTP.
#
#   deploy/restore-test.sh <user@host|local> <snapshot-dir> [options]
#
# "local" runs on this machine; anything else is an ssh target and the script is piped to
# `sudo bash` there. Never put real host names in this file: pass them on the command line.
#
# Passing means: every archive matches the manifest; the files that come out are the files
# that went in (per-file hashes, not just a good archive); the master key, the binaries and
# the config needed to run are present; the restored server and store come up; and they
# agree with live on the vehicle list, the app instance id, and what the store loaded.
#
# Answers are compared with live, so run this soon after the snapshot: a trip that lands
# in between is a legitimate difference (the store's row counts will not match).
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: restore-test.sh <user@host|local> <snapshot-dir> [options]
options:
  --no-live          do not compare with live (the files and the boot are still checked)
  --live-tsdb URL    live cairn-tsdb      (default: the -app-snapshot-url in the snapshot's server.env)
  --live-local URL   live app local listener   (default: its -app-local-addr)
  --live-serve URL   live app plain listener   (default: its -app-serve-addr)
  --ports BASE       first of four spare loopback ports (default 19600)
  --as USER          run the restored services as USER (default: cairn when running as root
                     and it exists, otherwise the invoking user)
EOF
}

# ---- on the operator's machine: pick the host and hand over -------------------------------
if [ "${1:-}" != --on-host ]; then
  HOST="${1:-}"
  case "$HOST" in ''|-*) usage; exit 2 ;; esac
  shift
  if [ "$HOST" = local ]; then exec bash "$0" --on-host "$@"; fi
  # shellcheck disable=SC2046
  exec ssh "$HOST" "sudo -n bash -s -- --on-host $(printf '%q ' "$@")" < "$0"
fi
shift

# ---- on the host ---------------------------------------------------------------------------
SNAP="${1:-}"; [ $# -gt 0 ] && shift
NO_LIVE=0; L_TSDB=""; L_LOCAL=""; L_SERVE=""; BASE=19600; RUN_AS=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-live) NO_LIVE=1 ;;
    --live-tsdb) L_TSDB="${2:?--live-tsdb needs a value}"; shift ;;
    --live-local) L_LOCAL="${2:?--live-local needs a value}"; shift ;;
    --live-serve) L_SERVE="${2:?--live-serve needs a value}"; shift ;;
    --ports) BASE="${2:?--ports needs a value}"; shift ;;
    --as) RUN_AS="${2:?--as needs a value}"; shift ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done
[ -n "$SNAP" ] || { usage; exit 2; }

log() { echo "==> $*" >&2; }
fail() { echo "restore-test: $*" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then SHA=(sha256sum); else SHA=(shasum -a 256); fi
sha() { "${SHA[@]}" "$@"; }

[ -f "$SNAP/MANIFEST" ] || fail "no MANIFEST in $SNAP"
head -1 "$SNAP/MANIFEST" | grep -q '^cairn-snapshot 1$' || fail "$SNAP/MANIFEST is not a version 1 snapshot manifest"

P_TSDB=$BASE; P_INGEST=$((BASE + 1)); P_LOCAL=$((BASE + 2)); P_SERVE=$((BASE + 3))
busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
for p in $P_TSDB $P_INGEST $P_LOCAL $P_SERVE; do
  busy "$p" && fail "port $p is in use; pick another range with --ports"
done

# Who runs the restored services. As root they must not run as root (the unit does not), and
# the restored files must belong to whoever does.
if [ -z "$RUN_AS" ]; then
  if [ "$(id -u)" = 0 ] && id cairn >/dev/null 2>&1; then RUN_AS=cairn; else RUN_AS="$(id -un)"; fi
fi
# exec, so a backgrounded call is the service itself and not a shell around it
as_user() {
  if [ "$(id -un)" = "$RUN_AS" ]; then exec "$@"
  elif command -v setpriv >/dev/null 2>&1; then
    exec setpriv --reuid="$RUN_AS" --regid="$(id -g "$RUN_AS")" --clear-groups "$@"
  else exec runuser -u "$RUN_AS" -- "$@"; fi
}

root="$(mktemp -d "${TMPDIR:-/tmp}/cairn-restore.XXXXXX")"
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do
    [ -n "$p" ] || continue
    pkill -P "$p" 2>/dev/null || true   # runuser's child, if the fallback was used
    kill "$p" 2>/dev/null || true
  done
  sleep 1
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true; done
  rm -rf "$root"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
chmod 0755 "$root"

manifest() { awk -v k="$1" '$1==k' "$SNAP/MANIFEST"; }

# ---- 1. the archives are what the manifest says -------------------------------------------
log "verifying the archives in $SNAP"
manifest archive | while read -r _ want name; do
  [ -f "$SNAP/$name" ] || { echo "restore-test: the manifest lists $name but it is missing" >&2; exit 1; }
  got="$(sha "$SNAP/$name" | cut -d' ' -f1)"
  [ "$want" = "$got" ] || { echo "restore-test: $name differs from the manifest" >&2; exit 1; }
done
echo "    every archive matches its recorded hash" >&2

# ---- 2. extract, and prove the files are the files that went in ---------------------------
log "restoring into $root"
mkdir "$root/data" "$root/tsdb-sd" "$root/etc" "$root/bin" "$root/scratch"
tar -xpzf "$SNAP/data.tar.gz" -C "$root/data"
[ -f "$SNAP/tsdb-sd.tar.gz" ] && tar -xpzf "$SNAP/tsdb-sd.tar.gz" -C "$root/tsdb-sd"
tar -xpzf "$SNAP/config.tar.gz" -C "$root/etc"
tar -xpzf "$SNAP/bin.tar.gz" -C "$root/bin"
cp "$SNAP/keystore.master" "$root/keystore.master"
chmod 0400 "$root/keystore.master"
if [ "$(id -un)" != "$RUN_AS" ]; then chown -R "$RUN_AS" "$root"; fi
chmod 0700 "$root/data"

tree() { ( cd "$1" && find . -type f -print0 | sort -z | xargs -0 -n 64 "${SHA[@]}" | sha | cut -d' ' -f1 ); }
nfiles() { find "$1" -type f | wc -l | tr -d ' '; }
check_tree() { # <archive> <dir>
  local line want_d want_n
  line="$(manifest tree | awk -v a="$1" '$2==a')"
  [ -n "$line" ] || fail "the manifest has no tree record for $1"
  want_d="$(echo "$line" | cut -d' ' -f3)"; want_n="$(echo "$line" | cut -d' ' -f4)"
  [ "$(nfiles "$2")" = "$want_n" ] || fail "$1: restored $(nfiles "$2") files, the snapshot recorded $want_n"
  [ "$(tree "$2")" = "$want_d" ] || fail "$1: a restored file differs from the file that was snapshotted"
  echo "    $1: $want_n files, every hash matches" >&2
}
check_tree data.tar.gz "$root/data"
[ -f "$SNAP/tsdb-sd.tar.gz" ] && check_tree tsdb-sd.tar.gz "$root/tsdb-sd"
manifest count | while read -r _ name n; do
  [ "$(nfiles "$root/data/$name")" = "$n" ] || { echo "restore-test: data/$name has the wrong number of files" >&2; exit 1; }
done

need=(keystore.master etc/server.env bin/cairn-server bin/cairn-tsdb data/keystore.json data/keys/receipt.seed data/devices.json data/vehicles.json)
for f in "${need[@]}"; do [ -e "$root/$f" ] || fail "the snapshot has no $f"; done
echo "    the master key, config, binaries and stores needed to run are present" >&2

# ---- 3. boot the restored stack on spare ports --------------------------------------------
log "booting the restored stack on 127.0.0.1:$BASE-$((BASE + 3))"
as_user "$root/bin/cairn-tsdb" -data "$root/data" -keystore "$root/data/keystore.json" \
  -keystore-master "$root/keystore.master" -sd "$root/tsdb-sd" -scratch "$root/scratch" \
  -addr "127.0.0.1:$P_TSDB" -memory 512MB >"$root/tsdb.log" 2>&1 &
pids+=($!)
# -dev relaxes only the transport (the certificates are checked for presence above, not
# exercised); keys, stores and the app API are the production ones.
as_user "$root/bin/cairn-server" -dev -addr "127.0.0.1:$P_INGEST" -data "$root/data" \
  -keystore-master "$root/keystore.master" -app-local-addr "127.0.0.1:$P_LOCAL" \
  -app-serve-addr "127.0.0.1:$P_SERVE" -app-snapshot-url "http://127.0.0.1:$P_TSDB" \
  >"$root/server.log" 2>&1 &
pids+=($!)

wait_for() {
  for _ in $(seq 1 120); do curl -fsS -o /dev/null "$1" 2>/dev/null && return 0; sleep 0.5; done
  echo "restore-test: timed out waiting for $1" >&2
  for l in tsdb server; do echo "--- $l.log" >&2; tail -8 "$root/$l.log" >&2 || true; done
  return 1
}
wait_for "http://127.0.0.1:$P_TSDB/healthz" || exit 1
wait_for "http://127.0.0.1:$P_INGEST/api/v2/health" || exit 1
wait_for "http://127.0.0.1:$P_SERVE/v1/health" || exit 1
echo "    cairn-tsdb and cairn-server are up on the restored data" >&2

# The receipt key is what every dongle pins. A server that came up on a freshly minted key
# would look healthy and refuse every device, so the one it serves must be the one on disk.
want_key="$(as_user "$root/bin/cairn-server" -data "$root/data" -keystore-master "$root/keystore.master" -print-receipt-key 2>/dev/null)"
got_key="$(curl -fsS "http://127.0.0.1:$P_INGEST/api/v2/server/receipt-key" | grep -o '"public_key": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{64\}')"
[ -n "$want_key" ] && [ "$want_key" = "$got_key" ] || fail "the restored server does not serve the receipt key stored in its data"
echo "    the restored server serves the receipt key held in the snapshot" >&2

# ---- 4. the restored stack against the live one -------------------------------------------
if [ "$NO_LIVE" = 1 ]; then
  log "restore test passed (not compared with live: --no-live)"
  exit 0
fi

# The live endpoints are the ones the snapshotted server.env names, unless overridden.
arg() { grep -h '^CAIRN_ARGS=' "$root/etc/server.env" | tr ' ' '\n' | awk -v f="$1" 'p{print; exit} $0==f{p=1}' || true; }
if [ -z "$L_TSDB" ]; then L_TSDB="$(arg -app-snapshot-url)"; fi
if [ -z "$L_LOCAL" ] && v="$(arg -app-local-addr)" && [ -n "$v" ]; then L_LOCAL="http://$v"; fi
if [ -z "$L_SERVE" ] && v="$(arg -app-serve-addr)" && [ -n "$v" ]; then L_SERVE="http://$v"; fi
[ -n "$L_TSDB" ] && [ -n "$L_LOCAL" ] && [ -n "$L_SERVE" ] ||
  fail "cannot tell where the live stack listens (its server.env has no -app-snapshot-url, -app-local-addr and -app-serve-addr): pass --live-tsdb, --live-local, --live-serve, or --no-live"

log "comparing with live ($L_TSDB, $L_LOCAL, $L_SERVE)"
differ=0
same() { # <what> <live> <restored>
  if [ "$2" = "$3" ]; then echo "    same   $1" >&2; else echo "    DIFFER $1" >&2; echo "      live:     $2" >&2; echo "      restored: $3" >&2; differ=1; fi
}
get() { curl -fsS --max-time 20 "$1" 2>/dev/null || echo "UNREACHABLE $1"; }
post() { curl -fsS --max-time 30 -X POST --data "$2" "$1" 2>/dev/null || echo "UNREACHABLE $1"; }
inst() { grep -o '"\(instance_id\|protocol_version\)": *"\?[^",}]*' | tr -d ' \n'; }
mets() { grep -E '^cairn_tsdb_(bundles|bundles_reproduced|problems|decoder_version|rows)[ {]'; }

same "vehicles (/v1/local/vehicles)" "$(get "$L_LOCAL/v1/local/vehicles")" "$(get "http://127.0.0.1:$P_LOCAL/v1/local/vehicles")"
same "app instance id and protocol (/v1/health)" "$(get "$L_SERVE/v1/health" | inst)" "$(get "http://127.0.0.1:$P_SERVE/v1/health" | inst)"
same "store contract (/healthz)" "$(get "$L_TSDB/healthz" | grep -o '"store_contract": *[^,}]*' | tr -d ' ')" "$(get "http://127.0.0.1:$P_TSDB/healthz" | grep -o '"store_contract": *[^,}]*' | tr -d ' ')"
same "what the store loaded (/metrics)" "$(get "$L_TSDB/metrics" | mets)" "$(get "http://127.0.0.1:$P_TSDB/metrics" | mets)"
Q='SELECT vehicle_id FROM v_vehicles ORDER BY vehicle_id'
rows() { tr -d ' \n' | sed 's/,"elapsed_us":[0-9]*//'; }
same "vehicles the store holds (v_vehicles)" "$(post "$L_TSDB/query" "$Q" | rows)" "$(post "http://127.0.0.1:$P_TSDB/query" "$Q" | rows)"

[ "$differ" = 0 ] || fail "the restored stack does not answer like the live one"
log "restore test passed: the snapshot is complete, restores faithfully, boots, and answers like live"
