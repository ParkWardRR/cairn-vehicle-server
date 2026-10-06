#!/usr/bin/env bash
#
# deploy/snapshot.sh and deploy/restore-test.sh, end to end, against a scratch stack.
#
# Builds the repository's own cairn-server, cairn-admin, cairn-syncdemo and cairn-tsdb,
# makes a scratch data directory (an enrolled device, a vehicle, a client invite, one
# synced bundle), runs a scratch "live" server and store on spare ports, and then:
#
#   1. the snapshot is refused while the server is running;
#   2. with the server stopped, a snapshot is taken (the real script, run as "local");
#   3. restore-test.sh passes against it, comparing with the scratch live stack;
#   4. restore-test.sh FAILS when the archive is damaged, when a stored file is altered
#      behind the manifest's back, and when live has moved on from the snapshot.
#
# Nothing outside the scratch directory is touched, and no systemd unit is involved
# (--unit none): this never goes near a real /var/lib/cairn.
#
# Usage: tests/snapshot-restore.sh
#   PORT=19700     first of the live ports (the restore test uses PORT+10 upward)
#   PREBUILT=DIR   use cairn-server, cairn-admin, cairn-syncdemo and cairn-tsdb from DIR
#                  instead of building (for a shared host that should not be made to compile)
#   KEEP=1         leave the scratch directory (and print it) for inspection
#
# cairn-tsdb needs cgo and a C toolchain; without them this skips the store half loudly.

set -uo pipefail

PORT="${PORT:-19700}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/cairn-snaptest.XXXXXX")"
PIDS=()

cleanup() {
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill "$p" 2>/dev/null; done
    sleep 0.5
    for p in "${PIDS[@]:-}"; do [[ -n "$p" ]] && kill -9 "$p" 2>/dev/null; done
    if [[ -n "${KEEP:-}" ]]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    for l in "$WORK"/*.log; do [[ -s "$l" ]] && { echo "--- $(basename "$l")" >&2; tail -5 "$l" >&2; }; done
    exit 1
}
ok() { echo "  ok: $*"; }

B="$WORK/build"; L="$WORK/live"
mkdir -p "$B" "$L/data" "$L/etc" "$L/bin" "$L/sd/bundles" "$L/snaps"

if [[ -n "${PREBUILT:-}" ]]; then
    B="$PREBUILT"
else
    echo "building"
    ( cd "$REPO_ROOT" && go build -o "$B/" ./cmd/cairn-server ./cmd/cairn-admin ./cmd/cairn-syncdemo ) || fail "build"
    ( cd "$REPO_ROOT" && CGO_ENABLED=1 go build -o "$B/cairn-tsdb" ./cmd/cairn-tsdb ) || fail "cairn-tsdb needs cgo and a C toolchain"
fi
# the "installed" binaries the snapshot will capture
for b in cairn-server cairn-admin cairn-tsdb; do cp "$B/$b" "$L/bin/$b"; done

P_INGEST=$PORT; P_LOCAL=$((PORT + 1)); P_SERVE=$((PORT + 2)); P_TSDB=$((PORT + 3))
RPORT=$((PORT + 10))

openssl rand -hex 32 > "$L/etc/keystore.master"; chmod 0400 "$L/etc/keystore.master"
# what deploy/systemd would have: the flags the live server runs with
echo "CAIRN_ARGS=-addr 127.0.0.1:$P_INGEST -data $L/data -app-local-addr 127.0.0.1:$P_LOCAL -app-serve-addr 127.0.0.1:$P_SERVE -app-snapshot-url http://127.0.0.1:$P_TSDB" > "$L/etc/server.env"

IDENTITY="$("$B/cairn-syncdemo" -print-identity)"
field() { awk -v k="$1" '$1==k{print $2}' <<<"$IDENTITY"; }
DEVICE_ID="101112131415161718191a1b1c1d1e1f"
"$B/cairn-server" -data "$L/data" -keystore-master "$L/etc/keystore.master" \
    -enroll "$DEVICE_ID" -enroll-key "$(field public_key)" -enroll-root "$(field storage_root)" \
    -enroll-name snaptest >/dev/null || fail "enrolment"
"$B/cairn-admin" -data "$L/data" vehicle add --id "$(field vehicle_id)" --name "snapshot test car" >/dev/null || fail "vehicle add"
"$B/cairn-admin" -data "$L/data" assign --assignment-id "$(field assignment_id)" "$DEVICE_ID" "$(field vehicle_id)" >/dev/null || fail "assign"
"$B/cairn-admin" -data "$L/data" client invite --name "snapshot test phone" >/dev/null || fail "client invite"

start_live() {
    "$L/bin/cairn-server" -dev -addr "127.0.0.1:$P_INGEST" -data "$L/data" \
        -keystore-master "$L/etc/keystore.master" -app-local-addr "127.0.0.1:$P_LOCAL" \
        -app-serve-addr "127.0.0.1:$P_SERVE" -app-snapshot-url "http://127.0.0.1:$P_TSDB" \
        >>"$WORK/live-server.log" 2>&1 &
    SERVER_PID=$!; PIDS+=("$SERVER_PID")
    "$L/bin/cairn-tsdb" -data "$L/data" -keystore "$L/data/keystore.json" -keystore-master "$L/etc/keystore.master" \
        -sd "$L/sd" -scratch "$WORK" -addr "127.0.0.1:$P_TSDB" -memory 512MB >>"$WORK/live-tsdb.log" 2>&1 &
    TSDB_PID=$!; PIDS+=("$TSDB_PID")
    for _ in $(seq 1 100); do
        curl -sf "http://127.0.0.1:$P_INGEST/api/v2/health" >/dev/null 2>&1 &&
            curl -sf "http://127.0.0.1:$P_TSDB/healthz" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    fail "the scratch live stack did not come up; see $WORK/live-*.log"
}
stop_live() {
    kill "$SERVER_PID" "$TSDB_PID" 2>/dev/null; wait "$SERVER_PID" "$TSDB_PID" 2>/dev/null
    SERVER_PID=""; TSDB_PID=""
}

# The store needs one bundle to have something to answer with, so sync before it first builds.
echo "scratch live stack on 127.0.0.1:$PORT-$((PORT + 3))"
"$L/bin/cairn-server" -dev -addr "127.0.0.1:$P_INGEST" -data "$L/data" -keystore-master "$L/etc/keystore.master" \
    >"$WORK/seed-server.log" 2>&1 &
SEED_PID=$!; PIDS+=("$SEED_PID")
for _ in $(seq 1 100); do curl -sf "http://127.0.0.1:$P_INGEST/api/v2/health" >/dev/null 2>&1 && break; sleep 0.2; done
"$B/cairn-syncdemo" -server "http://127.0.0.1:$P_INGEST" -insecure >"$WORK/sync.log" 2>&1 || { cat "$WORK/sync.log"; fail "the seed sync failed"; }
kill "$SEED_PID"; wait "$SEED_PID" 2>/dev/null
start_live
ok "scratch live stack is up and holds a synced bundle"

SNAP_ARGS=(--unit none --data "$L/data" --tsdb-sd "$L/sd" --etc "$L/etc" --bin "$L/bin" --systemd "$L/nonexistent" --dest "$L/snaps")
REST_ARGS=(--ports "$RPORT")

echo
echo "1. the snapshot is refused while the server runs"
if "$REPO_ROOT/deploy/snapshot.sh" local "${SNAP_ARGS[@]}" >"$WORK/refused.log" 2>&1; then
    fail "snapshot.sh copied a data directory a server was writing"
fi
grep -q 'is using' "$WORK/refused.log" || { cat "$WORK/refused.log"; fail "refused, but not for the right reason"; }
[[ -z "$(ls -A "$L/snaps")" ]] || fail "a refused snapshot left a directory behind"
ok "refused, and nothing was written"

echo
echo "2. a cold snapshot"
stop_live
SNAP="$("$REPO_ROOT/deploy/snapshot.sh" local "${SNAP_ARGS[@]}" 2>"$WORK/snap.log" | tail -1)" || { cat "$WORK/snap.log"; fail "snapshot.sh failed"; }
start_live
[[ -f "$SNAP/MANIFEST" && -f "$SNAP/data.tar.gz" && -f "$SNAP/keystore.master" ]] || fail "the snapshot is incomplete: $(ls "$SNAP")"
for a in "$SNAP"/*.tar.gz; do
    tar -tzf "$a" | grep -q 'keystore\.master' && fail "the master key is inside $(basename "$a")"
done
[[ "$(stat -c %a "$SNAP" 2>/dev/null || stat -f %Lp "$SNAP")" = 700 ]] || fail "the snapshot directory is not 0700"
ok "$(basename "$SNAP"): master key kept beside the archives, directory 0700"

echo
echo "3. the restore test passes against the live stack"
"$REPO_ROOT/deploy/restore-test.sh" local "$SNAP" "${REST_ARGS[@]}" 2>&1 | sed 's/^/    /' ; [[ "${PIPESTATUS[0]}" = 0 ]] || fail "restore-test.sh failed on a good snapshot"
ok "restored, booted and answered like live"

echo
echo "4. the restore test fails when it should"
# 4a. damaged archive
cp -R "$SNAP" "$WORK/damaged"; printf 'x' >> "$WORK/damaged/data.tar.gz"
"$REPO_ROOT/deploy/restore-test.sh" local "$WORK/damaged" --no-live "${REST_ARGS[@]}" >"$WORK/damaged.log" 2>&1 && fail "a damaged archive restored"
grep -q 'differs from the manifest' "$WORK/damaged.log" || { cat "$WORK/damaged.log"; fail "damaged archive: wrong failure"; }
ok "a damaged archive is refused"

# 4b. a file altered inside a valid archive, with the archive hash re-recorded: only the
# per-file hashes can notice
cp -R "$SNAP" "$WORK/altered"; mkdir "$WORK/altered-data"
tar -xzf "$WORK/altered/data.tar.gz" -C "$WORK/altered-data"
echo '{}' > "$WORK/altered-data/clients.json"
tar -C "$WORK/altered-data" -czf "$WORK/altered/data.tar.gz" .
new="$(sha256sum "$WORK/altered/data.tar.gz" 2>/dev/null || shasum -a 256 "$WORK/altered/data.tar.gz")"; new="${new%% *}"
sed -i.bak "s/^archive [0-9a-f]* data.tar.gz/archive $new data.tar.gz/" "$WORK/altered/MANIFEST"
"$REPO_ROOT/deploy/restore-test.sh" local "$WORK/altered" --no-live "${REST_ARGS[@]}" >"$WORK/altered.log" 2>&1 && fail "an altered store restored"
grep -q 'differs from the file that was snapshotted' "$WORK/altered.log" || { cat "$WORK/altered.log"; fail "altered file: wrong failure"; }
ok "a store altered behind the manifest is refused"

# 4c. live has moved on: a vehicle added after the snapshot
"$B/cairn-admin" -data "$L/data" vehicle add --name "added after the snapshot" >/dev/null || fail "vehicle add"
"$REPO_ROOT/deploy/restore-test.sh" local "$SNAP" "${REST_ARGS[@]}" >"$WORK/moved.log" 2>&1 && fail "the restore matched a live stack that had moved on"
grep -q 'DIFFER' "$WORK/moved.log" || { cat "$WORK/moved.log"; fail "moved on: wrong failure"; }
ok "a live stack that has moved on is reported as different"

echo
echo "PASS"
