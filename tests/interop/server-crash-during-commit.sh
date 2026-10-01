#!/usr/bin/env bash
#
# Fault matrix row: server crash during commit.
#
# Property: a request is either un-receipted, or durably recoverable after
# restart. A device must never hold a receipt the server has no record of —
# that would mean the device prunes data the server cannot produce.
#
# This row lives in a shell script rather than in the Rust harness because it
# needs to kill and restart the server process, which is not the emulator's job.
#
# Two cases are checked:
#
#   1. Deterministic: crash *after* a successful commit. The receipt must
#      survive the restart and a retry must return the same one.
#   2. Randomised: kill the server at an arbitrary moment during a sync, restart,
#      and assert the invariant holds whatever the outcome was. Repeated, because
#      the interesting window is narrow.
#
# Usage: tests/server-crash-during-commit.sh [iterations]

set -uo pipefail

ITERATIONS="${1:-6}"
PORT="${PORT:-18600}"
BASE="http://127.0.0.1:${PORT}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
DATA="${WORK}/data"
SERVER_BIN="${WORK}/cairn-server"
SYNC_BIN="${WORK}/cairn-syncdemo"
SERVER_PID=""

# The synthetic device identity used by cairn-syncdemo.
DEVICE_ID="101112131415161718191a1b1c1d1e1f"

cleanup() {
    [[ -n "${SERVER_PID}" ]] && kill "${SERVER_PID}" 2>/dev/null
    wait "${SERVER_PID}" 2>/dev/null
    rm -rf "${WORK}"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# The receipt signing key must persist across restarts.
#
# Running with an ephemeral key — which -dev alone would do — makes every
# previously issued receipt unverifiable after a restart, stranding synced
# bundles as permanently un-prunable. That is why the server refuses an
# ephemeral key outside dev mode, and why this test passes an explicit key
# path: a real deployment always has one. Case 3 below exercises the rotation
# hazard on purpose.
RECEIPT_KEY=""

start_server() {
    "${SERVER_BIN}" -data "${DATA}" -addr "127.0.0.1:${PORT}" -dev \
        -receipt-key "${RECEIPT_KEY}" \
        >>"${WORK}/server.log" 2>&1 &
    SERVER_PID=$!

    for _ in $(seq 1 50); do
        if curl -sf "${BASE}/api/v2/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    fail "server did not become ready; see ${WORK}/server.log"
}

# SIGKILL, not SIGTERM: a graceful shutdown would defeat the purpose.
kill_server_hard() {
    [[ -n "${SERVER_PID}" ]] || return 0
    kill -9 "${SERVER_PID}" 2>/dev/null
    wait "${SERVER_PID}" 2>/dev/null
    SERVER_PID=""
}

count_receipts() {
    find "${DATA}/receipts" -name '*.cbor' 2>/dev/null | wc -l | tr -d ' '
}

echo "building"
( cd "${REPO_ROOT}/server" && go build -o "${SERVER_BIN}" ./cmd/cairn-server ) || fail "server build"
( cd "${REPO_ROOT}/server" && go build -o "${SYNC_BIN}" ./cmd/cairn-syncdemo ) || fail "syncdemo build"

PUBKEY="$("${SYNC_BIN}" -print-identity | awk '/public_key/{print $2}')"
[[ -n "${PUBKEY}" ]] || fail "could not determine the device public key"

mkdir -p "${DATA}"
RECEIPT_KEY="${WORK}/receipt.seed"
"${SERVER_BIN}" -data "${DATA}" \
    -enroll "${DEVICE_ID}" -enroll-key "${PUBKEY}" -enroll-name crash-test >/dev/null \
    || fail "enrolment"

# ── case 1: crash after a successful commit ─────────────────────────────────
echo
echo "case 1: crash after a successful commit"
start_server

"${SYNC_BIN}" -server "${BASE}" -insecure >"${WORK}/sync1.log" 2>&1 \
    || { cat "${WORK}/sync1.log"; fail "the initial sync failed"; }

RECEIPT_ID_BEFORE="$(grep -o 'receipt_id   [0-9a-f]*' "${WORK}/sync1.log" | awk '{print $2}')"
[[ -n "${RECEIPT_ID_BEFORE}" ]] || fail "no receipt id in the sync output"
[[ "$(count_receipts)" == "1" ]] || fail "expected exactly 1 persisted receipt, found $(count_receipts)"

kill_server_hard
echo "  killed the server (SIGKILL) with a receipt on disk"

start_server
[[ "$(count_receipts)" == "1" ]] || fail "the receipt did not survive the crash"

"${SYNC_BIN}" -server "${BASE}" -insecure >"${WORK}/sync2.log" 2>&1 \
    || { cat "${WORK}/sync2.log"; fail "the retry after restart failed"; }

RECEIPT_ID_AFTER="$(grep -o 'receipt_id   [0-9a-f]*' "${WORK}/sync2.log" | awk '{print $2}')"
[[ "${RECEIPT_ID_AFTER}" == "${RECEIPT_ID_BEFORE}" ]] \
    || fail "the retry returned a different receipt (${RECEIPT_ID_BEFORE} then ${RECEIPT_ID_AFTER})"

grep -q "already committed" "${WORK}/sync2.log" \
    || fail "the retry was not recognised as already committed"

echo "  pass: the receipt survived SIGKILL and the retry returned the same one"

# ── case 2: kill at an arbitrary moment during a sync ───────────────────────
echo
echo "case 2: kill at an arbitrary moment during ${ITERATIONS} syncs"

for i in $(seq 1 "${ITERATIONS}"); do
    # A fresh data directory each iteration, so one run cannot mask another.
    kill_server_hard
    rm -rf "${DATA}"
    mkdir -p "${DATA}"
    "${SERVER_BIN}" -data "${DATA}" \
        -enroll "${DEVICE_ID}" -enroll-key "${PUBKEY}" -enroll-name crash-test >/dev/null \
        || fail "enrolment on iteration ${i}"
    start_server

    # Many small chunks, so the sync lasts long enough to interrupt.
    "${SYNC_BIN}" -server "${BASE}" -insecure -chunk-size 64 \
        >"${WORK}/sync-iter-${i}.log" 2>&1 &
    SYNC_PID=$!

    # Kill somewhere inside the transfer. The window is narrow, which is the
    # point: most iterations land before the commit, some after.
    DELAY="0.0$(( (RANDOM % 9) + 1 ))"
    sleep "${DELAY}"
    kill_server_hard

    wait "${SYNC_PID}" 2>/dev/null
    SYNC_EXIT=$?

    RECEIPTS_ON_DISK="$(count_receipts)"

    # Restart and let the device retry. Whatever happened, it must converge.
    start_server
    RECEIPTS_AFTER_RESTART="$(count_receipts)"

    if [[ "${RECEIPTS_ON_DISK}" != "${RECEIPTS_AFTER_RESTART}" ]]; then
        fail "iteration ${i}: receipts changed across restart (${RECEIPTS_ON_DISK} then ${RECEIPTS_AFTER_RESTART})"
    fi

    # The invariant: if the device believed it got a receipt, the server must
    # still have it. A device that reported success against a server with no
    # record would be the failure that costs data.
    if [[ "${SYNC_EXIT}" -eq 0 ]]; then
        if [[ "${RECEIPTS_AFTER_RESTART}" -lt 1 ]]; then
            fail "iteration ${i}: the device obtained a receipt the server has no record of"
        fi
        OUTCOME="receipted before the kill"
    else
        OUTCOME="un-receipted (${RECEIPTS_AFTER_RESTART} on disk)"
    fi

    # Either way, a retry against the restarted server must succeed.
    "${SYNC_BIN}" -server "${BASE}" -insecure -chunk-size 64 \
        >"${WORK}/retry-iter-${i}.log" 2>&1 \
        || { cat "${WORK}/retry-iter-${i}.log"; fail "iteration ${i}: the retry after restart failed"; }

    [[ "$(count_receipts)" == "1" ]] \
        || fail "iteration ${i}: expected exactly 1 receipt after the retry, found $(count_receipts)"

    echo "  iteration ${i}: killed after ${DELAY}s — ${OUTCOME}; retry converged to 1 receipt"
done

# ── case 3: the signing key rotates across a restart ───────────────────────
#
# Property: a receipt the device already holds must never be accepted once the
# server's key has changed. A rotated or impostor server must not be able to
# induce a prune.
echo
echo "case 3: the server's signing key rotates across a restart"

kill_server_hard
rm -rf "${DATA}"
mkdir -p "${DATA}"
"${SERVER_BIN}" -data "${DATA}" \
    -enroll "${DEVICE_ID}" -enroll-key "${PUBKEY}" -enroll-name crash-test >/dev/null \
    || fail "enrolment for case 3"
start_server

"${SYNC_BIN}" -server "${BASE}" -insecure >"${WORK}/sync-rotate-1.log" 2>&1 \
    || { cat "${WORK}/sync-rotate-1.log"; fail "the pre-rotation sync failed"; }

kill_server_hard

# Rotate: a different signing key, with the old receipt still on disk.
RECEIPT_KEY="${WORK}/receipt-rotated.seed"
start_server

if "${SYNC_BIN}" -server "${BASE}" -insecure >"${WORK}/sync-rotate-2.log" 2>&1; then
    fail "the device accepted a receipt signed by a rotated key — it could now prune unsafely"
fi

grep -q "must NOT be pruned" "${WORK}/sync-rotate-2.log" \
    || { cat "${WORK}/sync-rotate-2.log"; fail "the device did not refuse on signature grounds"; }

echo "  pass: the device refused the receipt and declined to treat the bundle as safe"

echo
echo "pass: server crash during commit leaves the request un-receipted or"
echo "      durably recoverable; a retry always converges to exactly one receipt;"
echo "      and a rotated signing key cannot induce a prune"
