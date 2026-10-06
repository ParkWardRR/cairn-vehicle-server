#!/usr/bin/env bash
#
# The runner-policy check is only worth having if it can fail. This feeds it good and
# bad workflows and requires the right verdict for each.
#
# Usage: tests/check-runners-selftest.sh

set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="$here/check-runners.sh"
guard="    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"
fail=0

mk() { # name, triggers, job-extra-lines
  local d; d="$(mktemp -d)"
  mkdir -p "$d"
  cat > "$d/ci.yml" <<YAML
name: t
on:
$2
jobs:
  a:
    runs-on: [self-hosted, cairn]
$3
    steps:
      - run: echo hi
YAML
  echo "$d"
}

expect() { # want(pass|fail), label, dir
  "$check" "$3" >/dev/null 2>&1
  local rc=$?
  if { [ "$1" = pass ] && [ $rc -ne 0 ]; } || { [ "$1" = fail ] && [ $rc -eq 0 ]; }; then
    echo "WRONG VERDICT ($1 expected): $2"; fail=1
  else
    echo "ok: $2"
  fi
}

push="  push:
    branches: [main]
  pull_request:
    branches: [main]"

expect pass "a guarded job on push and pull_request"            "$(mk x "$push" "$guard")"
expect fail "a job with no guard"                               "$(mk x "$push" "")"
expect fail "a guard that is not the exact string"              "$(mk x "$push" "    if: always()")"
expect fail "pull_request_target"                               "$(mk x "  pull_request_target:
    branches: [main]" "$guard")"
expect fail "workflow_run"                                      "$(mk x "  workflow_run:
    workflows: [CI]" "$guard")"
expect fail "a hosted runner"                                   "$(d=$(mk x "$push" "$guard"); sed -i.bak 's/\[self-hosted, cairn\]/ubuntu-latest/' "$d/ci.yml"; echo "$d")"

exit $fail
