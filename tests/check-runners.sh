#!/usr/bin/env bash
#
# Runner policy: every job in every workflow runs on the self-hosted `cairn`
# runner, and never on a GitHub-hosted one.
#
# GitHub has no repository setting that turns hosted runners off, so the policy
# is enforced here instead. The check is deliberately strict: the only accepted
# form is the literal `runs-on: [self-hosted, cairn]`. A matrix, an expression
# or a block-style list could resolve to `ubuntu-latest` at run time, and a
# static check cannot see through them, so they are rejected rather than
# guessed at. A job-level `uses:` (a reusable workflow) is rejected for the
# same reason: the callee picks the runner.
#
# Usage: tests/check-runners.sh [workflow-dir]

set -euo pipefail

dir="${1:-.github/workflows}"
want='runs-on: [self-hosted, cairn]'
bad=0

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)

if [ "${#files[@]}" -eq 0 ]; then
  echo "FAIL: no workflow files under $dir"
  exit 1
fi

for f in "${files[@]}"; do
  jobs=$(grep -cE '^  [A-Za-z0-9_-]+:[[:space:]]*(#.*)?$' <(sed -n '/^jobs:/,$p' "$f") || true)
  ok=$(grep -cE "^    runs-on: \[self-hosted, cairn\][[:space:]]*(#.*)?$" "$f" || true)
  any=$(grep -cE '^[[:space:]]*runs-on:' "$f" || true)

  while IFS= read -r line; do
    echo "FAIL: $f: not '$want': $line"
    bad=1
  done < <(grep -nE '^[[:space:]]*runs-on:' "$f" | grep -vE "^[0-9]+:    runs-on: \[self-hosted, cairn\][[:space:]]*(#.*)?$" || true)

  while IFS= read -r line; do
    echo "FAIL: $f: job-level reusable workflow, runner not checkable: $line"
    bad=1
  done < <(grep -nE '^    uses:' "$f" || true)

  # Every job must declare its runner; a job with none is a job we did not check.
  if [ "$ok" -ne "$jobs" ] || [ "$any" -ne "$jobs" ]; then
    echo "FAIL: $f: $jobs jobs, $ok on '$want', $any runs-on lines"
    bad=1
  fi
done

if [ "$bad" -ne 0 ]; then
  echo
  echo "Every job must use exactly: $want"
  exit 1
fi

echo "OK: all jobs in ${#files[@]} workflow file(s) use '$want'"
