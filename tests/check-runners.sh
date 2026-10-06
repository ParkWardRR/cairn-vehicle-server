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
# It also enforces the trusted-code rules that make a self-hosted runner on a public
# repository safe to leave running:
#
#   - every job carries the same-repository guard, so a fork's pull request never
#     reaches the runner;
#   - no workflow uses pull_request_target or workflow_run, which run with the base
#     repository's privileges on code a stranger influences.
#
# Usage: tests/check-runners.sh [workflow-dir]

set -euo pipefail

dir="${1:-.github/workflows}"
want='runs-on: [self-hosted, cairn]'
guard="    if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"
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

  # The same-repository guard, exactly, on every job.
  guarded=$(grep -cxF "$guard" "$f" || true)
  if [ "$guarded" -ne "$jobs" ]; then
    echo "FAIL: $f: $jobs jobs but $guarded carry the same-repository guard:"
    echo "  $guard"
    bad=1
  fi

  while IFS= read -r line; do
    echo "FAIL: $f: forbidden trigger on a repository with a self-hosted runner: $line"
    bad=1
  done < <(grep -nE '^[[:space:]]*(pull_request_target|workflow_run)[[:space:]]*:' "$f" || true)

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

echo "OK: all jobs in ${#files[@]} workflow file(s) use '$want', guarded against fork pull requests"
