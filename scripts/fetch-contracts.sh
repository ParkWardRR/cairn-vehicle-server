#!/usr/bin/env bash
# Fetches the Cairn Vehicle Data Protocols this repository is pinned to.
#
#   scripts/fetch-contracts.sh             fetch (or verify) the pinned release into .contracts/
#   scripts/fetch-contracts.sh --release   as above, and refuse an override or a dirty tree
#
# contracts.lock names a repository, a tag AND the commit that tag must resolve to; both
# are checked, so a moved or re-created tag cannot change what this repository builds
# against. The contract root is .contracts/contracts/.
#
# CAIRN_CONTRACTS=<dir> wins over the fetch, so a contract and its implementation can
# change together on a laptop. It prints what it resolved and whether that tree is dirty.
# A release build must not use it, which is what --release enforces.
set -euo pipefail

cd "$(dirname "$0")/.."
release=0; [ "${1:-}" = "--release" ] && release=1

field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" contracts.lock | head -1; }
repo="$(field repo)"; tag="$(field tag)"; commit="$(field commit)"
[ -n "$repo" ] && [ -n "$tag" ] && [ -n "$commit" ] || { echo "contracts.lock is missing repo, tag or commit" >&2; exit 1; }

if [ -n "${CAIRN_CONTRACTS:-}" ]; then
  [ "$release" = 0 ] || { echo "release build: CAIRN_CONTRACTS is set ($CAIRN_CONTRACTS); a release uses the pinned contracts" >&2; exit 1; }
  top="$(git -C "$CAIRN_CONTRACTS" rev-parse --show-toplevel 2>/dev/null || true)"
  if [ -n "$top" ]; then
    dirty=clean; [ -z "$(git -C "$top" status --porcelain)" ] || dirty=DIRTY
    echo "contracts override: $CAIRN_CONTRACTS at $(git -C "$top" rev-parse HEAD) ($dirty)"
  else
    echo "contracts override: $CAIRN_CONTRACTS (not a git checkout)"
  fi
  exit 0
fi

if [ -d .contracts/.git ] && [ "$(git -C .contracts rev-parse HEAD)" = "$commit" ]; then
  :
else
  rm -rf .contracts
  git clone --quiet --depth 1 --branch "$tag" "$repo" .contracts
fi

got="$(git -C .contracts rev-parse "refs/tags/$tag^{commit}" 2>/dev/null || git -C .contracts rev-parse HEAD)"
if [ "$got" != "$commit" ]; then
  echo "contracts tag $tag resolves to $got, but contracts.lock pins $commit; refusing" >&2
  rm -rf .contracts
  exit 1
fi
if [ "$release" = 1 ] && [ -n "$(git -C .contracts status --porcelain)" ]; then
  echo "release build: .contracts has local changes" >&2
  exit 1
fi
echo "contracts $tag ($commit)"
