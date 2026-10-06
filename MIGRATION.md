# Provenance

This repository was extracted, with its history, from the Cairn monorepo. It is not a
fresh start: every commit below the first one here is a commit of that history, filtered
to the paths this repository owns.

| | |
|---|---|
| Source | <https://github.com/ParkWardRR/cairn-driving-log-selfhosted> |
| Source tag | `monorepo-final` |
| Source commit | `b3ada35e78414e0ed179b95f356231da877f80a9` |
| Extraction | `git filter-repo` a40bce548d2c, driven by `split/extract` in that repository |
| Path map | `split/paths.tsv` in that repository, at the commit above |

## Where each path came from

| Source path (in the monorepo) | Path here |
|---|---|
| `server/` | the directory's contents become the repository root |
| `deploy/migrations/` | `deploy/migrations/` |
| `deploy/systemd/cairn-server.service` | `deploy/systemd/cairn-server.service` |
| `deploy/systemd/cairn-tsdb.service` | `deploy/systemd/cairn-tsdb.service` |
| `deploy/systemd/server.env.example` | `deploy/systemd/server.env.example` |
| `deploy/deploy-v3.sh` | `deploy/deploy-v3.sh` |
| `deploy/make-certs.sh` | `deploy/make-certs.sh` |
| `deploy/tsdb-mirror.sh` | `deploy/tsdb-mirror.sh` |
| `docs/device-provisioning.md` | `docs/device-provisioning.md` |
| `docs/deploying.md` | `docs/deploying.md` |
| `docs/tailscale-deployment.md` | `docs/tailscale-deployment.md` |
| `docs/retention-and-backup.md` | `docs/retention-and-backup.md` |
| `tests/check-runners.sh` | `tests/check-runners.sh` |
| `tests/check-runners-selftest.sh` | `tests/check-runners-selftest.sh` |
| `tests/ci/` | `tests/ci/` |
| `tests/server-crash-during-commit.sh` | `tests/interop/server-crash-during-commit.sh` |


## What was and was not carried over

- **History of paths that no longer exist** (the legacy stack, v1/v2 migrations, old
  compose files) is not in this repository. It remains in the archive,
  <https://github.com/ParkWardRR/cairn-original-monorepo-archive>, and in the front door's history.
- **Commit hashes differ** from the monorepo: a filtered history is a new history.
  Author, date and message of every kept commit are unchanged, and the extraction was
  verified against the source (the final tree and sampled historical trees match byte
  for byte, modes and symlinks included).
- **Tags**: the old `v0.1.0` tools release stays with the front door and the archive.

## What was changed after extraction

Each change is one commit on top of the extracted history, so `git log` shows exactly
what was rewritten and nothing else was touched:

- **docs: record where this repository came from**: this file
- **build: rename the Go module to this repository's path**: the Go module path and every import of it
- **docs: point links that crossed a repository boundary at the repository that owns them**: relative links to files that now live in another repository became absolute links
- **deploy: sync from this repository's root; add --build-only**: `deploy/deploy-v3.sh` syncs the repository root (the server used to be a subdirectory) and can stop after the build
- **docs: add a README and the licence**: README and LICENSE
- **chore: ignore rules for this repository**: `.gitignore`
- **build: pin the contracts (contracts.lock and its fetch script)**: `contracts.lock` and `scripts/fetch-contracts.sh`: the protocol specs and vectors are fetched at a pinned tag and commit, not copied
- **ci: run on the self-hosted runner under the trusted-code policy**: `.github/workflows/ci.yml`, `tests/check-runners.sh` and its self-test

