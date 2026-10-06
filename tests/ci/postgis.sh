#!/usr/bin/env bash
#
# A throwaway PostgreSQL 16 + PostGIS for the decode-pipeline tests, with no Docker.
#
# The CI runner is a container with no container socket (on purpose: a job that can
# reach a socket can reach the host that also serves production), so GitHub Actions
# `services:` cannot work there. This starts a real database inside the job instead:
# same engine, same extension, torn down afterwards. No mock: partitioning, geography
# columns, generated columns and ON CONFLICT are exactly what a fake gets wrong.
#
#   tests/ci/postgis.sh start    installs if needed, starts, creates the database,
#                                applies deploy/migrations, prints the DSN
#   tests/ci/postgis.sh stop     stops it and removes the data
#
# Needs root (the runner container is root). Port and directory are overridable.

set -euo pipefail

PORT="${CAIRN_PG_PORT:-55432}"
DIR="${CAIRN_PG_DIR:-/tmp/cairn-pg}"
BIN=/usr/lib/postgresql/16/bin
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MIGRATIONS="${CAIRN_MIGRATIONS:-$ROOT/deploy/migrations}"

install_postgres() {
  [ -x "$BIN/initdb" ] && return 0
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends curl ca-certificates gnupg lsb-release >/dev/null
  install -d /usr/share/postgresql-common/pgdg
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
  echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  # Do not create or start a default cluster: this script owns its own.
  mkdir -p /etc/postgresql-common
  printf 'create_main_cluster = false\n' > /etc/postgresql-common/createcluster.conf
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends postgresql-16 postgresql-16-postgis-3 >/dev/null
}

case "${1:-}" in
  start)
    install_postgres
    rm -rf "$DIR"
    mkdir -p "$DIR"
    chown postgres:postgres "$DIR"
    su postgres -c "$BIN/initdb -D $DIR/data -A trust -U postgres >/dev/null"
    # fsync off: this is disposable test data, and the speedup is large.
    su postgres -c "$BIN/pg_ctl -D $DIR/data -l $DIR/log -w -o '-p $PORT -k $DIR -c listen_addresses=127.0.0.1 -c fsync=off -c shared_buffers=128MB -c max_connections=50' start" >/dev/null
    PSQL=("$BIN/psql" -h 127.0.0.1 -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -q)
    "${PSQL[@]}" -d postgres -c 'CREATE DATABASE cairn'
    for f in "$MIGRATIONS"/*.sql; do
      echo "applying $(basename "$f")" >&2
      "${PSQL[@]}" -d cairn -f "$f"
    done
    echo "postgres://postgres@127.0.0.1:$PORT/cairn?sslmode=disable"
    ;;
  stop)
    su postgres -c "$BIN/pg_ctl -D $DIR/data -m immediate -w stop" >/dev/null 2>&1 || true
    rm -rf "$DIR"
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac
