#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-phase3_artifacts}"
C="$(docker ps --filter ancestor=postgres:16.15 --format '{{.ID}}' | head -1)"
test -n "$C"
BEFORE_MAX="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW max_connections')"
docker exec "$C" psql -U arenyxa -d arenyxa_ci -c "ALTER SYSTEM SET max_connections = '256';"
docker restart "$C"
READY=0
for i in $(seq 1 45); do
  if docker exec "$C" pg_isready -U arenyxa -d arenyxa_ci >/dev/null 2>&1; then READY=1; break; fi
  sleep 2
done
test "$READY" = 1
SERVER_VERSION="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW server_version')"
SERVER_NUM="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW server_version_num')"
MAX_CONN="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW max_connections')"
FSYNC="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW fsync')"
SYNC_COMMIT="$(docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc 'SHOW synchronous_commit')"
printf 'before_max_connections=%s\nserver_version=%s\nserver_version_num=%s\nmax_connections=%s\nfsync=%s\nsynchronous_commit=%s\n' "$BEFORE_MAX" "$SERVER_VERSION" "$SERVER_NUM" "$MAX_CONN" "$FSYNC" "$SYNC_COMMIT" | tee "$OUT/postgresql-settings.txt"
test "$SERVER_NUM" = "160015"
test "$MAX_CONN" = "256"
test "$FSYNC" = "on"
test "$SYNC_COMMIT" = "on"
