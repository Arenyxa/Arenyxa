#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-phase3_artifacts}"
mkdir -p "$OUT"
sha256sum src/arenyxa/enterprise/runtime_storage.py src/arenyxa/enterprise/distributed_queue.py scripts/postgresql_32_worker_gate.py scripts/postgresql_64_worker_128_concurrency_gate.py > "$OUT/source-hashes-after.sha256"
test "$(sha256sum src/arenyxa/enterprise/runtime_storage.py | awk '{print $1}')" = "5702ee19406e72525c96d848eeb7b909141872e0d8c0ebdb29c149b4d596594a"
test "$(sha256sum src/arenyxa/enterprise/distributed_queue.py | awk '{print $1}')" = "8d34fef8df28b3ef7521dd2c465aa2bdf8a6217244635f151c6f752d704c2ccd"
test "$(sha256sum scripts/postgresql_32_worker_gate.py | awk '{print $1}')" = "1dcb09ea7490abebb8e73546178415530adc852422a0346b8d72de56e5322657"
test "$(sha256sum scripts/postgresql_64_worker_128_concurrency_gate.py | awk '{print $1}')" = "ba766b7e02b0f511c1e721628e8e0d615adada27b24918762a73bc1ef7762588"
git diff -- scripts/postgresql_32_worker_gate.py scripts/postgresql_64_worker_128_concurrency_gate.py > "$OUT/executed-scripts-final.diff"
test ! -s "$OUT/executed-scripts-final.diff"
C="$(docker ps -a --filter ancestor=postgres:16.15 --format '{{.ID}}' | head -1)"
if [ -n "$C" ]; then
  docker exec "$C" psql -U arenyxa -d arenyxa_ci -Atc "SELECT current_setting('server_version'),current_setting('max_connections'),current_setting('fsync'),current_setting('synchronous_commit'),current_setting('track_io_timing'),current_setting('track_wal_io_timing'),current_setting('shared_preload_libraries');" > "$OUT/postgresql-final-settings.txt"
fi
