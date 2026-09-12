#!/usr/bin/env bash
set -euo pipefail
OUT="${1:-phase3_artifacts}"
mkdir -p "$OUT"
OS_VERSION="$(. /etc/os-release; echo "$VERSION_ID")"
CPU_COUNT="$(nproc)"
CPU_ALLOWED="$(awk -F: '/Cpus_allowed_list/ {gsub(/[ \t]/,"",$2); print $2}' /proc/self/status)"
CPU_MODEL="$(lscpu | awk -F: '/Model name/ {gsub(/^[ \t]+/,"",$2); print $2}')"
RAM_BYTES="$(awk '/MemTotal/ {print $2*1024}' /proc/meminfo)"
FSTYPE="$(df -T . | awk 'NR==2 {print $2}')"
KERNEL="$(uname -r)"
python3 - "$CPU_COUNT" "$CPU_ALLOWED" "$RAM_BYTES" <<'PY'
import sys
count=int(sys.argv[1]); spec=sys.argv[2]; ram=int(float(sys.argv[3]))
cpus=set()
for part in spec.split(','):
    if '-' in part:
        a,b=map(int,part.split('-',1)); cpus.update(range(a,b+1))
    elif part:
        cpus.add(int(part))
assert count == 4, (count, spec)
assert len(cpus) == 4, (count, spec, sorted(cpus))
assert ram >= 8 * 1024**3, ram
PY
test "$OS_VERSION" = "24.04"
{
  echo "OS_VERSION=$OS_VERSION"
  echo "KERNEL=$KERNEL"
  echo "CPU_COUNT=$CPU_COUNT"
  echo "CPU_ALLOWED=$CPU_ALLOWED"
  echo "CPU_MODEL=$CPU_MODEL"
  echo "RAM_BYTES=$RAM_BYTES"
  echo "FILESYSTEM=$FSTYPE"
  lscpu
} | tee "$OUT/execution-environment.txt"

test "$(git merge-base HEAD db1c1213b090e71320143273e9c51e049b861b87)" = "db1c1213b090e71320143273e9c51e049b861b87"
test "$(sha256sum scripts/postgresql_32_worker_gate.py | awk '{print $1}')" = "1dcb09ea7490abebb8e73546178415530adc852422a0346b8d72de56e5322657"
test "$(sha256sum scripts/postgresql_64_worker_128_concurrency_gate.py | awk '{print $1}')" = "ba766b7e02b0f511c1e721628e8e0d615adada27b24918762a73bc1ef7762588"
git apply --check .github/phase3/reconstructed-abg.patch
git apply .github/phase3/reconstructed-abg.patch
test "$(sha256sum src/arenyxa/enterprise/runtime_storage.py | awk '{print $1}')" = "5702ee19406e72525c96d848eeb7b909141872e0d8c0ebdb29c149b4d596594a"
test "$(sha256sum src/arenyxa/enterprise/distributed_queue.py | awk '{print $1}')" = "8d34fef8df28b3ef7521dd2c465aa2bdf8a6217244635f151c6f752d704c2ccd"
test "$(git diff --name-only db1c1213b090e71320143273e9c51e049b861b87 -- src/arenyxa | sort | tr '\n' ' ')" = "src/arenyxa/enterprise/distributed_queue.py src/arenyxa/enterprise/runtime_storage.py "
test -z "$(git diff -- scripts/postgresql_32_worker_gate.py scripts/postgresql_64_worker_128_concurrency_gate.py)"
git diff db1c1213b090e71320143273e9c51e049b861b87 -- src/arenyxa > "$OUT/executed-source.diff"
git diff -- scripts/postgresql_32_worker_gate.py scripts/postgresql_64_worker_128_concurrency_gate.py > "$OUT/executed-scripts.diff"
sha256sum src/arenyxa/enterprise/runtime_storage.py src/arenyxa/enterprise/distributed_queue.py scripts/postgresql_32_worker_gate.py scripts/postgresql_64_worker_128_concurrency_gate.py > "$OUT/source-hashes-before.sha256"
