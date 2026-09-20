$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Sha256([string]$Path, [string]$Expected) {
    $actual = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for ${Path}: expected ${Expected}, got ${actual}"
    }
}

New-Item -ItemType Directory -Force evidence | Out-Null

@'
import base64, hashlib, os, tarfile
from pathlib import Path
parts = sorted(Path('.phase3/bundle').glob('part-*.b64'))
if not parts:
    raise SystemExit('Phase 3 CI bundle chunks are missing')
bundle = Path('phase3_ci_bundle.tar.xz')
bundle.write_bytes(base64.b64decode(''.join(p.read_text('ascii').strip() for p in parts), validate=True))
actual = hashlib.sha256(bundle.read_bytes()).hexdigest()
if actual != os.environ['PHASE3_CI_BUNDLE_SHA256']:
    raise SystemExit(f'Phase 3 CI bundle hash mismatch: {actual}')
with tarfile.open(bundle, 'r:xz') as archive:
    members = archive.getmembers()
    for member in members:
        path = Path(member.name)
        if path.is_absolute() or '..' in path.parts or not member.isfile():
            raise SystemExit(f'unsafe Phase 3 CI bundle member: {member.name}')
    archive.extractall('.')
print(f'verified and extracted {len(members)} Phase 3 CI bundle members')
'@ | python -
if ($LASTEXITCODE -ne 0) { throw 'CI bundle extraction failed' }

git merge-base --is-ancestor $env:PHASE2_BASE_COMMIT HEAD
if ($LASTEXITCODE -ne 0) { throw 'Phase 2 base commit is not an ancestor' }
$Allowed = @(
    '.github/workflows/phase3-live-pg16.yml',
    '.github/workflows/phase3-windows-pg16.yml',
    '.phase3/run_windows_phase3.ps1'
)
$Unexpected = @(git diff --name-only $env:PHASE2_BASE_COMMIT HEAD | Where-Object {
    $_ -notmatch '^\.phase3/bundle/' -and $_ -notin $Allowed
})
if ($Unexpected.Count -ne 0) {
    throw "unexpected committed paths before Phase 2 reconstruction: $($Unexpected -join ', ')"
}
Assert-Sha256 '.phase3/phase2_pg_runtime_from_main.patch' $env:PHASE2_RUNTIME_PATCH_SHA256
Assert-Sha256 '.phase3/phase2_pg_runtime_file_hashes.json' $env:PHASE2_RUNTIME_MANIFEST_SHA256

git apply --check .phase3/phase2_pg_runtime_from_main.patch
if ($LASTEXITCODE -ne 0) { throw 'Phase 2 runtime patch preflight failed' }
git apply .phase3/phase2_pg_runtime_from_main.patch
if ($LASTEXITCODE -ne 0) { throw 'Phase 2 runtime patch failed' }

@'
import hashlib, json, os
from pathlib import Path
manifest = json.loads(Path('.phase3/phase2_pg_runtime_file_hashes.json').read_text('utf-8'))
if manifest['phase2_source_archive_sha256'] != os.environ['PHASE2_ARCHIVE_SHA256']:
    raise SystemExit('Phase 2 archive identity mismatch')
failures = []
for relative, expected in manifest['files'].items():
    path = Path(relative)
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    if actual != expected:
        failures.append({'path': relative, 'expected': expected, 'actual': actual})
if failures:
    raise SystemExit(f'Phase 2 runtime closure mismatch: {failures[:5]}')
print(f"verified {len(manifest['files'])} exact Phase 2 runtime files")
'@ | python -
if ($LASTEXITCODE -ne 0) { throw 'Phase 2 runtime closure verification failed' }
Assert-Sha256 '.phase3/tools/postgresql_64_worker_128_concurrency_gate.py' $env:HISTORICAL_GATE_SHA256

python -m pip install --upgrade pip
python -m pip install 'tzdata>=2025.2' 'cryptography>=50,<51' 'httpx>=0.28,<1' 'psycopg[binary]>=3.2,<4' 'psycopg-pool>=3.2,<4' 'opentelemetry-api>=1.30,<2'
if ($LASTEXITCODE -ne 0) { throw 'Python dependency installation failed' }

choco install postgresql16 --version=16.15.0 --yes --no-progress --params '/Password:arenyxa-ci /Port:55432'
if ($LASTEXITCODE -notin @(0, 1641, 3010)) { throw "Chocolatey PostgreSQL install failed: $LASTEXITCODE" }
$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
$env:PYTHONPATH = "$env:GITHUB_WORKSPACE\src;$env:GITHUB_WORKSPACE\.phase3\tools"
$env:PGPASSWORD = 'arenyxa-ci'

$Ready = $false
for ($i = 0; $i -lt 60; $i++) {
    & pg_isready -h 127.0.0.1 -p 55432 -U postgres
    if ($LASTEXITCODE -eq 0) { $Ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $Ready) { throw 'PostgreSQL 16.15 did not become ready' }

& psql -h 127.0.0.1 -p 55432 -U postgres -d postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE arenyxa LOGIN PASSWORD 'arenyxa-ci';"
if ($LASTEXITCODE -ne 0) { throw 'CREATE ROLE failed' }
& createdb -h 127.0.0.1 -p 55432 -U postgres -O arenyxa arenyxa_ci
if ($LASTEXITCODE -ne 0) { throw 'CREATE DATABASE failed' }
& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET max_connections = '256';"
& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET fsync = 'on';"
& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -v ON_ERROR_STOP=1 -c "ALTER SYSTEM SET synchronous_commit = 'on';"
if ($LASTEXITCODE -ne 0) { throw 'ALTER SYSTEM failed' }

$Service = Get-Service -Name 'postgresql-x64-16' -ErrorAction Stop
Restart-Service -Name $Service.Name
$Ready = $false
for ($i = 0; $i -lt 60; $i++) {
    & pg_isready -h 127.0.0.1 -p 55432 -U postgres
    if ($LASTEXITCODE -eq 0) { $Ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $Ready) { throw 'PostgreSQL restart did not become ready' }
if ((& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -Atc 'SHOW server_version_num;').Trim() -ne '160015') { throw 'server_version_num is not 160015' }
if ((& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -Atc 'SHOW max_connections;').Trim() -ne '256') { throw 'max_connections is not 256' }
if ((& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -Atc 'SHOW fsync;').Trim() -ne 'on') { throw 'fsync is not on' }
if ((& psql -h 127.0.0.1 -p 55432 -U postgres -d arenyxa_ci -Atc 'SHOW synchronous_commit;').Trim() -ne 'on') { throw 'synchronous_commit is not on' }

@'
import json, os, platform
from pathlib import Path
import psycopg
with psycopg.connect(os.environ['ARENYXA_POSTGRES_TEST_DSN']) as connection:
    row = connection.execute("SELECT version(), current_database(), current_setting('server_version'), current_setting('max_connections'), current_setting('fsync'), current_setting('synchronous_commit')").fetchone()
data = {
    'evidence_class': 'WINDOWS CI PG16 EVIDENCE — NOT USER WINDOWS 11 SIGN-OFF',
    'runner_os': platform.platform(), 'python': platform.python_version(), 'cpu_count': os.cpu_count(),
    'postgresql': {'version': row[0], 'database': row[1], 'server_version': row[2], 'max_connections': row[3], 'fsync': row[4], 'synchronous_commit': row[5]},
    'phase2_source_archive_sha256': os.environ['PHASE2_ARCHIVE_SHA256'],
    'phase2_base_commit': os.environ['PHASE2_BASE_COMMIT'],
    'phase2_runtime_patch_sha256': os.environ['PHASE2_RUNTIME_PATCH_SHA256'],
    'phase2_runtime_manifest_sha256': os.environ['PHASE2_RUNTIME_MANIFEST_SHA256'],
    'historical_gate_sha256': os.environ['HISTORICAL_GATE_SHA256'],
}
Path('evidence/ENVIRONMENT.json').write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')
'@ | python -
if ($LASTEXITCODE -ne 0) { throw 'environment capture failed' }

python .phase3/tools/phase3_postgresql_correctness_gate.py --race-iterations 50 --reconcile-jobs 256 --reset-database arenyxa_ci --report evidence/CORRECTNESS.json
if ($LASTEXITCODE -ne 0) { throw 'live PostgreSQL correctness gate failed' }
python .phase3/tools/postgresql_64_worker_128_concurrency_gate.py --jobs 1024 --p99-ms 500 --report evidence/AUTHORITATIVE_64W_128C_GATE.json
if ($LASTEXITCODE -ne 0) { throw 'authoritative P99 gate failed' }
python .phase3/tools/phase3_postgresql_p99_campaign.py --runs 10 --jobs 1024 --hard-p99-ms 500 --preferred-p99-ms 300 --correctness-race-iterations 50 --correctness-reconcile-jobs 256 --reset-database arenyxa_ci --report evidence/P99_CAMPAIGN.json
if ($LASTEXITCODE -ne 0) { throw 'natural-warm campaign failed formal release gate' }
