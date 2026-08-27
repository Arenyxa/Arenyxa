$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap.ps1 first.' }
& $Python (Join-Path $PSScriptRoot 'enterprise_server.py') @args
exit $LASTEXITCODE
