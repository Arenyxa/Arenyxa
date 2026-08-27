$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$DataDir = Join-Path $ProjectRoot 'server-data'
& $Python -m arenyxa.server --data-dir $DataDir @args

