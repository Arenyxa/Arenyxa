$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$Python = Join-Path $ProjectRoot '.venv-win7\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap-win7.ps1 first.' }
$env:ARENYXA_RUNTIME_TIER = 'legacy-enterprise'
$env:ARENYXA_RUNTIME_TIER = 'legacy-enterprise' # The current release retains the 6.8.0 internal/plugin compatibility identity
$env:QT_OPENGL = 'software'
& $Python -m arenyxa
exit $LASTEXITCODE
