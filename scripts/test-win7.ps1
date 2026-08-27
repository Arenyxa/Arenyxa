$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$Python = Join-Path $ProjectRoot '.venv-win7\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap-win7.ps1 first.' }
$env:ARENYXA_RUNTIME_TIER = 'legacy-enterprise'
$env:ARENYXA_RUNTIME_TIER = 'legacy-enterprise' # The current release retains the 6.8.0 internal/plugin compatibility identity
$env:QT_QPA_PLATFORM = 'offscreen'
$env:QT_OPENGL = 'software'
& $Python (Join-Path $ProjectRoot 'scripts\check_python38_grammar.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python -m compileall -q (Join-Path $ProjectRoot 'legacy\win7\src') (Join-Path $ProjectRoot 'legacy\win7\tests')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:PYTHONPATH = (Join-Path $ProjectRoot 'legacy\win7\src')
& $Python -m pytest -q --disable-warnings --maxfail=1 (Join-Path $ProjectRoot 'legacy\win7\tests')
exit $LASTEXITCODE
