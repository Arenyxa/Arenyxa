$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap.ps1 first.' }

Write-Host '[1/5] Compiling modern Python sources...'
& $Python -m compileall -q (Join-Path $ProjectRoot 'src\arenyxa') (Join-Path $ProjectRoot 'scripts') (Join-Path $ProjectRoot 'tests')
if ($LASTEXITCODE -ne 0) { Write-Error 'Python compileall failed.'; exit $LASTEXITCODE }

Write-Host '[2/5] Running release-blocking critical Ruff plus retained full Ruff/Mypy audits...'
& $Python (Join-Path $PSScriptRoot 'static_quality_gate.py')
if ($LASTEXITCODE -ne 0) { Write-Error 'Static quality gate failed.'; exit $LASTEXITCODE }

Write-Host '[3/5] Checking frozen Windows 7 legacy Python 3.8 lane...'
& $Python (Join-Path $PSScriptRoot 'check_python38_grammar.py')
if ($LASTEXITCODE -ne 0) { Write-Error 'Windows 7 legacy grammar gate failed.'; exit $LASTEXITCODE }

Write-Host '[4/5] Running release-blocking pytest...'
$PreviousQtQpaPlatform = [Environment]::GetEnvironmentVariable('QT_QPA_PLATFORM', 'Process')
try {
    $env:QT_QPA_PLATFORM = 'offscreen'
    & $Python -m pytest -q --disable-warnings --maxfail=1
    $PytestExitCode = $LASTEXITCODE
} finally {
    if ($null -eq $PreviousQtQpaPlatform) { Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue } else { $env:QT_QPA_PLATFORM = $PreviousQtQpaPlatform }
}
if ($PytestExitCode -ne 0) { Write-Error 'pytest failed.'; exit $PytestExitCode }

Write-Host '[5/5] Running integrity and publication gates...'
& $Python (Join-Path $PSScriptRoot 'phase0_gate.py') --skip-pytest --skip-static
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python (Join-Path $PSScriptRoot 'github_publication_gate.py') --allow-local-artifacts
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host 'All release-blocking test gates passed; advisory static-analysis reports are under dist\audit.'
exit 0
