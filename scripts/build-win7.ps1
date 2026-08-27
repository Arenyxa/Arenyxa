$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$Python = Join-Path $ProjectRoot '.venv-win7\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap-win7.ps1 first.' }

& $Python (Join-Path $ProjectRoot 'scripts\verify_v73_release_identity.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python (Join-Path $ProjectRoot 'scripts\build_source_repair_seed.py') --win7
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python (Join-Path $ProjectRoot 'scripts\build_source_manifest.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& (Join-Path $ScriptRoot 'test-win7.ps1')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Push-Location $ProjectRoot
try {
    if (Test-Path -LiteralPath (Join-Path $ProjectRoot 'dist\Arenyxa')) { Remove-Item -Recurse -Force (Join-Path $ProjectRoot 'dist\Arenyxa') }
    & $Python -m PyInstaller --noconfirm --clean (Join-Path $ProjectRoot 'packaging\arenyxa_win7.spec')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python (Join-Path $ProjectRoot 'scripts\build_repair_payload.py')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} finally { Pop-Location }

Write-Host 'Legacy portable build complete. Compile packaging\installer_win7.iss with Inno Setup on a supported build workstation to create the Win7-targeted installer.'
