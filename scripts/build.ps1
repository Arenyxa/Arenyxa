param(
    [switch]$SkipTests,
    [switch]$RequireInno
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { throw 'Run scripts\bootstrap.ps1 first.' }

& $Python (Join-Path $ProjectRoot 'scripts\verify_v81_release_identity.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $Python (Join-Path $ProjectRoot 'scripts\build_source_repair_seed.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Python (Join-Path $ProjectRoot 'scripts\build_source_manifest.py')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot 'test.ps1')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Push-Location $ProjectRoot
try {
    & $Python -m PyInstaller --noconfirm --clean (Join-Path $ProjectRoot 'packaging\arenyxa.spec')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python -m PyInstaller --noconfirm --clean --distpath (Join-Path $ProjectRoot 'dist\service') (Join-Path $ProjectRoot 'packaging\arenyxa_service.spec')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $ServiceExe = Join-Path $ProjectRoot 'dist\service\ArenyxaService.exe'
    if (-not (Test-Path -LiteralPath $ServiceExe)) { throw 'ArenyxaService.exe was not produced.' }
    Copy-Item -LiteralPath $ServiceExe -Destination (Join-Path $ProjectRoot 'dist\Arenyxa\ArenyxaService.exe') -Force
    & $Python (Join-Path $ProjectRoot 'scripts\build_repair_payload.py')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    $ReleaseChannel = if ($env:ARENYXA_RELEASE_CHANNEL) { $env:ARENYXA_RELEASE_CHANNEL } else { 'community' }
    $SigningKey = $env:ARENYXA_RELEASE_SIGNING_KEY
    $Manifest = Join-Path $ProjectRoot 'dist\Arenyxa\repair\install_manifest.json'
    $Attestation = Join-Path $ProjectRoot 'dist\Arenyxa\repair\release_attestation.json'
    
    # Improvement: read the version dynamically from __init__.py
    $VersionRaw = Get-Content (Join-Path $ProjectRoot 'src\arenyxa\__init__.py') | Where-Object { $_ -match '__distribution_version__\s*=\s*"(.*)"' }
    if ($VersionRaw -match '"(.*)"') {
        $ProjectVersion = $Matches[1]
    } else {
    $ProjectVersion = '8.1.1'
    }

    if ($ReleaseChannel -eq 'official' -and -not $SigningKey) {
        throw 'Official builds require ARENYXA_RELEASE_SIGNING_KEY. Refusing to create an unsigned official distribution.'
    }
    if ($SigningKey) {
        & $Python (Join-Path $ProjectRoot 'scripts\build_release_attestation.py') `
            --manifest $Manifest --output $Attestation --private-key $SigningKey --channel $ReleaseChannel --version $ProjectVersion
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    } else {
        Write-Warning 'No release signing key configured. Portable build will be functional but shown as an unverified distribution.'
    }
} finally {
    Pop-Location
}

$ISCCCandidates = @(
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$ISCC = $ISCCCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if ($ISCC) {
    Write-Host "Using Inno Setup compiler: $ISCC"
    & $ISCC (Join-Path $ProjectRoot 'packaging\installer.iss')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
} else {
    if ($RequireInno) {
        throw 'Inno Setup 6/7 compiler not found; reproducible release build requires installer packaging.'
    }
    Write-Warning 'Inno Setup 6/7 compiler not found; the portable PyInstaller build is complete.'
}
