param(
    [switch]$SkipBrowserRuntime,
    [string]$ReportPath = ""
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$RunningOnWindows = if ($PSVersionTable.PSEdition -eq 'Core') {
    [bool]$IsWindows
} else {
    [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
}
if (-not $RunningOnWindows) {
    throw 'Arenyxa reproducible Windows build must run on Windows.'
}

$Started = [DateTimeOffset]::UtcNow
$BuildRoot = Join-Path $ProjectRoot 'dist\build'
New-Item -ItemType Directory -Force -Path $BuildRoot | Out-Null
if (-not $ReportPath) { $ReportPath = Join-Path $BuildRoot 'BUILD_REPORT.json' }

function Resolve-InnoCompiler {
    $Candidates = @(
        "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )
    return $Candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
}

$Inno = $null
$InnoVersion = $null
$GitCommit = $null
$GitDirty = $null
$Stage = 'source-provenance'

# Reproducibility controls for Python hashing and tools that honor SOURCE_DATE_EPOCH.
$PreviousPythonHashSeed = $env:PYTHONHASHSEED
$PreviousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$env:PYTHONHASHSEED = '0'
try {
    $Git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $Git) { throw 'Git is required to establish release source provenance.' }
    $GitRoot = ((& git -C $ProjectRoot rev-parse --show-toplevel 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or -not $GitRoot) { throw 'Git source provenance is unavailable: project is not a Git checkout.' }
    if (-not [string]::Equals([IO.Path]::GetFullPath($GitRoot), [IO.Path]::GetFullPath($ProjectRoot), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Git checkout root does not match the release project root.'
    }
    $GitCommit = ((& git -C $ProjectRoot rev-parse --verify HEAD 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $GitCommit -notmatch '^[0-9a-f]{40,64}$') { throw 'Git commit identity cannot be verified.' }
    $Status = ((& git -C $ProjectRoot status --porcelain 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Git status failed; source cleanliness is unknown.' }
    $GitDirty = [bool]$Status
    if ($GitDirty) { throw 'Git checkout contains uncommitted or untracked release inputs.' }
    if (-not $env:SOURCE_DATE_EPOCH) {
        $Epoch = ((& git -C $ProjectRoot log -1 --format=%ct 2>$null) | Out-String).Trim()
        if ($LASTEXITCODE -ne 0 -or $Epoch -notmatch '^\d+$') { throw 'Git commit epoch cannot be verified.' }
        $env:SOURCE_DATE_EPOCH = $Epoch
    }
    if ($env:SOURCE_DATE_EPOCH -notmatch '^\d+$') { throw 'SOURCE_DATE_EPOCH must be an integer epoch.' }
    $Stage = 'build-tools'
    $Inno = Resolve-InnoCompiler
    if (-not $Inno) { throw 'Inno Setup 6/7 is required for a release package.' }
    $InnoVersion = (Get-Item -LiteralPath $Inno).VersionInfo.FileVersion
    $Stage = 'bootstrap'
    & (Join-Path $PSScriptRoot 'bootstrap.ps1') -SkipBrowserRuntime:$SkipBrowserRuntime
    if ($LASTEXITCODE -ne 0) { throw "bootstrap failed with exit code $LASTEXITCODE" }
    $Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
    $PythonVersion = (& $Python --version 2>&1 | Out-String).Trim()
    $PipVersion = (& $Python -m pip --version 2>&1 | Out-String).Trim()
    $ResolvedDependencies = @(& $Python -m pip freeze --all)
    if ($LASTEXITCODE -ne 0) { throw 'Resolved dependency capture failed.' }

    $Stage = 'test'
    & (Join-Path $PSScriptRoot 'test.ps1')
    if ($LASTEXITCODE -ne 0) { throw "test failed with exit code $LASTEXITCODE" }

    $Stage = 'build-package'
    & (Join-Path $PSScriptRoot 'build.ps1') -SkipTests -RequireInno
    if ($LASTEXITCODE -ne 0) { throw "build/package failed with exit code $LASTEXITCODE" }

    $Artifacts = @()
    $ArtifactCandidates = Get-ChildItem -LiteralPath (Join-Path $ProjectRoot 'dist') -File -Recurse |
        Where-Object { $_.Extension -in @('.exe', '.json', '.spdx', '.cdx') -or $_.Name -like '*SBOM*' }
    foreach ($Item in $ArtifactCandidates) {
        $Hash = Get-FileHash -LiteralPath $Item.FullName -Algorithm SHA256
        $Artifacts += [ordered]@{
            path = [IO.Path]::GetRelativePath($ProjectRoot, $Item.FullName)
            bytes = $Item.Length
            sha256 = $Hash.Hash.ToLowerInvariant()
        }
    }

    $Stage = 'source-provenance-after-build'
    $FinalCommit = ((& git -C $ProjectRoot rev-parse --verify HEAD 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $FinalCommit -ne $GitCommit) { throw 'Git source identity changed during the build.' }
    $Status = ((& git -C $ProjectRoot status --porcelain 2>$null) | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) { $GitDirty = $null; throw 'Git status failed after build; cleanliness is unknown.' }
    $GitDirty = [bool]$Status
    if ($GitDirty) { throw 'Git source inputs changed during the build.' }

    $Report = [ordered]@{
        schema = 'arenyxa.windows-reproducible-build/v1'
        started_at = $Started.ToString('o')
        finished_at = [DateTimeOffset]::UtcNow.ToString('o')
        project_root = $ProjectRoot
        powershell = $PSVersionTable.PSVersion.ToString()
        python = $PythonVersion
        pip = $PipVersion
        inno_setup = [ordered]@{ path = $Inno; version = $InnoVersion }
        source_date_epoch = $env:SOURCE_DATE_EPOCH
        pythonhashseed = $env:PYTHONHASHSEED
        git = [ordered]@{ commit = $GitCommit; dirty = $GitDirty }
        resolved_dependencies = $ResolvedDependencies
        reproducibility = [ordered]@{ controls_recorded = $true; bit_identical_verified = $false; dependency_lock_enforced = $false }
        phases = @('bootstrap', 'test', 'build', 'package')
        artifacts = $Artifacts
        passed = $true
    }
    $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "Windows build passed; reproducibility controls and resolved dependencies recorded. Bit-identical rebuilding is unverified. Report: $ReportPath"
} catch {
    $Failure = [ordered]@{
        schema = 'arenyxa.windows-reproducible-build/v1'
        started_at = $Started.ToString('o')
        finished_at = [DateTimeOffset]::UtcNow.ToString('o')
        passed = $false
        stage = $Stage
        error = $_.Exception.Message
        git = [ordered]@{ commit = $GitCommit; dirty = $GitDirty }
        powershell = $PSVersionTable.PSVersion.ToString()
        inno_setup = [ordered]@{ path = $Inno; version = $InnoVersion }
        source_date_epoch = $env:SOURCE_DATE_EPOCH
    }
    $Failure | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    throw
} finally {
    if ($null -eq $PreviousPythonHashSeed) { Remove-Item Env:PYTHONHASHSEED -ErrorAction SilentlyContinue } else { $env:PYTHONHASHSEED = $PreviousPythonHashSeed }
    if ($null -eq $PreviousSourceDateEpoch) { Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue } else { $env:SOURCE_DATE_EPOCH = $PreviousSourceDateEpoch }
}
