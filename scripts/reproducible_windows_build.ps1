param(
    [switch]$SkipBrowserRuntime,
    [string]$ReportPath = ""
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
if (-not $IsWindows -and $PSVersionTable.PSEdition -eq 'Core') {
    throw 'Arenyxa reproducible Windows build must run on Windows.'
}
if ($env:OS -ne 'Windows_NT') {
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

$Inno = Resolve-InnoCompiler
if (-not $Inno) { throw 'Inno Setup 6/7 is required for a release package.' }
$InnoVersion = (Get-Item -LiteralPath $Inno).VersionInfo.FileVersion

# Reproducibility controls for Python hashing and tools that honor SOURCE_DATE_EPOCH.
$PreviousPythonHashSeed = $env:PYTHONHASHSEED
$PreviousSourceDateEpoch = $env:SOURCE_DATE_EPOCH
$env:PYTHONHASHSEED = '0'
if (-not $env:SOURCE_DATE_EPOCH) {
    $Git = Get-Command git -ErrorAction SilentlyContinue
    if ($Git) {
        $Epoch = (& git -C $ProjectRoot log -1 --format=%ct 2>$null)
        if ($LASTEXITCODE -eq 0 -and $Epoch -match '^\d+$') { $env:SOURCE_DATE_EPOCH = $Epoch }
    }
    if (-not $env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH = '0' }
}

try {
    & (Join-Path $PSScriptRoot 'bootstrap.ps1') -SkipBrowserRuntime:$SkipBrowserRuntime
    if ($LASTEXITCODE -ne 0) { throw "bootstrap failed with exit code $LASTEXITCODE" }
    $Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
    $PythonVersion = (& $Python --version 2>&1 | Out-String).Trim()
    $PipVersion = (& $Python -m pip --version 2>&1 | Out-String).Trim()

    & (Join-Path $PSScriptRoot 'test.ps1')
    if ($LASTEXITCODE -ne 0) { throw "test failed with exit code $LASTEXITCODE" }

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

    $GitCommit = ''
    $GitDirty = $null
    $Git = Get-Command git -ErrorAction SilentlyContinue
    if ($Git) {
        $GitCommit = ((& git -C $ProjectRoot rev-parse HEAD 2>$null) | Out-String).Trim()
        $Status = ((& git -C $ProjectRoot status --porcelain 2>$null) | Out-String).Trim()
        $GitDirty = [bool]$Status
    }

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
        phases = @('bootstrap', 'test', 'build', 'package')
        artifacts = $Artifacts
        passed = $true
    }
    $Report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
    Write-Host "Reproducible Windows build passed. Report: $ReportPath"
} catch {
    $Failure = [ordered]@{
        schema = 'arenyxa.windows-reproducible-build/v1'
        started_at = $Started.ToString('o')
        finished_at = [DateTimeOffset]::UtcNow.ToString('o')
        passed = $false
        error = $_.Exception.Message
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
