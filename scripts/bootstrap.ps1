param(
    [switch]$SkipBrowserRuntime
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvRoot = Join-Path $ProjectRoot '.venv'
$VenvPython = Join-Path $VenvRoot 'Scripts\python.exe'
$Probe = @'
import sys
import venv
import pip
supported = (3, 11) <= sys.version_info[:2] < (3, 14)
win64 = sys.maxsize > 2**32
raise SystemExit(0 if supported and win64 else 2)
'@

function Test-SupportedPython {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$PrefixArgs = @()
    )
    try {
        $ProbeArgs = @($PrefixArgs) + @('-c', $Probe)
        & $Executable @ProbeArgs *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Resolve-SupportedPython {
    $Candidates = @(
        @{ Executable = 'py'; Args = @('-3.13') },
        @{ Executable = 'py'; Args = @('-3.12') },
        @{ Executable = 'py'; Args = @('-3.11') },
        @{ Executable = 'python'; Args = @() }
    )
    foreach ($Candidate in $Candidates) {
        if (Test-SupportedPython -Executable $Candidate.Executable -PrefixArgs $Candidate.Args) {
            return $Candidate
        }
    }
    return $null
}

function Move-VenvAside {
    param([Parameter(Mandatory = $true)][string]$Reason)
    if (-not (Test-Path -LiteralPath $VenvRoot)) { return }
    $Suffix = Get-Date -Format 'yyyyMMddHHmmssfff'
    $BackupVenv = Join-Path $ProjectRoot ('.venv.' + $Reason + '.' + $Suffix)
    Write-Warning "Existing .venv is $Reason. Moving it to: $BackupVenv"
    Move-Item -LiteralPath $VenvRoot -Destination $BackupVenv
}

if (Test-Path -LiteralPath $VenvRoot) {
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        Move-VenvAside -Reason 'incomplete'
    } elseif (-not (Test-SupportedPython -Executable $VenvPython)) {
        Move-VenvAside -Reason 'incompatible'
    }
}

if (-not (Test-Path -LiteralPath $VenvPython)) {
    $Python = Resolve-SupportedPython
    if (-not $Python) {
        throw 'Python 3.11, 3.12, or 3.13 (64-bit) was not found. Install supported x64 Python and rerun.'
    }
    $CreateArgs = @($Python.Args) + @('-m', 'venv', $VenvRoot)
    & $Python.Executable @CreateArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $VenvPython)) {
        throw 'Failed to create the Arenyxa virtual environment.'
    }
    if (-not (Test-SupportedPython -Executable $VenvPython)) {
        throw 'The new Arenyxa virtual environment is not a supported 64-bit Python 3.11-3.13 environment.'
    }
}

& $VenvPython -m pip install --upgrade pip 'setuptools>=68,<76' 'wheel>=0.41,<0.46'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $VenvPython -m pip install -e "${ProjectRoot}[dev,desktop,analysis,server,capture,browser,database]"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not $SkipBrowserRuntime) {
    & $VenvPython -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Arenyxa environment ready: $VenvPython"
