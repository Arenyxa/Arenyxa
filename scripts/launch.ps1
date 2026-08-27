$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Bootstrap = Join-Path $PSScriptRoot 'bootstrap.ps1'
$ProbeHelper = Join-Path $PSScriptRoot 'launch_probe.ps1'
$VenvRoot = Join-Path $ProjectRoot '.venv'
$Python = Join-Path $VenvRoot 'Scripts\python.exe'
$script:ArenyxaEnvironmentDiagnostic = ''
$EnvironmentProbe = @'
import importlib
import sys
from pathlib import Path
import arenyxa
from arenyxa.qt_compat import QtCore

for module_name in ("lxml", "cssselect", "dns", "openpyxl", "cryptography", "tzdata"):
    importlib.import_module(module_name)

supported = (3, 11) <= sys.version_info[:2] < (3, 14)
project_source = (Path.cwd() / "src").resolve()
module_path = Path(arenyxa.__file__).resolve()
current_source = module_path.is_relative_to(project_source)
print("probe_python=" + sys.executable)
print("probe_version=" + sys.version.replace("\n", " "))
print("probe_arenyxa=" + str(module_path))
print("probe_release=" + getattr(arenyxa, "__display_version__", "unknown"))
if not current_source:
    print("probe_error=stale editable install: Arenyxa is not imported from the current project src directory")
raise SystemExit(0 if supported and sys.maxsize > 2**32 and current_source else 2)
'@

. $ProbeHelper

function Format-ArenyxaProbeDiagnostic {
    param([Parameter(Mandatory = $true)]$ProbeResult)
    $Lines = @(
        "Python executable: $($ProbeResult.PythonExecutable)",
        "Python version: $($ProbeResult.PythonVersion)",
        "Working directory: $($ProbeResult.WorkingDirectory)",
        "ExitCode: $($ProbeResult.ExitCode)",
        'stdout:',
        [string]$ProbeResult.Stdout,
        'stderr:',
        [string]$ProbeResult.Stderr
    )
    return (($Lines -join [Environment]::NewLine).Trim())
}

function Test-ArenyxaEnvironment {
    $script:ArenyxaEnvironmentDiagnostic = ''
    $ProbeResult = Invoke-ArenyxaProcessProbe -PythonExecutable $Python -WorkingDirectory $ProjectRoot -ProbeScript $EnvironmentProbe
    $script:ArenyxaEnvironmentDiagnostic = Format-ArenyxaProbeDiagnostic -ProbeResult $ProbeResult
    if ($ProbeResult.Started -and $ProbeResult.ExitCode -eq 0) {
        return $true
    }
    return $false
}

try {
    Set-Location -LiteralPath $ProjectRoot

    if (-not (Test-ArenyxaEnvironment)) {
        Write-Host '[Arenyxa] First run or incomplete environment detected.'
        Write-Host '[Arenyxa] Environment probe diagnostic:' -ForegroundColor Yellow
        Write-Host $script:ArenyxaEnvironmentDiagnostic -ForegroundColor Yellow
        Write-Host '[Arenyxa] Preparing the local virtual environment...'
        & $Bootstrap
        if ($LASTEXITCODE -ne 0) {
            throw "bootstrap.ps1 failed with exit code $LASTEXITCODE."
        }
        if (-not (Test-ArenyxaEnvironment)) {
            Write-Host '[Arenyxa] Environment probe diagnostic after bootstrap:' -ForegroundColor Yellow
            Write-Host $script:ArenyxaEnvironmentDiagnostic -ForegroundColor Yellow
            throw 'The Arenyxa environment is still unavailable after bootstrap completed. See the diagnostic above.'
        }
    }

    Write-Host '[Arenyxa] Environment probe passed.'
    Write-Host $script:ArenyxaEnvironmentDiagnostic

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $Python
    $StartInfo.Arguments = '-m arenyxa'
    $StartInfo.WorkingDirectory = $ProjectRoot
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $false

    $Process = [System.Diagnostics.Process]::Start($StartInfo)
    if ($null -eq $Process) {
        throw 'Windows did not create the Arenyxa process.'
    }

    Write-Host '[Arenyxa] Started successfully with python.exe -m arenyxa.'
    exit 0
} catch {
    Write-Error ("Arenyxa source launcher failed: " + $_.Exception.Message)
    exit 1
}
