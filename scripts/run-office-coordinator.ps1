param(
    [string]$DataDir = "",
    [string]$HostAddress = "0.0.0.0",
    [int]$Port = 0,
    [Parameter(Mandatory=$true)][string]$Username
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) { throw "Arenyxa .venv is unavailable. Run scripts\bootstrap.ps1 first." }
$Args = @((Join-Path $PSScriptRoot "office_coordinator.py"), "--host", $HostAddress, "--port", "$Port", "--username", $Username)
if ($DataDir) { $Args += @("--data-dir", $DataDir) }
& $Python @Args
exit $LASTEXITCODE
