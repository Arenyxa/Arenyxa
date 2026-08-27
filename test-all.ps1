$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$PowerShellHost = (Get-Process -Id $PID).Path
& $PowerShellHost -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ProjectRoot 'scripts\test.ps1')
exit $LASTEXITCODE
