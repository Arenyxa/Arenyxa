$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'launch_probe.ps1')
$Python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $Python) {
    $Python = (Get-Command python -ErrorAction Stop).Source
}

$Good = Invoke-ArenyxaProcessProbe -PythonExecutable $Python -WorkingDirectory $Root -ProbeScript @'
import sys
print("stdout-ok")
sys.stderr.write("warning-on-stderr\n")
raise SystemExit(0)
'@
if (-not $Good.Started -or $Good.ExitCode -ne 0) { throw 'successful probe was misclassified' }
if ($Good.Stdout -notmatch 'stdout-ok') { throw 'stdout was not captured' }
if ($Good.Stderr -notmatch 'warning-on-stderr') { throw 'stderr warning was not captured separately' }

$Bad = Invoke-ArenyxaProcessProbe -PythonExecutable $Python -WorkingDirectory $Root -ProbeScript @'
import sys
print("stdout-before-failure")
sys.stderr.write("synthetic traceback marker\n")
raise SystemExit(7)
'@
if (-not $Bad.Started -or $Bad.ExitCode -ne 7) { throw "exit code was not preserved: $($Bad.ExitCode)" }
if ($Bad.Stdout -notmatch 'stdout-before-failure') { throw 'failing stdout was not captured' }
if ($Bad.Stderr -notmatch 'synthetic traceback marker') { throw 'failing stderr was not captured' }
Write-Host 'launch probe regression passed'

$Slow = Invoke-ArenyxaProcessProbe -PythonExecutable $Python -WorkingDirectory $Root -TimeoutSeconds 1 -ProbeScript @'
import time
print("stdout-before-timeout", flush=True)
time.sleep(30)
'@
if (-not $Slow.Started -or $Slow.ExitCode -ne -2) { throw "timeout probe was not classified as -2: $($Slow.ExitCode)" }
if ($Slow.Stdout -notmatch 'stdout-before-timeout') { throw 'timeout stdout was not preserved' }
if ($Slow.Stderr -notmatch 'timed out') { throw 'timeout diagnostic was not preserved' }
Write-Host 'launch probe timeout regression passed'
