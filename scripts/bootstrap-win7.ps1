$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptRoot
$VenvRoot = Join-Path $ProjectRoot '.venv-win7'
$VenvPython = Join-Path $VenvRoot 'Scripts\python.exe'


$IsX64Os = ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64') -or ($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64')
if (-not $IsX64Os) {
    throw 'Arenyxa Legacy Enterprise requires Windows 7 SP1 x64 or newer x64 Windows.'
}

$Os = Get-WmiObject -Class Win32_OperatingSystem
$Version = [Version]$Os.Version
if (($Version.Major -lt 6) -or (($Version.Major -eq 6) -and ($Version.Minor -lt 1))) {
    throw 'Arenyxa Legacy Enterprise minimum OS is Windows 7 SP1 x64.'
}
if (($Version.Major -eq 6) -and ($Version.Minor -eq 1) -and ([int]$Os.ServicePackMajorVersion -lt 1)) {
    throw 'Windows 7 Service Pack 1 is required.'
}






if (($Version.Major -eq 6) -and ($Version.Minor -eq 1)) {
    if (-not ('ArenyxaWin7LoaderProbe' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class ArenyxaWin7LoaderProbe {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandle(string moduleName);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr module, string procName);
}
'@
    }
    $Kernel32 = [ArenyxaWin7LoaderProbe]::GetModuleHandle('kernel32.dll')
    $LoaderApi = [ArenyxaWin7LoaderProbe]::GetProcAddress($Kernel32, 'SetDefaultDllDirectories')
    if (($Kernel32 -eq [IntPtr]::Zero) -or ($LoaderApi -eq [IntPtr]::Zero)) {
        throw 'Windows 7 is missing the loader update required by CPython 3.8 (KB2533623 capability: SetDefaultDllDirectories).'
    }
}



try { [Net.ServicePointManager]::SecurityProtocol = 3072 } catch {}

$Candidates = @(
    @{ Executable = 'py'; Args = @('-3.8') },
    @{ Executable = 'python'; Args = @() }
)
function Test-Python38X64 {
    param([string]$Executable, [string[]]$PrefixArgs)
    try {
        $ProbeArgs = @($PrefixArgs) + @('-c', 'import sys; raise SystemExit(0 if sys.version_info[:2] == (3,8) and sys.maxsize > 2**32 else 2)')
        & $Executable @ProbeArgs > $null 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}
$Python = $null
foreach ($Candidate in $Candidates) {
    if (Test-Python38X64 $Candidate.Executable $Candidate.Args) { $Python = $Candidate; break }
}
if (-not $Python) { throw '64-bit CPython 3.8.x was not found. Install Python 3.8 x64 for the Win7 legacy source/build lane.' }

if (Test-Path -LiteralPath $VenvRoot) {
    if (-not (Test-Path -LiteralPath $VenvPython) -or -not (Test-Python38X64 $VenvPython @())) {
        $Backup = $VenvRoot + '.incompatible.' + (Get-Date -Format 'yyyyMMddHHmmss')
        Move-Item -LiteralPath $VenvRoot -Destination $Backup
    }
}
if (-not (Test-Path -LiteralPath $VenvPython)) {
    $CreateArgs = @($Python.Args) + @('-m', 'venv', $VenvRoot)
    & $Python.Executable @CreateArgs
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

& $VenvPython -m pip install --upgrade 'pip==24.3.1' 'setuptools==75.3.2' 'wheel==0.45.1'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $VenvPython -m pip install -r (Join-Path $ProjectRoot 'requirements-dev-win7.txt')
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$SrcRoot = Join-Path $ProjectRoot 'legacy\win7\src'
$PthCode = "import site,pathlib; pathlib.Path(site.getsitepackages()[0], 'arenyxa_legacy_source.pth').write_text(r'''$SrcRoot''' + '\\n', encoding='utf-8')"
& $VenvPython -c $PthCode
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Arenyxa Win7 Legacy environment ready: $VenvPython"
