Set-StrictMode -Version 2.0

function Invoke-ArenyxaProcessProbe {
    param(
        [Parameter(Mandatory = $true)][string]$PythonExecutable,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$ProbeScript,
        [int]$TimeoutSeconds = 30
    )

    if (-not (Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) {
        return [PSCustomObject]@{
            Started = $false
            ExitCode = -1
            Stdout = ''
            Stderr = "Python executable was not found: $PythonExecutable"
            PythonExecutable = $PythonExecutable
            PythonVersion = ''
            WorkingDirectory = $WorkingDirectory
        }
    }

    $ProbeBytes = [System.Text.Encoding]::UTF8.GetBytes($ProbeScript)
    $ProbeBase64 = [Convert]::ToBase64String($ProbeBytes)
    $Command = "import base64;exec(compile(base64.b64decode('$ProbeBase64'),'<arenyxa-environment-probe>','exec'))"

    $StartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $StartInfo.FileName = $PythonExecutable
    $StartInfo.Arguments = '-c "' + $Command.Replace('"', '\"') + '"'
    $StartInfo.WorkingDirectory = $WorkingDirectory
    $StartInfo.UseShellExecute = $false
    $StartInfo.CreateNoWindow = $true
    $StartInfo.RedirectStandardOutput = $true
    $StartInfo.RedirectStandardError = $true

    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $StartInfo
    try {
        $Started = $Process.Start()
        if (-not $Started) {
            return [PSCustomObject]@{
                Started = $false
                ExitCode = -1
                Stdout = ''
                Stderr = 'System.Diagnostics.Process.Start returned false.'
                PythonExecutable = $PythonExecutable
                PythonVersion = ''
                WorkingDirectory = $WorkingDirectory
            }
        }
        # Begin both reads before waiting. Sequential ReadToEnd can deadlock when the child fills
        # the other redirected pipe; asynchronous reads keep stdout/stderr independent even for
        # large Python tracebacks or warning bursts.
        $StdoutTask = $Process.StandardOutput.ReadToEndAsync()
        $StderrTask = $Process.StandardError.ReadToEndAsync()
        $Completed = $Process.WaitForExit([Math]::Max(1, [int]($TimeoutSeconds * 1000)))
        if (-not $Completed) {
            try {
                $Process.Kill()
            } catch {
                [Console]::Error.WriteLine("Arenyxa launch probe timeout cleanup failed: " + $_.Exception.Message)
            }
            $Process.WaitForExit()
            $Stdout = $StdoutTask.GetAwaiter().GetResult()
            $Stderr = $StderrTask.GetAwaiter().GetResult()
            return [PSCustomObject]@{
                Started = $true
                ExitCode = -2
                Stdout = $Stdout
                Stderr = (($Stderr + [Environment]::NewLine + "Arenyxa launch probe timed out after $TimeoutSeconds seconds.").Trim())
                PythonExecutable = $PythonExecutable
                PythonVersion = ''
                WorkingDirectory = $WorkingDirectory
            }
        }
        $Stdout = $StdoutTask.GetAwaiter().GetResult()
        $Stderr = $StderrTask.GetAwaiter().GetResult()
        $ExitCode = [int]$Process.ExitCode
    } catch {
        return [PSCustomObject]@{
            Started = $false
            ExitCode = -1
            Stdout = ''
            Stderr = $_.Exception.ToString()
            PythonExecutable = $PythonExecutable
            PythonVersion = ''
            WorkingDirectory = $WorkingDirectory
        }
    } finally {
        $Process.Dispose()
    }

    $VersionStart = New-Object System.Diagnostics.ProcessStartInfo
    $VersionStart.FileName = $PythonExecutable
    $VersionStart.Arguments = '--version'
    $VersionStart.WorkingDirectory = $WorkingDirectory
    $VersionStart.UseShellExecute = $false
    $VersionStart.CreateNoWindow = $true
    $VersionStart.RedirectStandardOutput = $true
    $VersionStart.RedirectStandardError = $true
    $VersionProcess = New-Object System.Diagnostics.Process
    $VersionProcess.StartInfo = $VersionStart
    $PythonVersion = ''
    try {
        if ($VersionProcess.Start()) {
            $VersionStdoutTask = $VersionProcess.StandardOutput.ReadToEndAsync()
            $VersionStderrTask = $VersionProcess.StandardError.ReadToEndAsync()
            if ($VersionProcess.WaitForExit(10000)) {
                $VersionStdout = $VersionStdoutTask.GetAwaiter().GetResult()
                $VersionStderr = $VersionStderrTask.GetAwaiter().GetResult()
                $PythonVersion = (($VersionStdout + $VersionStderr).Trim())
            } else {
                try {
                    $VersionProcess.Kill()
                } catch {
                    [Console]::Error.WriteLine("Arenyxa Python version probe timeout cleanup failed: " + $_.Exception.Message)
                }
                $VersionProcess.WaitForExit()
                $PythonVersion = 'version probe timed out after 10 seconds'
            }
        }
    } catch {
        $PythonVersion = 'version probe failed: ' + $_.Exception.Message
    } finally {
        $VersionProcess.Dispose()
    }

    return [PSCustomObject]@{
        Started = $true
        ExitCode = $ExitCode
        Stdout = $Stdout
        Stderr = $Stderr
        PythonExecutable = $PythonExecutable
        PythonVersion = $PythonVersion
        WorkingDirectory = $WorkingDirectory
    }
}
