param(
    [Parameter(Mandatory=$true)][string]$InstallRoot,
    [Parameter(Mandatory=$true)][string]$DataRoot,
    [Parameter(Mandatory=$true)][string]$PlanPath,
    [Parameter(Mandatory=$true)][int]$WaitPid
)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = 'Arenyxa Repair Center · Automatic Repair'
$RepairRoot = Join-Path $DataRoot 'repair'
$ExternalLog = Join-Path $RepairRoot 'external-repair.log'
New-Item -ItemType Directory -Path $RepairRoot -Force | Out-Null
$ForceKnownGood = $false

function Log([string]$Text, [ConsoleColor]$Color = [ConsoleColor]::Gray) {
    $line = ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Text)
    Write-Host $line -ForegroundColor $Color
    Add-Content -LiteralPath $ExternalLog -Value $line -Encoding UTF8
}

function Wait-ForArenyxa([int]$PidToWait) {
    Log 'Waiting for the Arenyxa window process to exit safely...' Cyan
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Process -Id $PidToWait -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) {
        Start-Sleep -Milliseconds 200
    }
    if (Get-Process -Id $PidToWait -ErrorAction SilentlyContinue) {
        throw 'Arenyxa did not exit within 30 seconds. Repair was stopped to avoid replacing files in use.'
    }
}

function Test-SafeRelativePath([string]$Relative) {
    if ([string]::IsNullOrWhiteSpace($Relative)) { return $false }
    if ($Relative -match '^[\\/]' -or $Relative -match '(^|[\\/])\.\.([\\/]|$)' -or $Relative -match ':') { return $false }
    return $true
}

function Select-RecoveryPair {
    $installed = [PSCustomObject]@{ Source='installed'; Manifest=(Join-Path $InstallRoot 'repair\install_manifest.json'); Payload=(Join-Path $InstallRoot 'repair\recovery_payload.zip') }
    $knownGood = [PSCustomObject]@{ Source='known_good'; Manifest=(Join-Path $RepairRoot 'known_good\install_manifest.json'); Payload=(Join-Path $RepairRoot 'known_good\recovery_payload.zip') }
    if ($script:ForceKnownGood) {
        $candidates = @($knownGood)
        Log 'Release attestation is invalid; refusing to trust the installation-side recovery payload.' Yellow
    } else {
        $candidates = @($installed, $knownGood)
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate.Manifest -PathType Leaf)) { continue }
        if (-not (Test-Path -LiteralPath $candidate.Payload -PathType Leaf)) { continue }
        try {
            $manifest = Get-Content -LiteralPath $candidate.Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($candidate.Source -eq 'known_good' -and $script:ForceKnownGood) {
                $attestationPath = Join-Path $RepairRoot 'known_good\release_attestation.json'
                if (-not (Test-Path -LiteralPath $attestationPath -PathType Leaf)) { throw 'Known-good signed attestation is missing.' }
                $attestation = Get-Content -LiteralPath $attestationPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ([string]$attestation.signature_algorithm -ne 'Ed25519') { throw 'Known-good attestation algorithm is invalid.' }
                $manifestHash = (Get-FileHash -LiteralPath $candidate.Manifest -Algorithm SHA256).Hash.ToLowerInvariant()
                $attestedHash = ([string]$attestation.signed.manifest_sha256).ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($attestedHash) -or $manifestHash -ne $attestedHash) { throw 'Known-good manifest does not match its signed attestation.' }
            }
            $expectedHash = [string]$manifest.recovery_payload.sha256
            $expectedSize = [int64]$manifest.recovery_payload.size
            if ([string]::IsNullOrWhiteSpace($expectedHash)) { throw 'Manifest has no recovery payload hash.' }
            if ($expectedSize -ge 0 -and (Get-Item -LiteralPath $candidate.Payload).Length -ne $expectedSize) { throw 'Recovery payload size mismatch.' }
            $actualHash = (Get-FileHash -LiteralPath $candidate.Payload -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $expectedHash.ToLowerInvariant()) { throw 'Recovery payload SHA-256 mismatch.' }
            return [PSCustomObject]@{ Source=$candidate.Source; ManifestPath=$candidate.Manifest; PayloadPath=$candidate.Payload; Manifest=$manifest }
        } catch {
            Log ("Recovery source '{0}' is unusable: {1}" -f $candidate.Source, $_.Exception.Message) Yellow
        }
    }
    throw 'No verified offline recovery source is available.'
}

function Restore-ProgramFiles {
    Log 'Selecting and validating the offline recovery package...' Cyan
    $pair = Select-RecoveryPair
    $manifestPath = [string]$pair.ManifestPath
    $payloadPath = [string]$pair.PayloadPath
    $manifest = $pair.Manifest
    Log ("Using recovery source: {0}" -f $pair.Source) DarkGray

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($payloadPath)
    try {
        foreach ($entry in $zip.Entries) {
            $name = [string]$entry.FullName
            if (-not (Test-SafeRelativePath $name)) { throw "Unsafe path in recovery package: $name" }
        }
    } finally {
        $zip.Dispose()
    }

    $temp = Join-Path $env:TEMP ('ArenyxaRepair-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        [System.IO.Compression.ZipFile]::ExtractToDirectory($payloadPath, $temp)
        Log 'Verifying every extracted program file...' Cyan
        $count = 0
        foreach ($property in $manifest.files.PSObject.Properties) {
            $relative = [string]$property.Name
            if (-not (Test-SafeRelativePath $relative)) { throw "Unsafe manifest path: $relative" }
            $meta = $property.Value
            $source = Join-Path $temp ($relative -replace '/', '\')
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Recovery file missing: $relative" }
            if ($null -ne $meta.size -and (Get-Item -LiteralPath $source).Length -ne [int64]$meta.size) {
                throw "Recovery file size mismatch: $relative"
            }
            $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne ([string]$meta.sha256).ToLowerInvariant()) { throw "Recovery file hash mismatch: $relative" }
            $count++
        }

        Log ("Restoring {0} verified files into the current installation directory..." -f $count) Cyan
        foreach ($property in $manifest.files.PSObject.Properties) {
            $relative = [string]$property.Name
            $source = Join-Path $temp ($relative -replace '/', '\')
            $target = Join-Path $InstallRoot ($relative -replace '/', '\')
            $parent = Split-Path -Parent $target
            if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
            Copy-Item -LiteralPath $source -Destination $target -Force
        }

        Log 'Performing post-copy SHA-256 verification...' Cyan
        foreach ($property in $manifest.files.PSObject.Properties) {
            $relative = [string]$property.Name
            $target = Join-Path $InstallRoot ($relative -replace '/', '\')
            if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Installed file missing after repair: $relative" }
            $hash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($hash -ne ([string]$property.Value.sha256).ToLowerInvariant()) { throw "Installed file hash mismatch after repair: $relative" }
        }
        if ($pair.Source -eq 'known_good') {
            $installRepair = Join-Path $InstallRoot 'repair'
            New-Item -ItemType Directory -Path $installRepair -Force | Out-Null
            Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $installRepair 'install_manifest.json') -Force
            Copy-Item -LiteralPath $payloadPath -Destination (Join-Path $installRepair 'recovery_payload.zip') -Force
            $knownAttestation = Join-Path $RepairRoot 'known_good\release_attestation.json'
            if (Test-Path -LiteralPath $knownAttestation -PathType Leaf) {
                Copy-Item -LiteralPath $knownAttestation -Destination (Join-Path $installRepair 'release_attestation.json') -Force
            }
            Log 'Restored the installation-side recovery manifest, payload, and available signed attestation from the known-good cache.' Green
        }
        Log 'Program-file restoration completed successfully.' Green
    } finally {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    Clear-Host
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host '             Arenyxa Self-Healing Repair Center             ' -ForegroundColor White
    Write-Host '============================================================' -ForegroundColor DarkCyan
    Write-Host 'No commands or manual operations are required.' -ForegroundColor DarkGray
    Write-Host 'Backup -> repair -> verify -> restart -> automatic exit' -ForegroundColor DarkGray
    Write-Host ''

    $plan = Get-Content -LiteralPath $PlanPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($finding in @($plan.detected_findings)) {
        if ([string]$finding.code -eq 'RELEASE_ATTESTATION_INVALID') {
            $script:ForceKnownGood = $true
            break
        }
    }
    Wait-ForArenyxa $WaitPid

    $restoreCategories = @('program_files','dependencies')
    $restoreFindingCodes = @('PROGRAM_FILE_HASH_MISMATCH','PACKAGED_RECOVERY_INVALID','REQUIRED_DEPENDENCIES_MISSING','PYSIDE6_MISSING','RELEASE_ATTESTATION_INVALID')
    $needsProgramRestore = $false
    foreach ($category in @($plan.categories)) {
        if ($restoreCategories -contains [string]$category) { $needsProgramRestore = $true; break }
    }
    if (-not $needsProgramRestore) {
        foreach ($finding in @($plan.detected_findings)) {
            if ($restoreFindingCodes -contains [string]$finding.code) { $needsProgramRestore = $true; break }
        }
    }
    if ($needsProgramRestore) {
        Restore-ProgramFiles
    } else {
        Log 'Program-file restoration is not required for the selected problem type.' DarkGray
    }

    $exe = Join-Path $InstallRoot 'Arenyxa.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Arenyxa.exe is unavailable after the program-file phase: $exe" }

    Log 'Running configuration, database, cache, plugin and runtime repair stages...' Cyan
    & $exe --repair-worker $PlanPath
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -eq 0) {
        Log 'Automatic repair completed. Arenyxa has been restarted.' Green
    } else {
        Log ("Repair completed with unresolved items (exit code {0}). See repair logs for details." -f $code) Yellow
    }
    Log 'This repair terminal will close automatically in 2 seconds.' DarkGray
    Start-Sleep -Seconds 2
    exit $code
} catch {
    Log ("Repair worker stopped: {0}" -f $_.Exception.Message) Red
    Log ("A diagnostic log was saved to: {0}" -f $ExternalLog) Yellow
    Start-Sleep -Seconds 5
    exit 4
}
