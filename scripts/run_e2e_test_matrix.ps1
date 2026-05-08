[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [string]$ReportPath = "integration/out/e2e_test_matrix_report.json",
    [switch]$SkipWorkshopQuickstart,
    [switch]$StopOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$results = New-Object System.Collections.Generic.List[object]
$overallStatus = "pass"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter()]
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        $argsText = ($Arguments -join " ")
        throw "Command failed (exit=$LASTEXITCODE): $FilePath $argsText"
    }
}

function Invoke-PsScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter()]
        [string[]]$Arguments = @()
    )

    Invoke-Checked -FilePath "powershell" -Arguments (
        @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $ScriptPath
        ) + $Arguments
    )
}

function Assert-PythonVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    $version = & $FilePath -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to determine Python version for $FilePath"
    }

    $parts = [string]$version -split "\."
    $major = [int]$parts[0]
    $minor = [int]$parts[1]
    if (($major -lt 3) -or (($major -eq 3) -and ($minor -lt 11))) {
        throw "Python >= 3.11 is required; found $version at $FilePath"
    }
}

function Add-Result {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail,
        [double]$DurationSeconds
    )

    $results.Add([pscustomobject]@{
        name = $Name
        status = $Status
        detail = $Detail
        durationSeconds = [Math]::Round($DurationSeconds, 3)
        timestampUtc = [DateTime]::UtcNow.ToString("o")
    }) | Out-Null
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )

    Write-Host "[e2e] Running category: $Name"
    $start = [DateTime]::UtcNow

    $status = "pass"
    $detail = "completed"
    try {
        & $Action
    }
    catch {
        $status = "fail"
        $detail = $_.Exception.Message
        $script:overallStatus = "fail"
    }

    $duration = ([DateTime]::UtcNow - $start).TotalSeconds
    Add-Result -Name $Name -Status $status -Detail $detail -DurationSeconds $duration

    if ($status -eq "fail" -and $StopOnFailure) {
        throw "Category failed: $Name :: $detail"
    }
}

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}
Assert-PythonVersion -FilePath $PythonExe

$env:PYTHONPATH = "src"

Invoke-Step -Name "compile_sources" -Action {
    Invoke-Checked -FilePath $PythonExe -Arguments @(
        "-m", "compileall", "-q", "src", "tests", "scripts"
    )
}

Invoke-Step -Name "unit_all" -Action {
    Invoke-Checked -FilePath $PythonExe -Arguments @(
        "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"
    )
}

Invoke-Step -Name "unit_security_hardening" -Action {
    Invoke-Checked -FilePath $PythonExe -Arguments @(
        "-m", "unittest", "discover", "-s", "tests", "-p", "test_security_hardening.py"
    )
}

Invoke-Step -Name "unit_workshop_server" -Action {
    Invoke-Checked -FilePath $PythonExe -Arguments @(
        "-m", "unittest", "discover", "-s", "tests", "-p", "test_workshop_server.py"
    )
}

Invoke-Step -Name "local_quality_gate" -Action {
    Invoke-PsScript -ScriptPath "scripts/local_quality_gate.ps1" -Arguments @(
        "-PythonExe", $PythonExe
    )
}

Invoke-Step -Name "preprod_inspection" -Action {
    Invoke-PsScript -ScriptPath "scripts/preprod_inspection.ps1" -Arguments @(
        "-PythonExe", $PythonExe
    )
}

Invoke-Step -Name "advanced_integration_preflight" -Action {
    Invoke-PsScript -ScriptPath "scripts/advanced_integration_preflight.ps1" -Arguments @(
        "-PythonExe", $PythonExe
    )
}

if (-not $SkipWorkshopQuickstart) {
    Invoke-Step -Name "workshop_quickstart" -Action {
        Invoke-PsScript -ScriptPath "scripts/workshop_quickstart.ps1" -Arguments @(
            "-PythonExe", $PythonExe
        )
    }
}

Invoke-Step -Name "report_artifacts" -Action {
    $advancedReport = Join-Path $repoRoot "integration/out/advanced_integration_report.json"
    if (-not (Test-Path -LiteralPath $advancedReport)) {
        throw "Missing advanced integration report: $advancedReport"
    }

    $advancedStatus = (
        Get-Content -LiteralPath $advancedReport -Raw | ConvertFrom-Json
    ).status
    if ($advancedStatus -ne "pass") {
        throw "Advanced integration report status is not pass"
    }

    if (-not $SkipWorkshopQuickstart) {
        $workshopReport = Join-Path $repoRoot "integration/out/workshop_report.json"
        if (-not (Test-Path -LiteralPath $workshopReport)) {
            throw "Missing workshop report: $workshopReport"
        }
    }
}

if (Test-Path -LiteralPath "state") {
    Remove-Item -LiteralPath "state" -Recurse -Force -ErrorAction SilentlyContinue
}

$passedCount = @($results | Where-Object { $_.status -eq "pass" }).Count
$failedCount = @($results | Where-Object { $_.status -eq "fail" }).Count

$report = [pscustomobject]@{
    reportVersion = "1.0.0"
    reportType = "e2e_test_matrix"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    status = $overallStatus
    options = [pscustomobject]@{
        stopOnFailure = [bool]$StopOnFailure
        skipWorkshopQuickstart = [bool]$SkipWorkshopQuickstart
    }
    summary = [pscustomobject]@{
        total = $results.Count
        passed = $passedCount
        failed = $failedCount
    }
    checks = $results
}

$reportFullPath = Join-Path $repoRoot $ReportPath
$reportDir = Split-Path -Parent $reportFullPath
if (-not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $reportFullPath -Encoding UTF8

Write-Host "[e2e] Report written: $reportFullPath"
Write-Host "[e2e] Status: $overallStatus"

if ($overallStatus -ne "pass") {
    throw "E2E test matrix failed"
}
