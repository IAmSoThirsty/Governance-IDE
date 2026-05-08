[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [switch]$SkipE2E
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not $env:SOVEREIGN_SIGNING_KEY -and -not (Test-Path -LiteralPath ".env")) {
    throw "Production readiness requires SOVEREIGN_SIGNING_KEY via environment or .env."
}

if (-not $env:SOVEREIGN_SERVICE_TOKEN) {
    throw "Production readiness requires SOVEREIGN_SERVICE_TOKEN for service API protection."
}

Invoke-Checked -FilePath "powershell" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "scripts/local_quality_gate.ps1",
    "-PythonExe",
    $PythonExe
)

Invoke-Checked -FilePath "powershell" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "scripts/preprod_inspection.ps1",
    "-PythonExe",
    $PythonExe
)

Invoke-Checked -FilePath "powershell" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "scripts/advanced_integration_preflight.ps1",
    "-PythonExe",
    $PythonExe
)

if (-not $SkipE2E) {
    Invoke-Checked -FilePath "powershell" -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts/run_e2e_test_matrix.ps1",
        "-PythonExe",
        $PythonExe,
        "-StopOnFailure"
    )
}

Write-Host "[production] Readiness gate passed"
