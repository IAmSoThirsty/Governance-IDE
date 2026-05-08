[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [string]$ImageName = $env:SOVEREIGN_IMAGE_REF,
    [string]$DockerExe = "docker",
    [switch]$SkipE2E,
    [switch]$SkipContainerSmoke,
    [switch]$AllowLocalEnvFile,
    [switch]$AllowLocalImage
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

function Assert-RequiredEnv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($value)) {
        throw "Production readiness requires $Name."
    }
    return $value
}

function Assert-ProductionImageRef {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ($AllowLocalImage) {
        return
    }
    if ($Value -match '(^localhost[:/])|(^127\.0\.0\.1[:/])|(:local$)') {
        throw "SOVEREIGN_IMAGE_REF must name a durable registry image for production: $Value"
    }
    if ($Value -notmatch '/' -or $Value -notmatch ':') {
        throw "SOVEREIGN_IMAGE_REF must include registry/namespace and tag: $Value"
    }
}

function Assert-ProductionEnvContract {
    if (-not $AllowLocalEnvFile -and (Test-Path -LiteralPath ".env")) {
        throw "Production readiness must not depend on a developer .env file. Inject secrets through the environment."
    }

    $signingKey = Assert-RequiredEnv -Name "SOVEREIGN_SIGNING_KEY"
    if ($signingKey -match 'REPLACE|PLACEHOLDER|CHANGE_ME|test|dev') {
        throw "SOVEREIGN_SIGNING_KEY looks like a placeholder or test value."
    }

    $serviceToken = Assert-RequiredEnv -Name "SOVEREIGN_SERVICE_TOKEN"
    if ($serviceToken -match 'REPLACE|PLACEHOLDER|CHANGE_ME|smoke|test|dev') {
        throw "SOVEREIGN_SERVICE_TOKEN looks like a placeholder or test value."
    }

    $imageRef = Assert-RequiredEnv -Name "SOVEREIGN_IMAGE_REF"
    Assert-ProductionImageRef -Value $imageRef

    $stateBackend = Assert-RequiredEnv -Name "SOVEREIGN_STATE_BACKEND"
    if ($stateBackend -match '^(local|dev|tmp|temporary)$') {
        throw "SOVEREIGN_STATE_BACKEND must be durable for production."
    }

    $stateUri = Assert-RequiredEnv -Name "SOVEREIGN_STATE_URI"
    if ($stateUri -match '(^state$)|(^\./)|(^\.\\)') {
        throw "SOVEREIGN_STATE_URI must identify deployment-backed durable storage."
    }

    $trainingCommand = Assert-RequiredEnv -Name "SOVEREIGN_TRAINING_COMMAND"
    if ($trainingCommand -match 'simulated|--execution-mode\s+simulated') {
        throw "SOVEREIGN_TRAINING_COMMAND must run actual fine-tuning, not simulation."
    }

    $artifactStore = Assert-RequiredEnv -Name "SOVEREIGN_TRAINING_ARTIFACT_STORE"
    if ($artifactStore -match '^(local|file://|\.\\|\./)') {
        throw "SOVEREIGN_TRAINING_ARTIFACT_STORE must be durable shared storage."
    }

    $approvers = (Assert-RequiredEnv -Name "SOVEREIGN_RELEASE_APPROVERS").Split(",") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ }
    if (@($approvers).Count -lt 2) {
        throw "SOVEREIGN_RELEASE_APPROVERS must name at least two approvers."
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

Assert-ProductionEnvContract

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

if (-not $SkipContainerSmoke) {
    if ([string]::IsNullOrWhiteSpace($ImageName)) {
        throw "Production readiness requires -ImageName or SOVEREIGN_IMAGE_REF for container smoke testing."
    }
    Invoke-Checked -FilePath "powershell" -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts/container_smoke_test.ps1",
        "-ImageName",
        $ImageName,
        "-DockerExe",
        $DockerExe
    )
}

Write-Host "[production] Readiness gate passed"
