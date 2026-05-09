[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [string]$ReportPath = "integration/out/advanced_integration_report.json"
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
        throw "Python >= 3.12 is required; found $version at $FilePath"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$checks = New-Object System.Collections.Generic.List[object]

function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail
    )

    $checks.Add([pscustomobject]@{
        name = $Name
        status = $Status
        detail = $Detail
        timestampUtc = [DateTime]::UtcNow.ToString("o")
    }) | Out-Null
}

try {
    if (-not (Test-Path -LiteralPath $PythonExe)) {
        throw "Python executable not found at $PythonExe"
    }
    Assert-PythonVersion -FilePath $PythonExe
    Add-Check -Name "python_executable" -Status "pass" -Detail $PythonExe

    $requiredPaths = @(
        "policies/baseline_policy.json",
        "policies/workshop_policy.json",
        "governance/enforcement_mappings.yaml",
        "governance/event_taxonomy.yaml",
        "governance/failure_mode_matrix.yaml",
        "deployments/tier0-workstation.yaml",
        "deployments/tier1-enterprise.yaml",
        "deployments/tier3-airgap-enclave.yaml",
        "deployments/tier4-national-federation.yaml",
        "schemas/decision_record.schema.json",
        "schemas/mutation_governance_binding.schema.json",
        "schemas/policy_pack.schema.json",
        "schemas/transfer_manifest.schema.json",
        "schemas/trust_bundle.schema.json",
        "integration/system_integration_contract.yaml",
        "integration/workshop_system_contract.yaml",
        "integration/advanced_integration_runbook.md",
        "workshop/founding/server_charter_v1.json",
        "workshop/founding/authority_chain.yaml",
        "workshop/founding/mutation_classes.yaml",
        "workshop/founding/model_promotion_law.yaml",
        "workshop/services/workshop_cluster_topology.yaml",
        "workshop/benchmarks/constitutional_benchmark_manifest.yaml",
        "workshop/sprints/12_sprint_plan.yaml",
        "scripts/local_quality_gate.ps1",
        "scripts/preprod_inspection.ps1"
    )

    foreach ($path in $requiredPaths) {
        if (-not (Test-Path -LiteralPath $path)) {
            throw "Required integration artifact missing: $path"
        }
    }
    Add-Check -Name "required_artifacts" -Status "pass" -Detail "All required integration artifacts found"

    $dotenvPath = Join-Path $repoRoot ".env"
    if (-not (Test-Path -LiteralPath $dotenvPath)) {
        throw ".env file missing"
    }

    $signingLine = (Get-Content -LiteralPath $dotenvPath | Where-Object {
        $_ -match "^SOVEREIGN_SIGNING_KEY="
    } | Select-Object -First 1)

    if (-not $signingLine) {
        throw "SOVEREIGN_SIGNING_KEY missing in .env"
    }

    $signingKey = $signingLine.Split("=", 2)[1].Trim()
    if (-not $signingKey -or $signingKey -eq "REPLACE_WITH_64_BYTE_HEX_OR_HIGH_ENTROPY_SECRET") {
        throw "SOVEREIGN_SIGNING_KEY is placeholder or empty"
    }
    if ($signingKey.Length -lt 64) {
        throw "SOVEREIGN_SIGNING_KEY is too short"
    }
    Add-Check -Name "signing_key_hygiene" -Status "pass" -Detail "Signing key is non-placeholder and length-compliant"

    $env:PYTHONPATH = "src"

    Invoke-Checked -FilePath "powershell" -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File", "scripts/local_quality_gate.ps1",
        "-PythonExe", $PythonExe
    )
    Add-Check -Name "local_quality_gate" -Status "pass" -Detail "Compile and test gates passed"

    Invoke-Checked -FilePath "powershell" -Arguments @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "scripts/preprod_inspection.ps1",
        "-PythonExe",
        $PythonExe
    )
    Add-Check -Name "preprod_inspection" -Status "pass" -Detail "Preprod inspection passed"

    $overallStatus = "pass"
}
catch {
    Add-Check -Name "preflight_failure" -Status "fail" -Detail $_.Exception.Message
    $overallStatus = "fail"
}

$report = [pscustomobject]@{
    reportVersion = "1.0.0"
    reportType = "advanced_integration_preflight"
    generatedAtUtc = [DateTime]::UtcNow.ToString("o")
    status = $overallStatus
    checks = $checks
}

$reportFullPath = Join-Path $repoRoot $ReportPath
$reportDir = Split-Path -Parent $reportFullPath
if (-not (Test-Path -LiteralPath $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportFullPath -Encoding UTF8

Write-Host "[integration-preflight] Report written: $reportFullPath"
Write-Host "[integration-preflight] Status: $overallStatus"

if ($overallStatus -ne "pass") {
    throw "Advanced integration preflight failed"
}
