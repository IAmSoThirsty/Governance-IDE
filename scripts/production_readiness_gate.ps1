[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [string]$ImageName = $env:SOVEREIGN_IMAGE_REF,
    [string]$DockerExe = "docker",
    [string]$ReleaseManifestPath = $env:SOVEREIGN_RELEASE_MANIFEST,
    [string]$ProductionEvidenceManifestPath = $env:SOVEREIGN_PRODUCTION_EVIDENCE_MANIFEST,
    [switch]$SkipE2E,
    [switch]$SkipContainerSmoke,
    [switch]$AllowLocalEnvFile,
    [switch]$AllowLocalImage,
    [switch]$AllowMissingReleaseManifest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Add-Issue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [string]$Code,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Issues.Add(
        [PSCustomObject]@{
            category = $Category
            code = $Code
            message = $Message
        }
    ) | Out-Null
}

function Add-Warning {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $script:Warnings.Add($Message) | Out-Null
}

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

function Resolve-ManifestPath {
    if (-not [string]::IsNullOrWhiteSpace($ProductionEvidenceManifestPath)) {
        return $ProductionEvidenceManifestPath
    }
    if (-not [string]::IsNullOrWhiteSpace($ReleaseManifestPath)) {
        return $ReleaseManifestPath
    }
    return ""
}

function Resolve-Classification {
    param(
        [object[]]$IssueList = @(),
        [Parameter(Mandatory = $true)]
        [bool]$RehearsalOverride
    )

    if ($null -eq $IssueList -or $IssueList.Count -eq 0) {
        if ($RehearsalOverride) {
            return "rehearsal-only pass"
        }
        return "production-ready pass"
    }

    $categories = @($IssueList | Select-Object -ExpandProperty category -Unique)
    if ($categories -contains "repo-code blocked") {
        return "repo-code blocked"
    }
    if ($categories -contains "environment blocked") {
        return "environment blocked"
    }
    if ($categories -contains "production-evidence blocked") {
        return "production-evidence blocked"
    }
    if ($categories -contains "dependency-security blocked") {
        return "dependency-security blocked"
    }
    return "production-evidence blocked"
}

function Invoke-EvidenceValidation {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WorkspaceRoot,
        [string]$ManifestPath = ""
    )

    $args = @(
        "-m",
        "sovereign_ide.production_evidence",
        "--workspace-root",
        $WorkspaceRoot,
        "--status-only"
    )

    if (-not [string]::IsNullOrWhiteSpace($ManifestPath)) {
        $args += @("--manifest-path", $ManifestPath)
    }
    if ($AllowLocalEnvFile) {
        $args += "--allow-local-env-file"
    }
    if ($AllowLocalImage) {
        $args += "--allow-local-image"
    }
    if ($AllowMissingReleaseManifest) {
        $args += "--allow-missing-manifest"
    }

    $previousPythonPath = [Environment]::GetEnvironmentVariable("PYTHONPATH")
    $srcPythonPath = Join-Path $WorkspaceRoot "src"
    try {
        if ([string]::IsNullOrWhiteSpace($previousPythonPath)) {
            [Environment]::SetEnvironmentVariable("PYTHONPATH", $srcPythonPath)
        } else {
            [Environment]::SetEnvironmentVariable(
                "PYTHONPATH",
                "$srcPythonPath;$previousPythonPath"
            )
        }
        $stdout = & $PythonExe @args
    } finally {
        [Environment]::SetEnvironmentVariable("PYTHONPATH", $previousPythonPath)
    }

    if ($LASTEXITCODE -ne 0) {
        Add-Issue -Category "environment blocked" -Code "evidence_validation_execution_failed" -Message "unable to execute production evidence validator"
        return $null
    }

    $joined = ($stdout -join "`n").Trim()
    if ([string]::IsNullOrWhiteSpace($joined)) {
        Add-Issue -Category "environment blocked" -Code "evidence_validation_no_output" -Message "production evidence validator returned no output"
        return $null
    }

    try {
        return $joined | ConvertFrom-Json
    } catch {
        Add-Issue -Category "environment blocked" -Code "evidence_validation_invalid_json" -Message "production evidence validator returned invalid JSON"
        return $null
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$Issues = New-Object System.Collections.Generic.List[object]
$Warnings = New-Object System.Collections.Generic.List[string]

$rehearsalOverride = $AllowLocalEnvFile -or $AllowLocalImage -or $AllowMissingReleaseManifest
$effectiveManifestPath = Resolve-ManifestPath

if (-not (Test-Path -LiteralPath $PythonExe)) {
    Add-Issue -Category "environment blocked" -Code "python_runtime_missing" -Message "production readiness requires Python runtime for evidence validation"
}

$evidenceValidation = $null
if ($Issues.Count -eq 0) {
    $evidenceValidation = Invoke-EvidenceValidation ([string]$repoRoot) ([string]$effectiveManifestPath)
}

if ($null -ne $evidenceValidation) {
    foreach ($issue in @($evidenceValidation.issues)) {
        Add-Issue -Category ([string]$issue.category) -Code ([string]$issue.code) -Message ([string]$issue.message)
    }
    foreach ($warning in @($evidenceValidation.warnings)) {
        Add-Warning -Message ([string]$warning)
    }
}

$shouldRunRepoGates = $Issues.Count -eq 0

if ($shouldRunRepoGates) {
    try {
        Invoke-Checked -FilePath "powershell" -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "scripts/local_quality_gate.ps1",
            "-PythonExe",
            $PythonExe
        )
    } catch {
        Add-Issue -Category "repo-code blocked" -Code "local_quality_gate_failed" -Message ([string]$_.Exception.Message)
    }
}

if ($shouldRunRepoGates -and $Issues.Count -eq 0) {
    try {
        Invoke-Checked -FilePath "powershell" -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "scripts/preprod_inspection.ps1",
            "-PythonExe",
            $PythonExe
        )
    } catch {
        Add-Issue -Category "repo-code blocked" -Code "preprod_inspection_failed" -Message ([string]$_.Exception.Message)
    }
}

if ($shouldRunRepoGates -and $Issues.Count -eq 0) {
    try {
        Invoke-Checked -FilePath "powershell" -Arguments @(
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            "scripts/advanced_integration_preflight.ps1",
            "-PythonExe",
            $PythonExe
        )
    } catch {
        Add-Issue -Category "repo-code blocked" -Code "advanced_integration_preflight_failed" -Message ([string]$_.Exception.Message)
    }
}

if ($shouldRunRepoGates -and $Issues.Count -eq 0 -and -not $SkipE2E) {
    try {
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
    } catch {
        Add-Issue -Category "repo-code blocked" -Code "e2e_matrix_failed" -Message ([string]$_.Exception.Message)
    }
}

if ($shouldRunRepoGates -and $Issues.Count -eq 0 -and -not $SkipContainerSmoke) {
    if ([string]::IsNullOrWhiteSpace($ImageName)) {
        Add-Issue -Category "environment blocked" -Code "container_smoke_image_missing" -Message "container smoke requires -ImageName or SOVEREIGN_IMAGE_REF"
    } else {
        try {
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
        } catch {
            Add-Issue -Category "repo-code blocked" -Code "container_smoke_failed" -Message ([string]$_.Exception.Message)
        }
    }
}

$classification = Resolve-Classification -IssueList ($Issues.ToArray()) -RehearsalOverride:$rehearsalOverride

$overridesActive = New-Object System.Collections.Generic.List[string]
if ($AllowLocalEnvFile) {
    $overridesActive.Add("-AllowLocalEnvFile") | Out-Null
}
if ($AllowLocalImage) {
    $overridesActive.Add("-AllowLocalImage") | Out-Null
}
if ($AllowMissingReleaseManifest) {
    $overridesActive.Add("-AllowMissingReleaseManifest") | Out-Null
}

$overriddenEvidence = New-Object System.Collections.Generic.List[string]
if ($null -ne $evidenceValidation) {
    foreach ($entry in @($evidenceValidation.overridden_evidence)) {
        $entryText = [string]$entry
        if (-not [string]::IsNullOrWhiteSpace($entryText)) {
            $overriddenEvidence.Add($entryText) | Out-Null
        }
    }
}

$manifestPathSummary = $effectiveManifestPath
$manifestSummaryPayload = @{}
if ($null -ne $evidenceValidation) {
    $manifestPathSummary = [string]$evidenceValidation.manifest_path
    $manifestSummaryPayload = $evidenceValidation.manifest_summary
}

$summary = [PSCustomObject]@{
    generated_at = (Get-Date).ToString("o")
    classification = $classification
    allowed = ($Issues.Count -eq 0)
    production_claim = (-not $rehearsalOverride -and $Issues.Count -eq 0)
    overrides_active = $overridesActive.ToArray()
    overridden_evidence = $overriddenEvidence.ToArray()
    manifest_path = $manifestPathSummary
    manifest_summary = $manifestSummaryPayload
    issues = $Issues.ToArray()
    warnings = $Warnings.ToArray()
}

$summary | ConvertTo-Json -Depth 8

if ($Issues.Count -gt 0) {
    throw "Production readiness gate blocked: $classification"
}

if ($rehearsalOverride) {
    $overridesText = (@($summary.overrides_active) -join ", ")
    $overriddenEvidenceText = (@($summary.overridden_evidence) -join ", ")
    Write-Host "[production] Rehearsal override gate passed (no production-readiness claim)"
    if (-not [string]::IsNullOrWhiteSpace($overridesText)) {
        Write-Host "[production] Active overrides: $overridesText"
    }
    if (-not [string]::IsNullOrWhiteSpace($overriddenEvidenceText)) {
        Write-Host "[production] Overridden evidence: $overriddenEvidenceText"
    }
} else {
    Write-Host "[production] Readiness gate passed"
}
