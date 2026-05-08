[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe",
    [string]$PolicyPath = "policies/workshop_policy.json",
    [string]$DocsGlob = "docs/*.txt",
    [int]$MaxTrainingAttempts = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter()]
        [string[]]$Arguments = @()
    )

    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $argsText = ($Arguments -join " ")
        $stdout = ($output | Out-String)
        throw "Command failed (exit=$LASTEXITCODE): $FilePath $argsText`n$stdout"
    }

    $text = ($output | Out-String).Trim()
    if (-not $text) {
        throw "Expected JSON output but command returned no output."
    }

    try {
        return $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to parse JSON output: $text"
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
        throw "Python >= 3.11 is required; found $version at $FilePath"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}
Assert-PythonVersion -FilePath $PythonExe

$docPaths = Get-ChildItem -Path $DocsGlob -File -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty FullName
if (-not $docPaths -or $docPaths.Count -eq 0) {
    throw "No corpus documents found for pattern: $DocsGlob"
}

$artifactPaths = ($docPaths -join ",")

$common = @(
    "--workspace-root", $repoRoot,
    "--policy-path", $PolicyPath,
    "--actor", "workshop-operator",
    "--roles", "trust_administrator,release_authority,model_steward,data_steward,reviewer,security_reviewer",
    "--tenant", "tenant1",
    "--trust-domain", "domain1",
    "--classification", "confidential"
)

Write-Host "[workshop] Bootstrapping charter and genesis"
$bootstrapArgs = @(
    "-m", "sovereign_ide.cli", "workshop-init"
) + $common + @(
    "--quorum-proof", "founding-quorum"
)
$null = Invoke-CheckedJson -FilePath $PythonExe -Arguments $bootstrapArgs

Write-Host "[workshop] Admitting corpus artifacts"
$ingestArgs = @(
    "-m", "sovereign_ide.cli", "workshop-ingest"
) + $common + @(
    "--artifact-paths", $artifactPaths,
    "--artifact-type", "constitutional_doc",
    "--source-class", "curated",
    "--trust-class", "reviewed"
)
$null = Invoke-CheckedJson -FilePath $PythonExe -Arguments $ingestArgs

Write-Host "[workshop] Building constitutional datasets"
$buildArgs = @(
    "-m", "sovereign_ide.cli", "workshop-build-datasets"
) + $common
$build = Invoke-CheckedJson -FilePath $PythonExe -Arguments $buildArgs

$datasetIds = @($build.payload.dataset_ids)
if ($datasetIds.Count -eq 0) {
    throw "Dataset build returned no dataset ids."
}
$datasetCsv = ($datasetIds -join ",")

$checkpointId = $null
$evaluationId = $null
for ($attempt = 1; $attempt -le $MaxTrainingAttempts; $attempt++) {
    Write-Host "[workshop] Training attempt $attempt"
    $trainArgs = @(
        "-m", "sovereign_ide.cli", "workshop-train"
    ) + $common + @(
        "--quorum-proof", "train-quorum",
        "--model-family", "project-ai-constitutional-$attempt",
        "--dataset-ids", $datasetCsv,
        "--execution-mode", "simulated"
    )
    $train = Invoke-CheckedJson -FilePath $PythonExe -Arguments $trainArgs

    $checkpointId = [string]$train.payload.checkpoint.checkpoint_id

    Write-Host "[workshop] Shadow evaluation for checkpoint $checkpointId"
    $evalArgs = @(
        "-m", "sovereign_ide.cli", "workshop-eval"
    ) + $common + @(
        "--checkpoint-id", $checkpointId
    )
    $eval = Invoke-CheckedJson -FilePath $PythonExe -Arguments $evalArgs

    if ($eval.payload.verdict.passed) {
        $evaluationId = [string]$eval.payload.verdict.evaluation_id
        break
    }
}

if (-not $evaluationId) {
    throw "Unable to produce promotable checkpoint within max attempts."
}

Write-Host "[workshop] Promoting checkpoint $checkpointId"
$promoteArgs = @(
    "-m", "sovereign_ide.cli", "workshop-promote"
) + $common + @(
    "--quorum-proof", "promotion-quorum",
    "--checkpoint-id", $checkpointId,
    "--evaluation-id", $evaluationId,
    "--approvals", "approverA,approverB",
    "--charter-version", "1.0.0"
)
$promote = Invoke-CheckedJson -FilePath $PythonExe -Arguments $promoteArgs

Write-Host "[workshop] Exporting workshop report"
$report = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "workshop-report",
    "--workspace-root", $repoRoot,
    "--policy-path", $PolicyPath,
    "--output-path", "integration/out/workshop_report.json"
)

Write-Host "[workshop] Completed"
Write-Host "  checkpointId: $checkpointId"
Write-Host "  evaluationId: $evaluationId"
Write-Host "  promotionId: $($promote.payload.promotion_bundle.promotion_id)"
Write-Host "  reportPath: integration/out/workshop_report.json"
