[CmdletBinding()]
param(
    [string]$PythonExe = ".venv\Scripts\python.exe"
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
        throw (
            "Command failed (exit=$LASTEXITCODE): $FilePath $argsText`n" +
            $stdout
        )
    }

    $text = ($output | Out-String).Trim()
    if (-not $text) {
        throw "Expected JSON output but command returned no output."
    }

    try {
        return $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Expected JSON output but parse failed: $text"
    }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}

$dotenvPath = Join-Path $repoRoot ".env"
if (-not (Test-Path -LiteralPath $dotenvPath)) {
    throw ".env not found. Create it from .env.example before inspection."
}

$dotenvLines = Get-Content -LiteralPath $dotenvPath
$signingLine = $dotenvLines | Where-Object {
    $_ -match "^SOVEREIGN_SIGNING_KEY="
} | Select-Object -First 1

if (-not $signingLine) {
    throw "SOVEREIGN_SIGNING_KEY is missing from .env"
}

$signingKey = $signingLine.Split("=", 2)[1].Trim()
if ($signingKey -eq "REPLACE_WITH_64_BYTE_HEX_OR_HIGH_ENTROPY_SECRET") {
    throw "SOVEREIGN_SIGNING_KEY is still placeholder."
}

if ($signingKey.Length -lt 64) {
    throw "SOVEREIGN_SIGNING_KEY must be at least 64 chars."
}

$env:PYTHONPATH = "src"

Write-Host "[preprod] Running local quality gate"
Invoke-Checked -FilePath "powershell" -Arguments @(
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    "scripts/local_quality_gate.ps1",
    "-PythonExe",
    $PythonExe
)

Write-Host "[preprod] Initializing runtime"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "init", "--workspace-root", $repoRoot
)

Write-Host "[preprod] Smoke: allowed soft mutation"
$allowedSoft = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "simulate-mutation",
    "--workspace-root", $repoRoot,
    "--actor", "preprod",
    "--roles", "developer",
    "--tenant", "tenant1",
    "--trust-domain", "td1",
    "--classification", "confidential",
    "--action", "run_tests",
    "--resource", (Join-Path $repoRoot "src\inside.py"),
    "--mutation-class", "softMutation",
    "--scopes", "run_tests"
)
if ((-not $allowedSoft.applied) -or ($allowedSoft.decision.outcome -ne "approved")) {
    throw "Expected allowed soft mutation to be approved."
}

Write-Host "[preprod] Smoke: denied outside-root mutation"
$deniedOutside = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "simulate-mutation",
    "--workspace-root", $repoRoot,
    "--actor", "preprod",
    "--roles", "developer",
    "--tenant", "tenant1",
    "--trust-domain", "td1",
    "--classification", "confidential",
    "--action", "run_tests",
    "--resource", ("$repoRoot-outside\escape.py"),
    "--mutation-class", "softMutation",
    "--scopes", "run_tests"
)
if ($deniedOutside.applied -or ($deniedOutside.decision.outcome -ne "denied")) {
    throw "Expected outside-root mutation to be denied."
}
if ($deniedOutside.decision.reason -notlike "*resource_outside_allowed_roots*") {
    throw "Expected denial reason to include resource_outside_allowed_roots."
}

Write-Host "[preprod] Smoke: denied hard mutation without quorum"
$deniedNoQuorum = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "simulate-mutation",
    "--workspace-root", $repoRoot,
    "--actor", "preprod",
    "--roles", "developer",
    "--tenant", "tenant1",
    "--trust-domain", "td1",
    "--classification", "confidential",
    "--action", "apply_patch",
    "--resource", (Join-Path $repoRoot "src\file.py"),
    "--mutation-class", "hardMutation",
    "--scopes", "apply_patch"
)
if ($deniedNoQuorum.applied -or ($deniedNoQuorum.decision.outcome -ne "denied")) {
    throw "Expected hard mutation without quorum to be denied."
}
if ($deniedNoQuorum.decision.reason -notlike "*quorum_proof_missing*") {
    throw "Expected denial reason to include quorum_proof_missing."
}

Write-Host "[preprod] Smoke: approved hard mutation with quorum"
$approvedWithQuorum = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "simulate-mutation",
    "--workspace-root", $repoRoot,
    "--actor", "preprod",
    "--roles", "developer",
    "--tenant", "tenant1",
    "--trust-domain", "td1",
    "--classification", "confidential",
    "--action", "apply_patch",
    "--resource", (Join-Path $repoRoot "src\file.py"),
    "--mutation-class", "hardMutation",
    "--scopes", "apply_patch",
    "--quorum-proof", "quorum-ok"
)
if ((-not $approvedWithQuorum.applied) -or ($approvedWithQuorum.decision.outcome -ne "approved")) {
    throw "Expected hard mutation with quorum to be approved."
}

$targetDecisionId = [string]$approvedWithQuorum.decision.decision_id
if (-not $targetDecisionId) {
    throw "Expected approved mutation decision_id for compensation check."
}

Write-Host "[preprod] Smoke: authorized compensation"
$compensated = Invoke-CheckedJson -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.cli", "compensate",
    "--workspace-root", $repoRoot,
    "--actor", "ir1",
    "--roles", "incident_responder",
    "--tenant", "tenant1",
    "--trust-domain", "td1",
    "--classification", "confidential",
    "--target-decision-id", $targetDecisionId,
    "--reason", "preprod-inspection"
)
if ($compensated.decision.outcome -ne "compensated") {
    throw "Expected compensation flow outcome to be compensated."
}

Write-Host "[preprod] Cleaning transient state"
Remove-Item -LiteralPath "state" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "[preprod] Inspection completed successfully."
