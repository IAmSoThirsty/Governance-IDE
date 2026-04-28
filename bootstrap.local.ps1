[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [switch]$SkipVenv,
    [switch]$InstallProject,
    [switch]$SkipCodacyInstall,
    [switch]$ForceCodacyConfigWrite,
    [switch]$RunAnalyze,
    [string]$AnalyzePath = "src"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedExternal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter()]
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        $argsText = ($Arguments -join " ")
        throw "External command failed (exit=$LASTEXITCODE): $FilePath $argsText"
    }
}

$repoRoot = Split-Path -Parent $PSCommandPath
Set-Location $repoRoot

Write-Host "[bootstrap] Repository root: $repoRoot"

$codacyDir = Join-Path $repoRoot ".codacy"
if (-not (Test-Path -LiteralPath $codacyDir)) {
    New-Item -ItemType Directory -Path $codacyDir | Out-Null
}

$logsDir = Join-Path $codacyDir "logs"
if (-not (Test-Path -LiteralPath $logsDir)) {
    New-Item -ItemType Directory -Path $logsDir | Out-Null
}

$codacyYamlPath = Join-Path $codacyDir "codacy.yaml"
$codacyYaml = @"
runtimes:
  - python@3.11.11
tools:
  - pylint@3.3.6
  - opengrep@1.16.4
  - trivy@0.69.3
"@

if ((-not (Test-Path -LiteralPath $codacyYamlPath)) -or $ForceCodacyConfigWrite) {
        Set-Content -LiteralPath $codacyYamlPath -Value $codacyYaml -Encoding utf8
        Write-Host "[bootstrap] Wrote $codacyYamlPath"
}
else {
        Write-Host "[bootstrap] Preserving existing $codacyYamlPath"
}

if (-not $SkipVenv) {
    Write-Host "[bootstrap] Creating/updating local virtual environment (.venv)"
    Invoke-CheckedExternal -FilePath $PythonExe -Arguments @("-m", "venv", ".venv")

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Expected venv interpreter at $venvPython but it was not found."
    }

    Invoke-CheckedExternal -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel")

    if ($InstallProject) {
        Write-Host "[bootstrap] Installing project package in editable mode"
        Invoke-CheckedExternal -FilePath $venvPython -Arguments @("-m", "pip", "install", "--no-build-isolation", "-e", ".")
    }
    else {
        Write-Host "[bootstrap] Skipping project package install. Use -InstallProject to enable."
    }
}

$codacyCliPath = Join-Path $codacyDir "cli.sh"
if (-not $SkipCodacyInstall) {
    if (-not (Test-Path -LiteralPath $codacyCliPath)) {
        Write-Warning "[bootstrap] Codacy launcher not found at $codacyCliPath. Skipping Codacy bootstrap."
    }
    else {
        $bashCommand = Get-Command bash -ErrorAction SilentlyContinue
        if ($null -eq $bashCommand) {
            Write-Warning "[bootstrap] bash not found. Install Git Bash/WSL to run .codacy/cli.sh locally."
        }
        else {
            $bashPath = $bashCommand.Source
            Write-Host "[bootstrap] Downloading Codacy CLI binary"
            Invoke-CheckedExternal -FilePath $bashPath -Arguments @($codacyCliPath, "download")

            Write-Host "[bootstrap] Initializing Codacy CLI"
            Invoke-CheckedExternal -FilePath $bashPath -Arguments @($codacyCliPath, "init")

            if ($RunAnalyze) {
                Write-Host "[bootstrap] Running Codacy analyze on $AnalyzePath"
                Invoke-CheckedExternal -FilePath $bashPath -Arguments @($codacyCliPath, "analyze", $AnalyzePath, "--format", "sarif")
            }
        }
    }
}

Write-Host "[bootstrap] Completed successfully."
