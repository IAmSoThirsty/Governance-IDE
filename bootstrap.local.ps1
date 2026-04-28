[CmdletBinding()]
param(
    [string]$PythonExe = "python",
    [switch]$SkipVenv,
    [switch]$InstallProject
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

Write-Host "[bootstrap] Completed successfully."
