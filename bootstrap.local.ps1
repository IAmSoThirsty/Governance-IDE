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

$repoRoot = Split-Path -Parent $PSCommandPath
Set-Location $repoRoot

Write-Host "[bootstrap] Repository root: $repoRoot"
Assert-PythonVersion -FilePath $PythonExe

if (-not $SkipVenv) {
    Write-Host "[bootstrap] Creating/updating local virtual environment (.venv)"
    Invoke-CheckedExternal -FilePath $PythonExe -Arguments @("-m", "venv", ".venv")

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $venvPython)) {
        throw "Expected venv interpreter at $venvPython but it was not found."
    }
    Assert-PythonVersion -FilePath $venvPython

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
