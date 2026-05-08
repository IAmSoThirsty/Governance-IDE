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

$env:PYTHONPATH = "src"

Write-Host "[quality] Validating repository artifacts"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "sovereign_ide.validate_artifacts", "--workspace-root", $repoRoot
)

Write-Host "[quality] Compiling Python source files"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "compileall", "-q", "src", "tests", "scripts"
)

Write-Host "[quality] Running unit tests"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"
)

Write-Host "[quality] Gate passed"
