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

$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

if (-not (Test-Path -LiteralPath $PythonExe)) {
    throw "Python executable not found at $PythonExe"
}

$env:PYTHONPATH = "src"

Write-Host "[quality] Compiling Python source files"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "compileall", "-q", "src", "tests"
)

Write-Host "[quality] Running unit tests"
Invoke-Checked -FilePath $PythonExe -Arguments @(
    "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"
)

Write-Host "[quality] Gate passed"
