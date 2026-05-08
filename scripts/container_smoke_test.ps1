[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ImageName,
    [string]$ContainerName = "sovereign-ide-runtime-smoke",
    [int]$HostPort = 8765,
    [string]$SigningKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    [string]$ServiceToken = "smoke-token",
    [string]$DockerExe = "docker"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Docker {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $DockerExe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed: $DockerExe $($Arguments -join ' ')"
    }
}

function Wait-ForEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [hashtable]$Headers = @{}
    )

    $deadline = (Get-Date).AddSeconds(30)
    $lastError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            return Invoke-RestMethod -Uri $Uri -Headers $Headers -TimeoutSec 5
        }
        catch {
            $lastError = $_
            Start-Sleep -Milliseconds 750
        }
    }
    throw "Timed out waiting for $Uri. Last error: $lastError"
}

function Remove-SmokeContainer {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        & $DockerExe "rm" "-f" $ContainerName 2>$null | Out-Null
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
}

Remove-SmokeContainer

try {
    Invoke-Docker -Arguments @(
        "run",
        "-d",
        "--name",
        $ContainerName,
        "-p",
        "$($HostPort):8765",
        "-e",
        "SOVEREIGN_SIGNING_KEY=$SigningKey",
        "-e",
        "SOVEREIGN_SERVICE_TOKEN=$ServiceToken",
        $ImageName
    ) | Out-Null

    $health = Wait-ForEndpoint -Uri "http://127.0.0.1:$HostPort/health"
    $ready = Wait-ForEndpoint `
        -Uri "http://127.0.0.1:$HostPort/ready" `
        -Headers @{ Authorization = "Bearer $ServiceToken" }

    $uid = (& $DockerExe "exec" $ContainerName "id" "-u").Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect container user"
    }
    if ($uid -eq "0") {
        throw "Container is running as root"
    }

    & $DockerExe "exec" $ContainerName "python" "-c" "from pathlib import Path; Path('/app/state/container-smoke-write').write_text('ok', encoding='utf-8')"
    if ($LASTEXITCODE -ne 0) {
        throw "Container could not write to /app/state"
    }

    [pscustomobject]@{
        image = $ImageName
        health = $health.status
        readiness = $ready.status
        user_id = $uid
        state_write = "ok"
    } | ConvertTo-Json -Depth 4
}
finally {
    Remove-SmokeContainer
}
