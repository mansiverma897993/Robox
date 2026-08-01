$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $projectRoot
try {
    cargo fetch
    cargo test --workspace
    Push-Location (Join-Path $projectRoot "apps\web")
    try {
        & "C:\Program Files\nodejs\npm.cmd" ci --ignore-scripts --no-audit --no-fund --cache (Join-Path $projectRoot ".npm-cache")
        & "C:\Program Files\nodejs\npm.cmd" run build
    } finally { Pop-Location }
} finally { Pop-Location }

Write-Host "Robox is ready. Run .\scripts\dev.ps1 and open http://127.0.0.1:3000"

