$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$npm = (Get-Command npm.cmd -ErrorAction Stop).Source
$env:npm_config_cache = Join-Path $projectRoot ".npm-cache"

Push-Location $projectRoot
try {
    cargo fetch
    cargo test --workspace
    Push-Location (Join-Path $projectRoot "apps\web")
    try {
        & $npm ci --ignore-scripts --no-audit --no-fund --cache (Join-Path $projectRoot ".npm-cache")
        & $npm run lint
        & $npm run build
    } finally { Pop-Location }
} finally { Pop-Location }

Write-Host "Robox is ready. Run .\scripts\dev.ps1 and open http://127.0.0.1:3000"
