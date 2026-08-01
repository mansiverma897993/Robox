$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$apiBinary = Join-Path $projectRoot "target\debug\robox-api.exe"

Push-Location $projectRoot
try {
    cargo build -p robox-api
    $api = Start-Process -FilePath $apiBinary -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    try {
        Push-Location (Join-Path $projectRoot "apps\web")
        & "C:\Program Files\nodejs\npm.cmd" run dev
    } finally {
        Pop-Location
        if (!$api.HasExited) { Stop-Process -Id $api.Id }
    }
} finally { Pop-Location }

