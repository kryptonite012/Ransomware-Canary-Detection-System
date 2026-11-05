# PROJECT SENTINEL - Windows installer (PowerShell, run as Administrator).
#requires -RunAsAdministrator
param(
  [string]$InstallDir = "C:\Program Files\Sentinel",
  [string]$DataDir    = "C:\ProgramData\Sentinel"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "[*] creating directories"
New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir, "$DataDir\secrets" | Out-Null

Write-Host "[*] copying application"
Copy-Item "$repo\agent","$repo\backend" -Destination $InstallDir -Recurse -Force
if (Test-Path "$repo\frontend\dist") {
  New-Item -ItemType Directory -Force -Path "$InstallDir\frontend" | Out-Null
  Copy-Item "$repo\frontend\dist" -Destination "$InstallDir\frontend" -Recurse -Force
}

Write-Host "[*] creating virtualenv and installing dependencies"
python -m venv "$InstallDir\venv"
& "$InstallDir\venv\Scripts\pip.exe" install --quiet --upgrade pip
& "$InstallDir\venv\Scripts\pip.exe" install --quiet -r "$repo\requirements.txt" pywin32

if (-not (Test-Path "$DataDir\sentinel.yaml")) {
  Write-Host "[*] installing default configuration"
  (Get-Content "$repo\config\sentinel.yaml") `
    -replace './data', ($DataDir -replace '\\','/') | Set-Content "$DataDir\sentinel.yaml"
}

[Environment]::SetEnvironmentVariable("SENTINEL_CONFIG", "$DataDir\sentinel.yaml", "Machine")
$env:SENTINEL_CONFIG = "$DataDir\sentinel.yaml"

Write-Host "[*] initializing database and control-plane keys"
& "$InstallDir\venv\Scripts\python.exe" -m agent init
& "$InstallDir\venv\Scripts\python.exe" -m backend init-keys

Write-Host "[*] installing and starting the Windows service"
& "$InstallDir\venv\Scripts\python.exe" -m agent.service.windows_service --startup auto install
& "$InstallDir\venv\Scripts\python.exe" -m agent.service.windows_service start

Write-Host "[+] installed. Create an admin user with:"
Write-Host "    & '$InstallDir\venv\Scripts\python.exe' -m backend create-user admin admin@example.com --role admin"
