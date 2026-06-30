$ErrorActionPreference = 'Stop'

# Detect Architecture
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($arch -eq 'X64') {
    $assetName = "wisp-windows-amd64.exe"
} else {
    Write-Error "Unsupported Windows architecture: $arch"
    exit 1
}

$url = "https://github.com/YohannHommet/wisp/releases/latest/download/$assetName"
# User-level path added to PATH by default on Windows 10/11
$installDir = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps"
$dest = Join-Path $installDir "wisp.exe"

Write-Host "Downloading Wisp from $url..."
Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing

Write-Host "Successfully installed Wisp CLI to $dest!"
wisp --version
