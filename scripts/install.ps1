# Install only a checksum-verified published release, into a user-owned directory.
param([string]$Version = $env:WISP_VERSION, [string]$InstallDir = $env:WISP_INSTALL_DIR)
$ErrorActionPreference = 'Stop'
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'This installer currently supports Windows x64.'
}
$repo = 'https://github.com/YohannHommet/wisp'
if (-not $Version) {
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/YohannHommet/wisp/releases/latest'
    $Version = $release.tag_name
}
if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') { throw 'Version must be a tag such as v0.2.0.' }
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'Wisp\bin' }
$asset = 'wisp-windows-amd64.exe'
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
$staged = $null
try {
    Invoke-WebRequest -Uri "$repo/releases/download/$Version/$asset" -OutFile (Join-Path $temp $asset) -UseBasicParsing
    Invoke-WebRequest -Uri "$repo/releases/download/$Version/SHA256SUMS" -OutFile (Join-Path $temp 'SHA256SUMS') -UseBasicParsing
    $lines = @(Get-Content (Join-Path $temp 'SHA256SUMS') | Where-Object { $_ -match ('^[a-fA-F0-9]{64}\s+' + [regex]::Escape($asset) + '$') })
    if ($lines.Count -ne 1) { throw 'Missing or ambiguous release checksum.' }
    $expected = ($lines[0] -split '\s+')[0]
    $actual = (Get-FileHash (Join-Path $temp $asset) -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw 'Checksum mismatch; nothing installed.' }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $dest = Join-Path $InstallDir 'wisp.exe'
    $staged = Join-Path $InstallDir ('.wisp-install-' + [System.Guid]::NewGuid().ToString())
    Copy-Item (Join-Path $temp $asset) $staged
    if (Test-Path $dest) { [System.IO.File]::Replace($staged, $dest, $null) }
    else { [System.IO.File]::Move($staged, $dest) }
    Write-Host "Installed $Version at $dest"
    Write-Host "Add $InstallDir to your user PATH to run wisp from any directory."
} finally {
    Remove-Item $temp -Recurse -Force
    if ($staged -and (Test-Path $staged)) { Remove-Item $staged -Force }
}
