$ErrorActionPreference = "Stop"

$Repo = "TeamCadenceAI/cadence-cli"
$InstallDir = Join-Path $env:LOCALAPPDATA "Programs\cadence"

$arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture
switch ($arch) {
  "Arm64" { $target = "aarch64-pc-windows-msvc" }
  Default { $target = "x86_64-pc-windows-msvc" }
}

Write-Host "Detected Windows $arch ($target)"

Write-Host "Fetching latest release..."
$releaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
$release = Invoke-RestMethod -Uri $releaseUrl
$tag = $release.tag_name
if (-not $tag) {
  throw "Could not determine latest release tag."
}
Write-Host "Latest release: $tag"

$asset = "cadence-cli-$target.zip"
$downloadUrl = "https://github.com/$Repo/releases/download/$tag/$asset"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipPath = Join-Path $tmp $asset

Write-Host "Downloading $asset..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

Write-Host "Extracting..."
$extractDir = Join-Path $tmp "cadence-cli"
if (Test-Path $extractDir) {
  Remove-Item -Recurse -Force $extractDir
}
Expand-Archive -Path $zipPath -DestinationPath $extractDir

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$exeSource = Join-Path $extractDir "cadence.exe"
$exeDest = Join-Path $InstallDir "cadence.exe"
Copy-Item -Force $exeSource $exeDest

$path = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $path) { $path = "" }
if ($path -notlike "*${InstallDir}*") {
  $newPath = if ($path) { "$path;$InstallDir" } else { "$InstallDir" }
  [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  Write-Host "Added $InstallDir to your user PATH."
  Write-Host "Restart your terminal to pick up PATH changes."
}

Write-Host "Running initial setup..."
try {
  & $exeDest install
} catch {
  Write-Warning "'cadence install' failed. You can run it manually later."
}

Write-Host ""
Write-Host "cadence installed successfully!"
