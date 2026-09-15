# RECOGNITION_UNINSTALL_V1 — remove a per-user Recognition install.
#
#   pwsh -File installer\RECOGNITION_UNINSTALL_V1.ps1
#     [-InstallDir <path>]   # defaults to %LOCALAPPDATA%\Recognition
#     [-KeepData]            # keep runtime\ (profile, history, bookmarks) and packets\
#
# Token on success: RECOGNITION_UNINSTALL_V1_OK

param(
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Recognition"),
  [switch]$KeepData
)

$ErrorActionPreference = "Stop"

Write-Host ("Uninstalling Recognition from: " + $InstallDir) -ForegroundColor Cyan

# stop running instance
Get-Process -Name "RecognitionBrowser" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

# shortcuts
foreach($lnk in @(
  (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Recognition.lnk"),
  (Join-Path ([Environment]::GetFolderPath('Desktop')) "Recognition.lnk")
)){ if(Test-Path -LiteralPath $lnk){ Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue } }

# registry uninstall entry
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Recognition"
if(Test-Path -LiteralPath $key){ Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue }

# files
if(Test-Path -LiteralPath $InstallDir){
  if($KeepData){
    Get-ChildItem -LiteralPath $InstallDir -Force | ForEach-Object {
      if(@("runtime","packets","payload") -contains $_.Name){ return }
      Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  kept user data (runtime\, packets\, payload\)"
  } else {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host "RECOGNITION_UNINSTALL_V1_OK" -ForegroundColor Green
