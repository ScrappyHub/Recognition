# RECOGNITION_INSTALL_V1 — per-user installer for the Recognition governed browser.
#
# Run this from inside an extracted distribution (the folder that contains
# browser\RecognitionBrowser.exe + scripts\ + policies\ + proofs\trust\), produced by
# scripts\RUN_PACKAGE_DIST_V1.ps1 (dist\Recognition-win-x64.zip).
#
#   pwsh -File installer\RECOGNITION_INSTALL_V1.ps1
#     [-Source <dist folder>]   # defaults to the parent of this script
#     [-InstallDir <path>]      # defaults to %LOCALAPPDATA%\Recognition
#     [-NoShortcuts]            # skip Start Menu / Desktop shortcuts
#
# Installs per-user (no admin required). Token on success: RECOGNITION_INSTALL_V1_OK

param(
  [string]$Source,
  [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Recognition"),
  [switch]$NoShortcuts
)

$ErrorActionPreference = "Stop"
function Die([string]$m){ Write-Host ("INSTALL_FAIL: " + $m) -ForegroundColor Red; exit 1 }

# --- locate the source distribution -----------------------------------------
if(-not $Source){
  $here = Split-Path -Parent $MyInvocation.MyCommand.Path
  $Source = Split-Path -Parent $here          # installer\ -> dist root
}
$Source = (Resolve-Path -LiteralPath $Source).Path
$exeSrc = Join-Path $Source "browser\RecognitionBrowser.exe"
if(-not (Test-Path -LiteralPath $exeSrc)){
  Die ("could not find browser\RecognitionBrowser.exe under: " + $Source + " — run this from an extracted distribution.")
}

Write-Host ("Installing Recognition") -ForegroundColor Cyan
Write-Host ("  from: " + $Source)
Write-Host ("  to  : " + $InstallDir)

# --- stop any running instance ----------------------------------------------
Get-Process -Name "RecognitionBrowser" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 400

# --- copy files (preserve user data if reinstalling) ------------------------
if(-not (Test-Path -LiteralPath $InstallDir)){ New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null }
# copy everything except volatile per-user state (kept across reinstalls)
$exclude = @("runtime","packets","payload","dist",".git")
Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
  if($exclude -contains $_.Name){ return }
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $InstallDir $_.Name) -Recurse -Force
}

$exe = Join-Path $InstallDir "browser\RecognitionBrowser.exe"
if(-not (Test-Path -LiteralPath $exe)){ Die "copy failed: exe not present after install" }

# --- shortcuts (Start Menu + Desktop), icon from the exe --------------------
if(-not $NoShortcuts){
  $ws = New-Object -ComObject WScript.Shell
  $startDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
  foreach($lnkPath in @((Join-Path $startDir "Recognition.lnk"), (Join-Path ([Environment]::GetFolderPath('Desktop')) "Recognition.lnk"))){
    $lnk = $ws.CreateShortcut($lnkPath)
    $lnk.TargetPath       = $exe
    $lnk.WorkingDirectory = (Join-Path $InstallDir "browser")
    $lnk.IconLocation     = $exe + ",0"
    $lnk.Description       = "Recognition — governed, private browser"
    $lnk.Save()
  }
  Write-Host "  shortcuts: Start Menu + Desktop created"
}

# --- register in Apps & features (per-user uninstall entry) ------------------
$uninst = Join-Path $InstallDir "installer\RECOGNITION_UNINSTALL_V1.ps1"
$icon   = $exe + ",0"
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Recognition"
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name "DisplayName"     -Value "Recognition"          -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name "DisplayVersion"  -Value "1.3.1"                 -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name "Publisher"       -Value "ScrappyHub"            -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name "DisplayIcon"     -Value $icon                   -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name "InstallLocation" -Value $InstallDir             -PropertyType String -Force | Out-Null
New-ItemProperty -Path $key -Name "NoModify"        -Value 1                       -PropertyType DWord  -Force | Out-Null
New-ItemProperty -Path $key -Name "NoRepair"        -Value 1                       -PropertyType DWord  -Force | Out-Null
if(Test-Path -LiteralPath $uninst){
  $ps = if(Get-Command pwsh -ErrorAction SilentlyContinue){ "pwsh" } else { "powershell" }
  New-ItemProperty -Path $key -Name "UninstallString" -Value ("`"" + $ps + "`" -NoProfile -ExecutionPolicy Bypass -File `"" + $uninst + "`"") -PropertyType String -Force | Out-Null
}

# --- default-browser capability ----------------------------------------------
# Lists Recognition under Settings > Default apps (http, https, .htm, .html, .xhtml). Windows does not let a program make itself the
# default: the person chooses it there (Settings > Recognition > Open Windows Default apps). Per-user keys only.
function Reg-Default([string]$path,[string]$value){ New-Item -Path $path -Force | Out-Null; Set-ItemProperty -Path $path -Name "(Default)" -Value $value }
function Reg-Value([string]$path,[string]$name,[string]$value){ New-Item -Path $path -Force | Out-Null; New-ItemProperty -Path $path -Name $name -Value $value -PropertyType String -Force | Out-Null }
$openCmd = '"' + $exe + '" "%1"'
foreach($pid_ in @(@("RecognitionURL","Recognition URL"),@("RecognitionHTML","Recognition HTML Document"))){
  $c = "HKCU:\Software\Classes\" + $pid_[0]
  Reg-Default $c $pid_[1]
  if($pid_[0] -eq "RecognitionURL"){ Reg-Value $c "URL Protocol" "" }
  Reg-Default ($c + "\DefaultIcon") ($exe + ",0")
  Reg-Default ($c + "\shell\open\command") $openCmd
}
$ci = "HKCU:\Software\Clients\StartMenuInternet\Recognition"
Reg-Default $ci "Recognition"
Reg-Default ($ci + "\DefaultIcon") ($exe + ",0")
Reg-Default ($ci + "\shell\open\command") ('"' + $exe + '"')
Reg-Value ($ci + "\Capabilities") "ApplicationName" "Recognition"
Reg-Value ($ci + "\Capabilities") "ApplicationDescription" "Governed, private browser"
Reg-Value ($ci + "\Capabilities") "ApplicationIcon" ($exe + ",0")
Reg-Value ($ci + "\Capabilities\URLAssociations") "http" "RecognitionURL"
Reg-Value ($ci + "\Capabilities\URLAssociations") "https" "RecognitionURL"
foreach($ext in @(".htm",".html",".xhtml")){ Reg-Value ($ci + "\Capabilities\FileAssociations") $ext "RecognitionHTML" }
Reg-Value "HKCU:\Software\RegisteredApplications" "Recognition" "Software\Clients\StartMenuInternet\Recognition\Capabilities"
Write-Host "  default-browser: Recognition is now listed in Windows Default apps (you choose it there)"

# --- dependency hints (non-fatal) -------------------------------------------
if(-not (Get-Command pwsh -ErrorAction SilentlyContinue)){
  Write-Host "  NOTE: PowerShell 7 (pwsh) not found — locked-startup verification and packet export need it. Install from https://aka.ms/powershell" -ForegroundColor Yellow
}

Write-Host ""
Write-Host ("Installed to: " + $InstallDir) -ForegroundColor Green
Write-Host ("Launch from the Start Menu / Desktop shortcut, or run: " + $exe)
Write-Host "RECOGNITION_INSTALL_V1_OK" -ForegroundColor Green
