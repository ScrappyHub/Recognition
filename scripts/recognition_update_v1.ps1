# Recognition — Governed Updater CLI v1 (§54)
#
#   build  : package + sign a payload (private key must live OUTSIDE the repo)
#     pwsh scripts\recognition_update_v1.ps1 -RepoRoot . -Action build -PayloadDir <dir> -OutDir <new dir> -Version 1.1.0 [-KeyPath <key>] [-Channel stable]
#   verify : check a package against the pinned trust root without changing anything
#     pwsh scripts\recognition_update_v1.ps1 -RepoRoot . -Action verify -PackageDir <dir> [-InstallRoot <dir>]
#   apply  : verify, then install atomically (backup + post-verify + auto-rollback)
#     pwsh scripts\recognition_update_v1.ps1 -RepoRoot . -Action apply -PackageDir <dir> [-InstallRoot <dir>]
#
# Tokens: RECOGNITION_UPDATE_V1_BUILD_OK / _VERIFY_OK / _APPLY_OK  (refusal: RECOGNITION_UPDATE_V1_REFUSED, exit 1)

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("build","verify","apply")][string]$Action,
  [string]$PayloadDir = "", [string]$OutDir = "", [string]$Version = "", [string]$Channel = "stable",
  [string]$KeyPath = (Join-Path $HOME ".recognition/keys/recognition_runtime_bridge_attest_ed25519"),
  [string]$PackageDir = "", [string]$InstallRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($InstallRoot)){ $InstallRoot = $RepoRoot }
$InstallRoot = (Resolve-Path -LiteralPath $InstallRoot).Path
. (Join-Path $PSScriptRoot "_lib_recognition_update_v1.ps1")
$trust = Join-Path (Join-Path (Join-Path $InstallRoot "proofs") "trust") "allowed_signers"

switch($Action){
  "build" {
    if(-not $PayloadDir -or -not $OutDir -or -not $Version){ Write-Host "build needs -PayloadDir -OutDir -Version" -ForegroundColor Red; exit 2 }
    $r = RU-Build $PayloadDir $OutDir $Version $KeyPath $Channel $RepoRoot
    Write-Host ("Built update " + $r.version + " (" + $r.file_count + " files, payload_id " + $r.payload_id + ") -> " + $r.out)
    Write-Host "RECOGNITION_UPDATE_V1_BUILD_OK" -ForegroundColor Green
  }
  "verify" {
    if(-not $PackageDir){ Write-Host "verify needs -PackageDir" -ForegroundColor Red; exit 2 }
    $v = RU-Verify $PackageDir $InstallRoot $trust
    if(-not $v.ok){ Write-Host ("REFUSED: " + $v.reason) -ForegroundColor Red; Write-Host "RECOGNITION_UPDATE_V1_REFUSED"; exit 1 }
    Write-Host ("Update " + $v.version + " verified (payload_id " + $v.payload_id + ")")
    Write-Host "RECOGNITION_UPDATE_V1_VERIFY_OK" -ForegroundColor Green
  }
  "apply" {
    if(-not $PackageDir){ Write-Host "apply needs -PackageDir" -ForegroundColor Red; exit 2 }
    $r = RU-Apply $PackageDir $InstallRoot $trust
    if(-not $r.ok){ Write-Host ("REFUSED: " + $r.reason) -ForegroundColor Red; Write-Host "RECOGNITION_UPDATE_V1_REFUSED"; exit 1 }
    Write-Host ("Applied update " + $r.version + " (backup: " + $r.backup + ")")
    Write-Host "RECOGNITION_UPDATE_V1_APPLY_OK" -ForegroundColor Green
  }
}
