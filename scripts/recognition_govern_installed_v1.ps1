# Recognition — Govern INSTALLED browser extensions (real data, not samples)
#
# Discovers the extensions actually installed in your Chrome/Edge profile and
# runs each through governance: deterministic identity, policy decision, and a
# hash-chained ledger record. Idempotent — an extension already governed at its
# current bytes is reported, not re-recorded.
#
#   pwsh -File recognition_govern_installed_v1.ps1 -RepoRoot .
#   pwsh -File recognition_govern_installed_v1.ps1 -RepoRoot . -Browser edge
#
# Requires pwsh 7.2+.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [ValidateSet("chrome","edge")][string]$Browser = "chrome",
  [string]$Profile = "Default",
  [string]$UserDataDir = "",
  [string]$PolicyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_extension_governance_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($PolicyPath)){ $PolicyPath = Join-Path (Join-Path $RepoRoot "config") "extension_policy.v1.json" }
$Ledger = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.extension_governance.v1.ndjson"

if([string]::IsNullOrWhiteSpace($UserDataDir)){
  $UserDataDir = if($Browser -eq "edge"){ Join-Path $env:LOCALAPPDATA "Microsoft\Edge\User Data" } else { Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data" }
}
$extRoot = Join-Path (Join-Path $UserDataDir $Profile) "Extensions"
if(-not (Test-Path -LiteralPath $extRoot -PathType Container)){
  RG-Die ("EXTENSIONS_DIR_NOT_FOUND: " + $extRoot + " (wrong -Browser/-Profile/-UserDataDir?)")
}

# discover: <extRoot>/<ext_id>/<version>/manifest.json  (newest version per id)
$installed = @()
foreach($idDir in @(Get-ChildItem -LiteralPath $extRoot -Directory -ErrorAction SilentlyContinue)){
  $verDir = @(Get-ChildItem -LiteralPath $idDir.FullName -Directory -ErrorAction SilentlyContinue |
              Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "manifest.json") } |
              Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
  if(@($verDir).Count -eq 1){ $installed += [pscustomobject]@{ store_id = $idDir.Name; path = $verDir[0].FullName } }
}

if($installed.Count -eq 0){ Write-Host "No unpacked extensions found under $extRoot"; Write-Host "RECOGNITION_GOVERN_INSTALLED_V1_OK"; exit 0 }

$policy = RG-LoadPolicy $PolicyPath
Write-Host ("Discovered " + $installed.Count + " installed extension(s) in " + $Browser + "/" + $Profile) -ForegroundColor Cyan

$counts = @{ allow = 0; review = 0; deny = 0; existing = 0 }
foreach($ext in $installed){
  try {
    $idInfo = RG-ComputeIdentity $ext.path
    $existing = RG-LatestDecision $Ledger $idInfo.extension_id
    if($null -ne $existing){
      $d = [string](RG-Get $existing "policy_decision")
      $counts.existing++
      Write-Host ("  = already governed  " + $d.PadRight(6) + " " + $ext.store_id) -ForegroundColor DarkGray
      continue
    }
    $manifest = RG-ReadManifest $ext.path
    $decision = RG-Decide $manifest $idInfo.extension_id $policy
    $tail = RG-LedgerTailHash $Ledger
    $rec  = RG-BuildRecord ([int]$tail.seq + 1) $idInfo.extension_id $manifest (RG-Get $idInfo "files") $decision ([string]$tail.head)
    RCE-AppendLine $Ledger (RCE-CanonJson $rec)
    $d = [string](RG-Get $decision "decision")
    if($counts.ContainsKey($d)){ $counts[$d]++ }
    $color = if($d -eq "allow"){ "Green" } elseif($d -eq "deny"){ "Red" } else { "Yellow" }
    Write-Host ("  + governed          " + $d.PadRight(6) + " " + [string](RG-Get $manifest "name") + "  (" + $ext.store_id + ")") -ForegroundColor $color
  } catch {
    Write-Host ("  ! skipped " + $ext.store_id + ": " + $_.Exception.Message) -ForegroundColor DarkYellow
  }
}

Write-Host ""
Write-Host ("Governed now: allow=" + $counts.allow + " review=" + $counts.review + " deny=" + $counts.deny + " (already-governed=" + $counts.existing + ")")
Write-Host "RECOGNITION_GOVERN_INSTALLED_V1_OK" -ForegroundColor Green
