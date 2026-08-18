# Recognition Governed Launch PLAN v1 — CLI
#
# PLAN ONLY: Recognition does NOT launch or drive a browser. This verifies every
# configured extension against the governance ledger and, if all are governed
# 'allow', emits the governed launch manifest (the exact command a governed
# browser environment would use) plus a receipt. If any configured extension is
# unregistered, modified, or not 'allow', it refuses and emits nothing runnable.
#
# The intended-browser path is recorded for the manifest only; it is never
# executed. Recognition stays the deterministic governance / evidence layer.
#
#   pwsh -File recognition_launch_governed_v1.ps1 -RepoRoot .
#
# Config: config/launch.v1.json  { chromium_path, user_data_dir, extensions[] }
# Params -ChromiumPath / -UserDataDir override the config.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$ConfigPath = "",
  [string]$ChromiumPath = "",
  [string]$UserDataDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_launch_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($ConfigPath)){ $ConfigPath = Join-Path (Join-Path $RepoRoot "config") "launch.v1.json" }
$Ledger    = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.extension_governance.v1.ndjson"
$ReceiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.launch.v1.ndjson"

# --- config ------------------------------------------------------------------
if(-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)){ RGL-Die ("LAUNCH_CONFIG_MISSING: " + $ConfigPath) }
$cfg = RCE-ParseJson (Get-Content -Raw -LiteralPath $ConfigPath -Encoding UTF8)
$cfgChromium = [string](RG-Get $cfg "chromium_path")
$cfgUserDir  = [string](RG-Get $cfg "user_data_dir")
$extensions  = RG-GetArr $cfg "extensions"

if([string]::IsNullOrWhiteSpace($ChromiumPath)){ $ChromiumPath = $cfgChromium }
if([string]::IsNullOrWhiteSpace($UserDataDir)){ $UserDataDir = $cfgUserDir }
if([string]::IsNullOrWhiteSpace($UserDataDir)){ $UserDataDir = "runtime/chromium-profile" }
# resolve a relative user-data-dir under the repo
if(-not [System.IO.Path]::IsPathRooted($UserDataDir)){ $UserDataDir = Join-Path $RepoRoot $UserDataDir }

if(@($extensions).Count -eq 0){ RGL-Die "LAUNCH_NO_EXTENSIONS_CONFIGURED" }

# resolve extension paths relative to the repo
$extPaths = @()
foreach($e in @($extensions)){
  $ep = [string]$e
  if(-not [System.IO.Path]::IsPathRooted($ep)){ $ep = Join-Path $RepoRoot $ep }
  $extPaths += $ep
}

# --- governance gate ---------------------------------------------------------
$rows = RGL-EvaluateExtensions $Ledger $extPaths
Write-Host "=== governed launch: extension gate ===" -ForegroundColor Cyan
foreach($r in $rows){
  $color = if($r.gate -eq "permit"){ "Green" } else { "Red" }
  Write-Host ("  [" + $r.gate.ToUpper() + "] " + (Split-Path -Leaf $r.path) + "  decision=" + $r.decision + "  (" + $r.reason + ")") -ForegroundColor $color
}

$refused = @($rows | Where-Object { $_.gate -ne "permit" })
$allowPaths = @($rows | Where-Object { $_.gate -eq "permit" } | ForEach-Object { $_.path })

function EmitReceipt([string]$Verdict,[string]$Chromium){
  $rec = [ordered]@{
    schema         = "recognition.launch_plan.receipt.v1"
    ts_utc         = (RCE-NowUtc)
    verdict        = $Verdict          # "plan" | "refused"
    launched       = $false            # Recognition never launches a browser
    extensions     = @($rows | ForEach-Object { [ordered]@{ extension_id = $_.extension_id; decision = $_.decision; gate = $_.gate } })
    allow_count    = @($allowPaths).Count
    refused_count  = @($refused).Count
    intended_browser = $Chromium
    user_data_dir  = $UserDataDir
  }
  RCE-AppendLine $ReceiptPath (($rec | ConvertTo-Json -Depth 12 -Compress))
}

# --- refuse on any non-allow extension ---------------------------------------
if(@($refused).Count -gt 0){
  EmitReceipt "refused" ""
  Write-Host ""
  Write-Host ("RECOGNITION_LAUNCH_GOVERNED_V1_REFUSED: " + @($refused).Count + " extension(s) failed the gate; no launch manifest emitted.") -ForegroundColor Red
  exit 1
}

# --- emit the governed launch manifest (PLAN ONLY — never executed) ----------
$chromium = ""
try { $chromium = RGL-FindChromium $ChromiumPath } catch { $chromium = "" }
$cmdArgs = RGL-BuildArgs $UserDataDir $allowPaths

Write-Host ""
Write-Host ("intended browser : " + $(if($chromium){$chromium}else{"<none detected — informational only>"}))
Write-Host ("user-data-dir    : " + $UserDataDir)
Write-Host ("governed command : `"" + $chromium + "`" " + ($cmdArgs -join " "))
Write-Host "(plan only — Recognition verifies and records; it does not start a browser)"

EmitReceipt "plan" $chromium
Write-Host ""
Write-Host ("All configured extensions are governed 'allow' (" + @($allowPaths).Count + "). Governed launch manifest emitted.")
Write-Host "RECOGNITION_LAUNCH_GOVERNED_V1_PLAN_OK" -ForegroundColor Green
exit 0
