# Recognition History Engine v1 — CLI  (Canonical Handoff §24)
#
# Append-only, hash-chained browsing history. URLs are hashed; the chain proves
# nothing was modified/missing/reordered/forged; replay reconstructs the visits.
# Seal it into the vault with: recognition_runtime_seal_v1.ps1 -Action seal
#
# Actions:
#   add     -Url <url> [-Title <t>] [-Transition link|typed|reload|...] [-TabId <id>]
#   verify
#   replay
#   stats

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("add","verify","replay","stats")][string]$Action,
  [string]$Url = "",
  [string]$Title = "",
  [string]$Transition = "link",
  [string]$TabId = "",
  [string]$SessionId = "history",
  [string]$ChainPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_history_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($ChainPath)){ $ChainPath = Join-Path (Join-Path $RepoRoot "runtime") "history.v2.ndjson" }

if($Action -eq "add"){
  if([string]::IsNullOrWhiteSpace($Url)){ RCE-Die "ADD_URL_REQUIRED" }
  $evt = RH-AddVisit $ChainPath $Url $Title $Transition $TabId $SessionId
  Write-Host ("recorded visit seq=" + [string]$evt.seq + " url_sha256=" + ([string]$evt.event_hash).Substring(0,4) + ".. title=" + $Title)
  Write-Host ("RECOGNITION_HISTORY_V1_ADD_OK: seq=" + [string]$evt.seq) -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  if(-not (Test-Path -LiteralPath $ChainPath -PathType Leaf)){ Write-Host "RECOGNITION_HISTORY_V1_VERIFY_OK: events=0 (empty)"; exit 0 }
  $r = RH-Verify $ChainPath
  Write-Host ("history verified: events=" + $r.event_count + " head=" + $r.head_hash)
  Write-Host ("RECOGNITION_HISTORY_V1_VERIFY_OK: events=" + $r.event_count) -ForegroundColor Green
  exit 0
}

if($Action -eq "replay"){
  $visits = RH-Replay $ChainPath
  Write-Host ("RECOGNITION_HISTORY_V1_VISIT_COUNT: " + @($visits).Count)
  foreach($v in @($visits)){
    Write-Host ("  seq=" + $v.seq + "  " + $v.ts_utc + "  [" + $v.transition + "]  " + $v.title + "  url_sha256=" + ($v.url_sha256).Substring(0,12) + "...")
  }
  Write-Host "RECOGNITION_HISTORY_V1_REPLAY_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "stats"){
  $visits = @(RH-Replay $ChainPath)
  $first = if($visits.Count -gt 0){ ($visits | Select-Object -First 1).ts_utc } else { "-" }
  $last  = if($visits.Count -gt 0){ ($visits | Select-Object -Last 1).ts_utc } else { "-" }
  Write-Host ("visits=" + $visits.Count + " first=" + $first + " last=" + $last)
  Write-Host "RECOGNITION_HISTORY_V1_STATS_OK" -ForegroundColor Green
  exit 0
}
