# Recognition — CDP tab capture (read-only browser observation)
#
# Observes a Chrome/Chromium that YOU started with --remote-debugging-port and
# records its open tabs into the hash-chained evidence log. Recognition does not
# launch or drive the browser; it only reads the DevTools /json target list.
# URLs are hashed (url_sha256) — the evidence binds the target without storing
# the plaintext address.
#
# Start Chrome first, e.g.:
#   chrome.exe --remote-debugging-port=9222
# then:
#   pwsh -File recognition_cdp_capture_v1.ps1 -RepoRoot .
#
# Appends real tabs as history.visit records into the unified History Engine
# chain (runtime/history.v2.ndjson) — so actual browsing becomes replayable,
# verifiable evidence. Gitignored; sealable into the vault.
# Requires pwsh 7.2+.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [int]$Port = 9222,
  [string]$SessionId = "cdp-observe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_history_v1.ps1")  # RH-AddVisit + RCE-* beneath it

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$ChainPath  = Join-Path (Join-Path $RepoRoot "runtime") "history.v2.ndjson"
$ReceiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.cdp_capture.v1.ndjson"
$Endpoint   = ("http://127.0.0.1:" + $Port + "/json")

# --- read the running browser's target list ---------------------------------
$targets = $null
try {
  $targets = Invoke-RestMethod -Uri $Endpoint -TimeoutSec 5
} catch {
  RCE-Die ("CDP_NOT_REACHABLE at " + $Endpoint + " — start your browser with --remote-debugging-port=" + $Port + " first. (" + $_.Exception.Message + ")")
}

$pages = @($targets | Where-Object { $_.type -eq "page" })
Write-Host ("Observed " + $pages.Count + " page target(s) from " + $Endpoint) -ForegroundColor Cyan

# --- append each observed tab as a hash-chained history.visit ----------------
$recorded = 0
$prev = ""
foreach($t in $pages){
  $url   = [string]$t.url
  $title = [string]$t.title
  $tabId = [string]$t.id
  $evt = RH-AddVisit $ChainPath $url $title "observed" $tabId $SessionId
  $prev = [string]$evt.event_hash
  $recorded++
  Write-Host ("  + history.visit  tab=" + $tabId.Substring(0,[Math]::Min(8,$tabId.Length)) + "  url_sha256=" + (RCE-Sha256Hex $url).Substring(0,12) + "  " + $title)
}
if($recorded -eq 0){ $prev = [string](RCE-ChainTail $ChainPath).head_hash }

# --- receipt -----------------------------------------------------------------
$rec = [ordered]@{
  schema = "recognition.cdp_capture.receipt.v1"; ts_utc = (RCE-NowUtc)
  endpoint = $Endpoint; pages_observed = $pages.Count; events_appended = $recorded
  chain = "runtime/history.v2.ndjson"; head_hash = $prev
}
$rd = Split-Path -Parent $ReceiptPath
if(-not (Test-Path -LiteralPath $rd -PathType Container)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
[System.IO.File]::AppendAllText($ReceiptPath, (($rec | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host ("Recorded " + $recorded + " tab observation(s); chain head " + $prev.Substring(0,12) + "...")
Write-Host ("Verify anytime: pwsh -File scripts/recognition_verify_event_chain_v2.ps1 -RepoRoot . -ChainPath " + $ChainPath)
Write-Host "RECOGNITION_CDP_CAPTURE_V1_OK" -ForegroundColor Green
