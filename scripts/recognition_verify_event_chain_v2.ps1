# Verify a v2 hash-chained event log end to end.
# Proves: nothing modified, nothing missing, nothing reordered, nothing forged (spec section 15).
# Token: RECOGNITION_EVENT_CHAIN_VERIFY_V2_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$ChainPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($ChainPath)){
  $ChainPath = Join-Path (Join-Path $RepoRoot "runtime") "events.v2.ndjson"
}

$result = RCE-VerifyChain $ChainPath

$receipt = [ordered]@{
  schema = "recognition.event_chain.receipt.v2"
  action = "verify"
  chain = $ChainPath
  event_count = [int]$result.event_count
  head_seq = [int]$result.head_seq
  head_hash = [string]$result.head_hash
  proves = @("nothing_modified","nothing_missing","nothing_reordered","nothing_forged")
  ts_utc = RCE-NowUtc
}
RCE-AppendLine (Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.event_chain.v2.ndjson") (($receipt | ConvertTo-Json -Depth 20 -Compress))

Write-Output ("CHAIN_HEAD_HASH: " + [string]$result.head_hash)
Write-Host ("RECOGNITION_EVENT_CHAIN_VERIFY_V2_OK: events=" + [string]$result.event_count) -ForegroundColor Green
