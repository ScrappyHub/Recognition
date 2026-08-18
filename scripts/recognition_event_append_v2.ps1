# Append one event to a v2 hash-chained event log.
# Validates the current chain head before appending (no building on tampered state).
# Token: RECOGNITION_EVENT_APPEND_V2_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$Type,
  [Parameter(Mandatory=$true)][string]$SessionId,
  [Parameter(Mandatory=$false)][string]$ChainPath = "",
  [Parameter(Mandatory=$false)][string]$TabId = "",
  [Parameter(Mandatory=$false)][string]$DataJson = "{}",
  [Parameter(Mandatory=$false)][string]$ProfileId = "",
  [Parameter(Mandatory=$false)][string]$DeviceId = "",
  [Parameter(Mandatory=$false)][string]$TsUtc = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($ChainPath)){
  $ChainPath = Join-Path (Join-Path $RepoRoot "runtime") "events.v2.ndjson"
}

$data = RCE-ParseJson $DataJson
if($null -eq $data){ $data = [ordered]@{} }

$identity = [ordered]@{
  session_id = $SessionId
  profile_id = $(if([string]::IsNullOrWhiteSpace($ProfileId)){ $null } else { $ProfileId })
  device_id  = $(if([string]::IsNullOrWhiteSpace($DeviceId)){ $null } else { $DeviceId })
}

$tail = RCE-ChainTail $ChainPath

$ts = $TsUtc
if([string]::IsNullOrWhiteSpace($ts)){ $ts = RCE-NowUtc }
if($tail.ts_utc -and ($ts -lt [string]$tail.ts_utc)){ RCE-Die ("APPEND_TS_BEFORE_HEAD: " + $ts) }

$evt = RCE-BuildEvent `
  -Seq ([int]$tail.seq + 1) `
  -TsUtc $ts `
  -Type $Type `
  -TabId $(if([string]::IsNullOrWhiteSpace($TabId)){ $null } else { $TabId }) `
  -Data $data `
  -Identity $identity `
  -PrevHash ([string]$tail.head_hash)

RCE-AppendLine $ChainPath (RCE-CanonJson $evt)

$receipt = [ordered]@{
  schema = "recognition.event_chain.receipt.v2"
  action = "append"
  chain = $ChainPath
  seq = [int]$evt.seq
  type = $Type
  event_hash = [string]$evt.event_hash
  prev_hash = [string]$evt.prev_hash
  ts_utc = RCE-NowUtc
}
RCE-AppendLine (Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.event_chain.v2.ndjson") (($receipt | ConvertTo-Json -Depth 20 -Compress))

Write-Output ("EVENT_HASH: " + [string]$evt.event_hash)
Write-Host ("RECOGNITION_EVENT_APPEND_V2_OK: seq=" + [string]$evt.seq) -ForegroundColor Green
