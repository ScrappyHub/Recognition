# Migrate a v1 events.ndjson (no hashes) into a v2 hash chain.
# Preserves seq, ts_utc, type, tab_id, data; adds identity + hash links.
# Token: RECOGNITION_EVENT_CHAIN_MIGRATE_V2_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$SourcePath,
  [Parameter(Mandatory=$true)][string]$OutPath,
  [Parameter(Mandatory=$false)][string]$ProfileId = "",
  [Parameter(Mandatory=$false)][string]$DeviceId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$SourcePath = (Resolve-Path -LiteralPath $SourcePath).Path

if(Test-Path -LiteralPath $OutPath -PathType Leaf){ RCE-Die ("MIGRATE_OUT_EXISTS: " + $OutPath) }

$lines = RCE-ReadChainLines $SourcePath
if(@($lines).Count -lt 1){ RCE-Die "MIGRATE_SOURCE_EMPTY" }

# session_id comes from the v1 session.started event
$sessionId = ""
foreach($line in $lines){
  $e = RCE-ParseJson $line
  if([string]$e.type -eq "session.started" -and $e.Contains("data") -and $e.data.Contains("session_id")){
    $sessionId = [string]$e.data.session_id
    break
  }
}
if([string]::IsNullOrWhiteSpace($sessionId)){ RCE-Die "MIGRATE_SESSION_ID_MISSING" }

$identity = [ordered]@{
  session_id = $sessionId
  profile_id = $(if([string]::IsNullOrWhiteSpace($ProfileId)){ $null } else { $ProfileId })
  device_id  = $(if([string]::IsNullOrWhiteSpace($DeviceId)){ $null } else { $DeviceId })
}

$prevHash = RCE-GenesisHash
$seq = 0
$count = 0

foreach($line in $lines){
  $v1 = RCE-ParseJson $line
  $seq++
  if([int]$v1.seq -ne $seq){ RCE-Die ("MIGRATE_SEQ_BREAK: expected=" + $seq + " got=" + [string]$v1.seq) }

  $data = $null
  if($v1.Contains("data")){ $data = $v1.data }
  $tabId = $null
  if($v1.Contains("tab_id")){ $tabId = $v1.tab_id }

  $evt = RCE-BuildEvent `
    -Seq $seq `
    -TsUtc ([string]$v1.ts_utc) `
    -Type ([string]$v1.type) `
    -TabId $tabId `
    -Data $data `
    -Identity $identity `
    -PrevHash $prevHash

  # preserve original v1 event id for provenance
  $evt["data_migrated_from"] = [ordered]@{ v1_event_id = [string]$v1.event_id; source = $SourcePath }
  $evt.Remove("event_hash")
  $evt["event_hash"] = RCE-ComputeEventHash $evt

  RCE-AppendLine $OutPath (RCE-CanonJson $evt)
  $prevHash = [string]$evt.event_hash
  $count++
}

$verify = RCE-VerifyChain $OutPath

$receipt = [ordered]@{
  schema = "recognition.event_chain.receipt.v2"
  action = "migrate_v1_v2"
  source = $SourcePath
  out = $OutPath
  event_count = $count
  head_hash = [string]$verify.head_hash
  ts_utc = RCE-NowUtc
}
RCE-AppendLine (Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.event_chain.v2.ndjson") (($receipt | ConvertTo-Json -Depth 20 -Compress))

Write-Host ("RECOGNITION_EVENT_CHAIN_MIGRATE_V2_OK: events=" + $count) -ForegroundColor Green
