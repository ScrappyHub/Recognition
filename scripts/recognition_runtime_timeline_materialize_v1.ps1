param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$EventsPath = "",
  [Parameter(Mandatory=$false)][string]$OutDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function CanonJson([object]$Obj){
  return ($Obj | ConvertTo-Json -Depth 100)
}

function Sha256HexText([string]$Text){
  $enc=New-Object System.Text.UTF8Encoding($false)
  $bytes=$enc.GetBytes($Text)
  $sha=[System.Security.Cryptography.SHA256]::Create()
  try{
    $hash=$sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }
  $sb=New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($EventsPath)){
  $EventsPath = Join-Path $RepoRoot "runtime\events.ndjson"
}

if([string]::IsNullOrWhiteSpace($OutDir)){
  $OutDir = Join-Path $RepoRoot "runtime\timeline"
}

if(-not (Test-Path -LiteralPath $EventsPath -PathType Leaf)){
  Die ("TIMELINE_EVENTS_MISSING: " + $EventsPath)
}

EnsureDir $OutDir

$raw = Get-Content -Raw -LiteralPath $EventsPath -Encoding UTF8
$lines = @($raw -split "`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

if($lines.Count -lt 1){
  Die "TIMELINE_EVENTS_EMPTY"
}

$events = New-Object System.Collections.Generic.List[object]
$tabsById = @{}
$navList = New-Object System.Collections.Generic.List[object]

$sessionId = ""
$startedUtc = ""
$mode = ""
$lastSeq = 0
$count = 0
$lastUtc = ""

foreach($line in @($lines)){
  $evt = $line | ConvertFrom-Json

  $seq = [int]$evt.seq
  if($count -gt 0){
    if($seq -ne ($lastSeq + 1)){
      Die ("TIMELINE_SEQ_BREAK: prev=" + [string]$lastSeq + " current=" + [string]$seq)
    }
  }

  $utc = [string]$evt.ts_utc
  if((-not [string]::IsNullOrWhiteSpace($lastUtc)) -and ($utc -lt $lastUtc)){
    Die ("TIMELINE_UTC_NON_MONOTONIC: prev=" + $lastUtc + " current=" + $utc)
  }

  $lastSeq = $seq
  $lastUtc = $utc
  $count++

  $etype = [string]$evt.type

  [void]$events.Add([ordered]@{
    seq = $seq
    ts_utc = $utc
    type = $etype
    tab_id = $evt.tab_id
    event_id = [string]$evt.event_id
  })

  if($etype -eq "session.started"){
    $sessionId = [string]$evt.data.session_id
    $startedUtc = $utc
    $mode = [string]$evt.data.mode
    continue
  }

  if($etype -eq "tab.opened"){
    $tabId = [string]$evt.tab_id
    $tabsById[$tabId] = [ordered]@{
      tab_id = $tabId
      opened_seq = $seq
      opened_utc = $utc
      latest_seq = $seq
      latest_utc = $utc
      index = [int]$evt.data.index
      current_url = [string]$evt.data.url
      current_title = [string]$evt.data.title
      navigation_count = 0
      is_active = $true
      is_pinned = $false
    }
    continue
  }

  if($etype -eq "navigation.committed"){
    $tabId = [string]$evt.tab_id
    if(-not $tabsById.ContainsKey($tabId)){
      Die ("TIMELINE_NAV_WITHOUT_TAB: " + $tabId)
    }

    $tabsById[$tabId].latest_seq = $seq
    $tabsById[$tabId].latest_utc = $utc
    $tabsById[$tabId].current_url = [string]$evt.data.url
    $tabsById[$tabId].current_title = [string]$evt.data.title
    $tabsById[$tabId].navigation_count = ([int]$tabsById[$tabId].navigation_count + 1)

    [void]$navList.Add([ordered]@{
      seq = $seq
      ts_utc = $utc
      tab_id = $tabId
      url = [string]$evt.data.url
      title = [string]$evt.data.title
    })

    continue
  }
}

if([string]::IsNullOrWhiteSpace($sessionId)){
  Die "TIMELINE_SESSION_START_MISSING"
}

$tabList = New-Object System.Collections.Generic.List[object]
foreach($k in @($tabsById.Keys | Sort-Object)){
  [void]$tabList.Add($tabsById[$k])
}

$timeline = [ordered]@{
  schema = "recognition.runtime.timeline.v1"
  session_id = $sessionId
  started_utc = $startedUtc
  mode = $mode
  event_count = $events.Count
  tab_count = $tabList.Count
  navigation_count = $navList.Count
  last_seq = $lastSeq
  events = @($events.ToArray())
}

$tabsTimeline = [ordered]@{
  schema = "recognition.runtime.tabs_timeline.v1"
  session_id = $sessionId
  tabs = @($tabList.ToArray())
}

$navChain = [ordered]@{
  schema = "recognition.runtime.navigation_chain.v1"
  session_id = $sessionId
  navigation = @($navList.ToArray())
}

$summary = [ordered]@{
  schema = "recognition.runtime.session_summary.v1"
  session_id = $sessionId
  started_utc = $startedUtc
  mode = $mode
  event_count = $events.Count
  tab_count = $tabList.Count
  navigation_count = $navList.Count
  last_seq = $lastSeq
  source = $EventsPath
}

$timelinePath = Join-Path $OutDir "timeline.json"
$tabsPath = Join-Path $OutDir "tabs_timeline.json"
$navPath = Join-Path $OutDir "navigation_chain.json"
$summaryPath = Join-Path $OutDir "session_summary.json"

WriteUtf8NoBomLf $timelinePath (CanonJson $timeline)
WriteUtf8NoBomLf $tabsPath (CanonJson $tabsTimeline)
WriteUtf8NoBomLf $navPath (CanonJson $navChain)
WriteUtf8NoBomLf $summaryPath (CanonJson $summary)

$receiptObj = [ordered]@{
  schema = "recognition.runtime.timeline.receipt.v1"
  session_id = $sessionId
  event_count = $events.Count
  tab_count = $tabList.Count
  navigation_count = $navList.Count
  timeline_hash = Sha256HexText (CanonJson $timeline)
  tabs_timeline_hash = Sha256HexText (CanonJson $tabsTimeline)
  navigation_chain_hash = Sha256HexText (CanonJson $navChain)
  summary_hash = Sha256HexText (CanonJson $summary)
  ts_utc = (Get-Date).ToUniversalTime().ToString("o")
}

$ReceiptPath = Join-Path $RepoRoot "proofs\receipts\recognition.runtime.timeline.v1.ndjson"
WriteUtf8NoBomLf $ReceiptPath ((CanonJson $receiptObj))

Write-Host ("TIMELINE_OUTPUT_OK: " + $OutDir) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_TIMELINE_MATERIALIZE_V1_OK" -ForegroundColor Green
