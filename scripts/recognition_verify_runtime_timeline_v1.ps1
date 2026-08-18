param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$TimelineDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function RequireFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
    Die ("TIMELINE_VERIFY_MISSING_FILE: " + $Path)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($TimelineDir)){
  $TimelineDir = Join-Path $RepoRoot "runtime\timeline"
}

$TimelineDir = (Resolve-Path -LiteralPath $TimelineDir).Path

$TimelinePath = Join-Path $TimelineDir "timeline.json"
$TabsPath = Join-Path $TimelineDir "tabs_timeline.json"
$NavPath = Join-Path $TimelineDir "navigation_chain.json"
$SummaryPath = Join-Path $TimelineDir "session_summary.json"

foreach($p in @($TimelinePath,$TabsPath,$NavPath,$SummaryPath)){
  RequireFile $p
}

$timeline = Get-Content -Raw -LiteralPath $TimelinePath -Encoding UTF8 | ConvertFrom-Json
$tabsObj = Get-Content -Raw -LiteralPath $TabsPath -Encoding UTF8 | ConvertFrom-Json
$navObj = Get-Content -Raw -LiteralPath $NavPath -Encoding UTF8 | ConvertFrom-Json
$summary = Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8 | ConvertFrom-Json

if([string]$timeline.schema -ne "recognition.runtime.timeline.v1"){
  Die ("TIMELINE_VERIFY_BAD_TIMELINE_SCHEMA: " + [string]$timeline.schema)
}

if([string]$tabsObj.schema -ne "recognition.runtime.tabs_timeline.v1"){
  Die ("TIMELINE_VERIFY_BAD_TABS_SCHEMA: " + [string]$tabsObj.schema)
}

if([string]$navObj.schema -ne "recognition.runtime.navigation_chain.v1"){
  Die ("TIMELINE_VERIFY_BAD_NAV_SCHEMA: " + [string]$navObj.schema)
}

if([string]$summary.schema -ne "recognition.runtime.session_summary.v1"){
  Die ("TIMELINE_VERIFY_BAD_SUMMARY_SCHEMA: " + [string]$summary.schema)
}

$sessionId = [string]$summary.session_id

foreach($obj in @($timeline,$tabsObj,$navObj)){
  if([string]$obj.session_id -ne $sessionId){
    Die ("TIMELINE_VERIFY_SESSION_MISMATCH: expected=" + $sessionId + " actual=" + [string]$obj.session_id)
  }
}

$events = @($timeline.events)
$tabs = @($tabsObj.tabs)
$nav = @($navObj.navigation)

if([int]$timeline.event_count -ne $events.Count){
  Die ("TIMELINE_VERIFY_EVENT_COUNT_MISMATCH: declared=" + [int]$timeline.event_count + " actual=" + $events.Count)
}

if([int]$timeline.tab_count -ne $tabs.Count){
  Die ("TIMELINE_VERIFY_TAB_COUNT_MISMATCH: declared=" + [int]$timeline.tab_count + " actual=" + $tabs.Count)
}

if([int]$timeline.navigation_count -ne $nav.Count){
  Die ("TIMELINE_VERIFY_NAV_COUNT_MISMATCH: declared=" + [int]$timeline.navigation_count + " actual=" + $nav.Count)
}

if([int]$summary.event_count -ne [int]$timeline.event_count){
  Die "TIMELINE_VERIFY_SUMMARY_EVENT_COUNT_MISMATCH"
}

if([int]$summary.tab_count -ne [int]$timeline.tab_count){
  Die "TIMELINE_VERIFY_SUMMARY_TAB_COUNT_MISMATCH"
}

if([int]$summary.navigation_count -ne [int]$timeline.navigation_count){
  Die "TIMELINE_VERIFY_SUMMARY_NAV_COUNT_MISMATCH"
}

$lastSeq = 0
$seenSessionStart = $false
$openedTabs = @{}

foreach($evt in @($events)){
  $seq = [int]$evt.seq

  if($seq -ne ($lastSeq + 1)){
    Die ("TIMELINE_VERIFY_SEQ_BREAK: prev=" + [string]$lastSeq + " current=" + [string]$seq)
  }

  $lastSeq = $seq

  $type = [string]$evt.type

  if($type -eq "session.started"){
    $seenSessionStart = $true
    continue
  }

  if(-not $seenSessionStart){
    Die ("TIMELINE_VERIFY_EVENT_BEFORE_SESSION: " + $type)
  }

  if($type -eq "tab.opened"){
    $tabId = [string]$evt.tab_id
    $openedTabs[$tabId] = $true
    continue
  }

  if($type -eq "navigation.committed"){
    $tabId = [string]$evt.tab_id
    if(-not $openedTabs.ContainsKey($tabId)){
      Die ("TIMELINE_VERIFY_NAV_WITHOUT_TAB: " + $tabId)
    }
    continue
  }
}

if(-not $seenSessionStart){
  Die "TIMELINE_VERIFY_SESSION_START_MISSING"
}

if([int]$timeline.last_seq -ne $lastSeq){
  Die ("TIMELINE_VERIFY_LAST_SEQ_MISMATCH: declared=" + [int]$timeline.last_seq + " actual=" + $lastSeq)
}

foreach($n in @($nav)){
  $tabId = [string]$n.tab_id
  if(-not $openedTabs.ContainsKey($tabId)){
    Die ("TIMELINE_VERIFY_NAV_CHAIN_ORPHAN: " + $tabId)
  }
}

foreach($t in @($tabs)){
  $tabId = [string]$t.tab_id
  if(-not $openedTabs.ContainsKey($tabId)){
    Die ("TIMELINE_VERIFY_TAB_TIMELINE_UNKNOWN_TAB: " + $tabId)
  }
}

Write-Host ("TIMELINE_VERIFY_OK: " + $TimelineDir) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_TIMELINE_VERIFY_V1_OK" -ForegroundColor Green
