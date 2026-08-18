param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$EventsPath,
  [string]$OutPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReceiptLib = Join-Path $PSScriptRoot "_lib_recognition_runtime_receipts_v1.ps1"
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RUNTIME_RECEIPT_LIB: " + $ReceiptLib) }
. $ReceiptLib

function Die([string]$m){ throw $m }

$RepoRoot = (Resolve-Path $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($EventsPath)){
  $EventsPath = Join-Path $RepoRoot "runtime\events.ndjson"
}
if([string]::IsNullOrWhiteSpace($OutPath)){
  $OutPath = Join-Path $RepoRoot "runtime\replay\session_replay.json"
}

if(-not (Test-Path $EventsPath)){
  Die ("MISSING_EVENTS: " + $EventsPath)
}

$lines = @(Get-Content $EventsPath | Where-Object { $_.Trim() -ne "" })

$sessionId = $null
$tabs = @{}
$lastSeq = 0
$eventCount = 0
$navCount = 0

foreach($l in $lines){
  $evt = $l | ConvertFrom-Json
  $seq = [int]$evt.seq

  if($eventCount -gt 0){
    if($seq -ne ($lastSeq + 1)){ Die "SEQ_BREAK" }
  }

  $lastSeq = $seq
  $eventCount++

  if($evt.type -eq "session.started"){
    $sessionId = $evt.data.session_id
  }

  if($evt.type -eq "tab.opened"){
    $tabs[$evt.tab_id] = $evt.data
  }

  if($evt.type -eq "navigation.committed"){
    if(-not $tabs.ContainsKey($evt.tab_id)){ Die ("NAV_WITHOUT_TAB: " + $evt.tab_id) }
    $tabs[$evt.tab_id].url = $evt.data.url
    $tabs[$evt.tab_id].title = $evt.data.title
    $navCount++
  }
}

if(-not $sessionId){ Die "SESSION_START_NOT_FOUND" }

$out = [ordered]@{
  schema = "recognition.runtime.replay.v1"
  session_id = $sessionId
  event_count = $eventCount
  nav_count = $navCount
  tab_count = $tabs.Count
  tabs = @($tabs.Values)
}

$json = $out | ConvertTo-Json -Depth 10

$dir = Split-Path $OutPath
if(-not (Test-Path $dir)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }

[System.IO.File]::WriteAllText($OutPath,$json,(New-Object System.Text.UTF8Encoding($false)))

Write-RecognitionRuntimeReceipt -RepoRoot $RepoRoot -Action "runtime.replay" -Status "ok" -Data @{
  events_path = $EventsPath
  out_path    = $OutPath
}
Write-Host ("RUNTIME_REPLAY_OK: " + $OutPath) -ForegroundColor Green
