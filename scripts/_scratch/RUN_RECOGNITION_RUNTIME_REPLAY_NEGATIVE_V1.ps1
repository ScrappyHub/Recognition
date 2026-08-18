param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Die([string]$m){ throw $m }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf+="`n" }; [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ExpectFail([string]$Label,[string]$Expected,[string]$EventsPath,[string]$OutPath){
  $msg = ""
  try {
    & $script:ReplayPath -RepoRoot $script:RepoRoot -EventsPath $EventsPath -OutPath $OutPath | Out-Null
    Die ("NEGATIVE_UNEXPECTED_PASS:" + $Label)
  } catch {
    $msg = [string]$_.Exception.Message
  }
  if($msg -notmatch [regex]::Escape($Expected)){ Die ("NEGATIVE_TOKEN_MISSING:" + $Label + ": expected=" + $Expected + " got=" + $msg) }
  Write-Host ($Label + ": " + $Expected) -ForegroundColor Green
}
$script:RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$script:ReplayPath = Join-Path $script:RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"
if(-not (Test-Path -LiteralPath $script:ReplayPath -PathType Leaf)){ Die ("MISSING_REPLAY: " + $script:ReplayPath) }
$Root = Join-Path $script:RepoRoot "test_vectors\recognition_runtime_replay_negative_v1"
$Work = Join-Path $Root "work"
$Out  = Join-Path $Root "out"
if(Test-Path -LiteralPath $Root -PathType Container){ Remove-Item -LiteralPath $Root -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Work | Out-Null
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$seqGapPath = Join-Path $Work "seq_gap.events.ndjson"
$seqGap = (@('{"schema":"recognition.event.v1","event_id":"e1","seq":1,"ts_utc":"t","type":"session.started","tab_id":null,"data":{"mode":"standard","session_id":"x"}}','{"schema":"recognition.event.v1","event_id":"e2","seq":3,"ts_utc":"t","type":"tab.opened","tab_id":"tab-1","data":{"url":"u","title":"t","index":0}}') -join "`n")
WriteUtf8NoBomLf $seqGapPath $seqGap
ExpectFail "NEG_SEQ_BREAK_GAP" "SEQ_BREAK" $seqGapPath (Join-Path $Out "seq_gap.json")
$navPath = Join-Path $Work "nav_without_tab.events.ndjson"
$nav = (@('{"schema":"recognition.event.v1","event_id":"e1","seq":1,"ts_utc":"t","type":"session.started","tab_id":null,"data":{"mode":"standard","session_id":"x"}}','{"schema":"recognition.event.v1","event_id":"e2","seq":2,"ts_utc":"t","type":"navigation.committed","tab_id":"missing","data":{"url":"u","title":"t"}}') -join "`n")
WriteUtf8NoBomLf $navPath $nav
ExpectFail "NEG_NAV_WITHOUT_TAB" "NAV_WITHOUT_TAB" $navPath (Join-Path $Out "nav_without_tab.json")
$missPath = Join-Path $Work "missing_session.events.ndjson"
$miss = '{"schema":"recognition.event.v1","event_id":"e1","seq":1,"ts_utc":"t","type":"tab.opened","tab_id":"t1","data":{"url":"u","title":"t","index":0}}'
WriteUtf8NoBomLf $missPath $miss
ExpectFail "NEG_SESSION_START_NOT_FOUND" "SESSION_START_NOT_FOUND" $missPath (Join-Path $Out "missing_session.json")
$monoPath = Join-Path $Work "seq_non_monotonic.events.ndjson"
$mono = (@('{"schema":"recognition.event.v1","event_id":"e1","seq":1,"ts_utc":"t","type":"session.started","tab_id":null,"data":{"mode":"standard","session_id":"x"}}','{"schema":"recognition.event.v1","event_id":"e2","seq":1,"ts_utc":"t","type":"tab.opened","tab_id":"t1","data":{"url":"u","title":"t","index":0}}') -join "`n")
WriteUtf8NoBomLf $monoPath $mono
ExpectFail "NEG_SEQ_BREAK_NON_MONOTONIC" "SEQ_BREAK" $monoPath (Join-Path $Out "seq_non_monotonic.json")
Write-Host "RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1_OK" -ForegroundColor Green
