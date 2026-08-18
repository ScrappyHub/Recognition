param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe    = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$SessionOpenPath = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpenPath     = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$NavPath         = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"
$ReplayPath      = Join-Path $RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"

$RuntimeRoot = Join-Path $RepoRoot "runtime"
$ReplayOut   = Join-Path $RepoRoot "runtime\replay\session_replay.json"

if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpenPath -RepoRoot $RepoRoot -SessionId "recognition-runtime-replay-selftest-v1" -StartedUtc "2026-03-31T12:10:00.000Z" -Mode "standard" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpenPath -RepoRoot $RepoRoot -TabId "tab-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -OpenedUtc "2026-03-31T12:10:05.000Z" -IsActive 1 | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavPath -RepoRoot $RepoRoot -TabId "tab-001" -Url "https://example.com/docs" -Title "Example Docs" -CommittedUtc "2026-03-31T12:10:10.000Z" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ReplayPath -RepoRoot $RepoRoot -OutPath $ReplayOut | Out-Host

if(-not (Test-Path -LiteralPath $ReplayOut -PathType Leaf)){
  throw ("SELFTEST_REPLAY_MISSING: " + $ReplayOut)
}

$replay = Get-Content -Raw -LiteralPath $ReplayOut -Encoding UTF8 | ConvertFrom-Json -Depth 100

if([string]$replay.session_id -ne "recognition-runtime-replay-selftest-v1"){
  throw ("SELFTEST_REPLAY_BAD_SESSION_ID: " + [string]$replay.session_id)
}
if([int]$replay.event_count -ne 3){
  throw ("SELFTEST_REPLAY_BAD_EVENT_COUNT: " + [int]$replay.event_count)
}
if([int]$replay.nav_count -ne 1){
  throw ("SELFTEST_REPLAY_BAD_NAV_COUNT: " + [int]$replay.nav_count)
}
if([int]$replay.tab_count -ne 1){
  throw ("SELFTEST_REPLAY_BAD_TAB_COUNT: " + [int]$replay.tab_count)
}

$tabs = @($replay.tabs)
if($tabs.Count -ne 1){
  throw ("SELFTEST_REPLAY_TABS_COUNT_BAD: " + $tabs.Count)
}
if([string]$tabs[0].url -ne "https://example.com/docs"){
  throw ("SELFTEST_REPLAY_BAD_TAB_URL: " + [string]$tabs[0].url)
}
if([string]$tabs[0].title -ne "Example Docs"){
  throw ("SELFTEST_REPLAY_BAD_TAB_TITLE: " + [string]$tabs[0].title)
}

Write-Host ("SELFTEST_RECOGNITION_RUNTIME_REPLAY_V1_OK: " + $ReplayOut) -ForegroundColor Green
