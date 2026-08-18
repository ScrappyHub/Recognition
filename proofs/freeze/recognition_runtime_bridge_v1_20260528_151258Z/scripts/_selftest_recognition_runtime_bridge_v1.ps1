param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$Bridge = Join-Path $RepoRoot "scripts\recognition_runtime_bridge_event_v1.ps1"
$Replay = Join-Path $RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"
$RuntimeRoot = Join-Path $RepoRoot "runtime"
$ReplayOut = Join-Path $RepoRoot "runtime\replay\bridge_replay.json"
if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){ Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force }
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "session.open" -SessionId "recognition-bridge-selftest-v1" -Utc "2026-04-24T03:00:00.000Z" -Mode "standard" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "tab.open" -TabId "tab-bridge-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -Utc "2026-04-24T03:00:05.000Z" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "navigation.commit" -TabId "tab-bridge-001" -Url "https://example.com/bridge" -Title "Bridge Page" -Utc "2026-04-24T03:00:10.000Z" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Replay -RepoRoot $RepoRoot -OutPath $ReplayOut | Out-Host
if(-not (Test-Path -LiteralPath $ReplayOut -PathType Leaf)){ throw ("BRIDGE_REPLAY_MISSING: " + $ReplayOut) }
$r = Get-Content -Raw -LiteralPath $ReplayOut -Encoding UTF8 | ConvertFrom-Json
if([string]$r.session_id -ne "recognition-bridge-selftest-v1"){ throw ("BRIDGE_BAD_SESSION: " + [string]$r.session_id) }
if([int]$r.event_count -ne 3){ throw ("BRIDGE_BAD_EVENT_COUNT: " + [int]$r.event_count) }
if([int]$r.nav_count -ne 1){ throw ("BRIDGE_BAD_NAV_COUNT: " + [int]$r.nav_count) }
Write-Host "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK" -ForegroundColor Green
