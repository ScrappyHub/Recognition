param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "ENSUREDIR_EMPTY" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf+="`n" }; $dir=Split-Path -Parent $Path; if($dir){ EnsureDir $dir }; [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors); if($errors -and @($errors).Count -gt 0){ $e=@($errors)[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message) } }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir
$BridgePath = Join-Path $ScriptsDir "recognition_runtime_bridge_event_v1.ps1"
$SelfPath = Join-Path $ScriptsDir "_selftest_recognition_runtime_bridge_v1.ps1"
$B = New-Object System.Collections.Generic.List[string]
[void]$B.Add('param(')
[void]$B.Add('  [Parameter(Mandatory=$true)][string]$RepoRoot,')
[void]$B.Add('  [Parameter(Mandatory=$true)][ValidateSet("session.open","tab.open","navigation.commit")][string]$EventType,')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$SessionId = "recognition-bridge-session-v1",')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$TabId = "tab-001",')
[void]$B.Add('  [Parameter(Mandatory=$false)][int]$Index = 0,')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$Url = "about:blank",')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$Title = "",')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$Utc = "2026-04-24T00:00:00.000Z",')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$Mode = "standard"')
[void]$B.Add(')')
[void]$B.Add('Set-StrictMode -Version Latest')
[void]$B.Add('$ErrorActionPreference = "Stop"')
[void]$B.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$B.Add('$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"')
[void]$B.Add('$SessionOpen = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"')
[void]$B.Add('$TabOpen = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"')
[void]$B.Add('$NavCommit = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"')
[void]$B.Add('if($EventType -eq "session.open"){ & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpen -RepoRoot $RepoRoot -SessionId $SessionId -StartedUtc $Utc -Mode $Mode | Out-Host; Write-Host ("RUNTIME_BRIDGE_EVENT_OK: session.open " + $SessionId) -ForegroundColor Green; return }')
[void]$B.Add('if($EventType -eq "tab.open"){ & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpen -RepoRoot $RepoRoot -TabId $TabId -Index $Index -Url $Url -Title $Title -OpenedUtc $Utc -IsActive 1 | Out-Host; Write-Host ("RUNTIME_BRIDGE_EVENT_OK: tab.open " + $TabId) -ForegroundColor Green; return }')
[void]$B.Add('if($EventType -eq "navigation.commit"){ & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavCommit -RepoRoot $RepoRoot -TabId $TabId -Url $Url -Title $Title -CommittedUtc $Utc | Out-Host; Write-Host ("RUNTIME_BRIDGE_EVENT_OK: navigation.commit " + $TabId) -ForegroundColor Green; return }')
[void]$B.Add('throw ("UNKNOWN_BRIDGE_EVENT: " + $EventType)')
WriteUtf8NoBomLf $BridgePath ([string]::Join("`n",$B))
ParseGateFile $BridgePath
Write-Host ("BRIDGE_SCRIPT_OK: " + $BridgePath) -ForegroundColor Green
$S = New-Object System.Collections.Generic.List[string]
[void]$S.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)')
[void]$S.Add('Set-StrictMode -Version Latest')
[void]$S.Add('$ErrorActionPreference = "Stop"')
[void]$S.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$S.Add('$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"')
[void]$S.Add('$Bridge = Join-Path $RepoRoot "scripts\recognition_runtime_bridge_event_v1.ps1"')
[void]$S.Add('$Replay = Join-Path $RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"')
[void]$S.Add('$RuntimeRoot = Join-Path $RepoRoot "runtime"')
[void]$S.Add('$ReplayOut = Join-Path $RepoRoot "runtime\replay\bridge_replay.json"')
[void]$S.Add('if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){ Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force }')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "session.open" -SessionId "recognition-bridge-selftest-v1" -Utc "2026-04-24T03:00:00.000Z" -Mode "standard" | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "tab.open" -TabId "tab-bridge-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -Utc "2026-04-24T03:00:05.000Z" | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Bridge -RepoRoot $RepoRoot -EventType "navigation.commit" -TabId "tab-bridge-001" -Url "https://example.com/bridge" -Title "Bridge Page" -Utc "2026-04-24T03:00:10.000Z" | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Replay -RepoRoot $RepoRoot -OutPath $ReplayOut | Out-Host')
[void]$S.Add('if(-not (Test-Path -LiteralPath $ReplayOut -PathType Leaf)){ throw ("BRIDGE_REPLAY_MISSING: " + $ReplayOut) }')
[void]$S.Add('$r = Get-Content -Raw -LiteralPath $ReplayOut -Encoding UTF8 | ConvertFrom-Json -Depth 100')
[void]$S.Add('if([string]$r.session_id -ne "recognition-bridge-selftest-v1"){ throw ("BRIDGE_BAD_SESSION: " + [string]$r.session_id) }')
[void]$S.Add('if([int]$r.event_count -ne 3){ throw ("BRIDGE_BAD_EVENT_COUNT: " + [int]$r.event_count) }')
[void]$S.Add('if([int]$r.nav_count -ne 1){ throw ("BRIDGE_BAD_NAV_COUNT: " + [int]$r.nav_count) }')
[void]$S.Add('Write-Host "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK" -ForegroundColor Green')
WriteUtf8NoBomLf $SelfPath ([string]::Join("`n",$S))
ParseGateFile $SelfPath
Write-Host ("BRIDGE_SELFTEST_SCRIPT_OK: " + $SelfPath) -ForegroundColor Green
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SelfPath -RepoRoot $RepoRoot | Out-Host
Write-Host "RECOGNITION_RUNTIME_BRIDGE_V1_INSTALL_OK" -ForegroundColor Green
