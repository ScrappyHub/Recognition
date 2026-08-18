param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tokens=$null;$errors=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e=@($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"

$BridgePath = Join-Path $ScriptsDir "recognition_runtime_bridge_event_v1.ps1"

$bridge = @'
param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("session.open","tab.open","navigation.commit")][string]$EventType,
  [Parameter(Mandatory=$false)][string]$SessionId = "recognition-bridge-session-v1",
  [Parameter(Mandatory=$false)][string]$TabId = "tab-001",
  [Parameter(Mandatory=$false)][int]$Index = 0,
  [Parameter(Mandatory=$false)][string]$Url = "about:blank",
  [Parameter(Mandatory=$false)][string]$Title = "",
  [Parameter(Mandatory=$false)][string]$Utc = "2026-04-24T00:00:00.000Z",
  [Parameter(Mandatory=$false)][string]$Mode = "standard"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$SessionOpen = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpen     = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$NavCommit   = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"

if($EventType -eq "session.open"){
  & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpen -RepoRoot $RepoRoot -SessionId $SessionId -StartedUtc $Utc -Mode $Mode | Out-Host
  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: session.open " + $SessionId) -ForegroundColor Green
  return
}

if($EventType -eq "tab.open"){
  & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpen -RepoRoot $RepoRoot -TabId $TabId -Index $Index -Url $Url -Title $Title -OpenedUtc $Utc -IsActive 1 | Out-Host
  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: tab.open " + $TabId) -ForegroundColor Green
  return
}

if($EventType -eq "navigation.commit"){
  & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavCommit -RepoRoot $RepoRoot -TabId $TabId -Url $Url -Title $Title -CommittedUtc $Utc | Out-Host
  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: navigation.commit " + $TabId) -ForegroundColor Green
  return
}

throw ("UNKNOWN_BRIDGE_EVENT: " + $EventType)
