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
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function RunExpectFail {
  param(
    [Parameter(Mandatory=$true)][string]$ReplayPath,
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$EventsPath,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ExpectedToken
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $out = & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ReplayPath -RepoRoot $RepoRoot -EventsPath $EventsPath -OutPath $OutPath 2>&1
  $text = ($out | Out-String)

  if($LASTEXITCODE -eq 0){
    Die ("NEGATIVE_UNEXPECTED_PASS[" + $Label + "]")
  }

  if($text -notmatch [regex]::Escape($ExpectedToken)){
    Write-Host $text -ForegroundColor Red
    Die ("NEGATIVE_EXPECTED_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ($Label + ": " + $ExpectedToken) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
$ReplayPath = Join-Path $ScriptsDir "recognition_runtime_replay_from_events_v1.ps1"

if(-not (Test-Path -LiteralPath $ReplayPath -PathType Leaf)){ Die ("MISSING_REPLAY: " + $ReplayPath) }
ParseGateFile $ReplayPath

$RunnerPath = Join-Path $ScriptsDir "_scratch\RUN_RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1.ps1"

$runner = @'
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
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function RunExpectFail {
  param(
    [Parameter(Mandatory=$true)][string]$ReplayPath,
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$EventsPath,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ExpectedToken
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $out = & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ReplayPath -RepoRoot $RepoRoot -EventsPath $EventsPath -OutPath $OutPath 2>&1
  $text = ($out | Out-String)

  if($LASTEXITCODE -eq 0){
    Die ("NEGATIVE_UNEXPECTED_PASS[" + $Label + "]")
  }

  if($text -notmatch [regex]::Escape($ExpectedToken)){
    Write-Host $text -ForegroundColor Red
    Die ("NEGATIVE_EXPECTED_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ($Label + ": " + $ExpectedToken) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ReplayPath = Join-Path $RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"
if(-not (Test-Path -LiteralPath $ReplayPath -PathType Leaf)){ Die ("MISSING_REPLAY: " + $ReplayPath) }
ParseGateFile $ReplayPath

$Root = Join-Path $RepoRoot "test_vectors\recognition_runtime_replay_negative_v1"
$Work = Join-Path $Root "work"
$Out  = Join-Path $Root "out"

if(Test-Path -LiteralPath $Root -PathType Container){
  Remove-Item -LiteralPath $Root -Recurse -Force
}
EnsureDir $Work
EnsureDir $Out

$seqGap = @'
{"schema":"recognition.event.v1","event_id":"evt-0001","seq":1,"ts_utc":"2026-03-31T14:00:00.000Z","type":"session.started","tab_id":null,"data":{"mode":"standard","session_id":"neg-seq-gap"}}
{"schema":"recognition.event.v1","event_id":"evt-0003","seq":3,"ts_utc":"2026-03-31T14:00:10.000Z","type":"tab.opened","tab_id":"tab-001","data":{"url":"https://example.com/","title":"Example Domain","index":0}}
