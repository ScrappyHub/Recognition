param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function RunChild {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string[]]$Args,
    [Parameter(Mandatory=$true)][string]$ExpectedToken
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

  $out = & $PSExe `
    -NoProfile `
    -NonInteractive `
    -ExecutionPolicy Bypass `
    -File $ScriptPath `
    @Args 2>&1

  $text = ($out | Out-String)
  $out | Out-Host

  if($LASTEXITCODE -ne 0){
    Die ("CHILD_FAIL: " + $ScriptPath)
  }

  if($text -notmatch [regex]::Escape($ExpectedToken)){
    Die ("TOKEN_MISSING: " + $ExpectedToken)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$RuntimeRoot = Join-Path $RepoRoot "runtime"
if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

$SessionOpen = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpen = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$Nav = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"
$Timeline = Join-Path $RepoRoot "scripts\recognition_runtime_timeline_materialize_v1.ps1"
$TimelineVerify = Join-Path $RepoRoot "scripts\recognition_verify_runtime_timeline_v1.ps1"

foreach($p in @($SessionOpen,$TabOpen,$Nav,$Timeline,$TimelineVerify)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("MISSING_SCRIPT: " + $p)
  }
}

RunChild `
  -ScriptPath $SessionOpen `
  -Args @("-RepoRoot",$RepoRoot,"-SessionId","recognition-runtime-multitab-v1","-StartedUtc","2026-06-06T17:30:00.000Z","-Mode","standard") `
  -ExpectedToken "RUNTIME_SESSION_OPEN_OK"

RunChild `
  -ScriptPath $TabOpen `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-news","-Index","0","-Url","https://example.com/news","-Title","News Home","-OpenedUtc","2026-06-06T17:30:05.000Z","-IsActive","1") `
  -ExpectedToken "RUNTIME_TAB_OPEN_OK"

RunChild `
  -ScriptPath $Nav `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-news","-Url","https://example.com/news/world","-Title","World News","-CommittedUtc","2026-06-06T17:30:10.000Z") `
  -ExpectedToken "RUNTIME_NAV_COMMIT_OK"

RunChild `
  -ScriptPath $Nav `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-news","-Url","https://example.com/news/world/story-1","-Title","World Story 1","-CommittedUtc","2026-06-06T17:30:15.000Z") `
  -ExpectedToken "RUNTIME_NAV_COMMIT_OK"

RunChild `
  -ScriptPath $TabOpen `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-research","-Index","1","-Url","https://example.org/research","-Title","Research Home","-OpenedUtc","2026-06-06T17:30:20.000Z","-IsActive","0") `
  -ExpectedToken "RUNTIME_TAB_OPEN_OK"

RunChild `
  -ScriptPath $Nav `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-research","-Url","https://example.org/research/paper-a","-Title","Paper A","-CommittedUtc","2026-06-06T17:30:25.000Z") `
  -ExpectedToken "RUNTIME_NAV_COMMIT_OK"

RunChild `
  -ScriptPath $TabOpen `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-docs","-Index","2","-Url","https://docs.example.net","-Title","Docs","-OpenedUtc","2026-06-06T17:30:30.000Z","-IsActive","0") `
  -ExpectedToken "RUNTIME_TAB_OPEN_OK"

RunChild `
  -ScriptPath $Nav `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-docs","-Url","https://docs.example.net/runtime","-Title","Runtime Docs","-CommittedUtc","2026-06-06T17:30:35.000Z") `
  -ExpectedToken "RUNTIME_NAV_COMMIT_OK"

RunChild `
  -ScriptPath $Nav `
  -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-docs","-Url","https://docs.example.net/runtime/replay","-Title","Replay Docs","-CommittedUtc","2026-06-06T17:30:40.000Z") `
  -ExpectedToken "RUNTIME_NAV_COMMIT_OK"

RunChild `
  -ScriptPath $Timeline `
  -Args @("-RepoRoot",$RepoRoot) `
  -ExpectedToken "RECOGNITION_RUNTIME_TIMELINE_MATERIALIZE_V1_OK"

RunChild `
  -ScriptPath $TimelineVerify `
  -Args @("-RepoRoot",$RepoRoot) `
  -ExpectedToken "RECOGNITION_RUNTIME_TIMELINE_VERIFY_V1_OK"

Write-Host "RECOGNITION_RUNTIME_MULTITAB_CAPTURE_V1_OK" -ForegroundColor Green
