param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
    Die ("PARSE_MISSING: " + $Path)
  }

  $tokens=$null
  $errors=$null

  [void][System.Management.Automation.Language.Parser]::ParseFile(
    $Path,
    [ref]$tokens,
    [ref]$errors
  )

  if($errors -and @($errors).Count -gt 0){
    $e=@($errors)[0]
    Die ("PARSE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }

  Write-Host ("PARSE_OK: " + $Path) -ForegroundColor Green
}

function RunCapture {
  param(
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ExpectedToken
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $RunDir = Join-Path $RepoRoot "proofs\runs\recognition_runtime_bridge_seal_verify_v1"

  if(-not (Test-Path -LiteralPath $RunDir -PathType Container)){
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
  }

  $stdout = Join-Path $RunDir ($Label + ".stdout.txt")
  $stderr = Join-Path $RunDir ($Label + ".stderr.txt")

  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $p = Start-Process `
    -FilePath $PSExe `
    -ArgumentList @(
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy","Bypass",
      "-File",$ScriptPath,
      "-RepoRoot",$RepoRoot
    ) `
    -Wait `
    -PassThru `
    -NoNewWindow `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr

  $out = ""
  $err = ""

  if(Test-Path -LiteralPath $stdout -PathType Leaf){
    $out = Get-Content -Raw -LiteralPath $stdout -Encoding UTF8
  }

  if(Test-Path -LiteralPath $stderr -PathType Leaf){
    $err = Get-Content -Raw -LiteralPath $stderr -Encoding UTF8
  }

  if($out){ [Console]::Out.Write($out) }
  if($err){ [Console]::Error.Write($err) }

  if([int]$p.ExitCode -ne 0){
    Die ("RUN_FAIL[" + $Label + "]: " + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ("CAPTURE_OK: " + $Label) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$required = @(
  "scripts\recognition_runtime_bridge_event_v1.ps1",
  "scripts\recognition_runtime_session_open_v1.ps1",
  "scripts\recognition_runtime_tab_open_v1.ps1",
  "scripts\recognition_runtime_navigation_commit_v1.ps1",
  "scripts\recognition_runtime_export_from_runtime_v1.ps1",
  "scripts\recognition_runtime_replay_from_events_v1.ps1",
  "scripts\recognition_export_session_packet_v1.ps1",
  "scripts\pc_verify_packet_optionA_v1.ps1",
  "scripts\recognition_verify_runtime_bridge_attestation_v1.ps1",
  "scripts\recognition_runtime_timeline_materialize_v1.ps1",
  "scripts\recognition_verify_runtime_timeline_v1.ps1",
  "scripts\recognition_validate_runtime_workbench_v1.ps1",
  "scripts\_scratch\FREEZE_RECOGNITION_RUNTIME_WORKBENCH_V1.ps1",
  "scripts\_scratch\FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1.ps1",
  "scripts\_scratch\RUN_RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1.ps1",
  "scripts\_scratch\RUN_bridge_failhard_validate_v1.ps1",
  "scripts\_scratch\FREEZE_RECOGNITION_RUNTIME_V1.ps1",
  "scripts\_scratch\FREEZE_RECOGNITION_RUNTIME_BRIDGE_V1.ps1",
  "scripts\_scratch\RUN_RECOGNITION_RUNTIME_BRIDGE_ATTEST_V1.ps1"
)

foreach($rel in @($required)){
  ParseGateFile (Join-Path $RepoRoot $rel)
}

RunCapture `
  -Label "attestation_verify" `
  -ScriptPath (Join-Path $RepoRoot "scripts\recognition_verify_runtime_bridge_attestation_v1.ps1") `
  -ExpectedToken "RECOGNITION_RUNTIME_BRIDGE_ATTEST_VERIFY_V1_OK"

RunCapture `
  -Label "timeline_verify" `
  -ScriptPath (Join-Path $RepoRoot "scripts\recognition_verify_runtime_timeline_v1.ps1") `
  -ExpectedToken "RECOGNITION_RUNTIME_TIMELINE_VERIFY_V1_OK"

RunCapture `
  -Label "workbench_validate" `
  -ScriptPath (Join-Path $RepoRoot "scripts\recognition_validate_runtime_workbench_v1.ps1") `
  -ExpectedToken "RECOGNITION_RUNTIME_WORKBENCH_VALIDATE_V1_OK"

$SealIndex = Join-Path $RepoRoot "proofs\seal_index\recognition_runtime_bridge_seal_index_v1.json"
if(-not (Test-Path -LiteralPath $SealIndex -PathType Leaf)){
  Die ("SEAL_INDEX_MISSING: " + $SealIndex)
}

$idx = Get-Content -Raw -LiteralPath $SealIndex -Encoding UTF8 | ConvertFrom-Json
$tokens = @($idx.tokens)

foreach($tok in @(
  "RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1_OK",
  "FREEZE_RECOGNITION_RUNTIME_WORKBENCH_V1_OK"
)){
  if($tokens -notcontains $tok){
    Die ("SEAL_INDEX_TOKEN_MISSING: " + $tok)
  }
}

if([string]::IsNullOrWhiteSpace([string]$idx.workbench_freeze_bundle)){
  Die "SEAL_INDEX_WORKBENCH_FREEZE_BUNDLE_MISSING"
}

Write-Host "RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1_OK" -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_FULL_SEALED_WORKBENCH_V1_OK" -ForegroundColor Green
