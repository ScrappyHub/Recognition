# FULL GREEN RUNNER — Phase 2 (event hash chain) + Phase 3 (pinned trust root)
#   pwsh -NoProfile -File scripts/RUN_PHASE2_GREEN_V2.ps1 -RepoRoot .
# Final token: RECOGNITION_PHASE2_GREEN_V2_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if($PSVersionTable.PSVersion.Major -lt 7){
  throw "REQUIRES_PWSH7: run this under pwsh 7.2+, not Windows PowerShell 5.1"
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"

function ParseGate([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ throw ("PARSE_MISSING: " + $Path) }
  $tokens=$null; $errors=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e=@($errors)[0]
    throw ("PARSE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
  Write-Host ("PARSE_OK: " + $Path) -ForegroundColor Green
}

foreach($rel in @(
  "_lib_recognition_event_chain_v2.ps1",
  "recognition_event_append_v2.ps1",
  "recognition_verify_event_chain_v2.ps1",
  "recognition_event_chain_migrate_v1_v2.ps1",
  "recognition_verify_attestation_v2.ps1",
  "_selftest_recognition_event_chain_v2.ps1"
)){
  ParseGate (Join-Path $ScriptsDir $rel)
}

Write-Host "=== event_chain_v2 selftest ===" -ForegroundColor Cyan
$out = & (Join-Path $ScriptsDir "_selftest_recognition_event_chain_v2.ps1") -RepoRoot $RepoRoot *>&1 | Out-String
Write-Host $out
if($out -notmatch "SELFTEST_RECOGNITION_EVENT_CHAIN_V2_OK"){ throw "RUNNER_TOKEN_MISSING: event_chain_v2" }
Write-Host "RUNNER_OK: event_chain_v2" -ForegroundColor Green

Write-Host "=== migrate current runtime v1 events to v2 chain ===" -ForegroundColor Cyan
$v1Events = Join-Path (Join-Path $RepoRoot "runtime") "events.ndjson"
$v2Events = Join-Path (Join-Path $RepoRoot "runtime") "events.v2.ndjson"
if((Test-Path -LiteralPath $v1Events -PathType Leaf) -and -not (Test-Path -LiteralPath $v2Events -PathType Leaf)){
  $out = & (Join-Path $ScriptsDir "recognition_event_chain_migrate_v1_v2.ps1") -RepoRoot $RepoRoot -SourcePath $v1Events -OutPath $v2Events *>&1 | Out-String
  Write-Host $out
  if($out -notmatch "RECOGNITION_EVENT_CHAIN_MIGRATE_V2_OK"){ throw "RUNNER_TOKEN_MISSING: runtime_migration" }
}
if(Test-Path -LiteralPath $v2Events -PathType Leaf){
  $out = & (Join-Path $ScriptsDir "recognition_verify_event_chain_v2.ps1") -RepoRoot $RepoRoot -ChainPath $v2Events *>&1 | Out-String
  Write-Host $out
  if($out -notmatch "RECOGNITION_EVENT_CHAIN_VERIFY_V2_OK"){ throw "RUNNER_TOKEN_MISSING: runtime_chain_verify" }
  Write-Host "RUNNER_OK: runtime_chain_v2" -ForegroundColor Green
}

Write-Host "=== attestation verify v2 (pinned trust root) ===" -ForegroundColor Cyan
$out = & (Join-Path $ScriptsDir "recognition_verify_attestation_v2.ps1") -RepoRoot $RepoRoot *>&1 | Out-String
Write-Host $out
if($out -notmatch "RECOGNITION_ATTEST_VERIFY_V2_OK"){ throw "RUNNER_TOKEN_MISSING: attest_verify_v2" }
Write-Host "RUNNER_OK: attest_verify_v2" -ForegroundColor Green

Write-Host "RECOGNITION_PHASE2_GREEN_V2_OK" -ForegroundColor Green
