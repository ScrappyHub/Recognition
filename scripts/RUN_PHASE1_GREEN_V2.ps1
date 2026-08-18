# FULL GREEN RUNNER — Phase 1 (crypto core v2)
# Run under pwsh 7.2+:
#   pwsh -NoProfile -File scripts/RUN_PHASE1_GREEN_V2.ps1 -RepoRoot .
# Parse-gates all v2 scripts, then runs both selftests.
# Final token: RECOGNITION_PHASE1_GREEN_V2_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if($PSVersionTable.PSVersion.Major -lt 7){
  throw "REQUIRES_PWSH7: run this under pwsh 7.2+, not Windows PowerShell 5.1"
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

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

$ScriptsDir = Join-Path $RepoRoot "scripts"

foreach($rel in @(
  "_lib_recognition_crypto_v2.ps1",
  "recognition_encrypted_profile_v2.ps1",
  "recognition_locked_startup_v2.ps1",
  "recognition_seal_verify_v1.ps1",
  "_selftest_recognition_crypto_v2.ps1",
  "_selftest_recognition_encrypted_profile_v2.ps1"
)){
  ParseGate (Join-Path $ScriptsDir $rel)
}

function RunSelftest([string]$Label,[string]$ScriptName,[string]$ExpectedToken){
  Write-Host ("=== " + $Label + " ===") -ForegroundColor Cyan
  $out = & (Join-Path $ScriptsDir $ScriptName) -RepoRoot $RepoRoot *>&1 | Out-String
  Write-Host $out
  if($out -notmatch [regex]::Escape($ExpectedToken)){
    throw ("RUNNER_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }
  Write-Host ("RUNNER_OK: " + $Label) -ForegroundColor Green
}

RunSelftest "crypto_v2" "_selftest_recognition_crypto_v2.ps1" "SELFTEST_RECOGNITION_CRYPTO_V2_OK"
RunSelftest "encrypted_profile_v2" "_selftest_recognition_encrypted_profile_v2.ps1" "SELFTEST_RECOGNITION_ENCRYPTED_PROFILE_V2_OK"

Write-Host "RECOGNITION_PHASE1_GREEN_V2_OK" -ForegroundColor Green
