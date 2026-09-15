# FULL GREEN RUNNER — Phase 4 (Recognition Vault + runtime-at-rest seal)
# Run under pwsh 7.2+:
#   pwsh -NoProfile -File scripts/RUN_PHASE4_GREEN_V2.ps1 -RepoRoot .
# Parse-gates the vault stack, runs the vault selftest, and runs the pre-publish
# scan gate (read-only). Does NOT touch the real runtime/ or vault/ trees.
# Final token: RECOGNITION_PHASE4_GREEN_V2_OK

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
  "_lib_recognition_crypto_v2.ps1",
  "_lib_recognition_vault_v1.ps1",
  "recognition_vault_v1.ps1",
  "recognition_runtime_seal_v1.ps1",
  "recognition_publish_scan_v1.ps1",
  "recognition_cleanup_litter_v1.ps1",
  "recognition_rotate_attest_key_v1.ps1",
  "recognition_clean_publish_history_v1.ps1",
  "recognition_scrub_receipt_urls_v1.ps1",
  "recognition_prove_all_v1.ps1",
  "_lib_recognition_extension_governance_v1.ps1",
  "recognition_extension_governance_v1.ps1",
  "_selftest_recognition_extension_governance_v1.ps1",
  "_lib_recognition_launch_v1.ps1",
  "recognition_launch_governed_v1.ps1",
  "_selftest_recognition_launch_v1.ps1",
  "recognition_govern_installed_v1.ps1",
  "recognition_cdp_capture_v1.ps1",
  "recognition_v1.ps1",
  "_lib_recognition_history_v1.ps1",
  "recognition_history_v1.ps1",
  "_selftest_recognition_history_v1.ps1",
  "_lib_recognition_chain_anchor_v1.ps1",
  "recognition_chain_anchor_v1.ps1",
  "_selftest_recognition_chain_anchor_v1.ps1",
  "_lib_recognition_identity_v1.ps1",
  "recognition_identity_v1.ps1",
  "_selftest_recognition_identity_v1.ps1",
  "recognition_locked_startup_browser_v1.ps1",
  "RUN_RELEASE_GATE_V1.ps1",
  "RUN_PACKAGE_DIST_V1.ps1",
  "_selftest_recognition_vault_v1.ps1"
)){
  ParseGate (Join-Path $ScriptsDir $rel)
}

# --- vault selftest (self-contained temp tree) ---
# Stream output live via a tee'd log so a mid-run failure is visible (Out-String
# capture would discard everything on a terminating error).
Write-Host "=== vault_v1 selftest ===" -ForegroundColor Cyan
$selftest = Join-Path $ScriptsDir "_selftest_recognition_vault_v1.ps1"
$log = Join-Path ([System.IO.Path]::GetTempPath()) ("rv1_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& $selftest *>&1 | Tee-Object -FilePath $log | Out-Host
$out = if(Test-Path -LiteralPath $log){ Get-Content -Raw -LiteralPath $log } else { "" }
Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
if($out -notmatch [regex]::Escape("RECOGNITION_VAULT_V1_SELFTEST_OK")){
  throw "RUNNER_TOKEN_MISSING[vault_v1]: RECOGNITION_VAULT_V1_SELFTEST_OK"
}
Write-Host "RUNNER_OK: vault_v1" -ForegroundColor Green

# --- extension governance selftest (self-contained temp tree) ---
Write-Host "=== extension_governance_v1 selftest ===" -ForegroundColor Cyan
$egLog = Join-Path ([System.IO.Path]::GetTempPath()) ("eg_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& (Join-Path $ScriptsDir "_selftest_recognition_extension_governance_v1.ps1") *>&1 | Tee-Object -FilePath $egLog | Out-Host
$egOut = if(Test-Path -LiteralPath $egLog){ Get-Content -Raw -LiteralPath $egLog } else { "" }
Remove-Item -LiteralPath $egLog -Force -ErrorAction SilentlyContinue
if($egOut -notmatch [regex]::Escape("SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK")){
  throw "RUNNER_TOKEN_MISSING[extension_governance_v1]: SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK"
}
Write-Host "RUNNER_OK: extension_governance_v1" -ForegroundColor Green

# --- governed launcher selftest (gate logic, no browser) ---
Write-Host "=== launch_v1 selftest ===" -ForegroundColor Cyan
$lgLog = Join-Path ([System.IO.Path]::GetTempPath()) ("lg_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& (Join-Path $ScriptsDir "_selftest_recognition_launch_v1.ps1") *>&1 | Tee-Object -FilePath $lgLog | Out-Host
$lgOut = if(Test-Path -LiteralPath $lgLog){ Get-Content -Raw -LiteralPath $lgLog } else { "" }
Remove-Item -LiteralPath $lgLog -Force -ErrorAction SilentlyContinue
if($lgOut -notmatch [regex]::Escape("SELFTEST_RECOGNITION_LAUNCH_V1_OK")){
  throw "RUNNER_TOKEN_MISSING[launch_v1]: SELFTEST_RECOGNITION_LAUNCH_V1_OK"
}
Write-Host "RUNNER_OK: launch_v1" -ForegroundColor Green

# --- history engine selftest (append-only chain, no browser) ---
Write-Host "=== history_v1 selftest ===" -ForegroundColor Cyan
$hLog = Join-Path ([System.IO.Path]::GetTempPath()) ("hist_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& (Join-Path $ScriptsDir "_selftest_recognition_history_v1.ps1") *>&1 | Tee-Object -FilePath $hLog | Out-Host
$hOut = if(Test-Path -LiteralPath $hLog){ Get-Content -Raw -LiteralPath $hLog } else { "" }
Remove-Item -LiteralPath $hLog -Force -ErrorAction SilentlyContinue
if($hOut -notmatch [regex]::Escape("SELFTEST_RECOGNITION_HISTORY_V1_OK")){
  throw "RUNNER_TOKEN_MISSING[history_v1]: SELFTEST_RECOGNITION_HISTORY_V1_OK"
}
Write-Host "RUNNER_OK: history_v1" -ForegroundColor Green

# --- chain head anchor selftest (CHAIN-1: truncation/rebuild detection) ---
Write-Host "=== chain_anchor_v1 selftest ===" -ForegroundColor Cyan
$caLog = Join-Path ([System.IO.Path]::GetTempPath()) ("ca_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& (Join-Path $ScriptsDir "_selftest_recognition_chain_anchor_v1.ps1") *>&1 | Tee-Object -FilePath $caLog | Out-Host
$caOut = if(Test-Path -LiteralPath $caLog){ Get-Content -Raw -LiteralPath $caLog } else { "" }
Remove-Item -LiteralPath $caLog -Force -ErrorAction SilentlyContinue
if($caOut -notmatch [regex]::Escape("SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK")){
  throw "RUNNER_TOKEN_MISSING[chain_anchor_v1]: SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK"
}
Write-Host "RUNNER_OK: chain_anchor_v1" -ForegroundColor Green

# --- identity receipt chain selftest (WBS 4.1, self-contained, no NeverLost) ---
Write-Host "=== identity_v1 selftest ===" -ForegroundColor Cyan
$idLog = Join-Path ([System.IO.Path]::GetTempPath()) ("id_selftest_" + [Guid]::NewGuid().ToString('N') + ".log")
& (Join-Path $ScriptsDir "_selftest_recognition_identity_v1.ps1") *>&1 | Tee-Object -FilePath $idLog | Out-Host
$idOut = if(Test-Path -LiteralPath $idLog){ Get-Content -Raw -LiteralPath $idLog } else { "" }
Remove-Item -LiteralPath $idLog -Force -ErrorAction SilentlyContinue
if($idOut -notmatch [regex]::Escape("SELFTEST_RECOGNITION_IDENTITY_V1_OK")){
  throw "RUNNER_TOKEN_MISSING[identity_v1]: SELFTEST_RECOGNITION_IDENTITY_V1_OK"
}
Write-Host "RUNNER_OK: identity_v1" -ForegroundColor Green

# --- publish scan gate (read-only) ---
Write-Host "=== publish scan ===" -ForegroundColor Cyan
$scan = & (Join-Path $ScriptsDir "recognition_publish_scan_v1.ps1") -RepoRoot $RepoRoot *>&1 | Out-String
Write-Host $scan
if($scan -match [regex]::Escape("RECOGNITION_PUBLISH_SCAN_V1_OK")){
  Write-Host "RUNNER_OK: publish_scan (tree clean)" -ForegroundColor Green
} else {
  Write-Host "RUNNER_WARN: publish scan reported findings — see above; not gating Phase 4 on it." -ForegroundColor Yellow
}

Write-Host "RECOGNITION_PHASE4_GREEN_V2_OK" -ForegroundColor Green
