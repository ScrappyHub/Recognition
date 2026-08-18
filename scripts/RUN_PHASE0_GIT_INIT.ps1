# Phase 0 — one-time git bootstrap (run on Windows, any PowerShell)
#   powershell -NoProfile -File scripts\RUN_PHASE0_GIT_INIT.ps1 -RepoRoot .
# Token: RECOGNITION_PHASE0_GIT_INIT_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
Set-Location -LiteralPath $RepoRoot

$git = (Get-Command git -CommandType Application -ErrorAction Stop).Source

if(Test-Path -LiteralPath (Join-Path $RepoRoot ".git") -PathType Container){
  Write-Host "GIT_ALREADY_INITIALIZED" -ForegroundColor Yellow
} else {
  & $git init -b main
  if($LASTEXITCODE -ne 0){ throw "GIT_INIT_FAIL" }
}

& $git config core.autocrlf false
& $git add -A
if($LASTEXITCODE -ne 0){ throw "GIT_ADD_FAIL" }

& $git commit -m "Recognition: initial commit - canonical spec, audit v1, crypto core v2 (Phase 0+1)" `
  -m "docs: CANONICAL_HANDOFF_V1.md + RECOGNITION_AUDIT_V1.md; .gitignore for volatile/plaintext areas; seal verify promoted out of _scratch (F7); crypto core v2: AES-256-GCM, PBKDF2-SHA256 KEK, wrapped per-profile master key, HKDF domain subkeys, per-object nonces (F2); encrypted profile v2: per-item encryption, HMAC name index, secrets via env not argv, no plaintext output files (F1/F3); locked startup v2; selftests with negative vectors; removed leaked plaintext selftest artifact."
if($LASTEXITCODE -ne 0){ throw "GIT_COMMIT_FAIL" }

& $git log --oneline -1
Write-Host "RECOGNITION_PHASE0_GIT_INIT_OK" -ForegroundColor Green
