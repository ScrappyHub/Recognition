# Selftest — Recognition Identity Vault / Layer 0 v1 (§9,§27)
# The identity descriptor (identity.json) holds only non-secret, one-way hash
# outputs; the one true secret (the salt) must be DPAPI-sealed at rest, never
# written in cleartext. Verifies: descriptor has no salt field, salt is sealed as
# non-plaintext ciphertext, round-trip unseal recovers a well-formed salt,
# idempotent re-init doesn't touch the sealed file, and negative vectors: missing
# sealed file and tampered sealed file both fail closed. Throwaway repo root.
# Token: SELFTEST_RECOGNITION_IDENTITY_VAULT_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_identity_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("idvault_" + [Guid]::NewGuid().ToString("N"))
}
RCE-EnsureDir $TempRoot

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }

try {
  $P = RID-Paths $TempRoot

  $d1 = RID-EnsureIdentity $TempRoot
  Check (Test-Path -LiteralPath $P.Descriptor) "identity descriptor written"
  Check (Test-Path -LiteralPath $P.SaltEnc) "sealed salt file written"

  $raw = Get-Content -Raw -LiteralPath $P.Descriptor -Encoding UTF8
  Check ($raw -notmatch '"salt"\s*:') "descriptor has no cleartext salt field"
  Check ($raw -match '"salt_sealed"\s*:\s*true') "descriptor marks the salt as sealed"

  $saltBytesLen = (Get-Item -LiteralPath $P.SaltEnc).Length
  Check ($saltBytesLen -gt 32) "sealed salt file is DPAPI ciphertext, not the raw 16-byte salt"

  $salt1 = RID-UnsealSalt $P
  Check ($salt1 -match '^[0-9a-f]{32}$') "unsealed salt is a well-formed 32-hex-char (16-byte) value"

  # idempotent re-init must not touch the sealed salt or regenerate identity
  $sealedBefore = Get-Content -Raw -LiteralPath $P.SaltEnc -Encoding UTF8
  $d2 = RID-EnsureIdentity $TempRoot
  $sealedAfter = Get-Content -Raw -LiteralPath $P.SaltEnc -Encoding UTF8
  Check ((RID-Get $d1 "recognition_identity_id") -eq (RID-Get $d2 "recognition_identity_id")) "re-init is idempotent (same identity)"
  Check ($sealedBefore -eq $sealedAfter) "re-init does not touch the sealed salt"
  $salt2 = RID-UnsealSalt $P
  Check ($salt1 -eq $salt2) "unseal is deterministic across re-init"

  # --- negative: missing sealed file ---
  $backup = [System.IO.File]::ReadAllBytes($P.SaltEnc)
  Remove-Item -LiteralPath $P.SaltEnc -Force
  ShouldThrow { RID-UnsealSalt $P } "missing sealed salt file fails closed"

  # --- negative: tampered sealed file (DPAPI auth fails on modified ciphertext) ---
  $tampered = [byte[]]$backup.Clone()
  $tampered[$tampered.Length - 1] = $tampered[$tampered.Length - 1] -bxor 0xFF
  [System.IO.File]::WriteAllBytes($P.SaltEnc, $tampered)
  ShouldThrow { RID-UnsealSalt $P } "tampered sealed salt fails DPAPI authentication"

  # restore and confirm recovery still works (sanity: our tamper actually mattered)
  [System.IO.File]::WriteAllBytes($P.SaltEnc, $backup)
  $salt3 = RID-UnsealSalt $P
  Check ($salt1 -eq $salt3) "restoring the original ciphertext recovers the original salt"

  # --- legacy migration: an old descriptor with cleartext salt gets sealed + redacted ---
  $legacyRoot = Join-Path $TempRoot "legacy"
  RCE-EnsureDir $legacyRoot
  $LP = RID-Paths $legacyRoot
  RCE-EnsureDir $LP.Dir
  $legacyDescriptor = [ordered]@{
    schema = "recognition.identity.v1"; recognition_identity_id = ("a" * 64)
    device_id = ("b" * 64); user_id = ("c" * 64); vault_id = ("d" * 64)
    created_utc = (RCE-NowUtc); salt = "deadbeefdeadbeefdeadbeefdeadbeef"
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($LP.Descriptor, ((RCE-CanonJson $legacyDescriptor) + "`n"), $enc)
  $migrated = RID-EnsureIdentity $legacyRoot
  Check (Test-Path -LiteralPath $LP.SaltEnc) "legacy migration seals the cleartext salt"
  $legacyRaw = Get-Content -Raw -LiteralPath $LP.Descriptor -Encoding UTF8
  Check ($legacyRaw -notmatch '"salt"\s*:') "legacy descriptor is rewritten without the cleartext salt"
  Check ((RID-UnsealSalt $LP) -eq "deadbeefdeadbeefdeadbeefdeadbeef") "migrated salt unseals to the original value"
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("IDENTITY_VAULT_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_IDENTITY_VAULT_V1_OK" -ForegroundColor Green
