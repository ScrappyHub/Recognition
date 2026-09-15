# Selftest — Recognition Vault v1
# Roundtrip + negative vectors (tampered object, tampered manifest, wrong
# passphrase, content-hash mismatch, missing object file, rekey survival).
# Runs entirely in a throwaway RepoRoot so it never touches real vaults.
# Green token: RECOGNITION_VAULT_V1_SELFTEST_OK

param(
  [string]$RepoRoot = "",   # accepted for runner compatibility; the test uses its own temp tree
  [string]$TempRoot = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_vault_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("rv1_selftest_" + [Guid]::NewGuid().ToString("N"))
}
RC2-EnsureDir $TempRoot

$script:pass = 0
$script:fail = 0
function Check([bool]$Cond,[string]$Label){
  if($Cond){ $script:pass++; Write-Host ("  ok  - " + $Label) -ForegroundColor Green }
  else     { $script:fail++; Write-Host ("  FAIL- " + $Label) -ForegroundColor Red }
}
function ShouldThrow([scriptblock]$B,[string]$Label){
  $threw = $false
  try { & $B | Out-Null } catch { $threw = $true }
  Check $threw $Label
}

$env:RECOGNITION_PASSPHRASE = "selftest-pass-" + [Guid]::NewGuid().ToString("N")
$VaultId = "selftest"
$P = RV1-Paths $TempRoot $VaultId

try {
  # --- init ---
  RV1-Init $P
  Check (Test-Path -LiteralPath $P.Keystore) "keystore created"
  Check (Test-Path -LiteralPath $P.Manifest) "encrypted manifest created"

  # manifest file must NOT contain the schema of the plaintext manifest in clear
  $manRaw = Get-Content -Raw -LiteralPath $P.Manifest -Encoding UTF8
  Check ($manRaw -notmatch 'recognition\.vault\.manifest\.v1"') "plaintext manifest schema absent from disk (only envelope visible)"

  # --- put text + binary ---
  $master = RV1-OpenMaster $P
  try {
    $textBytes = RC2-Utf8Bytes "https://secret.example/private?token=abc123"
    $r1 = RV1-PutBytes $P $master "runtime/session/session_state.json" $textBytes "runtime-state"
    $bin = RC2-RandomBytes 4096
    $r2 = RV1-PutBytes $P $master "runtime/blob.bin" $bin "bytes"
    Check (([string]$r1.name_hmac).Length -eq 64) "name is HMAC-SHA256 (64 hex)"
    Check ($r1.name_hmac -ne "runtime/session/session_state.json") "logical name not stored in clear"

    # object file on disk must not leak the URL
    $objRaw = Get-Content -Raw -LiteralPath (Join-Path $P.Objects $r1.name_hmac) -Encoding UTF8
    Check ($objRaw -notmatch 'secret\.example') "plaintext URL absent from object file at rest"

    # roundtrip
    $g1 = RV1-GetBytes $P $master "runtime/session/session_state.json"
    Check ((RC2-B64 $g1) -eq (RC2-B64 $textBytes)) "text object roundtrips exactly"
    $g2 = RV1-GetBytes $P $master "runtime/blob.bin"
    Check ((RC2-B64 $g2) -eq (RC2-B64 $bin)) "binary object roundtrips exactly"

    $ver = RV1-Verify $P $master
    Check ($ver.object_count -eq 2 -and $ver.failure_count -eq 0) "verify: 2 objects, 0 failures"
  } finally { RC2-ZeroBytes $master }

  # --- negative: orphan object file not in the manifest (VAULT-1) ---
  $orphan = Join-Path $P.Objects "orphan_not_in_manifest"
  RC2-WriteUtf8NoBomLf $orphan "not-a-governed-object"
  $master = RV1-OpenMaster $P
  try { $ov = RV1-Verify $P $master } finally { RC2-ZeroBytes $master }
  Check ($ov.failure_count -ge 1) "orphan object file detected (VAULT-1)"
  Remove-Item -LiteralPath $orphan -Force

  # --- negative: wrong passphrase ---
  $good = $env:RECOGNITION_PASSPHRASE
  $env:RECOGNITION_PASSPHRASE = "WRONG"
  ShouldThrow { RV1-OpenMaster $P } "wrong passphrase cannot open keystore"
  $env:RECOGNITION_PASSPHRASE = $good

  # --- negative: tampered object ciphertext ---
  # recompute the object's name_hmac to locate its file on disk
  $master2 = RV1-OpenMaster $P
  try {
    $ik = RC2-Hkdf $master2 "vault.index.v1"
    try { $nhBlob = RC2-HmacHex $ik "runtime/blob.bin" } finally { RC2-ZeroBytes $ik }
  } finally { RC2-ZeroBytes $master2 }
  $objPath = Join-Path $P.Objects $nhBlob
  $obj = Get-Content -Raw -LiteralPath $objPath -Encoding UTF8 | ConvertFrom-Json -AsHashtable
  $ct = [Convert]::FromBase64String([string]$obj.blob.ct_b64)
  $ct[0] = $ct[0] -bxor 0xFF
  $obj.blob.ct_b64 = [Convert]::ToBase64String($ct)
  RC2-WriteUtf8NoBomLf $objPath (($obj | ConvertTo-Json -Depth 10))
  $master = RV1-OpenMaster $P
  try {
    $ver = RV1-Verify $P $master
    Check ($ver.failure_count -ge 1) "tampered object ciphertext fails verification"
  } finally { RC2-ZeroBytes $master }

  # --- negative: deleted object file ---
  Remove-Item -LiteralPath $objPath -Force
  $master = RV1-OpenMaster $P
  try {
    $ver = RV1-Verify $P $master
    Check ($ver.failure_count -ge 1) "missing object file fails verification"
  } finally { RC2-ZeroBytes $master }

  # --- negative: tampered manifest envelope ---
  $env2 = Get-Content -Raw -LiteralPath $P.Manifest -Encoding UTF8 | ConvertFrom-Json -AsHashtable
  $mct = [Convert]::FromBase64String([string]$env2.blob.ct_b64)
  $mct[0] = $mct[0] -bxor 0xFF
  $env2.blob.ct_b64 = [Convert]::ToBase64String($mct)
  RC2-WriteUtf8NoBomLf $P.Manifest (($env2 | ConvertTo-Json -Depth 10))
  $master = RV1-OpenMaster $P
  try {
    ShouldThrow { RV1-LoadManifest $P (RC2-Hkdf $master "vault.manifest-enc.v1") } "tampered manifest fails authentication"
  } finally { RC2-ZeroBytes $master }

  # --- rekey survival (fresh vault) ---
  $VaultId2 = "selftest-rekey"
  $P2 = RV1-Paths $TempRoot $VaultId2
  RV1-Init $P2
  $master = RV1-OpenMaster $P2
  try { $null = RV1-PutBytes $P2 $master "k" (RC2-Utf8Bytes "v") "text/utf8" } finally { RC2-ZeroBytes $master }
  RC2-RekeyKeystore $P2.Keystore $env:RECOGNITION_PASSPHRASE "new-pass-xyz"
  $env:RECOGNITION_PASSPHRASE = "new-pass-xyz"
  $master = RV1-OpenMaster $P2
  try {
    $g = RV1-GetBytes $P2 $master "k"
    Check ((New-Object System.Text.UTF8Encoding($false)).GetString($g) -eq "v") "object still decrypts after rekey"
  } finally { RC2-ZeroBytes $master }
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
  Remove-Item Env:\RECOGNITION_PASSPHRASE -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("VAULT_SELFTEST_FAIL: " + $script:fail + " check(s) failed"); exit 1 }
Write-Host "RECOGNITION_VAULT_V1_SELFTEST_OK" -ForegroundColor Green
