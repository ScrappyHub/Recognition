# Selftest: Recognition Crypto Core v2 (positive + negative vectors)
# Green token: SELFTEST_RECOGNITION_CRYPTO_V2_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$pass = 0

function Check([string]$Name,[bool]$Cond){
  if(-not $Cond){ RC2-Die ("SELFTEST_CHECK_FAIL: " + $Name) }
  $script:pass++
  Write-Host ("CHECK_OK: " + $Name) -ForegroundColor Green
}

function ExpectFail([string]$Name,[scriptblock]$Block){
  $failed = $false
  try { & $Block | Out-Null } catch { $failed = $true }
  if(-not $failed){ RC2-Die ("SELFTEST_NEGATIVE_DID_NOT_FAIL: " + $Name) }
  $script:pass++
  Write-Host ("NEGATIVE_OK: " + $Name) -ForegroundColor Green
}

# 1. KDF determinism + salt sensitivity
$salt1 = RC2-FromB64 "AAAAAAAAAAAAAAAAAAAAAA=="
$salt2 = RC2-FromB64 "AQAAAAAAAAAAAAAAAAAAAA=="
$k1 = RC2-DeriveKek "test-passphrase" $salt1 100000
$k2 = RC2-DeriveKek "test-passphrase" $salt1 100000
$k3 = RC2-DeriveKek "test-passphrase" $salt2 100000
Check "kdf_deterministic" ((RC2-B64 $k1) -eq (RC2-B64 $k2))
Check "kdf_salt_sensitive" ((RC2-B64 $k1) -ne (RC2-B64 $k3))
ExpectFail "kdf_low_iterations_rejected" { RC2-DeriveKek "x" $salt1 1000 }

# 2. HKDF label separation
$ikm = RC2-RandomBytes 32
$h1 = RC2-Hkdf $ikm "label.a"
$h2 = RC2-Hkdf $ikm "label.a"
$h3 = RC2-Hkdf $ikm "label.b"
Check "hkdf_deterministic" ((RC2-B64 $h1) -eq (RC2-B64 $h2))
Check "hkdf_label_separation" ((RC2-B64 $h1) -ne (RC2-B64 $h3))

# 3. GCM roundtrip
$key = RC2-RandomBytes 32
$blob = RC2-GcmEncryptText $key "recognition secret payload" "aad.domain.1"
$out = RC2-GcmDecryptText $key $blob.nonce_b64 $blob.ct_b64 $blob.tag_b64 "aad.domain.1"
Check "gcm_roundtrip" ($out -eq "recognition secret payload")

# 4. GCM negative vectors: tamper ct, tamper tag, wrong AAD, wrong key
$ctBytes = RC2-FromB64 $blob.ct_b64
$ctBytes[0] = $ctBytes[0] -bxor 0xFF
$tamperedCt = RC2-B64 $ctBytes
ExpectFail "gcm_ct_tamper_fails" { RC2-GcmDecryptText $key $blob.nonce_b64 $tamperedCt $blob.tag_b64 "aad.domain.1" }

$tagBytes = RC2-FromB64 $blob.tag_b64
$tagBytes[0] = $tagBytes[0] -bxor 0xFF
$tamperedTag = RC2-B64 $tagBytes
ExpectFail "gcm_tag_tamper_fails" { RC2-GcmDecryptText $key $blob.nonce_b64 $blob.ct_b64 $tamperedTag "aad.domain.1" }

ExpectFail "gcm_wrong_aad_fails" { RC2-GcmDecryptText $key $blob.nonce_b64 $blob.ct_b64 $blob.tag_b64 "aad.domain.WRONG" }

$wrongKey = RC2-RandomBytes 32
ExpectFail "gcm_wrong_key_fails" { RC2-GcmDecryptText $wrongKey $blob.nonce_b64 $blob.ct_b64 $blob.tag_b64 "aad.domain.1" }

# 5. Nonce uniqueness across encryptions
$b1 = RC2-GcmEncryptText $key "same plaintext" "aad"
$b2 = RC2-GcmEncryptText $key "same plaintext" "aad"
Check "gcm_nonce_unique" ($b1.nonce_b64 -ne $b2.nonce_b64)
Check "gcm_ct_differs_per_nonce" ($b1.ct_b64 -ne $b2.ct_b64)

# 6. Keystore lifecycle
$tmpDir = Join-Path $RepoRoot (Join-Path "tmp" ("selftest_crypto_v2_" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmssfff")))
RC2-EnsureDir $tmpDir
$ksPath = Join-Path $tmpDir "keystore.v2.json"

$master1 = RC2-NewKeystore $ksPath "correct-horse"
$master2 = RC2-OpenKeystore $ksPath "correct-horse"
Check "keystore_roundtrip" ((RC2-B64 $master1) -eq (RC2-B64 $master2))
Check "keystore_master_len" ($master1.Length -eq 32)

ExpectFail "keystore_wrong_passphrase_fails" { RC2-OpenKeystore $ksPath "battery-staple" }
ExpectFail "keystore_double_init_fails" { RC2-NewKeystore $ksPath "x" }

# 7. Keystore tamper (flip a wrapped-ct byte)
$ksRaw = Get-Content -Raw -LiteralPath $ksPath -Encoding UTF8 | ConvertFrom-Json
$wb = RC2-FromB64 ([string]$ksRaw.wrap.ct_b64)
$wb[0] = $wb[0] -bxor 0xFF
$ksRaw.wrap.ct_b64 = RC2-B64 $wb
RC2-WriteUtf8NoBomLf $ksPath ($ksRaw | ConvertTo-Json -Depth 10)
ExpectFail "keystore_tamper_fails" { RC2-OpenKeystore $ksPath "correct-horse" }

# 8. Rekey
Remove-Item -LiteralPath $ksPath -Force
$masterA = RC2-NewKeystore $ksPath "old-pass"
RC2-RekeyKeystore $ksPath "old-pass" "new-pass"
$masterB = RC2-OpenKeystore $ksPath "new-pass"
Check "rekey_preserves_master" ((RC2-B64 $masterA) -eq (RC2-B64 $masterB))
ExpectFail "rekey_old_passphrase_dead" { RC2-OpenKeystore $ksPath "old-pass" }

# Cleanup
Remove-Item -LiteralPath $tmpDir -Recurse -Force

# Receipt
$receipt = [ordered]@{
  schema = "recognition.crypto.selftest.receipt.v2"
  checks_passed = $pass
  cipher = "AES-256-GCM"
  kdf = "PBKDF2-SHA256"
  ts_utc = RC2-NowUtc
}
RC2-AppendUtf8NoBomLfLine (Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.crypto.v2.ndjson") (($receipt | ConvertTo-Json -Depth 10 -Compress))

Write-Host ("SELFTEST_CHECKS_PASSED: " + $pass) -ForegroundColor Green
Write-Host "SELFTEST_RECOGNITION_CRYPTO_V2_OK" -ForegroundColor Green
