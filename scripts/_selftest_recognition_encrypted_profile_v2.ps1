# Selftest: Recognition Encrypted Profile v2 (positive + negative vectors)
# Green token: SELFTEST_RECOGNITION_ENCRYPTED_PROFILE_V2_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ProfileScript = Join-Path $PSScriptRoot "recognition_encrypted_profile_v2.ps1"
$ProfileId = "selftest-profile-v2"
$ProfileDir = Join-Path (Join-Path $RepoRoot "profiles") $ProfileId
$pass = 0

function Step([string]$Name,[hashtable]$ScriptArgs,[string]$ExpectedToken){
  $out = & $ProfileScript @ScriptArgs *>&1 | Out-String
  Write-Host $out
  if($out -notmatch [regex]::Escape($ExpectedToken)){
    RC2-Die ("STEP_TOKEN_MISSING[" + $Name + "]: " + $ExpectedToken)
  }
  $script:pass++
  Write-Host ("STEP_OK: " + $Name) -ForegroundColor Green
  return $out
}

function StepFail([string]$Name,[hashtable]$ScriptArgs){
  $failed = $false
  try { & $ProfileScript @ScriptArgs *>&1 | Out-Null } catch { $failed = $true }
  if(-not $failed){ RC2-Die ("STEP_NEGATIVE_DID_NOT_FAIL: " + $Name) }
  $script:pass++
  Write-Host ("NEGATIVE_OK: " + $Name) -ForegroundColor Green
}

# Clean slate
if(Test-Path -LiteralPath $ProfileDir -PathType Container){
  Remove-Item -LiteralPath $ProfileDir -Recurse -Force
}

$env:RECOGNITION_PASSPHRASE = "selftest-pass-" + (RC2-B64 (RC2-RandomBytes 9))

try {
  # init / put / get roundtrip
  Step "init" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="init"} "ENCRYPTED_PROFILE_V2_INIT_OK" | Out-Null
  Step "put"  @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="put"; Key="bookmark.home"; Value="https://example.com/secret-page"} "ENCRYPTED_PROFILE_V2_PUT_OK" | Out-Null

  $getOut = Step "get" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="get"; Key="bookmark.home"} "ENCRYPTED_PROFILE_V2_GET_OK"
  if($getOut -match 'ENCRYPTED_PROFILE_V2_GET_VALUE_B64:\s*(\S+)'){
    $val = (New-Object System.Text.UTF8Encoding($false)).GetString([Convert]::FromBase64String($Matches[1]))
    if($val -ne "https://example.com/secret-page"){ RC2-Die "GET_ROUNDTRIP_VALUE_MISMATCH" }
    $pass++
    Write-Host "CHECK_OK: get_roundtrip_value" -ForegroundColor Green
  } else {
    RC2-Die "GET_VALUE_LINE_MISSING"
  }

  # store on disk must not contain plaintext key names or values
  $storeRaw = Get-Content -Raw -LiteralPath (Join-Path $ProfileDir "store.v2.json") -Encoding UTF8
  if($storeRaw -match 'bookmark\.home' -or $storeRaw -match 'secret-page'){ RC2-Die "PLAINTEXT_LEAK_IN_STORE" }
  $pass++
  Write-Host "CHECK_OK: no_plaintext_in_store" -ForegroundColor Green

  # receipts must not contain plaintext key names or values
  $receiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.encrypted_profile.v2.ndjson"
  $receiptRaw = Get-Content -Raw -LiteralPath $receiptPath -Encoding UTF8
  if($receiptRaw -match 'bookmark\.home' -or $receiptRaw -match 'secret-page'){ RC2-Die "PLAINTEXT_LEAK_IN_RECEIPTS" }
  $pass++
  Write-Host "CHECK_OK: no_plaintext_in_receipts" -ForegroundColor Green

  # verify green
  Step "verify" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="verify"} "ENCRYPTED_PROFILE_V2_VERIFY_OK" | Out-Null

  # update existing key + second key
  Step "put_update" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="put"; Key="bookmark.home"; Value="https://example.com/v2"} "ENCRYPTED_PROFILE_V2_PUT_OK" | Out-Null
  Step "put_second" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="put"; Key="setting.theme"; Value="dark"} "ENCRYPTED_PROFILE_V2_PUT_OK" | Out-Null
  $listOut = Step "list" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="list"} "ENCRYPTED_PROFILE_V2_LIST_OK"
  if($listOut -notmatch 'ENCRYPTED_PROFILE_V2_ITEM_COUNT:\s*2'){ RC2-Die "LIST_COUNT_MISMATCH" }
  $pass++
  Write-Host "CHECK_OK: list_count" -ForegroundColor Green

  # negative: missing key
  StepFail "get_missing_key" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="get"; Key="does.not.exist"}

  # negative: wrong passphrase
  $goodPass = $env:RECOGNITION_PASSPHRASE
  $env:RECOGNITION_PASSPHRASE = "wrong-passphrase"
  StepFail "wrong_passphrase" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="verify"}
  $env:RECOGNITION_PASSPHRASE = $goodPass

  # negative: tampered item ciphertext must fail verify
  $storePath = Join-Path $ProfileDir "store.v2.json"
  $backup = Get-Content -Raw -LiteralPath $storePath -Encoding UTF8
  $storeObj = $backup | ConvertFrom-Json -AsHashtable
  $firstKey = @($storeObj.items.Keys)[0]
  $ctb = [Convert]::FromBase64String([string]$storeObj.items[$firstKey].ct_b64)
  $ctb[0] = $ctb[0] -bxor 0xFF
  $storeObj.items[$firstKey].ct_b64 = [Convert]::ToBase64String($ctb)
  RC2-WriteUtf8NoBomLf $storePath ($storeObj | ConvertTo-Json -Depth 20)
  StepFail "tampered_item_fails_verify" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="verify"}
  RC2-WriteUtf8NoBomLf $storePath $backup
  Step "verify_after_restore" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="verify"} "ENCRYPTED_PROFILE_V2_VERIFY_OK" | Out-Null

  # rekey
  $env:RECOGNITION_PASSPHRASE_NEW = "selftest-new-" + (RC2-B64 (RC2-RandomBytes 9))
  Step "rekey" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="rekey"} "ENCRYPTED_PROFILE_V2_REKEY_OK" | Out-Null
  $env:RECOGNITION_PASSPHRASE = $env:RECOGNITION_PASSPHRASE_NEW
  $env:RECOGNITION_PASSPHRASE_NEW = $null
  Step "verify_after_rekey" @{RepoRoot=$RepoRoot; ProfileId=$ProfileId; Action="verify"} "ENCRYPTED_PROFILE_V2_VERIFY_OK" | Out-Null

} finally {
  $env:RECOGNITION_PASSPHRASE = $null
  $env:RECOGNITION_PASSPHRASE_NEW = $null
  if(Test-Path -LiteralPath $ProfileDir -PathType Container){
    Remove-Item -LiteralPath $ProfileDir -Recurse -Force
  }
}

Write-Host ("SELFTEST_STEPS_PASSED: " + $pass) -ForegroundColor Green
Write-Host "SELFTEST_RECOGNITION_ENCRYPTED_PROFILE_V2_OK" -ForegroundColor Green
