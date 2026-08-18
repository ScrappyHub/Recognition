# Recognition Vault v1 — CLI
#
# Encrypted object store. Passphrase from RECOGNITION_PASSPHRASE only (never argv).
# Receipts are append-only and contain no plaintext names, values, or URLs.
#
# Actions:
#   init                                      -> create keystore + empty manifest
#   put   -Name <logical> -InFile <path>      -> store a file's bytes
#   put   -Name <logical> -ValueFromEnv       -> store $env:RECOGNITION_VALUE (utf8)
#   get   -Name <logical> [-OutFile <path>]   -> -OutFile writes plaintext (explicit
#                                                 restore); otherwise prints base64
#   list                                      -> object count + name_hmacs + sizes
#   verify                                    -> decrypt every object, check hash/size
#   rekey                                     -> new passphrase from RECOGNITION_PASSPHRASE_NEW

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$VaultId,
  [Parameter(Mandatory=$true)][string]$Action,
  [string]$Name = "",
  [string]$InFile = "",
  [string]$OutFile = "",
  [switch]$ValueFromEnv,
  [string]$ContentType = "bytes"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_vault_v1.ps1")

$RECEIPT_SCHEMA = "recognition.vault.receipt.v1"
$P = RV1-Paths $RepoRoot $VaultId
$ReceiptPath = Join-Path (Join-Path (Join-Path $P.Repo "proofs") "receipts") "recognition.vault.v1.ndjson"

function Receipt([hashtable]$Fields){
  $obj = [ordered]@{ schema = $RECEIPT_SCHEMA; vault_id = $VaultId }
  foreach($k in $Fields.Keys){ $obj[$k] = $Fields[$k] }
  $obj["ts_utc"] = RC2-NowUtc
  RC2-AppendUtf8NoBomLfLine $ReceiptPath (($obj | ConvertTo-Json -Depth 20 -Compress))
}

if($Action -eq "init"){
  RV1-Init $P
  Receipt @{ action = "init"; encrypted = $true; cipher = "AES-256-GCM"; kdf = "PBKDF2-SHA256" }
  Write-Host ("RECOGNITION_VAULT_V1_INIT_OK: " + $P.VaultDir) -ForegroundColor Green
  exit 0
}

if($Action -eq "put"){
  if([string]::IsNullOrWhiteSpace($Name)){ RV1-Die "PUT_NAME_EMPTY" }
  if($ValueFromEnv){
    $v = $env:RECOGNITION_VALUE
    if($null -eq $v){ RV1-Die "PUT_VALUE_ENV_MISSING: set RECOGNITION_VALUE" }
    $bytes = RC2-Utf8Bytes $v
    if($ContentType -eq "bytes"){ $ContentType = "text/utf8" }
  } elseif(-not [string]::IsNullOrWhiteSpace($InFile)){
    if(-not (Test-Path -LiteralPath $InFile -PathType Leaf)){ RV1-Die ("PUT_INFILE_MISSING: " + $InFile) }
    $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $InFile).Path)
  } else {
    RV1-Die "PUT_NO_INPUT: supply -InFile or -ValueFromEnv"
  }

  $master = RV1-OpenMaster $P
  try {
    $res = RV1-PutBytes $P $master $Name $bytes $ContentType
  } finally { RC2-ZeroBytes $master; RC2-ZeroBytes $bytes }

  Receipt @{ action = "put"; name_hmac = $res.name_hmac; size = $res.size; sha256 = $res.sha256; encrypted = $true }
  Write-Host ("RECOGNITION_VAULT_V1_PUT_OK: " + $res.name_hmac) -ForegroundColor Green
  exit 0
}

if($Action -eq "get"){
  if([string]::IsNullOrWhiteSpace($Name)){ RV1-Die "GET_NAME_EMPTY" }
  $master = RV1-OpenMaster $P
  $persisted = $false
  try {
    $bytes = RV1-GetBytes $P $master $Name
    try {
      if(-not [string]::IsNullOrWhiteSpace($OutFile)){
        $dir = Split-Path -Parent $OutFile
        if($dir){ RC2-EnsureDir $dir }
        [System.IO.File]::WriteAllBytes($OutFile, $bytes)
        $persisted = $true
        Write-Host ("RECOGNITION_VAULT_V1_GET_WROTE: " + $OutFile) -ForegroundColor Green
      } else {
        Write-Output ("RECOGNITION_VAULT_V1_GET_VALUE_B64: " + (RC2-B64 $bytes))
      }
    } finally { RC2-ZeroBytes $bytes }
  } finally { RC2-ZeroBytes $master }

  # name_hmac recomputed for the receipt without exposing the plaintext name
  $master2 = RV1-OpenMaster $P
  try {
    $ik = RC2-Hkdf $master2 "vault.index.v1"
    try { $nh = RC2-HmacHex $ik $Name } finally { RC2-ZeroBytes $ik }
  } finally { RC2-ZeroBytes $master2 }
  Receipt @{ action = "get"; name_hmac = $nh; encrypted = $true; plaintext_persisted = $persisted }
  Write-Host "RECOGNITION_VAULT_V1_GET_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "list"){
  $master = RV1-OpenMaster $P
  try {
    $meta = RV1-ListMeta $P $master
  } finally { RC2-ZeroBytes $master }
  $count = @($meta).Count
  Write-Output ("RECOGNITION_VAULT_V1_OBJECT_COUNT: " + $count)
  foreach($o in $meta){
    Write-Output ("  " + [string]$o.name_hmac + "  size=" + [string]$o.size + "  type=" + [string]$o.content_type)
  }
  Write-Host "RECOGNITION_VAULT_V1_LIST_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  $master = RV1-OpenMaster $P
  try {
    $r = RV1-Verify $P $master
  } finally { RC2-ZeroBytes $master }
  if($r.failure_count -gt 0){
    Receipt @{ action = "verify"; object_count = $r.object_count; failures = $r.failure_count; all_authenticated = $false }
    RV1-Die ("VAULT_VERIFY_FAIL: " + $r.failure_count + " of " + $r.object_count + " objects failed")
  }
  Receipt @{ action = "verify"; object_count = $r.object_count; failures = 0; all_authenticated = $true }
  Write-Host ("RECOGNITION_VAULT_V1_VERIFY_OK: objects=" + $r.object_count) -ForegroundColor Green
  exit 0
}

if($Action -eq "rekey"){
  $oldPass = RC2-GetPassphrase
  $newPass = $env:RECOGNITION_PASSPHRASE_NEW
  if([string]::IsNullOrEmpty($newPass)){ RV1-Die "REKEY_NEW_PASSPHRASE_MISSING: set RECOGNITION_PASSPHRASE_NEW" }
  RC2-RekeyKeystore $P.Keystore $oldPass $newPass
  Receipt @{ action = "rekey"; encrypted = $true }
  Write-Host "RECOGNITION_VAULT_V1_REKEY_OK" -ForegroundColor Green
  exit 0
}

RV1-Die ("VAULT_UNKNOWN_ACTION: " + $Action)
