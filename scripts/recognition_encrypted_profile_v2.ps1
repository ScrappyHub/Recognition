# Recognition Encrypted Profile v2
# AES-256-GCM per-object encryption on a wrapped per-profile master key.
# Passphrase comes from RECOGNITION_PASSPHRASE env var — never from argv.
# Key names are stored as HMAC-SHA256 (encrypted index); receipts never contain
# plaintext names or values. `get` prints the value to stdout only; it never
# writes plaintext files.
#
# Actions: init | put | get | list | verify | rekey
#   put:  -Key <name> -Value <value>   (or -ValueFromEnv RECOGNITION_VALUE)
#   get:  -Key <name>                  -> "ENCRYPTED_PROFILE_V2_GET_VALUE_B64: <b64>"
#   rekey: new passphrase from RECOGNITION_PASSPHRASE_NEW

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ProfileId,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$false)][string]$Key = "",
  [Parameter(Mandatory=$false)][string]$Value = "",
  [Parameter(Mandatory=$false)][switch]$ValueFromEnv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")

$STORE_SCHEMA = "recognition.profile.store.v2"
$RECEIPT_SCHEMA = "recognition.encrypted_profile.receipt.v2"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if($ProfileId -notmatch '^[A-Za-z0-9_.-]+$'){ RC2-Die "PROFILE_BAD_ID" }

$ProfileDir   = Join-Path (Join-Path $RepoRoot "profiles") $ProfileId
$KeystorePath = Join-Path $ProfileDir "keystore.v2.json"
$StorePath    = Join-Path $ProfileDir "store.v2.json"
$ReceiptPath  = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.encrypted_profile.v2.ndjson"

function ItemAad([string]$NameHmac){ return ("recognition.profile.item.v2/" + $NameHmac) }

function Receipt([hashtable]$Fields){
  $obj = [ordered]@{ schema = $RECEIPT_SCHEMA; profile_id = $ProfileId }
  foreach($k in $Fields.Keys){ $obj[$k] = $Fields[$k] }
  $obj["ts_utc"] = RC2-NowUtc
  RC2-AppendUtf8NoBomLfLine $ReceiptPath (($obj | ConvertTo-Json -Depth 20 -Compress))
}

function LoadStore(){
  if(-not (Test-Path -LiteralPath $StorePath -PathType Leaf)){ RC2-Die ("PROFILE_STORE_MISSING: " + $StorePath) }
  $s = Get-Content -Raw -LiteralPath $StorePath -Encoding UTF8 | ConvertFrom-Json -AsHashtable
  if([string]$s.schema -ne $STORE_SCHEMA){ RC2-Die ("PROFILE_BAD_STORE_SCHEMA: " + [string]$s.schema) }
  if($null -eq $s.items){ $s.items = @{} }
  return $s
}

function SaveStore([hashtable]$Store){
  $Store.updated_utc = RC2-NowUtc
  RC2-WriteUtf8NoBomLf $StorePath ($Store | ConvertTo-Json -Depth 20)
}

function OpenMaster(){
  $pass = RC2-GetPassphrase
  return RC2-OpenKeystore $KeystorePath $pass
}

# ---------------------------------------------------------------------------

if($Action -eq "init"){
  if(Test-Path -LiteralPath $KeystorePath -PathType Leaf){ RC2-Die ("PROFILE_ALREADY_EXISTS: " + $ProfileId) }
  RC2-EnsureDir $ProfileDir

  $pass = RC2-GetPassphrase
  $master = RC2-NewKeystore $KeystorePath $pass
  RC2-ZeroBytes $master

  $store = [ordered]@{
    schema      = $STORE_SCHEMA
    profile_id  = $ProfileId
    cipher      = "AES-256-GCM"
    created_utc = RC2-NowUtc
    updated_utc = RC2-NowUtc
    items       = [ordered]@{}
  }
  RC2-WriteUtf8NoBomLf $StorePath ($store | ConvertTo-Json -Depth 20)

  Receipt @{ action = "init"; encrypted = $true; cipher = "AES-256-GCM"; kdf = "PBKDF2-SHA256" }
  Write-Host ("ENCRYPTED_PROFILE_V2_INIT_OK: " + $ProfileDir) -ForegroundColor Green
  exit 0
}

if($Action -eq "put"){
  if([string]::IsNullOrWhiteSpace($Key)){ RC2-Die "PUT_KEY_EMPTY" }
  if($ValueFromEnv){
    $Value = $env:RECOGNITION_VALUE
    if($null -eq $Value){ RC2-Die "PUT_VALUE_ENV_MISSING: set RECOGNITION_VALUE" }
  }

  $master = OpenMaster
  try {
    $indexKey = RC2-Hkdf $master "profile.index.v2"
    $encKey   = RC2-Hkdf $master "profile.item-enc.v2"
    try {
      $nameHmac = RC2-HmacHex $indexKey $Key
      $plain = ([ordered]@{ name = $Key; value = $Value } | ConvertTo-Json -Depth 5 -Compress)
      $blob = RC2-GcmEncryptText $encKey $plain (ItemAad $nameHmac)

      $store = LoadStore
      $store.items[$nameHmac] = $blob
      SaveStore $store
    } finally { RC2-ZeroBytes $indexKey; RC2-ZeroBytes $encKey }
  } finally { RC2-ZeroBytes $master }

  Receipt @{ action = "put"; name_hmac = $nameHmac; encrypted = $true }
  Write-Host ("ENCRYPTED_PROFILE_V2_PUT_OK: " + $nameHmac) -ForegroundColor Green
  exit 0
}

if($Action -eq "get"){
  if([string]::IsNullOrWhiteSpace($Key)){ RC2-Die "GET_KEY_EMPTY" }

  $master = OpenMaster
  try {
    $indexKey = RC2-Hkdf $master "profile.index.v2"
    $encKey   = RC2-Hkdf $master "profile.item-enc.v2"
    try {
      $nameHmac = RC2-HmacHex $indexKey $Key
      $store = LoadStore
      if(-not $store.items.ContainsKey($nameHmac)){ RC2-Die "GET_KEY_MISSING" }
      $blob = $store.items[$nameHmac]
      $plain = RC2-GcmDecryptText $encKey ([string]$blob.nonce_b64) ([string]$blob.ct_b64) ([string]$blob.tag_b64) (ItemAad $nameHmac)
      $obj = $plain | ConvertFrom-Json
      if([string]$obj.name -ne $Key){ RC2-Die "GET_NAME_BINDING_MISMATCH" }
      $valB64 = RC2-B64 (RC2-Utf8Bytes ([string]$obj.value))
      # stdout only — never persisted by this script. Callers must not log this line.
      Write-Output ("ENCRYPTED_PROFILE_V2_GET_VALUE_B64: " + $valB64)
    } finally { RC2-ZeroBytes $indexKey; RC2-ZeroBytes $encKey }
  } finally { RC2-ZeroBytes $master }

  Receipt @{ action = "get"; name_hmac = $nameHmac; encrypted = $true; plaintext_persisted = $false }
  Write-Host "ENCRYPTED_PROFILE_V2_GET_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "list"){
  $store = LoadStore
  $count = @($store.items.Keys).Count
  Write-Output ("ENCRYPTED_PROFILE_V2_ITEM_COUNT: " + $count)
  Write-Host "ENCRYPTED_PROFILE_V2_LIST_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  $master = OpenMaster
  $failures = 0
  $count = 0
  try {
    $encKey = RC2-Hkdf $master "profile.item-enc.v2"
    try {
      $store = LoadStore
      foreach($nameHmac in @($store.items.Keys)){
        $count++
        $blob = $store.items[$nameHmac]
        try {
          $null = RC2-GcmDecryptText $encKey ([string]$blob.nonce_b64) ([string]$blob.ct_b64) ([string]$blob.tag_b64) (ItemAad $nameHmac)
        } catch {
          $failures++
          Write-Host ("ENCRYPTED_PROFILE_V2_ITEM_FAIL: " + $nameHmac) -ForegroundColor Red
        }
      }
    } finally { RC2-ZeroBytes $encKey }
  } finally { RC2-ZeroBytes $master }

  if($failures -gt 0){ RC2-Die ("VERIFY_FAIL: " + $failures + " of " + $count + " items failed authentication") }

  Receipt @{ action = "verify"; item_count = $count; encrypted = $true; all_authenticated = $true }
  Write-Host ("ENCRYPTED_PROFILE_V2_VERIFY_OK: items=" + $count) -ForegroundColor Green
  exit 0
}

if($Action -eq "rekey"){
  $oldPass = RC2-GetPassphrase
  $newPass = $env:RECOGNITION_PASSPHRASE_NEW
  if([string]::IsNullOrEmpty($newPass)){ RC2-Die "REKEY_NEW_PASSPHRASE_MISSING: set RECOGNITION_PASSPHRASE_NEW" }

  RC2-RekeyKeystore $KeystorePath $oldPass $newPass

  Receipt @{ action = "rekey"; encrypted = $true }
  Write-Host "ENCRYPTED_PROFILE_V2_REKEY_OK" -ForegroundColor Green
  exit 0
}

RC2-Die ("PROFILE_UNKNOWN_ACTION: " + $Action)
