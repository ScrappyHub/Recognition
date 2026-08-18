param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ProfileId,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$Passphrase,
  [Parameter(Mandatory=$false)][string]$Key = "",
  [Parameter(Mandatory=$false)][string]$Value = "",
  [Parameter(Mandatory=$false)][string]$OutPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function AppendReceipt([string]$RepoRoot,[object]$Obj){
  $path = Join-Path $RepoRoot "proofs\receipts\recognition.encrypted_profile.v1.ndjson"
  $dir = Split-Path -Parent $path
  EnsureDir $dir
  $enc = New-Object System.Text.UTF8Encoding($false)
  $line = ($Obj | ConvertTo-Json -Depth 40 -Compress) + "`n"
  [System.IO.File]::AppendAllText($path,$line,$enc)
  Write-Host ("ENCRYPTED_PROFILE_RECEIPT_OK: " + $path) -ForegroundColor Green
}

function RandomBytes([int]$Count){
  $b = New-Object byte[] $Count
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($b) } finally { $rng.Dispose() }
  return $b
}

function ConcatBytes([byte[]]$A,[byte[]]$B,[byte[]]$C){
  $out = New-Object byte[] ($A.Length + $B.Length + $C.Length)
  [Buffer]::BlockCopy($A,0,$out,0,$A.Length)
  [Buffer]::BlockCopy($B,0,$out,$A.Length,$B.Length)
  [Buffer]::BlockCopy($C,0,$out,($A.Length+$B.Length),$C.Length)
  return $out
}

function DeriveKeys([string]$Passphrase,[byte[]]$Salt){
  $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase,$Salt,200000)
  $bytes = $kdf.GetBytes(64)
  $encKey = New-Object byte[] 32
  $macKey = New-Object byte[] 32
  [Buffer]::BlockCopy($bytes,0,$encKey,0,32)
  [Buffer]::BlockCopy($bytes,32,$macKey,0,32)
  return @{ enc=$encKey; mac=$macKey }
}

function ProtectText([string]$Passphrase,[string]$PlainText){
  $salt = RandomBytes 32
  $iv = RandomBytes 16
  $keys = DeriveKeys $Passphrase $salt

  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $keys.enc
  $aes.IV = $iv

  $plainBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($PlainText)
  $enc = $aes.CreateEncryptor()
  $cipher = $enc.TransformFinalBlock($plainBytes,0,$plainBytes.Length)

  $macInput = ConcatBytes $salt $iv $cipher
  $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$keys.mac)
  $mac = $hmac.ComputeHash($macInput)

  return [ordered]@{
    schema = "recognition.encrypted_profile.store.v1"
    cipher = "AES-256-CBC-HMAC-SHA256"
    kdf = "PBKDF2-SHA1-200000"
    salt_b64 = [Convert]::ToBase64String($salt)
    iv_b64 = [Convert]::ToBase64String($iv)
    ciphertext_b64 = [Convert]::ToBase64String($cipher)
    mac_b64 = [Convert]::ToBase64String($mac)
    updated_utc = (Get-Date).ToUniversalTime().ToString("o")
  }
}

function UnprotectText([string]$Passphrase,[object]$Store){
  $salt = [Convert]::FromBase64String([string]$Store.salt_b64)
  $iv = [Convert]::FromBase64String([string]$Store.iv_b64)
  $cipher = [Convert]::FromBase64String([string]$Store.ciphertext_b64)
  $expectedMac = [Convert]::FromBase64String([string]$Store.mac_b64)

  $keys = DeriveKeys $Passphrase $salt
  $macInput = ConcatBytes $salt $iv $cipher
  $hmac = [System.Security.Cryptography.HMACSHA256]::new([byte[]]$keys.mac)
  $actualMac = $hmac.ComputeHash($macInput)

  if([Convert]::ToBase64String($actualMac) -ne [Convert]::ToBase64String($expectedMac)){
    Die "ENCRYPTED_PROFILE_MAC_VERIFY_FAIL"
  }

  $aes = New-Object System.Security.Cryptography.AesManaged
  $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
  $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $keys.enc
  $aes.IV = $iv

  $dec = $aes.CreateDecryptor()
  $plain = $dec.TransformFinalBlock($cipher,0,$cipher.Length)
  return (New-Object System.Text.UTF8Encoding($false)).GetString($plain)
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if($ProfileId -notmatch '^[A-Za-z0-9_.-]+$'){
  Die "ENCRYPTED_PROFILE_BAD_PROFILE_ID"
}

$ProfileDir = Join-Path $RepoRoot ("profiles\" + $ProfileId)
$StorePath = Join-Path $ProfileDir "encrypted.store.json"
$MetaPath = Join-Path $ProfileDir "profile.meta.json"

EnsureDir $ProfileDir

if($Action -eq "init"){
  if(Test-Path -LiteralPath $StorePath -PathType Leaf){
    Die ("ENCRYPTED_PROFILE_ALREADY_EXISTS: " + $ProfileId)
  }

  $vault = [ordered]@{
    schema = "recognition.profile.vault.v1"
    profile_id = $ProfileId
    created_utc = (Get-Date).ToUniversalTime().ToString("o")
    items = [ordered]@{}
  }

  $plain = $vault | ConvertTo-Json -Depth 50
  $store = ProtectText $Passphrase $plain

  WriteUtf8NoBomLf $StorePath ($store | ConvertTo-Json -Depth 50)

  $meta = [ordered]@{
    schema = "recognition.profile.meta.v1"
    profile_id = $ProfileId
    encrypted = $true
    store = "encrypted.store.json"
    created_utc = $vault.created_utc
  }

  WriteUtf8NoBomLf $MetaPath ($meta | ConvertTo-Json -Depth 20)

  AppendReceipt $RepoRoot ([ordered]@{
    schema = "recognition.encrypted_profile.receipt.v1"
    action = "init"
    profile_id = $ProfileId
    encrypted = $true
    ts_utc = (Get-Date).ToUniversalTime().ToString("o")
  })

  Write-Host ("ENCRYPTED_PROFILE_INIT_OK: " + $ProfileDir) -ForegroundColor Green
  exit 0
}

if(-not (Test-Path -LiteralPath $StorePath -PathType Leaf)){
  Die ("ENCRYPTED_PROFILE_STORE_MISSING: " + $StorePath)
}

$storeObj = Get-Content -Raw -LiteralPath $StorePath -Encoding UTF8 | ConvertFrom-Json
$plainText = UnprotectText $Passphrase $storeObj
$vaultObj = $plainText | ConvertFrom-Json

$items = [ordered]@{}
foreach($p in @($vaultObj.items.PSObject.Properties)){
  $items[$p.Name] = [string]$p.Value
}

if($Action -eq "put"){
  if([string]::IsNullOrWhiteSpace($Key)){ Die "ENCRYPTED_PROFILE_PUT_KEY_EMPTY" }

  $items[$Key] = $Value

  $vault = [ordered]@{
    schema = "recognition.profile.vault.v1"
    profile_id = $ProfileId
    created_utc = [string]$vaultObj.created_utc
    items = $items
  }

  $store = ProtectText $Passphrase ($vault | ConvertTo-Json -Depth 50)
  WriteUtf8NoBomLf $StorePath ($store | ConvertTo-Json -Depth 50)

  AppendReceipt $RepoRoot ([ordered]@{
    schema = "recognition.encrypted_profile.receipt.v1"
    action = "put"
    profile_id = $ProfileId
    key = $Key
    encrypted = $true
    ts_utc = (Get-Date).ToUniversalTime().ToString("o")
  })

  Write-Host ("ENCRYPTED_PROFILE_PUT_OK: " + $Key) -ForegroundColor Green
  exit 0
}

if($Action -eq "get"){
  if([string]::IsNullOrWhiteSpace($Key)){ Die "ENCRYPTED_PROFILE_GET_KEY_EMPTY" }
  if(-not $items.Contains($Key)){ Die ("ENCRYPTED_PROFILE_KEY_MISSING: " + $Key) }

  if([string]::IsNullOrWhiteSpace($OutPath)){
    Die "ENCRYPTED_PROFILE_GET_OUTPATH_EMPTY"
  }

  WriteUtf8NoBomLf $OutPath ([string]$items[$Key])

  AppendReceipt $RepoRoot ([ordered]@{
    schema = "recognition.encrypted_profile.receipt.v1"
    action = "get"
    profile_id = $ProfileId
    key = $Key
    encrypted = $true
    wrote_output = $true
    ts_utc = (Get-Date).ToUniversalTime().ToString("o")
  })

  Write-Host ("ENCRYPTED_PROFILE_GET_OK: " + $OutPath) -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  if([string]$vaultObj.schema -ne "recognition.profile.vault.v1"){
    Die ("ENCRYPTED_PROFILE_BAD_VAULT_SCHEMA: " + [string]$vaultObj.schema)
  }

  AppendReceipt $RepoRoot ([ordered]@{
    schema = "recognition.encrypted_profile.receipt.v1"
    action = "verify"
    profile_id = $ProfileId
    encrypted = $true
    item_count = $items.Count
    ts_utc = (Get-Date).ToUniversalTime().ToString("o")
  })

  Write-Host ("ENCRYPTED_PROFILE_VERIFY_OK: " + $ProfileId) -ForegroundColor Green
  exit 0
}

Die ("ENCRYPTED_PROFILE_UNKNOWN_ACTION: " + $Action)
