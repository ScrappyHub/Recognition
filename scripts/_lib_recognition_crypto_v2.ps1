# Recognition Crypto Core v2
# Spec: CANONICAL_HANDOFF_V1 section 8.
# AES-256-GCM, per-profile random master key wrapped by passphrase-derived KEK,
# HKDF-SHA256 domain subkeys, per-object nonces, no plaintext secrets, no secrets on argv.
# REQUIRES PowerShell 7.2+ (.NET AesGcm / HKDF / Pbkdf2 statics).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:RC2_KDF_ITERATIONS = 600000
$script:RC2_HKDF_SALT_LABEL = "recognition.hkdf.v2"
$script:RC2_KEYSTORE_SCHEMA = "recognition.keystore.v2"
$script:RC2_KEYSTORE_AAD = "recognition.keystore.v2/master-wrap"

function RC2-Die([string]$m){ throw ("RC2_FAIL: " + $m) }

function RC2-RequirePwsh7(){
  if($PSVersionTable.PSVersion.Major -lt 7){
    RC2-Die "REQUIRES_PWSH7: crypto core v2 needs PowerShell 7.2+ (AES-256-GCM is unavailable on .NET Framework). Run under pwsh."
  }
}

RC2-RequirePwsh7

function RC2-EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ RC2-Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function RC2-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ RC2-EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function RC2-AppendUtf8NoBomLfLine([string]$Path,[string]$Line){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $txt = ($Line -replace "`r`n","`n") -replace "`r","`n"
  if(-not $txt.EndsWith("`n")){ $txt += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ RC2-EnsureDir $dir }
  [System.IO.File]::AppendAllText($Path,$txt,$enc)
}

function RC2-NowUtc(){
  return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}

# NB: the unary comma (`return ,$array`) is required on every byte[]-returning
# helper. Without it, PowerShell unwraps a single-element array to a scalar on
# return, so a 1-byte value would come back as a [byte] (which has no .Length)
# and blow up downstream. This bit the 1-byte-ciphertext path (see vault selftest
# rekey vector). Multi-element arrays are unaffected by the comma.
function RC2-RandomBytes([int]$Count){
  return ,([System.Security.Cryptography.RandomNumberGenerator]::GetBytes($Count))
}

function RC2-B64([byte[]]$Bytes){ return [Convert]::ToBase64String($Bytes) }
function RC2-FromB64([string]$S){ return ,([Convert]::FromBase64String($S)) }

function RC2-Utf8Bytes([string]$S){
  return ,((New-Object System.Text.UTF8Encoding($false)).GetBytes($S))
}

function RC2-ZeroBytes([byte[]]$B){
  if($null -ne $B){ [Array]::Clear($B,0,$B.Length) }
}

# --- Passphrase acquisition: never from command lines -----------------------

function RC2-GetPassphrase(){
  $p = $env:RECOGNITION_PASSPHRASE
  if(-not [string]::IsNullOrEmpty($p)){ return $p }
  RC2-Die "PASSPHRASE_MISSING: set the RECOGNITION_PASSPHRASE environment variable. Passphrases are never accepted as command-line arguments in v2."
}

# --- KDF / key hierarchy -----------------------------------------------------

function RC2-DeriveKek([string]$Passphrase,[byte[]]$Salt,[int]$Iterations){
  if([string]::IsNullOrEmpty($Passphrase)){ RC2-Die "KDF_EMPTY_PASSPHRASE" }
  if($Salt.Length -lt 16){ RC2-Die "KDF_SALT_TOO_SHORT" }
  if($Iterations -lt 100000){ RC2-Die "KDF_ITERATIONS_TOO_LOW" }
  return [System.Security.Cryptography.Rfc2898DeriveBytes]::Pbkdf2(
    $Passphrase, $Salt, $Iterations,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256, 32)
}

function RC2-Hkdf([byte[]]$Ikm,[string]$Label,[int]$Length = 32){
  if([string]::IsNullOrEmpty($Label)){ RC2-Die "HKDF_EMPTY_LABEL" }
  $salt = RC2-Utf8Bytes $script:RC2_HKDF_SALT_LABEL
  $info = RC2-Utf8Bytes $Label
  return [System.Security.Cryptography.HKDF]::DeriveKey(
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    $Ikm, $Length, $salt, $info)
}

function RC2-HmacHex([byte[]]$Key,[string]$Text){
  $h = [System.Security.Cryptography.HMACSHA256]::new($Key)
  try {
    $bytes = $h.ComputeHash((RC2-Utf8Bytes $Text))
  } finally { $h.Dispose() }
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $bytes){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

# --- AES-256-GCM --------------------------------------------------------------

function RC2-NewAesGcm([byte[]]$Key){
  if($Key.Length -ne 32){ RC2-Die "GCM_KEY_LENGTH" }
  try {
    return [System.Security.Cryptography.AesGcm]::new($Key,16)
  } catch [System.Management.Automation.MethodException] {
    return [System.Security.Cryptography.AesGcm]::new($Key)
  }
}

function RC2-GcmEncrypt([byte[]]$Key,[byte[]]$Plain,[string]$Aad){
  $nonce = RC2-RandomBytes 12
  $ct = New-Object byte[] $Plain.Length
  $tag = New-Object byte[] 16
  $aadBytes = RC2-Utf8Bytes $Aad
  $g = RC2-NewAesGcm $Key
  try {
    $g.Encrypt($nonce,$Plain,$ct,$tag,$aadBytes)
  } finally { $g.Dispose() }
  return [ordered]@{
    nonce_b64 = RC2-B64 $nonce
    ct_b64    = RC2-B64 $ct
    tag_b64   = RC2-B64 $tag
  }
}

function RC2-GcmDecrypt([byte[]]$Key,[string]$NonceB64,[string]$CtB64,[string]$TagB64,[string]$Aad){
  $nonce = RC2-FromB64 $NonceB64
  $ct    = RC2-FromB64 $CtB64
  $tag   = RC2-FromB64 $TagB64
  $plain = New-Object byte[] $ct.Length
  $aadBytes = RC2-Utf8Bytes $Aad
  $g = RC2-NewAesGcm $Key
  try {
    try {
      $g.Decrypt($nonce,$ct,$tag,$plain,$aadBytes)
    } catch {
      RC2-Die "GCM_AUTH_FAIL: ciphertext, tag, nonce, or AAD does not verify"
    }
  } finally { $g.Dispose() }
  return ,$plain
}

function RC2-GcmEncryptText([byte[]]$Key,[string]$PlainText,[string]$Aad){
  $pb = RC2-Utf8Bytes $PlainText
  try { return RC2-GcmEncrypt $Key $pb $Aad } finally { RC2-ZeroBytes $pb }
}

function RC2-GcmDecryptText([byte[]]$Key,[string]$NonceB64,[string]$CtB64,[string]$TagB64,[string]$Aad){
  $pb = RC2-GcmDecrypt $Key $NonceB64 $CtB64 $TagB64 $Aad
  try { return (New-Object System.Text.UTF8Encoding($false)).GetString($pb) } finally { RC2-ZeroBytes $pb }
}

# --- Keystore: random master key wrapped by passphrase-derived KEK ------------

function RC2-NewKeystore([string]$Path,[string]$Passphrase){
  if(Test-Path -LiteralPath $Path -PathType Leaf){ RC2-Die ("KEYSTORE_ALREADY_EXISTS: " + $Path) }

  $salt = RC2-RandomBytes 16
  $kek = RC2-DeriveKek $Passphrase $salt $script:RC2_KDF_ITERATIONS
  $master = RC2-RandomBytes 32
  try {
    $wrap = RC2-GcmEncrypt $kek $master $script:RC2_KEYSTORE_AAD
  } finally { RC2-ZeroBytes $kek }

  $ks = [ordered]@{
    schema        = $script:RC2_KEYSTORE_SCHEMA
    kdf           = "PBKDF2-SHA256"
    kdf_iterations = $script:RC2_KDF_ITERATIONS
    salt_b64      = RC2-B64 $salt
    cipher        = "AES-256-GCM"
    wrap          = $wrap
    created_utc   = RC2-NowUtc
  }

  RC2-WriteUtf8NoBomLf $Path ($ks | ConvertTo-Json -Depth 10)
  return $master
}

function RC2-OpenKeystore([string]$Path,[string]$Passphrase){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ RC2-Die ("KEYSTORE_MISSING: " + $Path) }
  $ks = Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json

  if([string]$ks.schema -ne $script:RC2_KEYSTORE_SCHEMA){ RC2-Die ("KEYSTORE_BAD_SCHEMA: " + [string]$ks.schema) }
  if([string]$ks.cipher -ne "AES-256-GCM"){ RC2-Die ("KEYSTORE_BAD_CIPHER: " + [string]$ks.cipher) }

  $salt = RC2-FromB64 ([string]$ks.salt_b64)
  $kek = RC2-DeriveKek $Passphrase $salt ([int]$ks.kdf_iterations)
  try {
    $master = RC2-GcmDecrypt $kek ([string]$ks.wrap.nonce_b64) ([string]$ks.wrap.ct_b64) ([string]$ks.wrap.tag_b64) $script:RC2_KEYSTORE_AAD
  } finally { RC2-ZeroBytes $kek }

  if($master.Length -ne 32){ RC2-Die "KEYSTORE_BAD_MASTER_LENGTH" }
  return $master
}

function RC2-RekeyKeystore([string]$Path,[string]$OldPassphrase,[string]$NewPassphrase){
  $master = RC2-OpenKeystore $Path $OldPassphrase
  try {
    $salt = RC2-RandomBytes 16
    $kek = RC2-DeriveKek $NewPassphrase $salt $script:RC2_KDF_ITERATIONS
    try {
      $wrap = RC2-GcmEncrypt $kek $master $script:RC2_KEYSTORE_AAD
    } finally { RC2-ZeroBytes $kek }

    $ks = [ordered]@{
      schema         = $script:RC2_KEYSTORE_SCHEMA
      kdf            = "PBKDF2-SHA256"
      kdf_iterations = $script:RC2_KDF_ITERATIONS
      salt_b64       = RC2-B64 $salt
      cipher         = "AES-256-GCM"
      wrap           = $wrap
      rekeyed_utc    = RC2-NowUtc
    }

    RC2-WriteUtf8NoBomLf $Path ($ks | ConvertTo-Json -Depth 10)
  } finally { RC2-ZeroBytes $master }
}
