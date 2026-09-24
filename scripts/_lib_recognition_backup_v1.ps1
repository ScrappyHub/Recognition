# Recognition Portable Backup / Recovery v1 (§21 Recovery Engine, Deterministic Backup)
#
# A single portable, passphrase-encrypted file carrying everything needed to
# restore a Recognition profile on ANY machine: the identity (including its
# DPAPI-sealed secret, unsealed and re-encrypted portably) and every governed
# runtime store (history/bookmarks/downloads/actions/cookies).
#
# Design note — why passphrase encryption, not DPAPI, for the bundle itself:
# Windows DPAPI (CurrentUser scope) ties ciphertext to one Windows account on
# one machine by design; a DPAPI-encrypted backup would be permanently
# unreadable anywhere else, which would make "portable backup" a false claim.
# So export DECRYPTS each DPAPI-sealed store to plaintext in memory, then
# RE-ENCRYPTS the whole bundle with AES-256-GCM under a key derived from
# RECOGNITION_PASSPHRASE via PBKDF2-SHA256 (600,000 iterations) — the same
# primitives already proven in the crypto core (`_lib_recognition_crypto_v2`).
# Import reverses this and DPAPI-reseals each store on the TARGET machine, so
# the restored profile is, once again, transparently DPAPI-protected there.
#
# REQUIRES PowerShell 7.2+ / Windows (DPAPI). Requires RECOGNITION_PASSPHRASE.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")     # RC2-* (PBKDF2 + AES-256-GCM)
. (Join-Path $PSScriptRoot "_lib_recognition_identity_v1.ps1")   # RID-* (identity + salt seal)

$script:RBK_ENVELOPE_SCHEMA = "recognition.backup.envelope.v1"
$script:RBK_BUNDLE_SCHEMA   = "recognition.backup.v1"
$script:RBK_AAD             = "recognition.backup.v1/bundle"
$script:RBK_KDF_ITERATIONS  = 600000
$script:RBK_STORE_NAMES     = @("history","bookmarks","downloads","actions","cookies")

function RBK-Die([string]$m){ throw ("RBK_FAIL: " + $m) }

function RBK-Sha256Hex([string]$Text){
  $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes([string]$Text)
  $h = [System.Security.Cryptography.SHA256]::HashData($b)
  $sb = New-Object System.Text.StringBuilder
  foreach($x in $h){ [void]$sb.AppendFormat("{0:x2}",$x) }
  return $sb.ToString()
}

# ---- DPAPI helpers (CurrentUser scope) — same model as the C# browser's
# WriteSecure/ReadSecure and the identity library's RID-WriteSecure/ReadSecure.
# Kept as a local copy rather than importing the identity lib's private
# functions, so this file has no hidden coupling beyond RID-* public API.
function RBK-WriteSecure([string]$Path,[string]$Text){
  $dir = Split-Path -Parent $Path
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $bytes = $enc.GetBytes([string]$Text)
  $blob = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  [System.IO.File]::WriteAllBytes($Path, $blob)
}
function RBK-ReadSecure([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ return $null }
  $blob = [System.IO.File]::ReadAllBytes($Path)
  $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
  return (New-Object System.Text.UTF8Encoding($false)).GetString($bytes)
}

function RBK-Paths([string]$RepoRoot){
  $repo = (Resolve-Path -LiteralPath $RepoRoot).Path
  $runtime = Join-Path $repo "runtime"
  return [ordered]@{
    Repo      = $repo
    Runtime   = $runtime
    History   = Join-Path $runtime "history.v1.enc"
    Bookmarks = Join-Path $runtime "bookmarks.v1.enc"
    Downloads = Join-Path $runtime "downloads.v1.enc"
    Actions   = Join-Path $runtime "actions.v1.enc"
    Cookies   = Join-Path $runtime "cookies.v1.enc"
  }
}
function RBK-StorePath([hashtable]$P,[string]$Name){
  switch($Name){
    "history"   { return $P.History }
    "bookmarks" { return $P.Bookmarks }
    "downloads" { return $P.Downloads }
    "actions"   { return $P.Actions }
    "cookies"   { return $P.Cookies }
    default     { RBK-Die ("UNKNOWN_STORE: " + $Name) }
  }
}

# Best-effort receipt into the SAME hash-chained, DPAPI-encrypted actions
# ledger the browser writes (runtime/actions.v1.enc) — matches the exact
# on-disk format proven in _selftest_recognition_action_receipts_v1.ps1, so a
# backup/restore shows up as one more governed, provable action rather than a
# side channel invisible to the evidence system. Never blocks backup/restore
# on failure (evidence is additive, not a gate on the recovery path itself).
function RBK-AppendActionReceipt([hashtable]$P,[string]$Action,[string]$Detail = ""){
  try {
    function J2([string]$s){ '"' + ([string]$s).Replace('\','\\').Replace('"','\"') + '"' }
    $text = RBK-ReadSecure $P.Actions
    $lines = @()
    $head = ("0" * 64)
    if($null -ne $text){
      foreach($raw in ($text -split "`n")){
        $line = $raw.Trim(); if($line.Length -eq 0){ continue }
        $lines += $line
        $r = $line | ConvertFrom-Json
        $head = [string]$r.hash
      }
    }
    $seq = $lines.Count + 1
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $dsha = if([string]::IsNullOrEmpty($Detail)){ "" } else { RBK-Sha256Hex $Detail }
    $body = "{" + (J2 "seq") + ":" + $seq + "," + (J2 "ts_utc") + ":" + (J2 $ts) + "," +
            (J2 "action") + ":" + (J2 $Action) + "," + (J2 "detail_sha256") + ":" + (J2 $dsha) + "," +
            (J2 "prev_hash") + ":" + (J2 $head) + "}"
    $hash = RBK-Sha256Hex $body
    $line = $body.Substring(0, $body.Length - 1) + "," + (J2 "hash") + ":" + (J2 $hash) + "}"
    $lines += $line
    RBK-WriteSecure $P.Actions (($lines -join "`n") + "`n")
  } catch { }   # evidence is additive; never fail the backup/restore over it
}

# ---- export ------------------------------------------------------------------

function RBK-Export([string]$RepoRoot,[string]$OutFile){
  $P = RBK-Paths $RepoRoot
  $descriptor = RID-EnsureIdentity $RepoRoot   # ensures + migrates + seals the salt
  $IP = RID-Paths $RepoRoot
  $salt = RID-UnsealSalt $IP

  $stores = [ordered]@{}
  foreach($name in $script:RBK_STORE_NAMES){
    $path = RBK-StorePath $P $name
    $plain = RBK-ReadSecure $path
    if($null -eq $plain){
      $stores[$name] = [ordered]@{ present = $false }
    } else {
      $stores[$name] = [ordered]@{ present = $true; sha256 = (RBK-Sha256Hex $plain); content = $plain }
    }
  }

  $bundle = [ordered]@{
    schema                  = $script:RBK_BUNDLE_SCHEMA
    exported_utc            = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    recognition_identity_id = [string](RID-Get $descriptor "recognition_identity_id")
    device_id               = [string](RID-Get $descriptor "device_id")
    user_id                 = [string](RID-Get $descriptor "user_id")
    vault_id                = [string](RID-Get $descriptor "vault_id")
    created_utc             = [string](RID-Get $descriptor "created_utc")
    identity_salt_hex       = $salt
    stores                  = $stores
  }
  $json = ($bundle | ConvertTo-Json -Depth 30 -Compress)
  $contentSha = RBK-Sha256Hex $json

  $salt16 = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(16)
  $pass = RC2-GetPassphrase
  $key = RC2-DeriveKek $pass $salt16 $script:RBK_KDF_ITERATIONS
  $blob = $null
  try { $blob = RC2-GcmEncryptText $key $json $script:RBK_AAD } finally { RC2-ZeroBytes $key }

  $envelope = [ordered]@{
    schema         = $script:RBK_ENVELOPE_SCHEMA
    kdf            = "PBKDF2-SHA256"
    kdf_iterations = $script:RBK_KDF_ITERATIONS
    salt_b64       = [Convert]::ToBase64String($salt16)
    cipher         = "AES-256-GCM"
    content_sha256 = $contentSha
    blob           = $blob
  }
  $dir = Split-Path -Parent $OutFile
  if($dir -and -not (Test-Path -LiteralPath $dir)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  [System.IO.File]::WriteAllText($OutFile, (($envelope | ConvertTo-Json -Depth 20) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

  $present = @($stores.Keys | Where-Object { $stores[$_].present })
  RBK-AppendActionReceipt $P "backup.export" $OutFile
  return [ordered]@{ out_file = $OutFile; stores_included = $present; recognition_identity_id = $bundle.recognition_identity_id }
}

# ---- decrypt (shared by verify + import) -------------------------------------

function RBK-DecryptBundle([string]$InFile){
  if(-not (Test-Path -LiteralPath $InFile -PathType Leaf)){ RBK-Die ("BACKUP_FILE_MISSING: " + $InFile) }
  $env = Get-Content -Raw -LiteralPath $InFile -Encoding UTF8 | ConvertFrom-Json
  if([string]$env.schema -ne $script:RBK_ENVELOPE_SCHEMA){ RBK-Die "BACKUP_BAD_ENVELOPE_SCHEMA" }
  if([string]$env.cipher -ne "AES-256-GCM"){ RBK-Die "BACKUP_BAD_CIPHER" }
  $salt16 = [Convert]::FromBase64String([string]$env.salt_b64)
  $pass = RC2-GetPassphrase
  $key = RC2-DeriveKek $pass $salt16 ([int]$env.kdf_iterations)
  $json = $null
  try {
    $b = $env.blob
    $json = RC2-GcmDecryptText $key ([string]$b.nonce_b64) ([string]$b.ct_b64) ([string]$b.tag_b64) $script:RBK_AAD
  } finally { RC2-ZeroBytes $key }
  if((RBK-Sha256Hex $json) -ne [string]$env.content_sha256){ RBK-Die "BACKUP_CONTENT_HASH_MISMATCH" }
  $bundle = $json | ConvertFrom-Json
  if([string]$bundle.schema -ne $script:RBK_BUNDLE_SCHEMA){ RBK-Die "BACKUP_BAD_BUNDLE_SCHEMA" }
  return $bundle
}

function RBK-Verify([string]$InFile){
  $bundle = RBK-DecryptBundle $InFile
  $present = @()
  foreach($name in $script:RBK_STORE_NAMES){
    $s = $bundle.stores.$name
    if($null -ne $s -and $s.present){ $present += $name }
  }
  return [ordered]@{
    recognition_identity_id = [string]$bundle.recognition_identity_id
    exported_utc            = [string]$bundle.exported_utc
    stores_present          = $present
  }
}

# ---- import / restore ---------------------------------------------------------

function RBK-Import([string]$RepoRoot,[string]$InFile,[switch]$Force){
  $bundle = RBK-DecryptBundle $InFile
  $P = RBK-Paths $RepoRoot
  $IP = RID-Paths $RepoRoot

  $existing = RID-LoadDescriptor $IP
  if($null -ne $existing){
    $existingId = [string](RID-Get $existing "recognition_identity_id")
    if($existingId -ne [string]$bundle.recognition_identity_id -and -not $Force){
      RBK-Die ("REFUSING: target already has a different identity (" + $existingId + ") — pass -Force to overwrite")
    }
  }

  New-Item -ItemType Directory -Force -Path $IP.Dir | Out-Null
  $newDescriptor = [ordered]@{
    schema                  = "recognition.identity.v1"
    recognition_identity_id = [string]$bundle.recognition_identity_id
    device_id               = [string]$bundle.device_id
    user_id                 = [string]$bundle.user_id
    vault_id                = [string]$bundle.vault_id
    created_utc             = [string]$bundle.created_utc
    salt_sealed             = $true
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText($IP.Descriptor, ((($newDescriptor | ConvertTo-Json -Depth 10) -replace "`r`n","`n") + "`n"), $enc)
  RBK-WriteSecure $IP.SaltEnc ([string]$bundle.identity_salt_hex)

  $restored = @()
  foreach($name in $script:RBK_STORE_NAMES){
    $s = $bundle.stores.$name
    if($null -eq $s -or -not $s.present){ continue }
    $path = RBK-StorePath $P $name
    if((Test-Path -LiteralPath $path -PathType Leaf) -and -not $Force){
      RBK-Die ("REFUSING: " + $name + " already exists at the target — pass -Force to overwrite")
    }
    RBK-WriteSecure $path ([string]$s.content)
    $restored += $name
  }

  RBK-AppendActionReceipt $P "backup.import" $InFile
  return [ordered]@{ recognition_identity_id = [string]$bundle.recognition_identity_id; stores_restored = $restored }
}
