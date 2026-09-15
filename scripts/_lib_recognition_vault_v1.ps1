# Recognition Vault v1 — encrypted object store (Canonical Handoff §7)
#
# Generalises the encrypted-profile-v2 pattern into a typed, byte-oriented
# object store with an ENCRYPTED, GCM-authenticated manifest and per-object
# content hashes. This is the root fix for audit F1 (plaintext at rest):
# everything persistent lives here as AES-256-GCM ciphertext; nothing but the
# passphrase-wrapped keystore is meaningful without the master key.
#
# Layout (under vault/<vault_id>/):
#   keystore.v2.json   random master key wrapped by passphrase-derived KEK
#   manifest.v1.json   single AES-256-GCM blob; plaintext = canonical manifest
#   objects/<hmac>     one AES-256-GCM blob per stored object
#
# Key hierarchy (HKDF-SHA256 from the master key):
#   vault.index.v1        -> HMAC key for logical-name -> name_hmac
#   vault.object-enc.v1   -> AES key for object bodies
#   vault.manifest-enc.v1 -> AES key for the manifest blob
#
# Names, sizes, and content hashes never appear in cleartext on disk or in
# receipts; the manifest that binds them is itself encrypted.
#
# REQUIRES PowerShell 7.2+ (inherits crypto core v2 requirements).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")

$script:RV1_MANIFEST_SCHEMA = "recognition.vault.manifest.v1"
$script:RV1_KEYSTORE_NAME    = "keystore.v2.json"
$script:RV1_MANIFEST_NAME    = "manifest.v1.json"

function RV1-Die([string]$m){ throw ("RV1_FAIL: " + $m) }

function RV1-Paths([string]$RepoRoot,[string]$VaultId){
  if($VaultId -notmatch '^[A-Za-z0-9_.-]+$'){ RV1-Die "VAULT_BAD_ID" }
  $repo = (Resolve-Path -LiteralPath $RepoRoot).Path
  $vaultDir = Join-Path (Join-Path $repo "vault") $VaultId
  return [ordered]@{
    Repo      = $repo
    VaultId   = $VaultId
    VaultDir  = $vaultDir
    Keystore  = Join-Path $vaultDir $script:RV1_KEYSTORE_NAME
    Manifest  = Join-Path $vaultDir $script:RV1_MANIFEST_NAME
    Objects   = Join-Path $vaultDir "objects"
  }
}

function RV1-ManifestAad([string]$VaultId){ return ("recognition.vault.manifest.v1/" + $VaultId) }
function RV1-ObjectAad([string]$NameHmac){ return ("recognition.vault.object.v1/" + $NameHmac) }

function RV1-Sha256Hex([byte[]]$Bytes){
  $h = [System.Security.Cryptography.SHA256]::HashData($Bytes)
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

function RV1-OpenMaster([hashtable]$P){
  $pass = RC2-GetPassphrase
  return RC2-OpenKeystore $P.Keystore $pass
}

# --- manifest read/write (encrypted, GCM-authenticated) ----------------------

function RV1-EmptyManifest([string]$VaultId){
  return [ordered]@{
    schema      = $script:RV1_MANIFEST_SCHEMA
    vault_id    = $VaultId
    cipher      = "AES-256-GCM"
    created_utc = RC2-NowUtc
    updated_utc = RC2-NowUtc
    objects     = [ordered]@{}
  }
}

function RV1-SaveManifest([hashtable]$P,[byte[]]$ManifestKey,$Manifest){
  $Manifest.updated_utc = RC2-NowUtc
  $json = ($Manifest | ConvertTo-Json -Depth 30)
  $blob = RC2-GcmEncryptText $ManifestKey $json (RV1-ManifestAad $P.VaultId)
  $env = [ordered]@{
    schema   = "recognition.vault.manifest-envelope.v1"
    vault_id = $P.VaultId
    cipher   = "AES-256-GCM"
    blob     = $blob
  }
  RC2-WriteUtf8NoBomLf $P.Manifest ($env | ConvertTo-Json -Depth 10)
}

function RV1-LoadManifest([hashtable]$P,[byte[]]$ManifestKey){
  if(-not (Test-Path -LiteralPath $P.Manifest -PathType Leaf)){ RV1-Die ("VAULT_MANIFEST_MISSING: " + $P.Manifest) }
  $env = Get-Content -Raw -LiteralPath $P.Manifest -Encoding UTF8 | ConvertFrom-Json -AsHashtable
  if([string]$env.schema -ne "recognition.vault.manifest-envelope.v1"){ RV1-Die "VAULT_MANIFEST_BAD_ENVELOPE" }
  $b = $env.blob
  $json = RC2-GcmDecryptText $ManifestKey ([string]$b.nonce_b64) ([string]$b.ct_b64) ([string]$b.tag_b64) (RV1-ManifestAad $P.VaultId)
  $m = $json | ConvertFrom-Json -AsHashtable
  if([string]$m.schema -ne $script:RV1_MANIFEST_SCHEMA){ RV1-Die ("VAULT_MANIFEST_BAD_SCHEMA: " + [string]$m.schema) }
  if($null -eq $m.objects){ $m.objects = @{} }
  return $m
}

# --- init --------------------------------------------------------------------

function RV1-Init([hashtable]$P){
  if(Test-Path -LiteralPath $P.Keystore -PathType Leaf){ RV1-Die ("VAULT_ALREADY_EXISTS: " + $P.VaultDir) }
  RC2-EnsureDir $P.VaultDir
  RC2-EnsureDir $P.Objects
  $pass = RC2-GetPassphrase
  $master = RC2-NewKeystore $P.Keystore $pass
  try {
    $mk = RC2-Hkdf $master "vault.manifest-enc.v1"
    try { RV1-SaveManifest $P $mk (RV1-EmptyManifest $P.VaultId) } finally { RC2-ZeroBytes $mk }
  } finally { RC2-ZeroBytes $master }
}

# --- put / get / verify / list ----------------------------------------------
# All take an already-open master key so callers can batch many objects under
# one keystore open (the runtime-seal tool relies on this).

function RV1-PutBytes([hashtable]$P,[byte[]]$Master,[string]$Name,[byte[]]$Bytes,[string]$ContentType){
  $indexKey = RC2-Hkdf $Master "vault.index.v1"
  $encKey   = RC2-Hkdf $Master "vault.object-enc.v1"
  $manKey   = RC2-Hkdf $Master "vault.manifest-enc.v1"
  try {
    $nameHmac = RC2-HmacHex $indexKey $Name
    $sha = RV1-Sha256Hex $Bytes
    $blob = RC2-GcmEncrypt $encKey $Bytes (RV1-ObjectAad $nameHmac)
    RC2-EnsureDir $P.Objects
    RC2-WriteUtf8NoBomLf (Join-Path $P.Objects $nameHmac) (([ordered]@{
      schema = "recognition.vault.object.v1"; blob = $blob
    }) | ConvertTo-Json -Depth 10)

    $m = RV1-LoadManifest $P $manKey
    $now = RC2-NowUtc
    $existing = $null
    if($m.objects.ContainsKey($nameHmac)){ $existing = $m.objects[$nameHmac] }
    $m.objects[$nameHmac] = [ordered]@{
      name_hmac    = $nameHmac
      content_type = $ContentType
      size         = $Bytes.Length
      sha256       = $sha
      created_utc  = $(if($existing){ [string]$existing.created_utc } else { $now })
      updated_utc  = $now
    }
    RV1-SaveManifest $P $manKey $m
    return [ordered]@{ name_hmac = $nameHmac; size = $Bytes.Length; sha256 = $sha }
  } finally { RC2-ZeroBytes $indexKey; RC2-ZeroBytes $encKey; RC2-ZeroBytes $manKey }
}

function RV1-GetBytes([hashtable]$P,[byte[]]$Master,[string]$Name){
  $indexKey = RC2-Hkdf $Master "vault.index.v1"
  $encKey   = RC2-Hkdf $Master "vault.object-enc.v1"
  $manKey   = RC2-Hkdf $Master "vault.manifest-enc.v1"
  try {
    $nameHmac = RC2-HmacHex $indexKey $Name
    $m = RV1-LoadManifest $P $manKey
    if(-not $m.objects.ContainsKey($nameHmac)){ RV1-Die "VAULT_OBJECT_MISSING" }
    $meta = $m.objects[$nameHmac]
    $objPath = Join-Path $P.Objects $nameHmac
    if(-not (Test-Path -LiteralPath $objPath -PathType Leaf)){ RV1-Die ("VAULT_OBJECT_FILE_MISSING: " + $nameHmac) }
    $o = Get-Content -Raw -LiteralPath $objPath -Encoding UTF8 | ConvertFrom-Json -AsHashtable
    $b = $o.blob
    $plain = RC2-GcmDecrypt $encKey ([string]$b.nonce_b64) ([string]$b.ct_b64) ([string]$b.tag_b64) (RV1-ObjectAad $nameHmac)
    $sha = RV1-Sha256Hex $plain
    if($sha -ne [string]$meta.sha256){ RC2-ZeroBytes $plain; RV1-Die "VAULT_CONTENT_HASH_MISMATCH" }
    return ,$plain   # comma preserves byte[] (a 1-byte value would otherwise unwrap to a scalar)
  } finally { RC2-ZeroBytes $indexKey; RC2-ZeroBytes $encKey; RC2-ZeroBytes $manKey }
}

function RV1-Verify([hashtable]$P,[byte[]]$Master){
  $encKey = RC2-Hkdf $Master "vault.object-enc.v1"
  $manKey = RC2-Hkdf $Master "vault.manifest-enc.v1"
  $count = 0; $failures = 0
  try {
    $m = RV1-LoadManifest $P $manKey
    foreach($nameHmac in @($m.objects.Keys)){
      $count++
      $meta = $m.objects[$nameHmac]
      $objPath = Join-Path $P.Objects $nameHmac
      try {
        if(-not (Test-Path -LiteralPath $objPath -PathType Leaf)){ throw "missing object file" }
        $o = Get-Content -Raw -LiteralPath $objPath -Encoding UTF8 | ConvertFrom-Json -AsHashtable
        $b = $o.blob
        $plain = RC2-GcmDecrypt $encKey ([string]$b.nonce_b64) ([string]$b.ct_b64) ([string]$b.tag_b64) (RV1-ObjectAad $nameHmac)
        try {
          $sha = RV1-Sha256Hex $plain
          if($sha -ne [string]$meta.sha256){ throw "content hash mismatch" }
          if([int]$plain.Length -ne [int]$meta.size){ throw "size mismatch" }
        } finally { RC2-ZeroBytes $plain }
      } catch {
        $failures++
        Write-Host ("RECOGNITION_VAULT_V1_OBJECT_FAIL: " + $nameHmac + " -> " + $_.Exception.Message) -ForegroundColor Red
      }
    }
    # VAULT-1: orphan detection — object files on disk not referenced by the
    # (GCM-authenticated) manifest. Inert, but flagged so nothing exists in the
    # vault that the manifest does not account for.
    if(Test-Path -LiteralPath $P.Objects -PathType Container){
      $known = @{}
      foreach($k in @($m.objects.Keys)){ $known[[string]$k] = $true }
      foreach($of in @(Get-ChildItem -LiteralPath $P.Objects -File -Force -ErrorAction SilentlyContinue)){
        if(-not $known.ContainsKey($of.Name)){
          $failures++
          Write-Host ("RECOGNITION_VAULT_V1_ORPHAN_OBJECT: " + $of.Name) -ForegroundColor Red
        }
      }
    }
  } finally { RC2-ZeroBytes $encKey; RC2-ZeroBytes $manKey }
  # NB: keys are 'object_count'/'failure_count', not 'count'/'failures' — on a
  # PowerShell dictionary, ".count" resolves to the dictionary's own Count
  # property and shadows a key of the same name.
  return [ordered]@{ object_count = $count; failure_count = $failures }
}

function RV1-ListMeta([hashtable]$P,[byte[]]$Master){
  $manKey = RC2-Hkdf $Master "vault.manifest-enc.v1"
  try {
    $m = RV1-LoadManifest $P $manKey
    return ,@($m.objects.Values)
  } finally { RC2-ZeroBytes $manKey }
}
