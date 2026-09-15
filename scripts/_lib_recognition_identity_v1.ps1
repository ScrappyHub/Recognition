# Recognition Identity + Receipt Chain v1 — WBS 4.1 (self-contained; NO NeverLost)
#
# Recognition is its own identity authority for the local instance (Handoff §2
# "no cloud dependency / no vendor lock", §9 Identity, §11/§12 event+timeline).
# It establishes a local identity descriptor and emits an append-only,
# hash-chained IDENTITY RECEIPT CHAIN of identity/lifecycle/evidence events
# (identity.created, session.started, packet.export, packet.verify, trust.change,
# ...). The chain reuses the event-chain v2 hashing and is anchorable via the
# chain head anchor (CHAIN-1), so it fails closed on tamper/truncation/rebuild.
#
# Identity ids are non-secret (hashes/salts), stored plaintext under
# proofs/identity/ during a session and sealable into the vault at shutdown.
# NeverLost integration, if ever added, is an OPTIONAL downstream consumer — the
# chain is complete and verifiable on its own.
#
# Requires pwsh 7.2+.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")  # RCE-* chain/hash

$script:RID_SCHEMA = "recognition.identity.v1"

function RID-Die([string]$m){ throw ("RID_FAIL: " + $m) }

function RID-Sha256Hex([string]$Text){
  $b = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
  $h = [System.Security.Cryptography.SHA256]::HashData($b)
  $sb = New-Object System.Text.StringBuilder
  foreach($x in $h){ [void]$sb.AppendFormat("{0:x2}",$x) }
  return $sb.ToString()
}
function RID-RandHex([int]$Bytes){
  $b = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($Bytes)
  $sb = New-Object System.Text.StringBuilder
  foreach($x in $b){ [void]$sb.AppendFormat("{0:x2}",$x) }
  return $sb.ToString()
}

function RID-Paths([string]$RepoRoot){
  $repo = (Resolve-Path -LiteralPath $RepoRoot).Path
  $dir  = Join-Path (Join-Path $repo "proofs") "identity"
  return [ordered]@{
    Repo       = $repo
    Dir        = $dir
    Descriptor = Join-Path $dir "identity.json"
    Chain      = Join-Path $dir "identity.chain.v1.ndjson"
  }
}

# safe dict read for parsed descriptor (OrderedDictionary)
function RID-Get($d,[string]$key){
  if($null -eq $d){ return $null }
  foreach($k in @($d.Keys)){ if([string]$k -eq $key){ return $d[$k] } }
  return $null
}

function RID-LoadDescriptor([hashtable]$P){
  if(-not (Test-Path -LiteralPath $P.Descriptor -PathType Leaf)){ return $null }
  return RCE-ParseJson (Get-Content -Raw -LiteralPath $P.Descriptor -Encoding UTF8)
}

function RID-IdentityBlock($descriptor){
  return [ordered]@{
    session_id = [string](RID-Get $descriptor "recognition_identity_id")
    profile    = [string](RID-Get $descriptor "user_id")
    device     = [string](RID-Get $descriptor "device_id")
  }
}

# append a hash-chained identity receipt using a known descriptor (no re-ensure)
function RID-AppendWith([hashtable]$P,$descriptor,[string]$Type,$Data){
  $tail = RCE-ChainTail $P.Chain
  $seq  = [int]$tail.seq + 1
  $prev = [string]$tail.head_hash
  $evt = RCE-BuildEvent $seq (RCE-NowUtc) $Type $null $Data (RID-IdentityBlock $descriptor) $prev
  RCE-AppendLine $P.Chain (RCE-CanonJson $evt)
  return $evt
}

# create the identity on first use; emit identity.created. Idempotent.
function RID-EnsureIdentity([string]$RepoRoot){
  $P = RID-Paths $RepoRoot
  $existing = RID-LoadDescriptor $P
  if($null -ne $existing){ return $existing }

  RCE-EnsureDir $P.Dir
  $salt       = RID-RandHex 16
  $createdUtc = RCE-NowUtc
  $deviceId   = RID-Sha256Hex (([string]$env:COMPUTERNAME) + "|" + $salt)
  $userId     = RID-Sha256Hex (([string]$env:USERNAME) + "|" + $salt)
  $vaultId    = RID-Sha256Hex ("vault|" + $salt)
  $ridBase    = RCE-CanonJson ([ordered]@{ device_id=$deviceId; user_id=$userId; vault_id=$vaultId; created_utc=$createdUtc; salt=$salt })
  $rid        = RID-Sha256Hex $ridBase

  $descriptor = [ordered]@{
    schema                  = $script:RID_SCHEMA
    recognition_identity_id = $rid
    device_id               = $deviceId
    user_id                 = $userId
    vault_id                = $vaultId
    created_utc             = $createdUtc
    salt                    = $salt
  }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $txt = (RCE-CanonJson $descriptor)
  if(-not $txt.EndsWith("`n")){ $txt += "`n" }
  [System.IO.File]::WriteAllText($P.Descriptor, $txt, $enc)

  # genesis receipt of the identity chain
  [void](RID-AppendWith $P $descriptor "identity.created" ([ordered]@{ recognition_identity_id = $rid }))
  return $descriptor
}

# public append (ensures identity first)
function RID-Event([string]$RepoRoot,[string]$Type,$Data){
  if([string]::IsNullOrWhiteSpace($Type)){ RID-Die "IDENTITY_EVENT_EMPTY_TYPE" }
  $descriptor = RID-EnsureIdentity $RepoRoot
  $P = RID-Paths $RepoRoot
  return RID-AppendWith $P $descriptor $Type $Data
}

function RID-Verify([string]$RepoRoot){
  $P = RID-Paths $RepoRoot
  if(-not (Test-Path -LiteralPath $P.Chain -PathType Leaf)){ RID-Die "IDENTITY_CHAIN_MISSING" }
  return RCE-VerifyChain $P.Chain
}
