# Recognition Extension Governance v1 — Canonical Handoff §6 (Layer 6) + §22
#
# "Extensions become governed. Every extension: identity, signature, permissions,
#  receipts, lifecycle, policy. No unrestricted execution."
#
# This makes the OSF paper's SoftwareID concrete for a real artifact:
#   extension_id = SHA-256( canonical JSON of the sorted {path, sha256, size} set )
# Any added/removed/modified file changes the id, so a governed extension whose
# bytes drift is detected and refused before load.
#
# A governance decision (allow / review / deny) is computed against a policy and
# recorded as a HASH-CHAINED governance ledger entry (prev_hash + record_hash),
# reusing the proven event-chain v2 canonicalizer. Verification proves the
# extension on disk still matches an allow decision — the load gate.
#
# NB: parsed JSON objects come back as OrderedDictionary. On some pwsh builds
# `$d["key"]` (string indexer read) throws "Argument types do not match" because
# OrderedDictionary exposes both Item[int] and Item[object]. We therefore read
# via DOT access ($d.key) throughout — the same convention the event-chain lib
# uses — which resolves unambiguously to a key lookup.
#
# Requires pwsh 7.2+.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")  # RCE-CanonJson / Sha256Hex / ParseJson / ReadChainLines / GenesisHash / AppendLine / NowUtc / EnsureDir

$script:RG_SCHEMA  = "recognition.extension_governance.v1"
$script:RG_GENESIS = (RCE-GenesisHash)

function RG-Die([string]$m){ throw ("RG_FAIL: " + $m) }

# Safe dictionary access for OrderedDictionary values (incl. collection values).
# Direct `$d["k"]` / `$d.k` reads throw "Argument types do not match" on some
# pwsh builds when the value is a List; iterating .Keys and indexing with the
# real key object (the same shape the event-chain canonicalizer uses) is stable.
function RG-Get($d,[string]$key){
  if($null -eq $d){ return $null }
  foreach($k in @($d.Keys)){ if([string]$k -eq $key){ return $d[$k] } }
  return $null
}
function RG-Has($d,[string]$key){
  if($null -eq $d){ return $false }
  foreach($k in @($d.Keys)){ if([string]$k -eq $key){ return $true } }
  return $false
}
# Array-safe read: absent key -> empty array (NOT @($null), which yields a
# phantom single null element and pollutes permission scans).
function RG-GetArr($d,[string]$key){
  $v = RG-Get $d $key
  if($null -eq $v){ return ,@() }
  return ,@($v)
}

function RG-FileSha256Hex([string]$Path){
  $h = [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($Path))
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

# --- deterministic extension identity ----------------------------------------
function RG-ComputeIdentity([string]$ExtRoot){
  if(-not (Test-Path -LiteralPath $ExtRoot -PathType Container)){ RG-Die ("EXT_ROOT_MISSING: " + $ExtRoot) }
  $root = (Resolve-Path -LiteralPath $ExtRoot).Path
  $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force |
             Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })
  if($files.Count -eq 0){ RG-Die "EXT_EMPTY" }

  $entries = New-Object System.Collections.Generic.List[object]
  foreach($f in $files){
    $rel = ($f.FullName.Substring($root.Length).TrimStart('\','/')) -replace '\\','/'
    $entries.Add([ordered]@{ path = $rel; sha256 = (RG-FileSha256Hex $f.FullName); size = [int]$f.Length })
  }
  # sort by path (ORDINAL) so the id is independent of enumeration order + culture
  $arr = $entries.ToArray()
  [Array]::Sort($arr, [System.Comparison[object]]{ param($x,$y) [string]::CompareOrdinal([string]$x.path,[string]$y.path) })
  $sorted = @($arr)
  $canon  = RCE-CanonJson (,$sorted)
  return [ordered]@{
    extension_id = (RCE-Sha256Hex $canon)
    file_count   = $sorted.Count
    files        = $sorted
  }
}

# --- manifest facts -----------------------------------------------------------
function RG-ReadManifest([string]$ExtRoot){
  $mp = Join-Path $ExtRoot "manifest.json"
  if(-not (Test-Path -LiteralPath $mp -PathType Leaf)){ RG-Die "EXT_NO_MANIFEST" }
  $m = RCE-ParseJson (Get-Content -Raw -LiteralPath $mp -Encoding UTF8)
  $perms = RG-GetArr $m "permissions"
  $hosts = RG-GetArr $m "host_permissions"
  # MV2 mixes host patterns into permissions; split anything URL-ish out
  $apiPerms = @(); $hostFromPerms = @()
  foreach($p in $perms){
    $ps = [string]$p
    if([string]::IsNullOrWhiteSpace($ps)){ continue }
    if($ps -match '://' -or $ps -eq '<all_urls>' -or $ps -match '^\*'){ $hostFromPerms += $ps } else { $apiPerms += $ps }
  }
  $mv = 0; if(RG-Has $m "manifest_version"){ $mv = [int](RG-Get $m "manifest_version") }
  return [ordered]@{
    name             = [string](RG-Get $m "name")
    version          = [string](RG-Get $m "version")
    manifest_version = $mv
    permissions      = @($apiPerms)
    host_permissions = @(@($hosts) + @($hostFromPerms))
  }
}

# --- policy decision (deterministic) -----------------------------------------
function RG-LoadPolicy([string]$PolicyPath){
  if(-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)){ RG-Die ("POLICY_MISSING: " + $PolicyPath) }
  return RCE-ParseJson (Get-Content -Raw -LiteralPath $PolicyPath -Encoding UTF8)
}

function RG-In($Set,[string]$Val){
  if($null -eq $Set){ return $false }
  foreach($x in @($Set)){ if([string]$x -eq $Val){ return $true } }
  return $false
}

function RG-Decide($Manifest,[string]$ExtId,$Policy){
  $reasons = New-Object System.Collections.Generic.List[string]
  $deny = $false; $review = $false

  $blocklist = RG-GetArr $Policy "blocklist"
  $allowlist = RG-GetArr $Policy "allowlist"
  if(RG-In $blocklist $ExtId){ $deny=$true; [void]$reasons.Add("blocklisted") }
  if(RG-In $allowlist $ExtId){ [void]$reasons.Add("allowlisted") }

  $mv = [int](RG-Get $Manifest "manifest_version")
  $maxMv = if(RG-Has $Policy "max_manifest_version"){ [int](RG-Get $Policy "max_manifest_version") } else { 3 }
  $minMv = if(RG-Has $Policy "min_manifest_version"){ [int](RG-Get $Policy "min_manifest_version") } else { 2 }
  if($mv -gt $maxMv -or $mv -lt $minMv){ $deny=$true; [void]$reasons.Add("manifest_version_out_of_range:" + $mv) }

  $denied  = RG-GetArr $Policy "denied_permissions"
  $reviewP = RG-GetArr $Policy "review_permissions"
  $allowed = RG-GetArr $Policy "allowed_permissions"

  $allPerms = @((RG-GetArr $Manifest "permissions") + (RG-GetArr $Manifest "host_permissions"))
  foreach($p in $allPerms){
    $ps = [string]$p
    if([string]::IsNullOrWhiteSpace($ps)){ continue }
    if(RG-In $denied $ps){ $deny=$true; [void]$reasons.Add("denied_permission:" + $ps); continue }
    if(RG-In $reviewP $ps){ $review=$true; [void]$reasons.Add("review_permission:" + $ps); continue }
    if(-not (RG-In $allowed $ps)){ $review=$true; [void]$reasons.Add("unknown_permission:" + $ps) }
  }

  $decision = if($deny){ "deny" } elseif($review -and -not (RG-In $allowlist $ExtId)){ "review" } else { "allow" }
  return [ordered]@{ decision = $decision; reasons = @($reasons) }
}

# --- hash-chained governance ledger ------------------------------------------
function RG-RecordHash($RecNoHash){ return RCE-Sha256Hex (RCE-CanonJson $RecNoHash) }

function RG-BuildRecord([int]$Seq,[string]$ExtId,$Manifest,$Files,$Decision,[string]$PrevHash){
  if($PrevHash -notmatch '^[0-9a-f]{64}$'){ RG-Die "REC_BAD_PREV_HASH" }
  $rec = [ordered]@{
    schema           = $script:RG_SCHEMA
    record_id        = ("extgov-" + $Seq.ToString("d6"))
    seq              = $Seq
    ts_utc           = (RCE-NowUtc)
    extension_id     = $ExtId
    name             = [string](RG-Get $Manifest "name")
    version          = [string](RG-Get $Manifest "version")
    manifest_version = [int](RG-Get $Manifest "manifest_version")
    permissions      = (RG-GetArr $Manifest "permissions")
    host_permissions = (RG-GetArr $Manifest "host_permissions")
    file_count       = @($Files).Count
    files            = $Files
    policy_decision  = [string](RG-Get $Decision "decision")
    reasons          = (RG-GetArr $Decision "reasons")
    prev_hash        = $PrevHash
  }
  $rec["record_hash"] = RG-RecordHash $rec
  return $rec
}

function RG-LedgerTailHash([string]$LedgerPath){
  $lines = RCE-ReadChainLines $LedgerPath
  if(@($lines).Count -eq 0){ return @{ seq = 0; head = $script:RG_GENESIS } }
  $last = RCE-ParseJson $lines[-1]
  $claimed = [string](RG-Get $last "record_hash")
  $last.Remove("record_hash")
  if((RG-RecordHash $last) -ne $claimed){ RG-Die "LEDGER_HEAD_TAMPERED" }
  return @{ seq = [int](RG-Get $last "seq"); head = $claimed }
}

function RG-VerifyLedger([string]$LedgerPath){
  $lines = RCE-ReadChainLines $LedgerPath
  $prev = $script:RG_GENESIS; $pseq = 0; $count = 0
  foreach($line in $lines){
    $r = RCE-ParseJson $line
    if([string](RG-Get $r "schema") -ne $script:RG_SCHEMA){ RG-Die ("LEDGER_BAD_SCHEMA seq=" + [string](RG-Get $r "seq")) }
    $claimed = [string](RG-Get $r "record_hash"); $r.Remove("record_hash")
    if((RG-RecordHash $r) -ne $claimed){ RG-Die ("LEDGER_HASH_MISMATCH seq=" + [string](RG-Get $r "seq")) }
    if([int](RG-Get $r "seq") -ne ($pseq + 1)){ RG-Die ("LEDGER_SEQ_BREAK at " + [string](RG-Get $r "seq")) }
    if([string](RG-Get $r "prev_hash") -ne $prev){ RG-Die ("LEDGER_PREV_LINK_BROKEN seq=" + [string](RG-Get $r "seq")) }
    $prev = $claimed; $pseq = [int](RG-Get $r "seq"); $count++
  }
  return [ordered]@{ record_count = $count; head_hash = $prev }
}

# latest allow-decision record for an extension_id (the load gate consults this)
function RG-LatestDecision([string]$LedgerPath,[string]$ExtId){
  $lines = RCE-ReadChainLines $LedgerPath
  $found = $null
  foreach($line in $lines){
    $r = RCE-ParseJson $line
    if([string](RG-Get $r "extension_id") -eq $ExtId){ $found = $r }
  }
  return $found
}
