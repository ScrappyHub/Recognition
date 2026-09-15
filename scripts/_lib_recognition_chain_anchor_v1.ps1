# Recognition Chain Head Anchor v1 — closes audit finding CHAIN-1 (§15 "nothing missing")
#
# The hash-chain verifiers prove INTERNAL consistency (seq/prev/hash) but cannot
# detect end-truncation or a full rebuild from genesis — nothing pins the
# expected head/length. This anchor pins {head_hash, record_count} for a chain
# inside the vault. Because the vault manifest+objects are AES-256-GCM
# authenticated under the master key, an attacker who truncates or rebuilds a
# chain cannot forge a matching anchor without the passphrase. Verify recomputes
# the chain head/count and compares to the anchored values.
#
# Works on any hash-chained ndjson whose last record carries an event_hash or
# record_hash field (event chain v2, history v2, extension governance ledger).
# Requires pwsh 7.2+ (vault crypto).

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_vault_v1.ps1")          # RV1-* (+ RC2-*)
. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")   # RCE-ReadChainLines / ParseJson / CanonJson / GenesisHash / NowUtc

function RCA-Die([string]$m){ throw ("RCA_FAIL: " + $m) }

# Generic head/count for a chain. head = last record's event_hash|record_hash.
function RCA-Head([string]$ChainPath){
  $lines = RCE-ReadChainLines $ChainPath
  $n = @($lines).Count
  if($n -eq 0){ return [ordered]@{ record_count = 0; head_hash = (RCE-GenesisHash) } }
  $last = RCE-ParseJson $lines[-1]
  $h = ""
  foreach($k in @($last.Keys)){
    $ks = [string]$k
    if($ks -eq "event_hash" -or $ks -eq "record_hash"){ $h = [string]$last[$k] }
  }
  if([string]::IsNullOrWhiteSpace($h)){ RCA-Die "CHAIN_HEAD_NO_HASH: last record has no event_hash/record_hash" }
  return [ordered]@{ record_count = $n; head_hash = $h }
}

# Store the anchor as an encrypted vault object "anchor/<Name>".
function RCA-Anchor([hashtable]$P,[byte[]]$Master,[string]$Name,[string]$ChainPath){
  $head = RCA-Head $ChainPath
  $payload = [ordered]@{
    schema       = "recognition.chain_anchor.v1"
    chain_name   = $Name
    head_hash    = [string]$head.head_hash
    record_count = [int]$head.record_count
    ts_utc       = (RCE-NowUtc)
  }
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes((RCE-CanonJson $payload))
  $res = RV1-PutBytes $P $Master ("anchor/" + $Name) $bytes "chain-anchor"
  return [ordered]@{ head_hash = [string]$head.head_hash; record_count = [int]$head.record_count; name_hmac = $res.name_hmac }
}

# Verify current chain head/count matches the anchored values (detects
# truncation / rebuild). Throws on mismatch.
function RCA-Verify([hashtable]$P,[byte[]]$Master,[string]$Name,[string]$ChainPath){
  $cur = RCA-Head $ChainPath
  $bytes = RV1-GetBytes $P $Master ("anchor/" + $Name)
  $stored = (New-Object System.Text.UTF8Encoding($false)).GetString($bytes) | ConvertFrom-Json
  $sCount = [int]$stored.record_count
  $sHead  = [string]$stored.head_hash
  if($sCount -ne [int]$cur.record_count){
    RCA-Die ("ANCHOR_COUNT_MISMATCH: anchored=" + $sCount + " current=" + [string]$cur.record_count + " (truncation or rebuild)")
  }
  if($sHead -ne [string]$cur.head_hash){
    RCA-Die ("ANCHOR_HEAD_MISMATCH: anchored=" + $sHead + " current=" + [string]$cur.head_hash + " (rebuild or reorder)")
  }
  return [ordered]@{ record_count = [int]$cur.record_count; head_hash = [string]$cur.head_hash }
}
