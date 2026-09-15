# Recognition History Engine v1 — Canonical Handoff §24
#
# "History becomes append-only. History receipts. History verification.
#  History replay. History sealing."
#
# A browsing-history record is a typed event on the proven event-chain v2:
#   type = "history.visit", data = { url_sha256, title, transition, tab_id }
# URLs are hashed (never stored in clear). The chain gives append-only ordering
# and §15 integrity (nothing modified/missing/reordered/forged); replay
# reconstructs the visit timeline. Sealing is via the runtime-seal tool, since
# the chain lives under runtime/ (runtime/history.v2.ndjson).
#
# Requires pwsh 7.2+.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")  # RCE-* chain primitives

# Safe dictionary read for parsed events (OrderedDictionary): iterate .Keys and
# index with the real key — direct $d.key / $d["key"] reads of collection-valued
# keys throw "Argument types do not match" on some pwsh builds.
function RH-Get($d,[string]$key){
  if($null -eq $d){ return $null }
  foreach($k in @($d.Keys)){ if([string]$k -eq $key){ return $d[$k] } }
  return $null
}

function RH-AddVisit([string]$ChainPath,[string]$Url,[string]$Title,[string]$Transition,[string]$TabId,[string]$SessionId){
  if([string]::IsNullOrWhiteSpace($Url)){ RCE-Die "HISTORY_EMPTY_URL" }
  $tail = RCE-ChainTail $ChainPath
  $seq  = [int]$tail.seq + 1
  $prev = [string]$tail.head_hash
  $identity = [ordered]@{ session_id = $SessionId; profile = "local"; device = [string]$env:COMPUTERNAME }
  $data = [ordered]@{
    url_sha256 = (RCE-Sha256Hex $Url)
    title      = $Title
    transition = $Transition
    tab_id     = $TabId
  }
  $evt = RCE-BuildEvent $seq (RCE-NowUtc) "history.visit" $TabId $data $identity $prev
  RCE-AppendLine $ChainPath (RCE-CanonJson $evt)
  return $evt
}

# Full chain verification (delegates to the proven verifier).
function RH-Verify([string]$ChainPath){ return RCE-VerifyChain $ChainPath }

# Reconstruct the visit timeline as an array of rows (ordered by seq).
function RH-Replay([string]$ChainPath){
  $lines = RCE-ReadChainLines $ChainPath
  $visits = New-Object System.Collections.Generic.List[object]
  foreach($line in $lines){
    $e = RCE-ParseJson $line
    if([string](RH-Get $e "type") -ne "history.visit"){ continue }
    $d = RH-Get $e "data"
    $visits.Add([pscustomobject]@{
      seq        = [int](RH-Get $e "seq")
      ts_utc     = [string](RH-Get $e "ts_utc")
      title      = [string](RH-Get $d "title")
      url_sha256 = [string](RH-Get $d "url_sha256")
      transition = [string](RH-Get $d "transition")
    })
  }
  # return the array plainly (no comma) so a caller's @() collects the rows;
  # a comma-wrapped return double-wraps under @() and yields a 1-element array.
  return $visits.ToArray()
}
