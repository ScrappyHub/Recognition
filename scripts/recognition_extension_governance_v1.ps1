# Recognition Extension Governance v1 — CLI
#
# Governs Chromium extensions deterministically (Handoff §22). No extension runs
# unrecognized: identity is the SHA-256 of its file set, a policy decides
# allow/review/deny, and the decision is written to a hash-chained ledger.
# `verify` is the load gate — Chromium should load an extension only when its
# current bytes still match a recorded 'allow'.
#
# Actions:
#   register     -ExtPath <dir> [-PolicyPath <json>]   compute id, decide, record
#   verify       -ExtPath <dir>                          load gate: unchanged + allow?
#   list                                                 show ledger entries
#   verify-chain                                         prove ledger integrity

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$Action,
  [string]$ExtPath = "",
  [string]$PolicyPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_extension_governance_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($PolicyPath)){
  $PolicyPath = Join-Path (Join-Path $RepoRoot "config") "extension_policy.v1.json"
}
$Ledger = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.extension_governance.v1.ndjson"

if($Action -eq "register"){
  if([string]::IsNullOrWhiteSpace($ExtPath)){ RG-Die "REGISTER_NO_EXTPATH" }
  $idInfo   = RG-ComputeIdentity $ExtPath
  $manifest = RG-ReadManifest $ExtPath
  $policy   = RG-LoadPolicy $PolicyPath
  $decision = RG-Decide $manifest $idInfo.extension_id $policy
  $tail     = RG-LedgerTailHash $Ledger
  $rec      = RG-BuildRecord ([int]$tail.seq + 1) $idInfo.extension_id $manifest (RG-Get $idInfo "files") $decision ([string]$tail.head)
  RCE-AppendLine $Ledger (RCE-CanonJson $rec)
  Write-Host ("extension_id : " + $idInfo.extension_id)
  Write-Host ("name/version : " + (RG-Get $manifest "name") + " " + (RG-Get $manifest "version") + " (mv" + (RG-Get $manifest "manifest_version") + ")")
  Write-Host ("decision     : " + (RG-Get $decision "decision") + "  [" + (@(RG-Get $decision "reasons") -join "; ") + "]")
  Write-Host ("RECOGNITION_EXT_GOV_V1_REGISTER_OK: " + $idInfo.extension_id + " decision=" + $decision.decision) -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  if([string]::IsNullOrWhiteSpace($ExtPath)){ RG-Die "VERIFY_NO_EXTPATH" }
  $idInfo = RG-ComputeIdentity $ExtPath
  $rec = RG-LatestDecision $Ledger $idInfo.extension_id
  if($null -eq $rec){
    RG-Die ("EXTENSION_NOT_GOVERNED_OR_TAMPERED: no ledger record for current bytes (id=" + $idInfo.extension_id + "). Bytes changed since registration, or never registered.")
  }
  $decision = [string](RG-Get $rec "policy_decision")
  if($decision -ne "allow"){
    RG-Die ("EXTENSION_LOAD_REFUSED: id=" + $idInfo.extension_id + " decision=" + $decision)
  }
  Write-Host ("extension_id : " + $idInfo.extension_id + "  (matches governed 'allow')")
  Write-Host ("RECOGNITION_EXT_GOV_V1_VERIFY_OK: " + $idInfo.extension_id) -ForegroundColor Green
  exit 0
}

if($Action -eq "list"){
  $lines = RCE-ReadChainLines $Ledger
  Write-Output ("RECOGNITION_EXT_GOV_V1_COUNT: " + @($lines).Count)
  foreach($line in $lines){
    $r = RCE-ParseJson $line
    Write-Output ("  seq=" + [string](RG-Get $r "seq") + " " + ([string](RG-Get $r "policy_decision")).PadRight(6) + " " + [string](RG-Get $r "name") + " " + [string](RG-Get $r "version") + "  " + ([string](RG-Get $r "extension_id")).Substring(0,16) + "...")
  }
  Write-Host "RECOGNITION_EXT_GOV_V1_LIST_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "verify-chain"){
  $r = RG-VerifyLedger $Ledger
  Write-Host ("ledger records: " + $r.record_count + "  head=" + $r.head_hash)
  Write-Host "RECOGNITION_EXT_GOV_V1_CHAIN_OK" -ForegroundColor Green
  exit 0
}

RG-Die ("EXT_GOV_UNKNOWN_ACTION: " + $Action)
