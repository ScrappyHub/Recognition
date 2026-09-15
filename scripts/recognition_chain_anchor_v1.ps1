# Recognition Chain Head Anchor v1 — CLI (closes CHAIN-1)
#
#   anchor : pin a chain's {head_hash, record_count} into the vault
#   verify : recompute and compare -> detects truncation / rebuild
#
#   $env:RECOGNITION_PASSPHRASE = "<passphrase>"
#   pwsh -File recognition_chain_anchor_v1.ps1 -RepoRoot . -Action anchor -ChainPath runtime\history.v2.ndjson -Name history
#   pwsh -File recognition_chain_anchor_v1.ps1 -RepoRoot . -Action verify -ChainPath runtime\history.v2.ndjson -Name history

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("anchor","verify")][string]$Action,
  [Parameter(Mandatory=$true)][string]$ChainPath,
  [Parameter(Mandatory=$true)][string]$Name,
  [string]$VaultId = "anchors"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_chain_anchor_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if(-not (Test-Path -LiteralPath $ChainPath -PathType Leaf)){ RCA-Die ("CHAIN_MISSING: " + $ChainPath) }

$P = RV1-Paths $RepoRoot $VaultId
if(-not (Test-Path -LiteralPath $P.Keystore -PathType Leaf)){ RV1-Init $P }

$ReceiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.chain_anchor.v1.ndjson"
function Receipt([hashtable]$Fields){
  $obj = [ordered]@{ schema = "recognition.chain_anchor.receipt.v1"; action = $Action; chain_name = $Name }
  foreach($k in $Fields.Keys){ $obj[$k] = $Fields[$k] }
  $obj["ts_utc"] = (RCE-NowUtc)
  RCE-AppendLine $ReceiptPath ($obj | ConvertTo-Json -Depth 8 -Compress)
}

$master = RV1-OpenMaster $P
try {
  if($Action -eq "anchor"){
    $r = RCA-Anchor $P $master $Name $ChainPath
    Receipt @{ head_hash = $r.head_hash; record_count = $r.record_count }
    Write-Host ("anchored " + $Name + ": count=" + $r.record_count + " head=" + $r.head_hash)
    Write-Host ("RECOGNITION_CHAIN_ANCHOR_V1_ANCHOR_OK: " + $Name) -ForegroundColor Green
  } else {
    $r = RCA-Verify $P $master $Name $ChainPath
    Receipt @{ head_hash = $r.head_hash; record_count = $r.record_count; matched = $true }
    Write-Host ("verified " + $Name + ": count=" + $r.record_count + " head=" + $r.head_hash + " matches anchor")
    Write-Host ("RECOGNITION_CHAIN_ANCHOR_V1_VERIFY_OK: " + $Name) -ForegroundColor Green
  }
} finally { RC2-ZeroBytes $master }
