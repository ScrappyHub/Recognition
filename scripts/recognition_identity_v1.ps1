# Recognition Identity + Receipt Chain v1 — CLI (WBS 4.1, self-contained)
#
#   init                       establish the local identity + genesis receipt
#   event -Type <t> [-Note n]  append a hash-chained identity/evidence receipt
#   verify                     verify the identity receipt chain
#   show                       print identity ids + chain head
#
# No NeverLost dependency. Anchor the chain with:
#   recognition_chain_anchor_v1.ps1 -Action anchor -ChainPath proofs\identity\identity.chain.v1.ndjson -Name identity

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("init","event","verify","show")][string]$Action,
  [string]$Type = "",
  [string]$Note = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_identity_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if($Action -eq "init"){
  $d = RID-EnsureIdentity $RepoRoot
  Write-Host ("recognition_identity_id : " + (RID-Get $d "recognition_identity_id"))
  Write-Host ("device_id               : " + (RID-Get $d "device_id"))
  Write-Host ("RECOGNITION_IDENTITY_V1_INIT_OK") -ForegroundColor Green
  exit 0
}

if($Action -eq "event"){
  if([string]::IsNullOrWhiteSpace($Type)){ RID-Die "EVENT_TYPE_REQUIRED" }
  $evt = RID-Event $RepoRoot $Type ([ordered]@{ note = $Note })
  Write-Host ("appended receipt seq=" + [string]$evt.seq + " type=" + $Type)
  Write-Host ("RECOGNITION_IDENTITY_V1_EVENT_OK: seq=" + [string]$evt.seq) -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  $r = RID-Verify $RepoRoot
  Write-Host ("identity chain verified: receipts=" + $r.event_count + " head=" + $r.head_hash)
  Write-Host ("RECOGNITION_IDENTITY_V1_VERIFY_OK: receipts=" + $r.event_count) -ForegroundColor Green
  exit 0
}

if($Action -eq "show"){
  $P = RID-Paths $RepoRoot
  $d = RID-LoadDescriptor $P
  if($null -eq $d){ Write-Host "no identity yet — run: recognition_identity_v1.ps1 -Action init"; exit 0 }
  Write-Host ("recognition_identity_id : " + (RID-Get $d "recognition_identity_id"))
  Write-Host ("device_id               : " + (RID-Get $d "device_id"))
  Write-Host ("user_id                 : " + (RID-Get $d "user_id"))
  Write-Host ("vault_id                : " + (RID-Get $d "vault_id"))
  Write-Host ("created_utc             : " + (RID-Get $d "created_utc"))
  if(Test-Path -LiteralPath $P.Chain -PathType Leaf){
    $r = RCE-VerifyChain $P.Chain
    Write-Host ("chain receipts          : " + $r.event_count + "  head=" + $r.head_hash)
  }
  Write-Host "RECOGNITION_IDENTITY_V1_SHOW_OK" -ForegroundColor Green
  exit 0
}
