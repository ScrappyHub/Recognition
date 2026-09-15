# Recognition — Prove Everything v1
#
# One command that exercises every independent verifier in the repo and emits a
# single deterministic proof-of-health receipt. This is the operator-facing face
# of the "evidence / verification engine": run it and either the whole system is
# provably green (with a proof hash over the component tokens) or it names what
# failed.
#
# Components (mandatory unless noted):
#   - Phase 1:  crypto core v2 + encrypted profile v2 selftests
#   - Event chain v2 selftest (hash-chained event integrity, negative vectors)
#   - Live event chain verify (runtime/events.v2.ndjson, if present)
#   - Phase 4:  vault v1 selftest + publish scan (parse-gated stack)
#   - Attestation v2 verify against the pinned trust root (latest bundle)
#   - Publish scan (advisory by default; -RequirePublishClean makes it mandatory)
#
# Requires pwsh 7.2+ and $env:RECOGNITION_PASSPHRASE (the selftests use it).
#
# Token on full success: RECOGNITION_PROVE_ALL_V1_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [switch]$RequirePublishClean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if($PSVersionTable.PSVersion.Major -lt 7){ throw "REQUIRES_PWSH7" }
if([string]::IsNullOrEmpty($env:RECOGNITION_PASSPHRASE)){
  throw "PASSPHRASE_MISSING: set `$env:RECOGNITION_PASSPHRASE before proving (the selftests need it)."
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
$enc = New-Object System.Text.UTF8Encoding($false)

function Sha256Hex([string]$Text){
  $h = [System.Security.Cryptography.SHA256]::HashData($enc.GetBytes($Text))
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

function RunComponent([string]$Script,[string]$Rr,[string]$Token){
  # Pass -RepoRoot explicitly. Array splatting proved unreliable here (an $Args
  # parameter shadowed the automatic $args), so we invoke directly.
  $path = Join-Path $ScriptsDir $Script
  if(-not (Test-Path -LiteralPath $path -PathType Leaf)){ return @{ ok=$false; note="script missing" } }
  try {
    $out = & $path -RepoRoot $Rr *>&1 | Out-String
    return @{ ok = ($out -match [regex]::Escape($Token)); note = "" }
  } catch {
    return @{ ok=$false; note=(($_ | Out-String).Trim() -split "`n")[0] }
  }
}

# --- assemble component plan -------------------------------------------------
$plan = New-Object System.Collections.Generic.List[object]
$plan.Add(@{ id="phase1_crypto_profile"; script="RUN_PHASE1_GREEN_V2.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_PHASE1_GREEN_V2_OK"; mandatory=$true })
$plan.Add(@{ id="event_chain_selftest";  script="_selftest_recognition_event_chain_v2.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_EVENT_CHAIN_V2_OK"; mandatory=$true })

$liveChain = Join-Path (Join-Path $RepoRoot "runtime") "events.v2.ndjson"
if(Test-Path -LiteralPath $liveChain -PathType Leaf){
  $plan.Add(@{ id="live_event_chain_verify"; script="recognition_verify_event_chain_v2.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_EVENT_CHAIN_VERIFY_V2_OK"; mandatory=$true })
}
$plan.Add(@{ id="extension_governance_selftest"; script="_selftest_recognition_extension_governance_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK"; mandatory=$true })
$plan.Add(@{ id="governed_launcher_selftest"; script="_selftest_recognition_launch_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_LAUNCH_V1_OK"; mandatory=$true })
$plan.Add(@{ id="history_engine_selftest"; script="_selftest_recognition_history_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_HISTORY_V1_OK"; mandatory=$true })
$plan.Add(@{ id="chain_anchor_selftest"; script="_selftest_recognition_chain_anchor_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK"; mandatory=$true })
$plan.Add(@{ id="identity_chain_selftest"; script="_selftest_recognition_identity_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="SELFTEST_RECOGNITION_IDENTITY_V1_OK"; mandatory=$true })
$plan.Add(@{ id="locked_startup"; script="recognition_locked_startup_browser_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_LOCKED_STARTUP_OK"; mandatory=$true })
$plan.Add(@{ id="vault_and_stack_phase4"; script="RUN_PHASE4_GREEN_V2.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_PHASE4_GREEN_V2_OK"; mandatory=$true })
$plan.Add(@{ id="attestation_verify";     script="recognition_verify_attestation_v2.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_ATTEST_VERIFY_V2_OK"; mandatory=$true })
$plan.Add(@{ id="publish_scan";           script="recognition_publish_scan_v1.ps1"; args=@("-RepoRoot",$RepoRoot); token="RECOGNITION_PUBLISH_SCAN_V1_OK"; mandatory=[bool]$RequirePublishClean })

# --- run ---------------------------------------------------------------------
Write-Host "=== Recognition: prove everything ===" -ForegroundColor Cyan
$results = @()
foreach($c in $plan){
  Write-Host ("-> " + $c.id + " ...") -NoNewline
  $r = RunComponent $c.script $RepoRoot $c.token
  $status = if($r.ok){ "PASS" } elseif(-not $c.mandatory){ "WARN" } else { "FAIL" }
  $color = if($r.ok){ "Green" } elseif(-not $c.mandatory){ "Yellow" } else { "Red" }
  Write-Host ("  " + $status) -ForegroundColor $color
  if(-not $r.ok -and $r.note){ Write-Host ("     " + $r.note) -ForegroundColor DarkGray }
  $results += [ordered]@{ id=$c.id; token=$c.token; mandatory=[bool]$c.mandatory; passed=[bool]$r.ok; status=$status }
}

# --- verdict + proof hash ----------------------------------------------------
$mandatoryFail = @($results | Where-Object { $_.mandatory -and -not $_.passed }).Count
$verdict = if($mandatoryFail -eq 0){ "GREEN" } else { "RED" }

$proofBody = [ordered]@{
  schema     = "recognition.prove_all.v1"
  repo_root  = $RepoRoot
  verdict    = $verdict
  components = $results
}
# canonical-ish stable serialization for the proof hash (compressed, sorted by id already fixed order)
$proofJson = ($proofBody | ConvertTo-Json -Depth 12 -Compress)
$proofHash = Sha256Hex $proofJson

$receipt = [ordered]@{
  schema     = "recognition.prove_all.receipt.v1"
  ts_utc     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  verdict    = $verdict
  proof_hash = $proofHash
  components = $results
}
$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.prove_all.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
[System.IO.File]::AppendAllText($rp, (($receipt | ConvertTo-Json -Depth 12 -Compress) + "`n"), $enc)

Write-Host ""
Write-Host ("Verdict: " + $verdict + "   proof_hash=" + $proofHash) -ForegroundColor $(if($verdict -eq "GREEN"){"Green"}else{"Red"})
Write-Host ("Proof receipt appended: proofs/receipts/recognition.prove_all.v1.ndjson")

if($verdict -ne "GREEN"){
  Write-Error ("PROVE_ALL_FAILED: " + $mandatoryFail + " mandatory component(s) failed")
  exit 1
}
Write-Host "RECOGNITION_PROVE_ALL_V1_OK" -ForegroundColor Green
