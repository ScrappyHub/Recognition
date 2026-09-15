# RUN_RELEASE_GATE_V1 — WBS 7.4 release checklist gate + signoff
#
# Single command that composes every proven runner and prints one earned token.
# Mandatory: packet law green + prove-all green. Advisory: publish-scan clean,
# browser build (skipped cleanly if .NET SDK is absent). No false-GREEN: each
# step must emit its real token or the gate fails.
#
#   $env:RECOGNITION_PASSPHRASE = "<passphrase>"
#   pwsh -File scripts\RUN_RELEASE_GATE_V1.ps1 -RepoRoot .
# Final token: RECOGNITION_RELEASE_GATE_V1_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [switch]$RequirePublishClean,
  [switch]$RequireBrowserBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if($PSVersionTable.PSVersion.Major -lt 7){ throw "REQUIRES_PWSH7" }
if([string]::IsNullOrEmpty($env:RECOGNITION_PASSPHRASE)){ throw "PASSPHRASE_MISSING: set `$env:RECOGNITION_PASSPHRASE" }

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$S = Join-Path $RepoRoot "scripts"
$results = @()

function Gate([string]$Label,[scriptblock]$Block,[string]$Token,[bool]$Mandatory){
  Write-Host ("=== " + $Label + " ===") -ForegroundColor Cyan
  $ok = $false; $note = ""
  try { $out = & $Block *>&1 | Out-String; $ok = ($out -match [regex]::Escape($Token)) }
  catch { $note = (($_ | Out-String).Trim() -split "`n")[0] }
  $status = if($ok){ "PASS" } elseif(-not $Mandatory){ "WARN" } else { "FAIL" }
  $color  = if($ok){ "Green" } elseif(-not $Mandatory){ "Yellow" } else { "Red" }
  Write-Host ("-> " + $Label + " : " + $status) -ForegroundColor $color
  if($note){ Write-Host ("   " + $note) -ForegroundColor DarkGray }
  $script:results += [ordered]@{ gate=$Label; token=$Token; mandatory=$Mandatory; passed=$ok; status=$status }
}

# 1) packet law (WBS 2.0/3.0) — powershell 5.1-compatible core, run via pwsh here
Gate "packet law"   { & (Join-Path $S "RUN_PACKET_LAW_GREEN_V1.ps1") -RepoRoot $RepoRoot } "RECOGNITION_PACKET_LAW_GREEN_V1_OK" $true

# 2) prove-all (crypto/vault/chain/history/anchor/identity/extension/launch/attestation)
Gate "prove all"    { & (Join-Path $S "recognition_prove_all_v1.ps1") -RepoRoot $RepoRoot } "RECOGNITION_PROVE_ALL_V1_OK" $true

# 3) publish scan (advisory unless -RequirePublishClean)
Gate "publish scan" { & (Join-Path $S "recognition_publish_scan_v1.ps1") -RepoRoot $RepoRoot } "RECOGNITION_PUBLISH_SCAN_V1_OK" ([bool]$RequirePublishClean)

# 4) browser build (advisory unless -RequireBrowserBuild; skipped if no dotnet)
$hasDotnet = [bool](Get-Command dotnet -ErrorAction SilentlyContinue)
if($hasDotnet){
  Gate "browser build" { & (Join-Path $RepoRoot "browser\build.ps1") -Configuration Release } "RECOGNITION_BROWSER_BUILD_OK" ([bool]$RequireBrowserBuild)
} else {
  Write-Host "=== browser build ===" -ForegroundColor Cyan
  Write-Host "-> browser build : SKIP (no .NET SDK)" -ForegroundColor Yellow
}

$mandatoryFail = @($results | Where-Object { $_.mandatory -and -not $_.passed }).Count
$verdict = if($mandatoryFail -eq 0){ "GREEN" } else { "RED" }

$receipt = [ordered]@{
  schema = "recognition.release_gate.receipt.v1"
  ts_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  verdict = $verdict
  gates = $results
}
$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.release_gate.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
[System.IO.File]::AppendAllText($rp, (($receipt | ConvertTo-Json -Depth 10 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host ("Release gate verdict: " + $verdict) -ForegroundColor $(if($verdict -eq "GREEN"){"Green"}else{"Red"})
if($verdict -ne "GREEN"){ Write-Error ("RELEASE_GATE_FAILED: " + $mandatoryFail + " mandatory gate(s) failed"); exit 1 }
Write-Host "RECOGNITION_RELEASE_GATE_V1_OK" -ForegroundColor Green
