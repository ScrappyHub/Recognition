# RUN_PACKET_LAW_GREEN_V1 — the single clean runner for the WBS critical path
# (WBS 2.4 / 3.2 / 3.3 / 7.1; DoD: Export law, Verification, Selftest, Runner
# hygiene, Quality gates).
#
# It does ONE thing honestly: parse-gate the COMMITTED packet scripts, run the
# selftest, run the export law against the default session export, verify the
# exported packet, and print a single GREEN token ONLY if every step truly
# passed (real token checks — no false-GREEN banners).
#
# It NEVER rewrites or patches any script (that is the source of the drift +
# non-deterministic PacketId in the old _RUN_install_* rewriters — do not use
# those). Windows PowerShell 5.1 compatible.
#
#   powershell -NoProfile -File scripts\RUN_PACKET_LAW_GREEN_V1.ps1 -RepoRoot .
# Final token: RECOGNITION_PACKET_LAW_GREEN_V1_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$S = Join-Path $RepoRoot "scripts"

function Die([string]$m){ Write-Host ("PACKET_LAW_FAIL: " + $m) -ForegroundColor Red; exit 1 }

# --- quality gate: parse the committed packet scripts (DoD: parse-gate) -------
function ParseGate([string]$rel){
  $p = Join-Path $S $rel
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("PARSE_MISSING: " + $rel) }
  $t = $null; $e = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$t,[ref]$e)
  if($e -and @($e).Count -gt 0){
    $x = @($e)[0]
    Die ("PARSE_FAIL: {0}:{1}:{2}: {3}" -f $rel,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
  Write-Host ("PARSE_OK: " + $rel) -ForegroundColor DarkGreen
}

foreach($f in @(
  "_lib_packet_constitution_v1.ps1",
  "_lib_recognition_receipts_v1.ps1",
  "pc_build_packet_optionA_v1.ps1",
  "pc_verify_packet_optionA_v1.ps1",
  "_selftest_packet_constitution_v1.ps1",
  "_selftest_packet_negative_v1.ps1",
  "recognition_export_session_packet_v1.ps1"
)){ ParseGate $f }

# --- run a step, require its success token in output (no false GREEN) ---------
function RunReq([string]$Label,[scriptblock]$Block,[string]$Token){
  Write-Host ("=== " + $Label + " ===") -ForegroundColor Cyan
  $out = ""
  try {
    # *>&1 (not 2>&1) so Write-Host / information-stream tokens are captured too
    $out = & $Block *>&1 | Out-String
  } catch {
    Write-Host $out
    Die ($Label + " threw: " + $_.Exception.Message)
  }
  Write-Host $out
  if($out -notmatch [regex]::Escape($Token)){ Die ($Label + ": required token missing (" + $Token + ")") }
  return $out
}

# --- 1) packet selftest (deterministic minimal vector) -----------------------
[void](RunReq "packet selftest" { & (Join-Path $S "_selftest_packet_constitution_v1.ps1") -RepoRoot $RepoRoot } "SELFTEST_OK")

# --- 1b) negative vectors: verifier must REJECT every tamper class ------------
[void](RunReq "packet negative vectors" { & (Join-Path $S "_selftest_packet_negative_v1.ps1") -RepoRoot $RepoRoot } "SELFTEST_PACKET_NEGATIVE_V1_OK")

# --- 2) export law: default payload\session_export -> packets\outbox ----------
$exportOut = RunReq "export law" { & (Join-Path $S "recognition_export_session_packet_v1.ps1") -RepoRoot $RepoRoot } "EXPORT_OK"
$mm = [regex]::Match($exportOut, "EXPORT_OK:\s*(?<d>.+)")
if(-not $mm.Success){ Die "export law: could not read packet dir from EXPORT_OK line" }
$pktDir = $mm.Groups["d"].Value.Trim()
if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ Die ("export law: packet dir not found: " + $pktDir) }

# --- 3) verify the exported packet (no manual edits) -------------------------
[void](RunReq "packet verify" { & (Join-Path $S "pc_verify_packet_optionA_v1.ps1") -PacketDir $pktDir } "VERIFY_OK")

# --- single, earned GREEN ----------------------------------------------------
Write-Host ""
Write-Host ("Packet law green: selftest + export + verify all passed with real tokens.")
Write-Host ("Exported packet: " + $pktDir)
Write-Host "RECOGNITION_PACKET_LAW_GREEN_V1_OK" -ForegroundColor Green
