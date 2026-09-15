# Selftest — Recognition History Engine v1 (§24)
# Append 3 visits, verify green, replay, then negative vectors: tampered visit,
# reordered chain, forged hash. Runs in a throwaway tree.
# Token: SELFTEST_RECOGNITION_HISTORY_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_history_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("hist_" + [Guid]::NewGuid().ToString("N"))
}
RCE-EnsureDir $TempRoot

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }
function WriteLines([string]$p,[string[]]$lines){ [System.IO.File]::WriteAllText($p, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }

try {
  $chain = Join-Path $TempRoot "history.v2.ndjson"

  $null = RH-AddVisit $chain "https://example.com/a" "Page A" "typed" "tab-1" "s1"
  $null = RH-AddVisit $chain "https://example.com/b" "Page B" "link"  "tab-1" "s1"
  $null = RH-AddVisit $chain "https://example.org/c" "Page C" "link"  "tab-2" "s1"

  $v = RH-Verify $chain
  Check ($v.event_count -eq 3) "3 visits verify as a valid chain"

  $visits = @(RH-Replay $chain)
  Check ($visits.Count -eq 3) "replay reconstructs 3 visits"
  $first = $visits | Select-Object -First 1
  Check ([string]$first.title -eq "Page A") "replay preserves order (first = Page A)"
  Check ([string]$first.url_sha256 -eq (RCE-Sha256Hex "https://example.com/a")) "visit stores url_sha256 (no cleartext URL)"

  $raw = Get-Content -Raw -LiteralPath $chain -Encoding UTF8
  Check ($raw -notmatch 'example\.com/a') "cleartext URL absent from the history chain at rest"

  # --- negative: tampered visit content ---
  $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })
  $tampered = @($lines)
  $tampered[1] = $tampered[1].Replace("Page B","Evil B")
  WriteLines $chain $tampered
  ShouldThrow { RH-Verify $chain } "tampered visit fails chain verification"

  # --- negative: reordered chain ---
  $reordered = @($lines[1], $lines[0], $lines[2])
  WriteLines $chain $reordered
  ShouldThrow { RH-Verify $chain } "reordered visits fail chain verification"

  # --- negative: forged event hash ---
  $forged = @($lines)
  $forged[2] = $forged[2] -replace '"event_hash":"[0-9a-f]{64}"','"event_hash":"0000000000000000000000000000000000000000000000000000000000000000"'
  WriteLines $chain $forged
  ShouldThrow { RH-Verify $chain } "forged event hash fails chain verification"
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("HISTORY_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_HISTORY_V1_OK" -ForegroundColor Green
