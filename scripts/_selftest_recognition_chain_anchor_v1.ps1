# Selftest — Recognition Chain Head Anchor v1 (closes CHAIN-1)
# Proves the vault-backed head anchor detects end-truncation and full rebuild,
# and re-accepts an identical or legitimately grown chain. Throwaway vault+chain.
# Token: SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_chain_anchor_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("anchor_" + [Guid]::NewGuid().ToString("N"))
}
RCE-EnsureDir $TempRoot

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }
function WriteLines([string]$p,[object]$lines){ [System.IO.File]::WriteAllText($p, ((@($lines) -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }
function BuildChain([string]$path,[int]$n){
  if(Test-Path -LiteralPath $path){ Remove-Item -LiteralPath $path -Force }
  $prev = RCE-GenesisHash
  for($i=1; $i -le $n; $i++){
    $e = RCE-BuildEvent $i ("2026-09-11T00:00:0" + $i + ".000Z") ("t" + $i) $null (@{ k = $i }) (@{ session_id = "s"; profile = "p"; device = "d" }) $prev
    RCE-AppendLine $path (RCE-CanonJson $e)
    $prev = [string]$e.event_hash
  }
}

$env:RECOGNITION_PASSPHRASE = "anchor-selftest-" + [Guid]::NewGuid().ToString("N")
$chain = Join-Path $TempRoot "events.v2.ndjson"

try {
  $P = RV1-Paths $TempRoot "anchors"
  RV1-Init $P
  $master = RV1-OpenMaster $P
  try {
    BuildChain $chain 3
    $a = RCA-Anchor $P $master "events" $chain
    Check ($a.record_count -eq 3) "anchored a 3-record chain"

    $ok = $true; try { RCA-Verify $P $master "events" $chain } catch { $ok = $false }
    Check $ok "anchored chain verifies OK"

    # end-truncation: drop the last record
    $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })
    WriteLines $chain ($lines[0..($lines.Count - 2)])
    ShouldThrow { RCA-Verify $P $master "events" $chain } "end-truncated chain -> anchor verify FAILS"

    # full rebuild: forge a valid 1-record chain from genesis
    $fe = RCE-BuildEvent 1 "2099-01-01T00:00:00.000Z" "forged" $null (@{ f = $true }) (@{ session_id = "s"; profile = "p"; device = "d" }) (RCE-GenesisHash)
    WriteLines $chain @((RCE-CanonJson $fe))
    ShouldThrow { RCA-Verify $P $master "events" $chain } "rebuilt chain -> anchor verify FAILS"

    # restore the identical chain -> head/count match the anchor again (determinism)
    BuildChain $chain 3
    $ok2 = $true; try { RCA-Verify $P $master "events" $chain } catch { $ok2 = $false }
    Check $ok2 "restored identical chain re-verifies against the anchor"

    # legitimate growth: append a 4th record, re-anchor, verify OK
    BuildChain $chain 4
    ShouldThrow { RCA-Verify $P $master "events" $chain } "grown chain fails against STALE anchor (count changed)"
    [void](RCA-Anchor $P $master "events" $chain)
    $ok3 = $true; try { RCA-Verify $P $master "events" $chain } catch { $ok3 = $false }
    Check $ok3 "re-anchored grown chain verifies OK"
  } finally { RC2-ZeroBytes $master }
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
  Remove-Item Env:\RECOGNITION_PASSPHRASE -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("CHAIN_ANCHOR_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_CHAIN_ANCHOR_V1_OK" -ForegroundColor Green
