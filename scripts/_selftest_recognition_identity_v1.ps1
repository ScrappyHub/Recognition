# Selftest — Recognition Identity + Receipt Chain v1 (WBS 4.1, self-contained)
# init -> genesis receipt; append events; verify; idempotent re-init; and the
# chain fails closed on tamper/reorder. Throwaway repo root. No NeverLost.
# Token: SELFTEST_RECOGNITION_IDENTITY_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_identity_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("ident_" + [Guid]::NewGuid().ToString("N"))
}
RCE-EnsureDir $TempRoot

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }
function WriteLines([string]$p,[object]$lines){ [System.IO.File]::WriteAllText($p, ((@($lines) -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }

try {
  $P = RID-Paths $TempRoot

  $d1 = RID-EnsureIdentity $TempRoot
  Check ((RID-Get $d1 "recognition_identity_id").Length -eq 64) "identity id is a 64-hex hash"
  Check (Test-Path -LiteralPath $P.Descriptor) "identity descriptor written"
  $v = RCE-VerifyChain $P.Chain
  Check ($v.event_count -eq 1) "genesis identity.created receipt present"

  # idempotent re-init returns the SAME identity
  $d2 = RID-EnsureIdentity $TempRoot
  Check ((RID-Get $d1 "recognition_identity_id") -eq (RID-Get $d2 "recognition_identity_id")) "re-init is idempotent (same identity)"

  # append lifecycle/evidence receipts
  [void](RID-Event $TempRoot "session.started" ([ordered]@{ note = "test session" }))
  [void](RID-Event $TempRoot "packet.export" ([ordered]@{ note = "exported one packet" }))
  $v2 = RID-Verify $TempRoot
  Check ($v2.event_count -eq 3) "chain grows to 3 receipts and verifies"

  # descriptor holds non-secret ids only (no vault master key, no passphrase)
  $raw = Get-Content -Raw -LiteralPath $P.Descriptor -Encoding UTF8
  Check ($raw -notmatch 'PRIVATE KEY' -and $raw -notmatch 'passphrase') "descriptor carries no secret material"

  # tamper a receipt -> verify fails
  $lines = @(Get-Content -LiteralPath $P.Chain -Encoding UTF8 | Where-Object { $_ -ne "" })
  $lines[1] = $lines[1].Replace("test session","HIJACKED")
  WriteLines $P.Chain $lines
  ShouldThrow { RID-Verify $TempRoot } "tampered receipt fails chain verification"

  # reorder -> verify fails
  $lines2 = @(Get-Content -LiteralPath $P.Chain -Encoding UTF8 | Where-Object { $_ -ne "" })
  if($lines2.Count -ge 2){ $tmp=$lines2[0]; $lines2[0]=$lines2[1]; $lines2[1]=$tmp }
  WriteLines $P.Chain $lines2
  ShouldThrow { RID-Verify $TempRoot } "reordered receipts fail chain verification"
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
if($script:fail -gt 0){ Write-Error ("IDENTITY_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_IDENTITY_V1_OK" -ForegroundColor Green
