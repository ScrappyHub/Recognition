# Selftest — Recognition Extension Governance v1
# Vectors: deterministic identity, allow/review/deny policy, tamper detection
# (a changed file flips the id so the load gate refuses), and hash-chained
# ledger integrity (tampered record + tampered head both rejected).
# Runs in a throwaway tree. Token: SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_extension_governance_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("extgov_" + [Guid]::NewGuid().ToString("N"))
}
RCE-EnsureDir $TempRoot

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }
function WriteFile([string]$p,[string]$c){ $d=Split-Path -Parent $p; if($d){ RCE-EnsureDir $d }; [System.IO.File]::WriteAllText($p,$c,(New-Object System.Text.UTF8Encoding($false))) }

function MakeExt([string]$dir,[string]$name,[string[]]$perms){
  RCE-EnsureDir $dir
  $permJson = ($perms | ForEach-Object { '"' + $_ + '"' }) -join ","
  WriteFile (Join-Path $dir "manifest.json") ('{"manifest_version":3,"name":"' + $name + '","version":"1.0.0","permissions":[' + $permJson + ']}')
  WriteFile (Join-Path $dir "background.js") "console.log('bg');"
  WriteFile (Join-Path $dir "content.js") "console.log('content');"
}

try {
  $policyPath = Join-Path $TempRoot "policy.json"
  Copy-Item -LiteralPath (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "config") "extension_policy.v1.json") -Destination $policyPath -ErrorAction SilentlyContinue
  if(-not (Test-Path $policyPath)){
    WriteFile $policyPath '{"schema":"recognition.extension_policy.v1","max_manifest_version":3,"min_manifest_version":2,"denied_permissions":["debugger","<all_urls>"],"review_permissions":["tabs","cookies"],"allowed_permissions":["storage","alarms","scripting"],"allowlist":[],"blocklist":[]}'
  }
  $policy = RG-LoadPolicy $policyPath
  $ledger = Join-Path $TempRoot "ledger.ndjson"

  # --- good extension: allow ---
  $good = Join-Path $TempRoot "ext-good"; MakeExt $good "Good Ext" @("storage","alarms")
  $id1 = (RG-ComputeIdentity $good)
  Check ($id1.extension_id -match '^[0-9a-f]{64}$') "identity is 64-hex SHA-256"
  Check ((RG-ComputeIdentity $good).extension_id -eq $id1.extension_id) "identity is deterministic (same bytes -> same id)"
  $man1 = RG-ReadManifest $good
  $dec1 = RG-Decide $man1 $id1.extension_id $policy
  Check ($dec1.decision -eq "allow") "good extension decision = allow"

  # register it
  $tail = RG-LedgerTailHash $ledger
  $rec1 = RG-BuildRecord ($tail.seq+1) $id1.extension_id $man1 (RG-Get $id1 "files") $dec1 $tail.head
  RCE-AppendLine $ledger (RCE-CanonJson $rec1)
  $latest = RG-LatestDecision $ledger $id1.extension_id
  Check ($null -ne $latest -and [string](RG-Get $latest "policy_decision") -eq "allow") "registered: load gate finds allow for current bytes"

  # --- tamper a file: id must change; load gate must refuse ---
  WriteFile (Join-Path $good "background.js") "console.log('TAMPERED');"
  $id1b = (RG-ComputeIdentity $good)
  Check ($id1b.extension_id -ne $id1.extension_id) "modifying a file flips the extension_id"
  Check ($null -eq (RG-LatestDecision $ledger $id1b.extension_id)) "tampered bytes are NOT governed (load gate would refuse)"

  # --- deny: dangerous permission ---
  $bad = Join-Path $TempRoot "ext-bad"; MakeExt $bad "Bad Ext" @("storage","debugger")
  $idB = (RG-ComputeIdentity $bad); $manB = RG-ReadManifest $bad
  $decB = RG-Decide $manB $idB.extension_id $policy
  Check ($decB.decision -eq "deny") "extension requesting 'debugger' -> deny"

  # --- review: sensitive-but-not-denied permission ---
  $rev = Join-Path $TempRoot "ext-review"; MakeExt $rev "Review Ext" @("storage","tabs")
  $idR = (RG-ComputeIdentity $rev); $manR = RG-ReadManifest $rev
  $decR = RG-Decide $manR $idR.extension_id $policy
  Check ($decR.decision -eq "review") "extension requesting 'tabs' -> review"

  # --- ledger chain integrity ---
  $tail2 = RG-LedgerTailHash $ledger
  $rec2 = RG-BuildRecord ($tail2.seq+1) $idR.extension_id $manR (RG-Get $idR "files") $decR $tail2.head
  RCE-AppendLine $ledger (RCE-CanonJson $rec2)
  $vl = RG-VerifyLedger $ledger
  Check ($vl.record_count -eq 2) "ledger verifies: 2 chained records"

  # tamper the FIRST record -> full-chain verify catches it
  $orig = @(Get-Content -LiteralPath $ledger -Encoding UTF8)
  $lines = @($orig)
  $lines[0] = $lines[0].Replace('"Good Ext"','"Evil Ext"')
  [System.IO.File]::WriteAllText($ledger, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
  ShouldThrow { RG-VerifyLedger $ledger } "tampered ledger record fails chain verification"

  # tamper the LAST record -> head-hash guard (append protection) catches it
  $lines2 = @($orig)
  $lines2[-1] = $lines2[-1].Replace('"Review Ext"','"Evil Ext"')
  [System.IO.File]::WriteAllText($ledger, (($lines2 -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
  ShouldThrow { RG-LedgerTailHash $ledger } "cannot append on a tampered ledger head"
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
if($script:fail -gt 0){ Write-Error ("EXTENSION_GOVERNANCE_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_EXTENSION_GOVERNANCE_V1_OK" -ForegroundColor Green
