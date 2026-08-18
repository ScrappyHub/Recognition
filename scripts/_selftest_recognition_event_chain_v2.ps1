# Selftest: Recognition Event Chain v2 (positive + negative vectors)
# Green token: SELFTEST_RECOGNITION_EVENT_CHAIN_V2_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$AppendScript = Join-Path $PSScriptRoot "recognition_event_append_v2.ps1"
$VerifyScript = Join-Path $PSScriptRoot "recognition_verify_event_chain_v2.ps1"
$MigrateScript = Join-Path $PSScriptRoot "recognition_event_chain_migrate_v1_v2.ps1"

$TmpDir = Join-Path $RepoRoot (Join-Path "tmp" ("selftest_event_chain_v2_" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmssfff")))
RCE-EnsureDir $TmpDir
$Chain = Join-Path $TmpDir "events.v2.ndjson"
$pass = 0

function Check([string]$Name,[bool]$Cond){
  if(-not $Cond){ RCE-Die ("SELFTEST_CHECK_FAIL: " + $Name) }
  $script:pass++
  Write-Host ("CHECK_OK: " + $Name) -ForegroundColor Green
}

function ExpectFail([string]$Name,[scriptblock]$Block){
  $failed = $false
  try { & $Block *>&1 | Out-Null } catch { $failed = $true }
  if(-not $failed){ RCE-Die ("SELFTEST_NEGATIVE_DID_NOT_FAIL: " + $Name) }
  $script:pass++
  Write-Host ("NEGATIVE_OK: " + $Name) -ForegroundColor Green
}

try {
  # --- build a 5-event chain via the append tool -----------------------------
  $sid = "selftest-session-v2"
  $common = @{ RepoRoot=$RepoRoot; ChainPath=$Chain; SessionId=$sid; ProfileId="selftest-profile-v2"; DeviceId="selftest-device" }

  & $AppendScript @common -Type "session.started" -DataJson ('{"mode":"selftest","session_id":"' + $sid + '"}') | Out-Null
  & $AppendScript @common -Type "tab.opened" -TabId "tab-001" -DataJson '{"url":"about:blank","index":0}' | Out-Null
  & $AppendScript @common -Type "navigation.committed" -TabId "tab-001" -DataJson '{"url":"https://example.com/a"}' | Out-Null
  & $AppendScript @common -Type "navigation.committed" -TabId "tab-001" -DataJson '{"url":"https://example.com/b"}' | Out-Null
  & $AppendScript @common -Type "session.ended" -DataJson '{}' | Out-Null
  Check "append_5_events" ((RCE-ReadChainLines $Chain).Count -eq 5)

  # --- verify green -----------------------------------------------------------
  $out = & $VerifyScript -RepoRoot $RepoRoot -ChainPath $Chain *>&1 | Out-String
  Check "verify_green" ($out -match "RECOGNITION_EVENT_CHAIN_VERIFY_V2_OK")

  $verify = RCE-VerifyChain $Chain
  Check "head_seq_5" ([int]$verify.head_seq -eq 5)

  $backup = Get-Content -Raw -LiteralPath $Chain -Encoding UTF8
  $lines = RCE-ReadChainLines $Chain

  # --- negative: modified (tamper a data field, keep stored hash) -------------
  $e3 = RCE-ParseJson $lines[2]
  $e3.data.url = "https://evil.example/tampered"
  $tampered = @($lines[0],$lines[1],(RCE-CanonJson $e3),$lines[3],$lines[4]) -join "`n"
  [System.IO.File]::WriteAllText($Chain,$tampered + "`n",(New-Object System.Text.UTF8Encoding($false)))
  ExpectFail "tampered_data_detected" { RCE-VerifyChain $Chain }

  # --- negative: forged (tamper + recompute own hash; prev link of successor breaks)
  $e3 = RCE-ParseJson $lines[2]
  $e3.data.url = "https://evil.example/forged"
  $e3.Remove("event_hash")
  $e3["event_hash"] = RCE-ComputeEventHash $e3
  $forged = @($lines[0],$lines[1],(RCE-CanonJson $e3),$lines[3],$lines[4]) -join "`n"
  [System.IO.File]::WriteAllText($Chain,$forged + "`n",(New-Object System.Text.UTF8Encoding($false)))
  ExpectFail "forged_event_detected" { RCE-VerifyChain $Chain }

  # --- negative: missing (drop the middle event) -------------------------------
  $missing = @($lines[0],$lines[1],$lines[3],$lines[4]) -join "`n"
  [System.IO.File]::WriteAllText($Chain,$missing + "`n",(New-Object System.Text.UTF8Encoding($false)))
  ExpectFail "missing_event_detected" { RCE-VerifyChain $Chain }

  # --- negative: reordered (swap events 3 and 4) -------------------------------
  $reordered = @($lines[0],$lines[1],$lines[3],$lines[2],$lines[4]) -join "`n"
  [System.IO.File]::WriteAllText($Chain,$reordered + "`n",(New-Object System.Text.UTF8Encoding($false)))
  ExpectFail "reordered_events_detected" { RCE-VerifyChain $Chain }

  # --- negative: append refuses a tampered head --------------------------------
  $e5 = RCE-ParseJson $lines[4]
  $e5.type = "session.forged"
  $badHead = @($lines[0],$lines[1],$lines[2],$lines[3],(RCE-CanonJson $e5)) -join "`n"
  [System.IO.File]::WriteAllText($Chain,$badHead + "`n",(New-Object System.Text.UTF8Encoding($false)))
  ExpectFail "append_on_tampered_head_refused" { & $AppendScript @common -Type "x" -DataJson '{}' }

  # --- restore and confirm green again -----------------------------------------
  [System.IO.File]::WriteAllText($Chain,$backup,(New-Object System.Text.UTF8Encoding($false)))
  $verify2 = RCE-VerifyChain $Chain
  Check "restored_chain_green" ([string]$verify2.head_hash -eq [string]$verify.head_hash)

  # --- migration: v1 events -> v2 chain -----------------------------------------
  $v1Path = Join-Path $TmpDir "events.v1.ndjson"
  $v1Lines = @(
    '{"schema":"recognition.event.v1","event_id":"evt-0001","seq":1,"ts_utc":"2026-06-07T16:00:00.000Z","type":"session.started","tab_id":null,"data":{"mode":"clean-browser","session_id":"legacy-session"}}',
    '{"schema":"recognition.event.v1","event_id":"evt-0002","seq":2,"ts_utc":"2026-06-07T16:00:05.000Z","type":"tab.opened","tab_id":"tab-a","data":{"url":"about:blank","title":"t","index":0}}',
    '{"schema":"recognition.event.v1","event_id":"evt-0003","seq":3,"ts_utc":"2026-06-07T16:00:10.000Z","type":"navigation.committed","tab_id":"tab-a","data":{"url":"https://example.com","title":"e"}}'
  )
  [System.IO.File]::WriteAllText($v1Path,(($v1Lines -join "`n") + "`n"),(New-Object System.Text.UTF8Encoding($false)))

  $v2Path = Join-Path $TmpDir "migrated.v2.ndjson"
  $mout = & $MigrateScript -RepoRoot $RepoRoot -SourcePath $v1Path -OutPath $v2Path -ProfileId "legacy-profile" *>&1 | Out-String
  Check "migrate_green" ($mout -match "RECOGNITION_EVENT_CHAIN_MIGRATE_V2_OK")

  $mv = RCE-VerifyChain $v2Path
  Check "migrated_chain_verifies" ([int]$mv.event_count -eq 3)

  $firstMigrated = RCE-ParseJson ((RCE-ReadChainLines $v2Path)[0])
  Check "migration_provenance_kept" ([string]$firstMigrated.data_migrated_from.v1_event_id -eq "evt-0001")
  Check "migration_identity_set" ([string]$firstMigrated.identity.session_id -eq "legacy-session")

} finally {
  if(Test-Path -LiteralPath $TmpDir -PathType Container){
    Remove-Item -LiteralPath $TmpDir -Recurse -Force
  }
}

Write-Host ("SELFTEST_CHECKS_PASSED: " + $pass) -ForegroundColor Green
Write-Host "SELFTEST_RECOGNITION_EVENT_CHAIN_V2_OK" -ForegroundColor Green
