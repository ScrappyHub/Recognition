# Selftest — Recognition Portable Backup / Recovery v1 (§21)
# Builds a throwaway "source" profile (identity + all 5 governed stores with
# known plaintext content, written directly via DPAPI — no browser needed),
# exports a portable encrypted backup, and restores it into a FRESH "target"
# profile tree. Verifies: identity is preserved byte-for-byte (same id, same
# unsealed salt), every store round-trips to the exact original plaintext, and
# restored hash-chain stores (actions) still verify post-restore. Then negative
# vectors: wrong passphrase, tampered ciphertext, refuse without -Force when
# identities differ, refuse without -Force when a store already exists, and a
# partial bundle (one store absent) restores cleanly without fabricating it.
# Token: SELFTEST_RECOGNITION_BACKUP_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_backup_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("bkup_" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }

# a hash-chained "actions"-format line, matching GovernedActions/RBK-AppendActionReceipt
function J2([string]$s){ '"' + ([string]$s).Replace('\','\\').Replace('"','\"') + '"' }
function OneActionLine([int]$seq,[string]$action,[string]$prev){
  $ts = "2026-01-01T00:00:00.00" + $seq + "Z"
  $body = "{" + (J2 "seq") + ":" + $seq + "," + (J2 "ts_utc") + ":" + (J2 $ts) + "," +
          (J2 "action") + ":" + (J2 $action) + "," + (J2 "detail_sha256") + ":" + (J2 "") + "," +
          (J2 "prev_hash") + ":" + (J2 $prev) + "}"
  $sha = [System.Security.Cryptography.SHA256]::HashData((New-Object System.Text.UTF8Encoding($false)).GetBytes($body))
  $hex = -join ($sha | ForEach-Object { $_.ToString("x2") })
  $line = $body.Substring(0, $body.Length - 1) + "," + (J2 "hash") + ":" + (J2 $hex) + "}"
  return @{ line = $line; hash = $hex }
}
function VerifyActionsChain([string]$text){
  $lines = @($text -split "`n" | Where-Object { $_.Trim() -ne "" })
  $prev = ("0" * 64); $expect = 1
  foreach($line in $lines){
    $r = $line | ConvertFrom-Json
    if([int]$r.seq -ne $expect){ return $false }
    if([string]$r.prev_hash -ne $prev){ return $false }
    $marker = "," + (J2 "hash") + ":"
    $idx = $line.LastIndexOf($marker)
    if($idx -lt 0){ return $false }
    $body = $line.Substring(0, $idx) + "}"
    $sha = [System.Security.Cryptography.SHA256]::HashData((New-Object System.Text.UTF8Encoding($false)).GetBytes($body))
    $hex = -join ($sha | ForEach-Object { $_.ToString("x2") })
    if($hex -ne [string]$r.hash){ return $false }
    $prev = $hex; $expect++
  }
  return $true
}

$script:originalPassphrase = $env:RECOGNITION_PASSPHRASE   # restored in finally — this selftest runs
                                                            # in-process inside prove_all, so $env: changes
                                                            # here would otherwise leak into every selftest
                                                            # that runs after it in the same pwsh session.
try {
  $env:RECOGNITION_PASSPHRASE = "selftest-backup-pass-" + [Guid]::NewGuid().ToString("N")

  $srcRoot = Join-Path $TempRoot "src"
  $dstRoot = Join-Path $TempRoot "dst"
  New-Item -ItemType Directory -Force -Path $srcRoot | Out-Null
  New-Item -ItemType Directory -Force -Path $dstRoot | Out-Null

  # --- build a source profile: identity + known content in 4 of 5 stores (cookies deliberately absent) ---
  $srcDesc = RID-EnsureIdentity $srcRoot
  $SP = RBK-Paths $srcRoot
  RBK-WriteSecure $SP.History   "history-line-1`nhistory-line-2`n"
  RBK-WriteSecure $SP.Bookmarks "bookmark-line-1`n"
  RBK-WriteSecure $SP.Downloads "download-line-1`n"
  $a1 = OneActionLine 1 "session.start" ("0"*64)
  $a2 = OneActionLine 2 "navigate" $a1.hash
  RBK-WriteSecure $SP.Actions (($a1.line + "`n" + $a2.line + "`n"))
  # cookies.v1.enc intentionally NOT written -> exercises "missing store" path

  $origSalt = RID-UnsealSalt (RID-Paths $srcRoot)

  # --- export ---
  $bkFile = Join-Path $TempRoot "profile.rbackup"
  $exp = RBK-Export $srcRoot $bkFile
  Check (Test-Path -LiteralPath $bkFile) "backup file written"
  Check (@($exp.stores_included) -notcontains "cookies") "export correctly omits the absent cookies store"
  Check (@($exp.stores_included).Count -eq 4) "export includes exactly the 4 populated stores"

  $rawBackup = Get-Content -Raw -LiteralPath $bkFile -Encoding UTF8
  Check ($rawBackup -notmatch 'history-line-1') "plaintext store content absent from the backup file at rest"
  Check ($rawBackup -notmatch $origSalt) "identity salt absent from the backup file at rest (encrypted, not inline)"

  # --- verify (decrypt-only, no writes) ---
  $v = RBK-Verify $bkFile
  Check ($v.recognition_identity_id -eq (RID-Get $srcDesc "recognition_identity_id")) "verify reports the correct source identity"
  Check (@($v.stores_present).Count -eq 4) "verify reports 4 stores present"

  # --- import into a FRESH target ---
  $imp = RBK-Import $dstRoot $bkFile
  Check ($imp.recognition_identity_id -eq (RID-Get $srcDesc "recognition_identity_id")) "import preserves the exact recognition_identity_id"
  Check (@($imp.stores_restored).Count -eq 4) "import restores exactly the 4 stores that were present"

  $DP = RBK-Paths $dstRoot
  Check ((RBK-ReadSecure $DP.History) -eq "history-line-1`nhistory-line-2`n") "history round-trips byte-for-byte"
  Check ((RBK-ReadSecure $DP.Bookmarks) -eq "bookmark-line-1`n") "bookmarks round-trip byte-for-byte"
  Check ((RBK-ReadSecure $DP.Downloads) -eq "download-line-1`n") "downloads round-trip byte-for-byte"
  Check (-not (Test-Path -LiteralPath $DP.Cookies)) "absent store is NOT fabricated on restore"

  $restoredActions = RBK-ReadSecure $DP.Actions
  Check (VerifyActionsChain $restoredActions) "restored actions store still passes hash-chain verification"

  $dstSalt = RID-UnsealSalt (RID-Paths $dstRoot)
  Check ($dstSalt -eq $origSalt) "restored identity unseals to the exact original salt"

  # --- negative: wrong passphrase ---
  $savedPass = $env:RECOGNITION_PASSPHRASE
  $env:RECOGNITION_PASSPHRASE = "a-completely-different-passphrase"
  ShouldThrow { RBK-Verify $bkFile } "wrong passphrase fails closed on verify"
  $env:RECOGNITION_PASSPHRASE = $savedPass

  # --- negative: tampered ciphertext ---
  $envJson = Get-Content -Raw -LiteralPath $bkFile -Encoding UTF8 | ConvertFrom-Json
  $tamperedCt = $envJson.blob.ct_b64.Substring(0, $envJson.blob.ct_b64.Length - 4) + "AAAA"
  $envJson.blob.ct_b64 = $tamperedCt
  $tamperedFile = Join-Path $TempRoot "tampered.rbackup"
  [System.IO.File]::WriteAllText($tamperedFile, ($envJson | ConvertTo-Json -Depth 20), (New-Object System.Text.UTF8Encoding($false)))
  ShouldThrow { RBK-Verify $tamperedFile } "tampered ciphertext fails GCM authentication"

  # --- negative: refuse without -Force when target identity differs ---
  $otherRoot = Join-Path $TempRoot "other"
  New-Item -ItemType Directory -Force -Path $otherRoot | Out-Null
  [void](RID-EnsureIdentity $otherRoot)   # gives it its OWN distinct identity
  ShouldThrow { RBK-Import $otherRoot $bkFile } "import refuses to overwrite a DIFFERENT existing identity without -Force"

  # -Force should succeed even with a differing identity
  $imp2 = RBK-Import $otherRoot $bkFile -Force
  Check ($imp2.recognition_identity_id -eq (RID-Get $srcDesc "recognition_identity_id")) "-Force allows restoring over a different identity"

  # --- negative: refuse without -Force when a store already exists at target ---
  ShouldThrow { RBK-Import $dstRoot $bkFile } "import refuses to overwrite an existing store without -Force"
  $imp3 = RBK-Import $dstRoot $bkFile -Force
  Check (@($imp3.stores_restored).Count -eq 4) "-Force allows re-restoring over existing stores"
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  $env:RECOGNITION_PASSPHRASE = $script:originalPassphrase
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("BACKUP_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_BACKUP_V1_OK" -ForegroundColor Green
