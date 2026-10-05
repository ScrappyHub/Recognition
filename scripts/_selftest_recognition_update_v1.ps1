# Selftest — Recognition Governed Updater v1 (§54)
# Self-contained: ephemeral Ed25519 keys + a throwaway "install" tree in temp; never touches the real
# repo or keys. Proves the updater applies ONLY a correctly signed, intact, strictly-newer package and
# leaves the install byte-identical on every refusal.
# Token: SELFTEST_RECOGNITION_UPDATE_V1_OK

param([string]$RepoRoot = ".")   # accepted for prove_all uniformity; not used

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_recognition_update_v1.ps1")

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function WriteText([string]$p,[string]$t){ New-Item -ItemType Directory -Force -Path (Split-Path -Parent $p) | Out-Null; [System.IO.File]::WriteAllText($p,$t,(New-Object System.Text.UTF8Encoding($false))) }
function PinKey([string]$pubPath,[string]$trustPath){
  $parts = ((Get-Content -Raw -LiteralPath $pubPath -Encoding UTF8).Trim()) -split '\s+'
  WriteText $trustPath ("recognition-runtime-bridge " + $parts[0] + " " + $parts[1] + "`n")
}
# Hash every file under a dir -> "rel=sha" sorted string (install-tree fingerprint)
function TreeFp([string]$dir){
  $root = (Resolve-Path -LiteralPath $dir).Path
  (@(Get-ChildItem -LiteralPath $root -Recurse -File -Force | Where-Object { $_.FullName -notmatch '\\(proofs\\receipts|runtime\\update_backup)\\' } |
    ForEach-Object { ($_.FullName.Substring($root.Length) -replace '\\','/') + "=" + (RU-Sha256File $_.FullName) } | Sort-Object) -join "`n")
}

$work = Join-Path ([System.IO.Path]::GetTempPath()) ("upd_self_" + [Guid]::NewGuid().ToString("N"))
$keys = Join-Path $work "keys"
$install = Join-Path $work "install"
$lock = $null
try {
  New-Item -ItemType Directory -Force -Path $keys | Out-Null
  $trust = Join-Path $install "proofs\trust\allowed_signers"

  $k1 = Join-Path $keys "k1"; $k2 = Join-Path $keys "k2"
  foreach($k in @($k1,$k2)){ $r = RU-RunSsh @("-t","ed25519","-f",$k,"-N","","-C","recognition-runtime-bridge"); if(-not (Test-Path -LiteralPath ($k+".pub"))){ throw "SELFTEST_KEYGEN_FAILED" } }
  PinKey ($k1 + ".pub") $trust

  # --- installed baseline (version 1.0.0) ---
  WriteText (Join-Path $install "config\version.v1.json") '{"schema":"recognition.version.v1","version":"1.0.0"}'
  WriteText (Join-Path $install "app\a.txt") "old-a"
  WriteText (Join-Path $install "app\b.txt") "old-b"
  WriteText (Join-Path $install "runtime\keep.txt") "user-data"

  # --- payload for 1.1.0 ---
  $pay = Join-Path $work "payload110"
  WriteText (Join-Path $pay "app\a.txt") "new-a"
  WriteText (Join-Path $pay "app\b.txt") "new-b"
  WriteText (Join-Path $pay "app\c.txt") "brand-new-c"

  $pkg = Join-Path $work "pkg110"
  $b = RU-Build $pay $pkg "1.1.0" $k1 "stable"
  Check ($b.file_count -eq 3) "build packages 3 files and signs the manifest"

  $v = RU-Verify $pkg $install $trust
  Check $v.ok "good package verifies (signature, hashes, payload_id, newer version)"

  # --- negative vectors on the PACKAGE (each against a fresh copy; install must stay untouched) ---
  $fpBefore = TreeFp $install
  function Mutated([string]$name,[scriptblock]$mutate){
    $d = Join-Path $work ("mut_" + $name); Copy-Item -LiteralPath $pkg -Destination $d -Recurse -Force; & $mutate $d; return $d
  }
  $d = Mutated "payload" { param($d) Add-Content -LiteralPath (Join-Path $d "payload\app\a.txt") -Value "x" -NoNewline }
  Check (-not (RU-Verify $d $install $trust).ok) "tampered payload byte -> refused"

  $d = Mutated "manifest" { param($d) $p = Join-Path $d "update_manifest.json"; $t = (Get-Content -Raw -LiteralPath $p).Replace('"1.1.0"','"9.9.9"'); [System.IO.File]::WriteAllText($p,$t,(New-Object System.Text.UTF8Encoding($false))) }
  Check (-not (RU-Verify $d $install $trust).ok) "edited manifest (version bumped) -> signature invalid -> refused"

  $d = Mutated "nosig" { param($d) Remove-Item -LiteralPath (Join-Path $d "update_manifest.sig") -Force }
  Check (-not (RU-Verify $d $install $trust).ok) "missing signature -> refused"

  $d = Mutated "extra" { param($d) WriteText (Join-Path $d "payload\app\evil.dll") "payload-smuggled" }
  Check (-not (RU-Verify $d $install $trust).ok) "unlisted file smuggled into the payload -> refused"

  $d = Mutated "missingfile" { param($d) Remove-Item -LiteralPath (Join-Path $d "payload\app\c.txt") -Force }
  Check (-not (RU-Verify $d $install $trust).ok) "listed file missing from payload -> refused"

  $trust2 = Join-Path $work "trust_other"; PinKey ($k2 + ".pub") $trust2
  Check (-not (RU-Verify $pkg $install $trust2).ok) "signature from a key that is not the pinned trust root -> refused"

  # protected / traversal paths are refused at BUILD time and at VERIFY time
  $badpay = Join-Path $work "payload_bad"; WriteText (Join-Path $badpay "proofs\trust\allowed_signers") "attacker-key"
  $threw = $false; try { RU-Build $badpay (Join-Path $work "pkg_bad") "1.2.0" $k1 | Out-Null } catch { $threw = $true }
  Check $threw "payload writing the trust root (proofs\trust\) -> refused at build"
  Check ((RU-PathProblem "../escape.txt") -ne $null) "path traversal '..' is rejected"
  Check ((RU-PathProblem "runtime/x.bin") -ne $null) "write into runtime\ is rejected"
  Check ((RU-PathProblem "C:/Windows/x.dll") -ne $null) "rooted path is rejected"
  Check ($null -eq (RU-PathProblem "app/ok.txt")) "ordinary relative path is accepted"

  # defense in depth: a VALIDLY SIGNED manifest that lists a protected path is still refused at verify
  # (simulates a compromised/malicious build tool). Re-sign an edited copy with the trusted key.
  $dp = Join-Path $work "mut_protected"; Copy-Item -LiteralPath $pkg -Destination $dp -Recurse -Force
  $mp = Join-Path $dp "update_manifest.json"
  [System.IO.File]::WriteAllText($mp, (Get-Content -Raw -LiteralPath $mp).Replace('"app/c.txt"','"runtime/c.txt"'), (New-Object System.Text.UTF8Encoding($false)))
  Remove-Item -LiteralPath (Join-Path $dp "update_manifest.sig") -Force
  $tmpSign = Join-Path $work "resign.tmp"; Copy-Item -LiteralPath $mp -Destination $tmpSign -Force
  $sg = RU-RunSsh @("-Y","sign","-f",$k1,"-n","recognition/update",$tmpSign)
  Move-Item -LiteralPath ($tmpSign + ".sig") -Destination (Join-Path $dp "update_manifest.sig") -Force
  $pv = RU-Verify $dp $install $trust
  Check (-not $pv.ok -and $pv.reason -match "protected") "validly-signed manifest listing a protected path (runtime\) -> still refused"

  Check ((TreeFp $install) -eq $fpBefore) "install tree byte-identical after all refused verifications"

  # --- apply: success path ---
  $a = RU-Apply $pkg $install $trust
  Check $a.ok "apply of the good 1.1.0 package succeeds"
  Check ((Get-Content -Raw -LiteralPath (Join-Path $install "app\a.txt")) -eq "new-a") "replaced file has new content"
  Check ((Get-Content -Raw -LiteralPath (Join-Path $install "app\c.txt")) -eq "brand-new-c") "new file was added"
  Check ((RU-GetInstalledVersion $install) -eq [version]"1.1.0") "installed version advanced to 1.1.0"
  Check ((Get-Content -Raw -LiteralPath (Join-Path $install "runtime\keep.txt")) -eq "user-data") "user data under runtime\ untouched"
  Check (Test-Path -LiteralPath (Join-Path $a.backup "app\a.txt")) "previous bytes of replaced files were backed up"
  Check ((Get-Content -Raw -LiteralPath (Join-Path $install "proofs\receipts\recognition.update.v1.ndjson")) -match '"outcome":"applied"') "apply was receipted"

  # --- replay / downgrade ---
  $r2 = RU-Verify $pkg $install $trust
  Check (-not $r2.ok -and $r2.reason -match "not newer") "re-applying the same version (replay) -> refused"
  $pay100 = Join-Path $work "payload100"; WriteText (Join-Path $pay100 "app\a.txt") "downgrade-a"
  $pkg100 = Join-Path $work "pkg100"; RU-Build $pay100 $pkg100 "1.0.5" $k1 | Out-Null
  $r3 = RU-Verify $pkg100 $install $trust
  Check (-not $r3.ok -and $r3.reason -match "not newer") "validly-signed OLDER version (downgrade) -> refused"

  # --- rollback: lock the 2nd file so the copy fails mid-apply, install must be restored ---
  $pay120 = Join-Path $work "payload120"
  WriteText (Join-Path $pay120 "app\a.txt") "v12-a"
  WriteText (Join-Path $pay120 "app\b.txt") "v12-b"
  $pkg120 = Join-Path $work "pkg120"; RU-Build $pay120 $pkg120 "1.2.0" $k1 | Out-Null
  $fpMid = TreeFp $install
  $lock = [System.IO.File]::Open((Join-Path $install "app\b.txt"), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  $ra = RU-Apply $pkg120 $install $trust
  $lock.Close(); $lock = $null
  Check (-not $ra.ok) "apply that fails mid-copy reports failure"
  Check ((TreeFp $install) -eq $fpMid) "failed apply was rolled back: install tree byte-identical to before"
  Check ((RU-GetInstalledVersion $install) -eq [version]"1.1.0") "failed apply did not advance the installed version"
  Check ((Get-Content -Raw -LiteralPath (Join-Path $install "proofs\receipts\recognition.update.v1.ndjson")) -match '"outcome":"rolled_back"') "rollback was receipted"

  # --- after rollback the same package applies cleanly (no lingering state) ---
  $rb = RU-Apply $pkg120 $install $trust
  Check ($rb.ok -and (RU-GetInstalledVersion $install) -eq [version]"1.2.0") "same package applies cleanly once the lock is gone"
}
catch {
  Write-Host ""; Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  if($lock){ try { $lock.Close() } catch {} }
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("UPDATE_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_UPDATE_V1_OK" -ForegroundColor Green
