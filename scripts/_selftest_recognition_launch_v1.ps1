# Selftest — Recognition Governed Chromium Launcher v1
# Exercises the extension gate without launching a browser:
#   allow -> permit ; review -> refuse ; unregistered -> refuse ; tampered -> refuse.
# Plus the Chromium arg builder. Runs in a throwaway tree with its own ledger.
# Token: SELFTEST_RECOGNITION_LAUNCH_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_launch_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("launch_" + [Guid]::NewGuid().ToString("N"))
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
}
function Register([string]$ledger,[string]$policyPath,[string]$dir){
  $id = RG-ComputeIdentity $dir; $man = RG-ReadManifest $dir; $pol = RG-LoadPolicy $policyPath
  $dec = RG-Decide $man $id.extension_id $pol
  $tail = RG-LedgerTailHash $ledger
  $rec = RG-BuildRecord ($tail.seq+1) $id.extension_id $man (RG-Get $id "files") $dec $tail.head
  RCE-AppendLine $ledger (RCE-CanonJson $rec)
}

try {
  $policyPath = Join-Path $TempRoot "policy.json"
  Copy-Item -LiteralPath (Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) "config") "extension_policy.v1.json") -Destination $policyPath -ErrorAction SilentlyContinue
  if(-not (Test-Path $policyPath)){
    WriteFile $policyPath '{"schema":"recognition.extension_policy.v1","max_manifest_version":3,"min_manifest_version":2,"denied_permissions":["debugger"],"review_permissions":["tabs"],"allowed_permissions":["storage","alarms"],"allowlist":[],"blocklist":[]}'
  }
  $ledger = Join-Path $TempRoot "ledger.ndjson"

  $good = Join-Path $TempRoot "ext-good"; MakeExt $good "Good" @("storage","alarms")
  $rev  = Join-Path $TempRoot "ext-review"; MakeExt $rev "Review" @("storage","tabs")
  $unreg = Join-Path $TempRoot "ext-unreg"; MakeExt $unreg "Unreg" @("storage")

  Register $ledger $policyPath $good
  Register $ledger $policyPath $rev

  # --- gate: allow -> permit ---
  $r = @(RGL-EvaluateExtensions $ledger @($good)); $g = $r | Select-Object -First 1
  Check ($r.Count -eq 1 -and $g.gate -eq "permit") "allow extension -> PERMIT"

  # --- gate: review -> refuse ---
  $r = @(RGL-EvaluateExtensions $ledger @($rev)); $g = $r | Select-Object -First 1
  Check ($g.gate -eq "refuse" -and $g.decision -eq "review") "review extension -> REFUSE"

  # --- gate: unregistered -> refuse ---
  $r = @(RGL-EvaluateExtensions $ledger @($unreg)); $g = $r | Select-Object -First 1
  Check ($g.gate -eq "refuse" -and $g.decision -eq "unregistered") "unregistered extension -> REFUSE"

  # --- gate: tampered (id flips) -> refuse ---
  WriteFile (Join-Path $good "background.js") "console.log('TAMPERED');"
  $r = @(RGL-EvaluateExtensions $ledger @($good)); $g = $r | Select-Object -First 1
  Check ($g.gate -eq "refuse") "tampered allow extension -> REFUSE (id no longer governed)"

  # --- mixed set: one refuse means the whole launch must refuse ---
  $r = @(RGL-EvaluateExtensions $ledger @($good, $rev))
  $refused = @($r | Where-Object { $_.gate -ne "permit" })
  Check ($refused.Count -ge 1) "any non-allow extension in the set forces refusal"

  # --- arg builder ---
  $cmdArgs = RGL-BuildArgs (Join-Path $TempRoot "profile") @($good)
  Check (($cmdArgs -join " ") -match "--user-data-dir=") "args include --user-data-dir"
  Check (($cmdArgs -join " ") -match "--load-extension=") "args include --load-extension for permitted set"

  # --- chromium probe: bogus explicit path must fail loudly ---
  ShouldThrow { RGL-FindChromium (Join-Path $TempRoot "nope\chrome.exe") } "explicit missing chromium path is rejected"
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
if($script:fail -gt 0){ Write-Error ("LAUNCH_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_LAUNCH_V1_OK" -ForegroundColor Green
