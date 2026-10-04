# Selftest — Recognition Per-Origin Site Policy v1 (§53.1/§54.1)
# Proves the decision engine the browser's PermissionRequested/WebResourceRequested
# handlers depend on. The on-disk format is the SAME GovernedActions hash-chained,
# append-only ledger already proven by _selftest_recognition_action_receipts_v1.ps1
# (reused wholesale, zero new crypto) — this selftest proves the NEW part: the
# "action = site_policy.set|<key>|<origin>|<value>" encoding and the "replay the
# ledger, latest record per (key,origin) wins" state-derivation the C# adapter
# implements in RebuildSitePolicyState/SitePolicySet/SitePolicyGet.
#
# Covers:
#   - an origin/permission never recorded decides "deny" (fail-closed default)
#   - an origin/tracker-blocking never recorded decides "inherit" (defers to global)
#   - setting the SAME (key,origin) twice: latest record wins, not the first
#   - two different origins never interfere with each other's decisions
#   - the chain is tamper-evident (reuses the proven negative vectors)
# Token: SELFTEST_RECOGNITION_SITE_POLICY_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sitepol_" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function WriteLines([string]$p,[string[]]$lines){ [System.IO.File]::WriteAllText($p, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }

$Enc = New-Object System.Text.UTF8Encoding($false)
$Sha = [System.Security.Cryptography.SHA256]::Create()
function Sha256Hex([string]$s){
  $b = $Sha.ComputeHash($Enc.GetBytes([string]$s))
  -join ($b | ForEach-Object { $_.ToString("x2") })
}
# Match C# GovernedActions.JJ exactly: escape backslash then double-quote.
function JJ([string]$s){ '"' + ([string]$s).Replace('\','\\').Replace('"','\"') + '"' }

# Build one receipt record given prev head; returns @{ line=..; hash=.. }
# (identical algorithm to GovernedActions.Append / the action-receipts selftest —
# action is cleartext, detail is SHA-256-only, which is why the site-policy VALUE
# is encoded into the action string itself rather than into detail.)
function New-Receipt([int]$seq,[string]$ts,[string]$action,[string]$detail,[string]$prev){
  $dsha = if([string]::IsNullOrEmpty($detail)){ "" } else { Sha256Hex $detail }
  $body = "{" + (JJ "seq") + ":" + $seq + "," + (JJ "ts_utc") + ":" + (JJ $ts) + "," +
          (JJ "action") + ":" + (JJ $action) + "," + (JJ "detail_sha256") + ":" + (JJ $dsha) + "," +
          (JJ "prev_hash") + ":" + (JJ $prev) + "}"
  $hash = Sha256Hex $body
  $line = $body.Substring(0, $body.Length - 1) + "," + (JJ "hash") + ":" + (JJ $hash) + "}"
  @{ line=$line; hash=$hash }
}

function Verify-Chain([string]$path){
  $lines = @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ -ne "" })
  $prev = ("0" * 64); $expect = 1; $count = 0
  $marker = "," + (JJ "hash") + ":"
  foreach($line in $lines){
    $r = $line | ConvertFrom-Json
    if([int]$r.seq -ne $expect){ throw "SEQ_BREAK at $expect" }
    if([string]$r.prev_hash -ne $prev){ throw "PREV_BREAK at $expect" }
    $h = [string]$r.hash
    $idx = $line.LastIndexOf($marker)
    if($idx -lt 0){ throw "MALFORMED at $expect" }
    $body = $line.Substring(0, $idx) + "}"
    if((Sha256Hex $body) -ne $h){ throw "HASH_BREAK at $expect" }
    $prev = $h; $expect++; $count++
  }
  @{ count=$count; head=$prev }
}
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }

# Mirrors C# RebuildSitePolicyState: replay the ledger, latest record per
# (key,origin) wins. Returns a hashtable keyed "key|origin" -> value.
function Replay-SitePolicy([string]$path){
  $state = @{}
  $lines = @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ -ne "" })
  foreach($line in $lines){
    $r = $line | ConvertFrom-Json
    $a = [string]$r.action
    if(-not $a.StartsWith("site_policy.set|")){ continue }
    $parts = $a.Split('|')
    if($parts.Count -ne 4){ continue }
    $state[$parts[1] + "|" + $parts[2].ToLowerInvariant()] = $parts[3]
  }
  $state
}
# Mirrors C# SitePolicyGet.
function Get-SitePolicy($state,[string]$origin,[string]$key,[string]$def){
  $k = $key + "|" + $origin.ToLowerInvariant()
  if($state.ContainsKey($k)){ return [string]$state[$k] }
  return $def
}

try {
  $chain = Join-Path $TempRoot "site_policy.v1.ndjson"
  $head = ("0" * 64)
  $recs = New-Object System.Collections.Generic.List[object]

  function Add-SitePolicyRecord([string]$key,[string]$origin,[string]$value){
    $script:seq = $script:seq + 1
    $r = New-Receipt $script:seq ("2026-01-01T00:00:00." + $script:seq.ToString("000") + "Z") ("site_policy.set|" + $key + "|" + $origin + "|" + $value) "" $script:head
    $script:head = $r.hash
    $script:recs.Add($r.line)
  }
  $script:seq = 0

  # --- default decisions: nothing recorded yet ---
  $emptyChain = Join-Path $TempRoot "empty.v1.ndjson"
  WriteLines $emptyChain @()
  $emptyState = @{}
  Check ((Get-SitePolicy $emptyState "example.com" "perm.Camera" "deny") -eq "deny") "unrecorded origin/permission defaults to deny (fail-closed)"
  Check ((Get-SitePolicy $emptyState "example.com" "tracker_blocking" "inherit") -eq "inherit") "unrecorded origin tracker-blocking defaults to inherit (defers to global)"

  # --- build a realistic ledger across two origins ---
  Add-SitePolicyRecord "perm.Camera"         "example.com"  "deny"    # explicit deny recorded
  Add-SitePolicyRecord "perm.Microphone"     "example.com"  "allow"
  Add-SitePolicyRecord "tracker_blocking"    "shop.example" "off"     # exemption for a different origin
  Add-SitePolicyRecord "perm.Microphone"     "example.com"  "deny"    # SAME key/origin as above — latest should win
  WriteLines $chain $recs

  $v = Verify-Chain $chain
  Check ($v.count -eq 4) "4 site-policy receipts verify as a valid chain"
  Check ($v.head -eq $head) "verified head matches last receipt hash"

  $raw = Get-Content -Raw -LiteralPath $chain -Encoding UTF8
  Check ($raw -match 'site_policy\.set\|perm\.Microphone\|example\.com\|deny') "latest decision (deny) is present in the raw ledger as its own cleartext record (tamper-evident, not confidentiality-protected)"
  Check ($raw -match 'site_policy\.set\|perm\.Microphone\|example\.com\|allow') "earlier decision (allow) also still present — ledger is append-only, never rewritten"

  $state = Replay-SitePolicy $chain
  Check ((Get-SitePolicy $state "example.com" "perm.Camera" "deny") -eq "deny") "replay: example.com camera = deny (as recorded)"
  Check ((Get-SitePolicy $state "example.com" "perm.Microphone" "deny") -eq "deny") "replay: latest record wins — microphone ends up deny, not the earlier allow"
  Check ((Get-SitePolicy $state "shop.example" "tracker_blocking" "inherit") -eq "off") "replay: shop.example tracker-blocking exemption recorded"
  Check ((Get-SitePolicy $state "shop.example" "perm.Camera" "deny") -eq "deny") "replay: shop.example camera untouched — still defaults to deny"
  Check ((Get-SitePolicy $state "example.com" "tracker_blocking" "inherit") -eq "inherit") "replay: different origins do not leak decisions into each other (example.com has no tracker override)"
  Check ((Get-SitePolicy $state "evil.test" "perm.Camera" "deny") -eq "deny") "replay: an origin never mentioned in the ledger still defaults to deny"

  $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })

  # --- negative: tampered decision (flip a deny to allow at rest) ---
  $t1 = @($lines); $t1[3] = $t1[3].Replace('perm.Microphone|example.com|deny','perm.Microphone|example.com|allow')
  WriteLines $chain $t1
  ShouldThrow { Verify-Chain $chain } "tampering a recorded decision breaks chain verification"

  # --- negative: reordered records ---
  $t2 = @($lines[1], $lines[0], $lines[2], $lines[3])
  WriteLines $chain $t2
  ShouldThrow { Verify-Chain $chain } "reordered site-policy receipts fail chain verification"

  # --- negative: forged hash ---
  $t3 = @($lines); $t3[3] = $t3[3] -replace '"hash":"[0-9a-f]{64}"','"hash":"0000000000000000000000000000000000000000000000000000000000000000"'
  WriteLines $chain $t3
  ShouldThrow { Verify-Chain $chain } "forged receipt hash fails chain verification"

  # --- negative: deleted middle record ---
  $t4 = @($lines[0], $lines[2], $lines[3])
  WriteLines $chain $t4
  ShouldThrow { Verify-Chain $chain } "deleted middle receipt fails chain verification"
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
if($script:fail -gt 0){ Write-Error ("SITE_POLICY_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_SITE_POLICY_V1_OK" -ForegroundColor Green
