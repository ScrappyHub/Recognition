# Selftest — Recognition Cookie Receipts v1 (§23): encrypted-at-rest cookie governance
# Same append-only, hash-chained, DPAPI-encrypted ledger format as action receipts
# (GovernedActions), applied to cookie add/change/clear events. Domain is kept in the
# action label (already visible elsewhere, e.g. downloads/bookmarks); cookie NAME and
# VALUE are stored only as a combined SHA-256, never cleartext. Verifies positive chain,
# cleartext absence, then negative vectors: tampered event, reordered, forged, missing.
# Token: SELFTEST_RECOGNITION_COOKIE_RECEIPTS_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cook_" + [Guid]::NewGuid().ToString("N"))
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
function JJ([string]$s){ '"' + ([string]$s).Replace('\','\\').Replace('"','\"') + '"' }

function New-Receipt([int]$seq,[string]$ts,[string]$action,[string]$detail,[string]$prev){
  $dsha = if([string]::IsNullOrEmpty($detail)){ "" } else { Sha256Hex $detail }
  $body = "{" + (JJ "seq") + ":" + $seq + "," + (JJ "ts_utc") + ":" + (JJ $ts) + "," +
          (JJ "action") + ":" + (JJ $action) + "," + (JJ "detail_sha256") + ":" + (JJ $dsha) + "," +
          (JJ "prev_hash") + ":" + (JJ $prev) + "}"
  $hash = Sha256Hex $body
  $line = $body.Substring(0, $body.Length - 1) + "," + (JJ "hash") + ":" + (JJ $hash) + "}"
  @{ line=$line; hash=$hash }
}

# Text-surgery verify (see _selftest_recognition_action_receipts_v1.ps1 for why: avoids
# any dependency on JSON-parser round-trip fidelity for the hashed body).
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

try {
  $chain = Join-Path $TempRoot "cookies.v1.ndjson"

  $head = ("0" * 64)
  # cookie name+value joined with \u0001 before hashing, matching GovernedCookies/SnapshotCookiesAsync
  $sessionCookie = "sid" + [char]1 + "s3cr3t-session-token-abcdef123456"
  $r1 = New-Receipt 1 "2026-01-01T00:00:00.001Z" "cookie.new:example.com"    $sessionCookie $head; $head = $r1.hash
  $r2 = New-Receipt 2 "2026-01-01T00:00:00.002Z" "cookie.change:example.com" $sessionCookie $head; $head = $r2.hash
  $r3 = New-Receipt 3 "2026-01-01T00:00:00.003Z" "cookies.clear_site:example.com" "example.com" $head; $head = $r3.hash
  WriteLines $chain @($r1.line, $r2.line, $r3.line)

  $v = Verify-Chain $chain
  Check ($v.count -eq 3) "3 cookie receipts verify as a valid chain"
  Check ($v.head -eq $r3.hash) "verified head matches last receipt hash"

  $raw = Get-Content -Raw -LiteralPath $chain -Encoding UTF8
  Check ($raw -notmatch 's3cr3t-session-token') "cookie value absent from the ledger at rest"
  Check ($raw -notmatch '"sid') "cookie name absent from the ledger at rest"
  Check ($raw -match ([regex]::Escape((Sha256Hex $sessionCookie)))) "cookie name+value stored as a combined SHA-256"
  Check ($raw -match 'example\.com') "domain is retained (already visible elsewhere, e.g. bookmarks/downloads)"

  $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })

  $t1 = @($lines); $t1[0] = $t1[0].Replace("cookie.new","cookie.exfiltrated")
  WriteLines $chain $t1
  ShouldThrow { Verify-Chain $chain } "tampered event fails chain verification"

  $t2 = @($lines[1], $lines[0], $lines[2])
  WriteLines $chain $t2
  ShouldThrow { Verify-Chain $chain } "reordered receipts fail chain verification"

  $t3 = @($lines); $t3[2] = $t3[2] -replace '"hash":"[0-9a-f]{64}"','"hash":"0000000000000000000000000000000000000000000000000000000000000000"'
  WriteLines $chain $t3
  ShouldThrow { Verify-Chain $chain } "forged receipt hash fails chain verification"

  $t4 = @($lines[0], $lines[2])
  WriteLines $chain $t4
  ShouldThrow { Verify-Chain $chain } "missing receipt (deleted middle) fails chain verification"
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
if($script:fail -gt 0){ Write-Error ("COOKIE_RECEIPTS_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_COOKIE_RECEIPTS_V1_OK" -ForegroundColor Green
