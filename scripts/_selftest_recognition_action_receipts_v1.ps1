# Selftest — Recognition Action Receipts v1 (§13/§15): prove-it-in-every-action
# Builds an append-only, hash-chained action-receipt stream in the SAME on-disk
# format the browser writes (GovernedActions), verifies it green, confirms details
# are SHA-256 only (no cleartext), then runs negative vectors: tampered action,
# reordered chain, forged hash, missing record. Runs in a throwaway tree.
# Token: SELFTEST_RECOGNITION_ACTION_RECEIPTS_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("acts_" + [Guid]::NewGuid().ToString("N"))
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
function New-Receipt([int]$seq,[string]$ts,[string]$action,[string]$detail,[string]$prev){
  $dsha = if([string]::IsNullOrEmpty($detail)){ "" } else { Sha256Hex $detail }
  $body = "{" + (JJ "seq") + ":" + $seq + "," + (JJ "ts_utc") + ":" + (JJ $ts) + "," +
          (JJ "action") + ":" + (JJ $action) + "," + (JJ "detail_sha256") + ":" + (JJ $dsha) + "," +
          (JJ "prev_hash") + ":" + (JJ $prev) + "}"
  $hash = Sha256Hex $body
  $line = $body.Substring(0, $body.Length - 1) + "," + (JJ "hash") + ":" + (JJ $hash) + "}"
  @{ line=$line; hash=$hash }
}

# Verify a chain file the way GovernedActions.Verify does: contiguous seq, prev_hash
# links to prior hash, and each record's recomputed body-hash matches. Throws on break.
# The body is recovered by TEXT SURGERY on the raw line (not by re-serializing parsed
# JSON fields) so the recomputed hash input is byte-identical to what New-Receipt/the
# C# Append() actually hashed — this sidesteps any JSON-parser type/formatting quirks.
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
    $body = $line.Substring(0, $idx) + "}"   # exact body New-Receipt hashed, minus the appended hash field
    if((Sha256Hex $body) -ne $h){ throw "HASH_BREAK at $expect" }
    $prev = $h; $expect++; $count++
  }
  @{ count=$count; head=$prev }
}
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }

try {
  $chain = Join-Path $TempRoot "actions.v1.ndjson"

  $head = ("0" * 64)
  $r1 = New-Receipt 1 "2026-01-01T00:00:00.001Z" "session.start" ""                       $head; $head = $r1.hash
  $r2 = New-Receipt 2 "2026-01-01T00:00:00.002Z" "navigate"      "https://example.com/a"  $head; $head = $r2.hash
  $r3 = New-Receipt 3 "2026-01-01T00:00:00.003Z" "vpn.pick"      "socks5://127.0.0.1:9050" $head; $head = $r3.hash
  WriteLines $chain @($r1.line, $r2.line, $r3.line)

  $v = Verify-Chain $chain
  Check ($v.count -eq 3) "3 receipts verify as a valid chain"
  Check ($v.head -eq $r3.hash) "verified head matches last receipt hash"

  $raw = Get-Content -Raw -LiteralPath $chain -Encoding UTF8
  Check ($raw -notmatch 'example\.com/a') "cleartext URL absent from the receipt chain at rest"
  Check ($raw -match ([regex]::Escape((Sha256Hex "https://example.com/a")))) "navigate detail stored as SHA-256"

  $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })

  # --- negative: tampered action content ---
  $t1 = @($lines); $t1[1] = $t1[1].Replace("navigate","evil.exfil")
  WriteLines $chain $t1
  ShouldThrow { Verify-Chain $chain } "tampered action fails chain verification"

  # --- negative: reordered chain ---
  $t2 = @($lines[1], $lines[0], $lines[2])
  WriteLines $chain $t2
  ShouldThrow { Verify-Chain $chain } "reordered receipts fail chain verification"

  # --- negative: forged hash ---
  $t3 = @($lines); $t3[2] = $t3[2] -replace '"hash":"[0-9a-f]{64}"','"hash":"0000000000000000000000000000000000000000000000000000000000000000"'
  WriteLines $chain $t3
  ShouldThrow { Verify-Chain $chain } "forged receipt hash fails chain verification"

  # --- negative: missing (deleted) record ---
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
if($script:fail -gt 0){ Write-Error ("ACTION_RECEIPTS_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_ACTION_RECEIPTS_V1_OK" -ForegroundColor Green
