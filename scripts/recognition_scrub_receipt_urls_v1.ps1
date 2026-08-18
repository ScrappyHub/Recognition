# Recognition — Scrub plaintext URLs from v1 receipts
#
# The pre-v2 runtime receipts embed cleartext URLs, which contradicts the
# privacy-preserving claim and trips the publish gate. This replaces every
# http(s) URL with `urlsha256:<hex>` in place: the receipt stays as verifiable
# evidence (the hash still binds the navigation target) but no cleartext target
# survives. A provenance receipt records original->scrubbed file hashes.
#
# Newer v2 event streams should hash URLs at write time; this is a one-shot fix
# for the legacy v1 receipts.
#
# DRY-RUN by default; pass -Execute to rewrite the files.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string[]]$Files = @(
    "proofs/receipts/recognition.runtime.v1.ndjson",
    "proofs/receipts/recognition.runtime.bridge.v1.ndjson"
  ),
  [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$enc = New-Object System.Text.UTF8Encoding($false)

function Sha256Hex([string]$Text){
  $h = [System.Security.Cryptography.SHA256]::HashData($enc.GetBytes($Text))
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}
function FileSha256([string]$Path){
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
}

# same character class as the verified reference pass: URL runs until whitespace,
# quote, comma, closing brace, or backslash
$pattern = 'https?://[^\s"'',}\\]+'
$evaluator = [System.Text.RegularExpressions.MatchEvaluator]{
  param($m) "urlsha256:" + (Sha256Hex $m.Value)
}

$results = @()
foreach($rel in $Files){
  $full = Join-Path $RepoRoot $rel
  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ Write-Host ("skip (absent): " + $rel) -ForegroundColor DarkGray; continue }
  $orig = [System.IO.File]::ReadAllText($full, $enc)
  $matches = [System.Text.RegularExpressions.Regex]::Matches($orig, $pattern)
  $scrubbed = [System.Text.RegularExpressions.Regex]::Replace($orig, $pattern, $evaluator)
  $remaining = [System.Text.RegularExpressions.Regex]::Matches($scrubbed, $pattern).Count
  $results += [pscustomobject]@{ rel=$rel; full=$full; count=$matches.Count; remaining=$remaining; orig=$orig; scrubbed=$scrubbed }
  Write-Host ("  " + $rel + ": " + $matches.Count + " URL(s) -> hashed; remaining after=" + $remaining)
}

if(@($results).Count -eq 0){ Write-Host "Nothing to scrub."; Write-Host "RECOGNITION_SCRUB_RECEIPT_URLS_V1_OK"; exit 0 }

if(-not $Execute){
  Write-Host ""
  Write-Host "DRY-RUN. Re-run with -Execute to rewrite the files above."
  Write-Host "RECOGNITION_SCRUB_RECEIPT_URLS_V1_PLAN_OK"
  exit 0
}

$receiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.scrub.v1.ndjson"
foreach($r in $results){
  if($r.remaining -ne 0){ Write-Error ("SCRUB_INCOMPLETE: " + $r.rel + " still has " + $r.remaining + " URL(s)"); exit 1 }
  $origHash = FileSha256 $r.full
  [System.IO.File]::WriteAllText($r.full, $r.scrubbed, $enc)
  $newHash = FileSha256 $r.full
  $rec = [ordered]@{
    schema="recognition.scrub.receipt.v1"; ts_utc=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    file=$r.rel; urls_hashed=$r.count; original_sha256=$origHash; scrubbed_sha256=$newHash
  }
  [System.IO.File]::AppendAllText($receiptPath, (($rec | ConvertTo-Json -Depth 6 -Compress) + "`n"), $enc)
  Write-Host ("scrubbed: " + $r.rel + "  (" + $r.count + " urls)  " + $origHash.Substring(0,12) + " -> " + $newHash.Substring(0,12)) -ForegroundColor Green
}
Write-Host "RECOGNITION_SCRUB_RECEIPT_URLS_V1_OK" -ForegroundColor Green
