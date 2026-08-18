#requires -Version 5.1
<#
  recognition_publish_scan_v1.ps1

  Pre-publish safety gate. Scans the git-TRACKED set only (that is exactly what
  a push would expose) for material that must never be published:

    - plaintext browsing URLs inside receipts / runtime state
    - private keys (OpenSSH / PEM)
    - a passphrase assigned a value, or a -Passphrase argument on a command line
    - backup litter (*.bak*) that slipped into the tracked set

  Exits non-zero if any finding is present. Green token on a clean tree:
  RECOGNITION_PUBLISH_SCAN_V1_OK

  Note: URLs inside docs/, README, and *.md are allowed (spec prose). The URL
  check is scoped to proofs/receipts/** and runtime/** where plaintext URLs are
  a privacy leak, not documentation.
#>
[CmdletBinding()]
param(
  [string]$RepoRoot = "."
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $RepoRoot).Path
Push-Location $root
try {
  $tracked = & git ls-files 2>$null
  if($LASTEXITCODE -ne 0){ Write-Error "NOT_A_GIT_REPO_OR_GIT_UNAVAILABLE"; exit 1 }
} finally { Pop-Location }

$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$sev,[string]$file,[int]$line,[string]$why,[string]$snippet){
  $findings.Add([pscustomobject]@{ severity=$sev; file=$file; line=$line; why=$why; snippet=$snippet })
}

$keyMarkers = @('BEGIN OPENSSH PRIVATE KEY','BEGIN RSA PRIVATE KEY','BEGIN PRIVATE KEY','BEGIN EC PRIVATE KEY')

foreach($rel in $tracked){
  $full = Join-Path $root $rel
  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ continue }
  # skip obvious binaries
  if($rel -match '\.(png|jpg|jpeg|gif|pdf|docx|xlsx|pptx|zip|gz|sig|pub)$'){
    # still check private-key markers won't be in these; skip
    continue
  }
  $isReceiptOrRuntime = ($rel -match '^proofs/receipts/' -or $rel -match '^runtime/')
  # selftests legitimately set throwaway test passphrases; don't flag those
  $isTest = ($rel -match '(^|/)_selftest_' -or $rel -match '(^|/)tests?/')
  $ln = 0
  foreach($text in [System.IO.File]::ReadLines($full)){
    $ln++
    if($isReceiptOrRuntime -and $text -match 'https?://'){
      Add-Finding "HIGH" $rel $ln "plaintext URL in receipt/runtime" ($text.Trim())
    }
    foreach($mk in $keyMarkers){
      if($text.Contains($mk)){ Add-Finding "CRITICAL" $rel $ln "private key material" $mk }
    }
    if(-not $isTest -and $text -match 'RECOGNITION_PASSPHRASE\s*=\s*\S' -and $text -notmatch '<passphrase>' -and $text -notmatch '\$env:RECOGNITION_PASSPHRASE_NEW' -and $text -notmatch '=\s*\$null'){
      Add-Finding "CRITICAL" $rel $ln "passphrase assigned a value" ($text.Trim())
    }
    if($text -match '-Passphrase\s+\S'){
      Add-Finding "HIGH" $rel $ln "-Passphrase on a command line (v2 forbids argv secrets)" ($text.Trim())
    }
  }
  if($rel -match '\.bak(_|$)'){ Add-Finding "MEDIUM" $rel 0 "backup litter is tracked" $rel }
}

if($findings.Count -eq 0){
  Write-Host "No publish-blocking findings in the tracked set."
  Write-Host "RECOGNITION_PUBLISH_SCAN_V1_OK"
  exit 0
}

Write-Host ("Publish scan findings: " + $findings.Count) -ForegroundColor Yellow
$findings | Sort-Object severity | ForEach-Object {
  Write-Host ("  [{0}] {1}:{2}  {3}" -f $_.severity, $_.file, $_.line, $_.why) -ForegroundColor Yellow
  if($_.snippet){ Write-Host ("        " + ($_.snippet.Substring(0,[Math]::Min(100,$_.snippet.Length)))) -ForegroundColor DarkGray }
}
Write-Host ""
Write-Host "RECOGNITION_PUBLISH_SCAN_V1_BLOCKED — resolve the findings above before pushing." -ForegroundColor Red
Write-Host "Typical fix: 'git rm --cached <file>' the offending v1 receipts and add them to .gitignore," -ForegroundColor DarkGray
Write-Host "or re-emit them with URLs hashed. Publish spec + code + trust root, not raw plaintext receipts." -ForegroundColor DarkGray
exit 1
