# Attestation verification v2 — pinned trust root (fixes audit F5).
# v1 verified signatures against the allowed_signers file INSIDE the attestation
# bundle, which an attacker who can modify the bundle can also replace.
# v2 verifies exclusively against the pinned trust root at proofs/trust/allowed_signers
# and additionally flags any bundle whose embedded allowed_signers diverges from it.
# Token: RECOGNITION_ATTEST_VERIFY_V2_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$AttestationDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function Sha256HexText([string]$Text){
  $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($Text)
  $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

# --- pinned trust root (must exist OUTSIDE any bundle) ------------------------
$TrustRoot = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "trust") "allowed_signers"
if(-not (Test-Path -LiteralPath $TrustRoot -PathType Leaf)){
  Die ("TRUST_ROOT_MISSING: " + $TrustRoot + " — pin a trusted allowed_signers file first")
}

if([string]::IsNullOrWhiteSpace($AttestationDir)){
  $Root = Join-Path (Join-Path $RepoRoot "proofs") "attestations"
  $latest = @(
    Get-ChildItem -LiteralPath $Root -Directory -Force |
    Where-Object { $_.Name -like "recognition_runtime_bridge_attest_v1_*" } |
    Sort-Object Name |
    Select-Object -Last 1
  )
  if(@($latest).Count -ne 1){ Die "ATTESTATION_BUNDLE_NOT_FOUND" }
  $AttestationDir = $latest[0].FullName
}

$AttestationDir = (Resolve-Path -LiteralPath $AttestationDir).Path

$ManifestPath = Join-Path $AttestationDir "attestation.json"
$HashPath     = Join-Path $AttestationDir "attestation.sha256.txt"
$SigPath      = Join-Path $AttestationDir "attestation.sig"
$BundleSigners = Join-Path $AttestationDir "allowed_signers"

foreach($p in @($ManifestPath,$HashPath,$SigPath)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("ATTEST_VERIFY_MISSING_FILE: " + $p)
  }
}

# --- bundle-embedded signer must match the pinned root ------------------------
if(Test-Path -LiteralPath $BundleSigners -PathType Leaf){
  $pinned = (Get-Content -Raw -LiteralPath $TrustRoot -Encoding UTF8).Trim()
  $embedded = (Get-Content -Raw -LiteralPath $BundleSigners -Encoding UTF8).Trim()
  if($pinned -ne $embedded){
    Die "ATTEST_BUNDLE_SIGNER_DIVERGES_FROM_TRUST_ROOT: bundle allowed_signers does not match proofs/trust/allowed_signers"
  }
  Write-Host "ATTEST_BUNDLE_SIGNER_MATCHES_TRUST_ROOT" -ForegroundColor Green
}

# --- manifest hash -------------------------------------------------------------
$expectedHash = (Get-Content -Raw -LiteralPath $HashPath -Encoding UTF8).Trim()
$manifestRaw = Get-Content -Raw -LiteralPath $ManifestPath -Encoding UTF8
$actualHash = Sha256HexText ($manifestRaw.TrimEnd([char]10,[char]13))
if($expectedHash -ne $actualHash){
  Die ("ATTEST_HASH_MISMATCH: expected=" + $expectedHash + " actual=" + $actualHash)
}

$manifest = $manifestRaw | ConvertFrom-Json
if([string]$manifest.schema -ne "recognition.runtime.bridge.attestation.v1"){
  Die ("ATTEST_BAD_SCHEMA: " + [string]$manifest.schema)
}

# --- signature against the PINNED trust root only ------------------------------
$SshKeygen = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $SshKeygen
foreach($a in @(
  "-Y","verify",
  "-f",$TrustRoot,
  "-I","recognition-runtime-bridge",
  "-n","recognition/runtime-bridge-attestation",
  "-s",$SigPath
)){ [void]$psi.ArgumentList.Add($a) }
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.RedirectStandardInput = $true
$psi.CreateNoWindow = $true

$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardInput.Write($manifestRaw)
$p.StandardInput.Close()
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
if(-not $p.WaitForExit(10000)){
  try { $p.Kill() } catch {}
  Die "ATTEST_VERIFY_TIMEOUT"
}
if($p.ExitCode -ne 0){
  Die ("ATTEST_SIGNATURE_VERIFY_FAIL_AGAINST_TRUST_ROOT: " + [string]$p.ExitCode + " " + $err.Trim())
}

# --- receipt --------------------------------------------------------------------
$receipt = [ordered]@{
  schema = "recognition.attestation.verify.receipt.v2"
  attestation_dir = $AttestationDir
  trust_root = $TrustRoot
  manifest_hash = $actualHash
  signature_verified = $true
  trust_root_pinned = $true
  ts_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}
$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.attestation.v2.ndjson"
$line = ($receipt | ConvertTo-Json -Depth 10 -Compress) + "`n"
$dir = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $dir -PathType Container)){ New-Item -ItemType Directory -Force -Path $dir | Out-Null }
[System.IO.File]::AppendAllText($rp,$line,(New-Object System.Text.UTF8Encoding($false)))

Write-Host ("ATTEST_VERIFY_OK: " + $AttestationDir) -ForegroundColor Green
Write-Host "RECOGNITION_ATTEST_VERIFY_V2_OK" -ForegroundColor Green
