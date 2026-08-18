param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$AttestationDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
    Die ("SHA256_MISSING_FILE: " + $Path)
  }

  $sha=[System.Security.Cryptography.SHA256]::Create()
  try{
    $bytes=[System.IO.File]::ReadAllBytes($Path)
    $hash=$sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }

  $sb=New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}

function Sha256HexText([string]$Text){
  $enc=New-Object System.Text.UTF8Encoding($false)
  $bytes=$enc.GetBytes($Text)
  $sha=[System.Security.Cryptography.SHA256]::Create()
  try{
    $hash=$sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }
  $sb=New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($AttestationDir)){
  $Root = Join-Path $RepoRoot "proofs\attestations"
  $latest = @(
    Get-ChildItem -LiteralPath $Root -Directory -Force |
    Where-Object { $_.Name -like "recognition_runtime_bridge_attest_v1_*" } |
    Sort-Object Name |
    Select-Object -Last 1
  )

  if(@($latest).Count -ne 1){
    Die "ATTESTATION_BUNDLE_NOT_FOUND"
  }

  $AttestationDir = $latest[0].FullName
}

$AttestationDir = (Resolve-Path -LiteralPath $AttestationDir).Path

$ManifestPath = Join-Path $AttestationDir "attestation.json"
$HashPath     = Join-Path $AttestationDir "attestation.sha256.txt"
$SigPath      = Join-Path $AttestationDir "attestation.sig"
$AllowedPath  = Join-Path $AttestationDir "allowed_signers"
$ShaPath      = Join-Path $AttestationDir "sha256sums.txt"

foreach($p in @($ManifestPath,$HashPath,$SigPath,$AllowedPath,$ShaPath)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("ATTEST_VERIFY_MISSING_FILE: " + $p)
  }
}

$expectedHash = (Get-Content -Raw -LiteralPath $HashPath -Encoding UTF8).Trim()
$manifestRaw = Get-Content -Raw -LiteralPath $ManifestPath -Encoding UTF8
$manifestNormalized = $manifestRaw.TrimEnd([char]10,[char]13)
$actualHash = Sha256HexText $manifestNormalized

if($expectedHash -ne $actualHash){
  Die ("ATTEST_HASH_MISMATCH: expected=" + $expectedHash + " actual=" + $actualHash)
}

$manifest = Get-Content -Raw -LiteralPath $ManifestPath -Encoding UTF8 | ConvertFrom-Json

if([string]$manifest.schema -ne "recognition.runtime.bridge.attestation.v1"){
  Die ("ATTEST_BAD_SCHEMA: " + [string]$manifest.schema)
}

$tokens = @($manifest.tokens)
foreach($tok in @(
  "FREEZE_RECOGNITION_RUNTIME_BRIDGE_V1_OK",
  "RECOGNITION_RUNTIME_BRIDGE_FAILHARD_GREEN",
  "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK",
  "RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1_OK"
)){
  if($tokens -notcontains $tok){
    Die ("ATTEST_REQUIRED_TOKEN_MISSING: " + $tok)
  }
}

$SshKeygen=(Get-Command ssh-keygen.exe -CommandType Application -ErrorAction Stop).Source
$VerifyOut=Join-Path $AttestationDir "verify_independent.stdout.txt"
$VerifyErr=Join-Path $AttestationDir "verify_independent.stderr.txt"

Remove-Item -LiteralPath $VerifyOut,$VerifyErr -Force -ErrorAction SilentlyContinue

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $SshKeygen
$psi.Arguments = "-Y verify -f " + '"' + $AllowedPath + '"' + " -I recognition-runtime-bridge -n recognition/runtime-bridge-attestation -s " + '"' + $SigPath + '"'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.RedirectStandardInput = $true
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()

$stdinText = Get-Content -Raw -LiteralPath $ManifestPath -Encoding UTF8
$p.StandardInput.Write($stdinText)
$p.StandardInput.Close()

$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()

if(-not $p.WaitForExit(10000)){
  try { $p.Kill() } catch {}
  Die "ATTEST_VERIFY_TIMEOUT"
}

$enc = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($VerifyOut,$out,$enc)
[System.IO.File]::WriteAllText($VerifyErr,$err,$enc)

if([int]$p.ExitCode -ne 0){
  Die ("ATTEST_SIGNATURE_VERIFY_FAIL: " + [string]$p.ExitCode)
}

Write-Host ("ATTEST_VERIFY_OK: " + $AttestationDir) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_BRIDGE_ATTEST_VERIFY_V1_OK" -ForegroundColor Green
