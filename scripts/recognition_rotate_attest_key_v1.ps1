# Recognition — Attestation Signing Key Rotation v1  (remediates audit F10)
#
# The previous Ed25519 signing key was committed to the repo and is therefore
# COMPROMISED. This script:
#   1. generates a NEW Ed25519 signing key OUTSIDE the repo (never inside it),
#   2. re-pins the new PUBLIC key as the trust root (proofs/trust/allowed_signers),
#   3. re-signs every attestation bundle's attestation.json with the new key,
#   4. updates each bundle's embedded allowed_signers + signer.pub,
#   5. verifies every bundle green against the new pinned root,
#   6. writes a rotation receipt.
#
# Only PUBLIC key material ever touches the repo. The private key stays at
# -KeyPath (default under your home dir) and must remain there / on a token.
#
# Usage (pwsh 7+, with OpenSSH ssh-keygen on PATH):
#   pwsh -File scripts/recognition_rotate_attest_key_v1.ps1 -RepoRoot .
#   # add -Force to overwrite an existing key at -KeyPath

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$KeyPath   = (Join-Path $HOME ".recognition/keys/recognition_runtime_bridge_attest_ed25519"),
  [string]$Principal = "recognition-runtime-bridge",
  [string]$Namespace = "recognition/runtime-bridge-attestation",
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ Write-Error $m; exit 1 }
function NowUtc(){ return (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::WriteAllText($Path,$t,(New-Object System.Text.UTF8Encoding($false)))
}
function Fingerprint([string]$PubPath){
  $o = & ssh-keygen -l -f $PubPath 2>&1
  if($LASTEXITCODE -ne 0){ return "UNKNOWN" }
  return ([string]$o).Trim()
}
# Run ssh-keygen with an explicit argument list so empty-string args (e.g. the
# empty passphrase -N "") are passed literally regardless of shell arg parsing.
function RunSsh([string]$Exe,[string[]]$SshArgs,[string]$StdinText = "",[int]$TimeoutMs = 20000){
  # NB: parameter must NOT be named $Args — that shadows the automatic $args and
  # would leave the argument list empty (ssh-keygen then prompts for everything).
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach($a in $SshArgs){ [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput  = $true   # answer prompts (or send EOF) — never hang
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  try { if($StdinText.Length -gt 0){ $p.StandardInput.Write($StdinText) }; $p.StandardInput.Close() } catch {}
  # async reads so a full stderr/stdout buffer can't deadlock the blocking read
  $outTask = $p.StandardOutput.ReadToEndAsync()
  $errTask = $p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit($TimeoutMs)){
    try { $p.Kill($true) } catch { try { $p.Kill() } catch {} }
    return @{ ExitCode = 124; Out = ""; Err = ("TIMEOUT: ssh-keygen did not exit in " + $TimeoutMs + " ms (prompt or missing OpenSSH?)") }
  }
  return @{ ExitCode = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ssh = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source

# --- the private key must live OUTSIDE the repo ------------------------------
$keyFull = [System.IO.Path]::GetFullPath($KeyPath)
if($keyFull.StartsWith($RepoRoot, [System.StringComparison]::OrdinalIgnoreCase)){
  Die ("KEYPATH_INSIDE_REPO: refuse to place a private key under the repo. Choose a -KeyPath outside " + $RepoRoot)
}
$keyDir = Split-Path -Parent $keyFull
if(-not (Test-Path -LiteralPath $keyDir)){ New-Item -ItemType Directory -Force -Path $keyDir | Out-Null }

$TrustRoot = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "trust") "allowed_signers"
$oldPinned = if(Test-Path -LiteralPath $TrustRoot){ (Get-Content -Raw -LiteralPath $TrustRoot -Encoding UTF8).Trim() } else { "" }

# --- 1. generate the new key --------------------------------------------------
if((Test-Path -LiteralPath $keyFull) -and -not $Force){
  Write-Host ("Reusing existing key at " + $keyFull + " (pass -Force to regenerate).")
} else {
  if(Test-Path -LiteralPath $keyFull){ Remove-Item -LiteralPath $keyFull,($keyFull + ".pub") -Force -ErrorAction SilentlyContinue }
  # -N "" = empty passphrase, non-interactively (ssh-keygen reads a prompted
  # passphrase from the console, not stdin, so the flag is the only reliable way).
  $kg = RunSsh $ssh @("-t","ed25519","-f",$keyFull,"-N","","-C",$Principal)
  if($kg.ExitCode -ne 0 -or -not (Test-Path -LiteralPath ($keyFull + ".pub"))){
    Die ("KEYGEN_FAILED (exit=" + $kg.ExitCode + "): out=[" + ([string]$kg.Out).Trim() + "] err=[" + ([string]$kg.Err).Trim() + "] ssh=[" + $ssh + "] keyPath=[" + $keyFull + "]")
  }
  Write-Host ("Generated new signing key: " + $keyFull)
}
$pubPath = $keyFull + ".pub"
if(-not (Test-Path -LiteralPath $pubPath)){ Die ("PUBKEY_MISSING: " + $pubPath) }

# --- 2. build + pin the new trust-root line ----------------------------------
$pub = (Get-Content -Raw -LiteralPath $pubPath -Encoding UTF8).Trim()
$parts = $pub -split '\s+'
if($parts.Count -lt 2 -or $parts[0] -ne "ssh-ed25519"){ Die ("PUBKEY_UNEXPECTED_FORMAT: " + $pub) }
$newLine = ($Principal + " " + $parts[0] + " " + $parts[1])
WriteUtf8NoBomLf $TrustRoot $newLine
Write-Host ("Pinned new trust root: " + $TrustRoot)

# --- 3-4. re-sign every attestation bundle -----------------------------------
$attRoot = Join-Path (Join-Path $RepoRoot "proofs") "attestations"
$bundles = @(Get-ChildItem -LiteralPath $attRoot -Directory -Force |
             Where-Object { $_.Name -like "recognition_runtime_bridge_attest_v1_*" -and (Test-Path -LiteralPath (Join-Path $_.FullName "attestation.json")) })
if($bundles.Count -eq 0){ Die "NO_ATTESTATION_BUNDLES_WITH_MANIFEST" }

$resigned = @()
foreach($b in $bundles){
  $manifest = Join-Path $b.FullName "attestation.json"
  $sigOut   = Join-Path $b.FullName "attestation.sig"
  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("attmanifest_" + [Guid]::NewGuid().ToString("N"))
  Copy-Item -LiteralPath $manifest -Destination $tmp -Force
  try {
    $sg = RunSsh $ssh @("-Y","sign","-f",$keyFull,"-n",$Namespace,$tmp)
    if($sg.ExitCode -ne 0){ Die ("SIGN_FAILED for " + $b.Name + ": " + $sg.Err.Trim()) }
    Move-Item -LiteralPath ($tmp + ".sig") -Destination $sigOut -Force
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
  # update bundle-embedded public trust material to match the new root
  WriteUtf8NoBomLf (Join-Path $b.FullName "allowed_signers") $newLine
  Copy-Item -LiteralPath $pubPath -Destination (Join-Path $b.FullName "signer.pub") -Force
  $resigned += $b.Name
  Write-Host ("  re-signed: " + $b.Name)
}

# --- 5. verify every bundle green against the new root -----------------------
$verifier = Join-Path (Join-Path $RepoRoot "scripts") "recognition_verify_attestation_v2.ps1"
foreach($b in $bundles){
  $out = & $verifier -RepoRoot $RepoRoot -AttestationDir $b.FullName *>&1 | Out-String
  if($out -notmatch "RECOGNITION_ATTEST_VERIFY_V2_OK"){
    Write-Host $out
    Die ("POST_ROTATION_VERIFY_FAILED for " + $b.Name)
  }
  Write-Host ("  verified: " + $b.Name) -ForegroundColor Green
}

# --- 6. receipt --------------------------------------------------------------
$receiptPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.keyrotation.v1.ndjson"
$rd = Split-Path -Parent $receiptPath
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
$rec = [ordered]@{
  schema        = "recognition.keyrotation.receipt.v1"
  ts_utc        = NowUtc
  principal     = $Principal
  namespace     = $Namespace
  new_key_path  = $keyFull
  new_fpr       = (Fingerprint $pubPath)
  old_trust_line= $oldPinned
  new_trust_line= $newLine
  bundles_resigned = $resigned
  note          = "previous key COMPROMISED (was committed); delete it and purge from history before publishing"
}
[System.IO.File]::AppendAllText($receiptPath, (($rec | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host ("Rotation complete. New key (KEEP PRIVATE, outside repo): " + $keyFull) -ForegroundColor Cyan
Write-Host  "Now DELETE the old compromised key under proofs/keys/ and purge it from git history" -ForegroundColor Yellow
Write-Host  "(run scripts/recognition_clean_publish_history_v1.ps1)." -ForegroundColor Yellow
Write-Host "RECOGNITION_ROTATE_ATTEST_KEY_V1_OK" -ForegroundColor Green
