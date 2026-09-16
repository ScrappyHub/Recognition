# Recognition — SoftwareID sealing (Handoff / OSF paper §4.1, §4.2)
#
# Computes SoftwareID = SHA-256(browser binary bytes), writes a signed record, and
# signs it with the pinned Ed25519 attestation key (same key/trust root as attestation).
# The running browser verifies itself against this record at locked startup.
#
#   pwsh -File scripts\recognition_seal_softwareid_v1.ps1 -RepoRoot . [-BinaryPath <file>]
#
# The PRIVATE key must live OUTSIDE the repo (default under your home dir), exactly like
# recognition_rotate_attest_key_v1.ps1. Token: RECOGNITION_SEAL_SOFTWAREID_V1_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$BinaryPath = "",
  [string]$KeyPath   = (Join-Path $HOME ".recognition/keys/recognition_runtime_bridge_attest_ed25519"),
  [string]$Principal = "recognition-runtime-bridge",
  [string]$Namespace = "recognition/software-id"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Die([string]$m){ Write-Host ("SEAL_FAIL: " + $m) -ForegroundColor Red; exit 1 }

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

function Sha256File([string]$Path){
  $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($Path))
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
}
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::WriteAllText($Path,$t,(New-Object System.Text.UTF8Encoding($false)))
}
function RunSsh([string]$Exe,[string[]]$SshArgs,[int]$TimeoutMs=20000){
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach($a in $SshArgs){ [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  try { $p.StandardInput.Close() } catch {}
  $o = $p.StandardOutput.ReadToEndAsync()
  $e = $p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit($TimeoutMs)){ try { $p.Kill() } catch {}; return @{ ExitCode=124; Err="TIMEOUT" } }
  return @{ ExitCode=$p.ExitCode; Out=$o.Result; Err=$e.Result }
}
function ResolveBinary([string]$RepoRoot,[string]$BinaryPath){
  if($BinaryPath -and (Test-Path -LiteralPath $BinaryPath -PathType Leaf)){ return (Resolve-Path -LiteralPath $BinaryPath).Path }
  foreach($c in @(
    "browser\bin\Release\net8.0-windows\RecognitionBrowser.dll",
    "browser\bin\Release\net8.0-windows\win-x64\publish\RecognitionBrowser.exe",
    "browser\RecognitionBrowser.dll"
  )){
    $p = Join-Path $RepoRoot $c
    if(Test-Path -LiteralPath $p -PathType Leaf){ return (Resolve-Path -LiteralPath $p).Path }
  }
  return ""
}

$ssh = $null
foreach($cand in @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'), (Join-Path ${env:ProgramFiles} 'Git\usr\bin\ssh-keygen.exe'))){ if($cand -and (Test-Path -LiteralPath $cand)){ $ssh = $cand; break } }
if(-not $ssh){ $ssh = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source }

$bin = ResolveBinary $RepoRoot $BinaryPath
if(-not $bin){ Die "no browser binary found to seal (build the browser first, or pass -BinaryPath)" }

$keyFull = [System.IO.Path]::GetFullPath($KeyPath)
if($keyFull.StartsWith($RepoRoot,[System.StringComparison]::OrdinalIgnoreCase)){ Die ("KEYPATH_INSIDE_REPO: keep the private key outside " + $RepoRoot) }
if(-not (Test-Path -LiteralPath $keyFull -PathType Leaf)){
  Die ("signing key not found at " + $keyFull + " — generate/pin it first with recognition_rotate_attest_key_v1.ps1")
}

$trust = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "trust") "allowed_signers"
if(-not (Test-Path -LiteralPath $trust -PathType Leaf)){ Die ("trust root missing: " + $trust) }

$softwareId = Sha256File $bin
$size = (Get-Item -LiteralPath $bin).Length

# canonical record (stable key order, LF, no BOM)
$record = [ordered]@{
  schema      = "recognition.software_id.v1"
  algo        = "sha256"
  software_id = $softwareId
  file        = (Split-Path -Leaf $bin)
  size        = $size
  principal   = $Principal
  namespace   = $Namespace
  signed_utc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
}
$recJson = ($record | ConvertTo-Json -Depth 8)

$softDir = Join-Path (Join-Path $RepoRoot "proofs") "software"
if(-not (Test-Path -LiteralPath $softDir)){ New-Item -ItemType Directory -Force -Path $softDir | Out-Null }
$recPath = Join-Path $softDir "software_id.json"
$sigPath = Join-Path $softDir "software_id.sig"
WriteUtf8NoBomLf $recPath $recJson

# sign the record file (ssh-keygen -Y sign <file> -> <file>.sig)
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sid_" + [Guid]::NewGuid().ToString("N"))
Copy-Item -LiteralPath $recPath -Destination $tmp -Force
try {
  $sg = RunSsh $ssh @("-Y","sign","-f",$keyFull,"-n",$Namespace,$tmp)
  if($sg.ExitCode -ne 0){ Die ("SIGN_FAILED: " + ([string]$sg.Err).Trim()) }
  Move-Item -LiteralPath ($tmp + ".sig") -Destination $sigPath -Force
} finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }

# pin the signer next to the record for reference (verification uses the trust root)
Copy-Item -LiteralPath $trust -Destination (Join-Path $softDir "allowed_signers") -Force

# self-verify immediately (verifier lives next to this script, not under -RepoRoot)
$verifier = Join-Path $PSScriptRoot "recognition_verify_softwareid_v1.ps1"
$vout = & $verifier -RepoRoot $RepoRoot -BinaryPath $bin *>&1 | Out-String
Write-Host $vout
if($vout -notmatch "RECOGNITION_SOFTWAREID_OK"){ Die "post-seal verification did not return OK" }

$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.software_id.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
$seal = [ordered]@{ schema="recognition.software_id.seal.receipt.v1"; ts_utc=$record.signed_utc; file=$record.file; software_id=$softwareId; size=$size }
[System.IO.File]::AppendAllText($rp, (($seal | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host ("Sealed SoftwareID for " + (Split-Path -Leaf $bin) + ": " + $softwareId) -ForegroundColor Cyan
Write-Host ("Record : " + $recPath)
Write-Host ("Signature: " + $sigPath)
Write-Host "RECOGNITION_SEAL_SOFTWAREID_V1_OK" -ForegroundColor Green
