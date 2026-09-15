# Recognition — SoftwareID verification (Handoff / OSF paper §4.1, §4.2, §5.1-5.3)
#
# Implements the paper's core thesis end-to-end for the shipped binary:
#   SoftwareID = SHA-256(canonical_bytes(browser_software))
#   authenticity = Ed25519 signature over the SoftwareID record, checked against the
#                  PINNED trust root (proofs/trust/allowed_signers) — no central authority.
#
# Three outcomes:
#   RECOGNITION_SOFTWAREID_OK        — signed record present, signature valid, hash matches
#   RECOGNITION_SOFTWAREID_UNATTESTED— no signed record (e.g. a dev build); advisory, exit 0
#   RECOGNITION_SOFTWAREID_BLOCKED   — record present but signature invalid or hash mismatch
#
#   pwsh -File scripts\recognition_verify_softwareid_v1.ps1 -RepoRoot . [-BinaryPath <file>]
# Exit code: 0 for OK/UNATTESTED, 1 for BLOCKED.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$BinaryPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

function Sha256File([string]$Path){
  $h = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($Path))
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.AppendFormat("{0:x2}",$b) }
  return $sb.ToString()
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

function Blocked([string]$why){
  Write-Host ("SoftwareID BLOCKED: " + $why) -ForegroundColor Red
  Write-Host "RECOGNITION_SOFTWAREID_BLOCKED" -ForegroundColor Red
  exit 1
}

$bin = ResolveBinary $RepoRoot $BinaryPath
if(-not $bin){
  Write-Host "SoftwareID: no browser binary found to verify (advisory)" -ForegroundColor Yellow
  Write-Host "RECOGNITION_SOFTWAREID_UNATTESTED"
  exit 0
}

$recPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "software") "software_id.json"
$sigPath = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "software") "software_id.sig"

if(-not (Test-Path -LiteralPath $recPath -PathType Leaf)){
  Write-Host ("SoftwareID: unattested build (no signed record) — " + (Split-Path -Leaf $bin)) -ForegroundColor Yellow
  Write-Host "RECOGNITION_SOFTWAREID_UNATTESTED"
  exit 0
}

$computed = Sha256File $bin
$raw = Get-Content -Raw -LiteralPath $recPath -Encoding UTF8
$obj = $raw | ConvertFrom-Json
$recorded  = [string]$obj.software_id
$principal = if($obj.PSObject.Properties.Name -contains "principal" -and $obj.principal){ [string]$obj.principal } else { "recognition-runtime-bridge" }
$namespace = if($obj.PSObject.Properties.Name -contains "namespace" -and $obj.namespace){ [string]$obj.namespace } else { "recognition/software-id" }

# --- authenticity: signature over the record, against the PINNED trust root ---
$trust = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "trust") "allowed_signers"
if(-not (Test-Path -LiteralPath $trust -PathType Leaf)){ Blocked "trust root missing (proofs/trust/allowed_signers)" }
if(-not (Test-Path -LiteralPath $sigPath -PathType Leaf)){ Blocked "signature missing (proofs/software/software_id.sig)" }

$ssh = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ssh
foreach($a in @("-Y","verify","-f",$trust,"-I",$principal,"-n",$namespace,"-s",$sigPath)){ [void]$psi.ArgumentList.Add($a) }
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$p = [System.Diagnostics.Process]::Start($psi)
$p.StandardInput.Write($raw)
$p.StandardInput.Close()
$o = $p.StandardOutput.ReadToEndAsync()
$e = $p.StandardError.ReadToEndAsync()
if(-not $p.WaitForExit(10000)){ try{ $p.Kill() }catch{}; Blocked "signature verify timed out" }
if($p.ExitCode -ne 0){ Blocked ("signature verify failed against pinned trust root: " + ([string]$e.Result).Trim()) }

# --- integrity: recorded hash must equal the running binary's hash ------------
if($recorded -ne $computed){
  Blocked ("hash mismatch — binary does not match the signed SoftwareID`n  recorded=" + $recorded + "`n  computed=" + $computed)
}

# --- receipt -----------------------------------------------------------------
$receipt = [ordered]@{
  schema      = "recognition.software_id.verify.receipt.v1"
  ts_utc      = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  binary      = (Split-Path -Leaf $bin)
  software_id = $computed
  verified    = $true
  trust_root_pinned = $true
}
$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.software_id.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
[System.IO.File]::AppendAllText($rp, (($receipt | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("SoftwareID verified authentic: " + $computed) -ForegroundColor Green
Write-Host "RECOGNITION_SOFTWAREID_OK" -ForegroundColor Green
exit 0
