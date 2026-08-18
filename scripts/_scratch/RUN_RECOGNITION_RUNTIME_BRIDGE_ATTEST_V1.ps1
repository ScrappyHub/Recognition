param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function Sha256HexFile([string]$Path){
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

function RelPath([string]$Base,[string]$Full){
  $b=(Resolve-Path -LiteralPath $Base).Path.TrimEnd([char]92,[char]47)
  $f=(Resolve-Path -LiteralPath $Full).Path
  return $f.Substring($b.Length).TrimStart([char]92,[char]47).Replace([char]92,[char]47)
}

function Quote-Arg([string]$s){
  if($null -eq $s){ return '""' }
  if($s.Length -eq 0){ return '""' }
  if($s -match '[\s"]'){
    return '"' + $s.Replace('"','\"') + '"'
  }
  return $s
}

function RunNativeTimeout {
  param(
    [Parameter(Mandatory=$true)][string]$FilePath,
    [Parameter(Mandatory=$true)][string[]]$Argv,
    [Parameter(Mandatory=$true)][string]$Stdout,
    [Parameter(Mandatory=$true)][string]$Stderr,
    [Parameter(Mandatory=$true)][string]$FailToken,
    [Parameter(Mandatory=$false)][int]$TimeoutMs = 10000,
    [Parameter(Mandatory=$false)][string]$StdinPath = ""
  )

  Remove-Item -LiteralPath $Stdout,$Stderr -Force -ErrorAction SilentlyContinue

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.RedirectStandardInput = $true
  $psi.CreateNoWindow = $true

  $psi.Arguments = (@($Argv) | ForEach-Object { Quote-Arg ([string]$_) }) -join " "

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()

  if(-not [string]::IsNullOrWhiteSpace($StdinPath)){
    $stdinText = Get-Content -Raw -LiteralPath $StdinPath -Encoding UTF8
    $p.StandardInput.Write($stdinText)
  }
  $p.StandardInput.Close()

  if(-not $p.WaitForExit($TimeoutMs)){
    try{ $p.Kill() } catch {}
    WriteUtf8NoBomLf $Stdout ""
    WriteUtf8NoBomLf $Stderr "TIMEOUT"
    Die ($FailToken + "_TIMEOUT")
  }

  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()

  WriteUtf8NoBomLf $Stdout $out
  WriteUtf8NoBomLf $Stderr $err

  if([int]$p.ExitCode -ne 0){
    Die ($FailToken + ":" + [string]$p.ExitCode)
  }
}

$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$FreezeRoot=Join-Path $RepoRoot "proofs\freeze"

$LatestBridge=@(
  Get-ChildItem -LiteralPath $FreezeRoot -Directory -Force |
  Where-Object { $_.Name -like "recognition_runtime_bridge_v1_*" } |
  Sort-Object Name |
  Select-Object -Last 1
)

if(@($LatestBridge).Count -ne 1){ Die "LATEST_BRIDGE_FREEZE_NOT_FOUND" }

$BridgeFreeze=$LatestBridge[0].FullName
$BridgeSha=Sha256HexFile (Join-Path $BridgeFreeze "sha256sums.txt")

$AttestRoot=Join-Path $RepoRoot "proofs\attestations"
EnsureDir $AttestRoot

$RunId="recognition_runtime_bridge_attest_v1_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$OutDir=Join-Path $AttestRoot $RunId
EnsureDir $OutDir

$SshKeygen=(Get-Command ssh-keygen.exe -CommandType Application -ErrorAction Stop).Source

$candidates = @(
  (Join-Path $RepoRoot "proofs\keys\recognition_runtime_bridge_attest_ed25519"),
  (Join-Path $RepoRoot "proofs\keys\recognition_ed25519"),
  (Join-Path $RepoRoot "proofs\trust\recognition_ed25519"),
  (Join-Path $RepoRoot "keys\recognition_ed25519")
)

$Priv = $null
foreach($c in @($candidates)){
  if(Test-Path -LiteralPath $c -PathType Leaf){
    $Priv = $c
    break
  }
}

if([string]::IsNullOrWhiteSpace($Priv)){
  WriteUtf8NoBomLf (Join-Path $OutDir "ATTEST_SIGNING_KEY_MISSING.txt") (@($candidates) -join "`n")
  Die "ATTEST_SIGNING_KEY_MISSING"
}

$Pub = $Priv + ".pub"
if(-not (Test-Path -LiteralPath $Pub -PathType Leaf)){
  Die ("ATTEST_PUBLIC_KEY_MISSING: " + $Pub)
}

$ManifestObj=[ordered]@{
  schema="recognition.runtime.bridge.attestation.v1"
  producer="recognition"
  subject="runtime_bridge_v1"
  bridge_freeze_bundle=$BridgeFreeze
  bridge_freeze_sha256sums_hash=$BridgeSha
  signing_key=$Priv
  issued_utc=(Get-Date).ToUniversalTime().ToString("o")
  tokens=@(
    "FREEZE_RECOGNITION_RUNTIME_BRIDGE_V1_OK",
    "RECOGNITION_RUNTIME_BRIDGE_FAILHARD_GREEN",
    "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK",
    "RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1_OK"
  )
}

$ManifestJson=$ManifestObj | ConvertTo-Json -Depth 20 -Compress
$AttestHash=Sha256HexText $ManifestJson

$ManifestPath=Join-Path $OutDir "attestation.json"
$HashPath=Join-Path $OutDir "attestation.sha256.txt"
$SigPath=Join-Path $OutDir "attestation.sig"
$PubCopy=Join-Path $OutDir "signer.pub"

WriteUtf8NoBomLf $ManifestPath $ManifestJson
WriteUtf8NoBomLf $HashPath $AttestHash
Copy-Item -LiteralPath $Pub -Destination $PubCopy -Force

$SignOut=Join-Path $OutDir "sign.stdout.txt"
$SignErr=Join-Path $OutDir "sign.stderr.txt"

Remove-Item -LiteralPath ($ManifestPath + ".sig"),$SigPath -Force -ErrorAction SilentlyContinue

RunNativeTimeout `
  -FilePath $SshKeygen `
  -Argv @("-Y","sign","-f",$Priv,"-P","recognition-runtime-bridge-attest-v1","-n","recognition/runtime-bridge-attestation",$ManifestPath) `
  -Stdout $SignOut `
  -Stderr $SignErr `
  -FailToken "SSH_SIGN_FAIL" `
  -TimeoutMs 10000

$GeneratedSig=$ManifestPath + ".sig"
if(Test-Path -LiteralPath $GeneratedSig -PathType Leaf){
  Move-Item -LiteralPath $GeneratedSig -Destination $SigPath -Force
}
if(-not (Test-Path -LiteralPath $SigPath -PathType Leaf)){ Die "SIGNATURE_MISSING" }

$Allowed=Join-Path $OutDir "allowed_signers"
$pubText=Get-Content -Raw -LiteralPath $Pub -Encoding UTF8
WriteUtf8NoBomLf $Allowed ("recognition-runtime-bridge " + $pubText.Trim())

$VerifyOut=Join-Path $OutDir "verify.stdout.txt"
$VerifyErr=Join-Path $OutDir "verify.stderr.txt"

RunNativeTimeout `
  -FilePath $SshKeygen `
  -Argv @("-Y","verify","-f",$Allowed,"-I","recognition-runtime-bridge","-n","recognition/runtime-bridge-attestation","-s",$SigPath) `
  -Stdout $VerifyOut `
  -Stderr $VerifyErr `
  -FailToken "SSH_VERIFY_FAIL" `
  -TimeoutMs 10000 `
  -StdinPath $ManifestPath

$ShaPath=Join-Path $OutDir "sha256sums.txt"
if(Test-Path -LiteralPath $ShaPath -PathType Leaf){ Remove-Item -LiteralPath $ShaPath -Force }

$files=@(
  Get-ChildItem -LiteralPath $OutDir -Recurse -File -Force |
  Where-Object { $_.FullName -ne $ShaPath } |
  Sort-Object FullName
)

$lines=New-Object System.Collections.Generic.List[string]
foreach($f in @($files)){
  [void]$lines.Add(("{0}  {1}" -f (Sha256HexFile $f.FullName),(RelPath $OutDir $f.FullName)))
}

WriteUtf8NoBomLf $ShaPath ((@($lines) -join "`n") + "`n")

Write-Host ("ATTESTATION_BUNDLE_OK: " + $OutDir) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_BRIDGE_ATTEST_V1_OK" -ForegroundColor Green
