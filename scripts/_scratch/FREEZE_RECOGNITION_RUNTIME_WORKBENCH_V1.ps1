param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "ENSUREDIR_EMPTY" }

  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"

  if(-not $lf.EndsWith("`n")){
    $lf += "`n"
  }

  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }

  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
    Die ("PARSE_GATE_MISSING: " + $Path)
  }

  $tokens=$null
  $errors=$null

  [void][System.Management.Automation.Language.Parser]::ParseFile(
    $Path,
    [ref]$tokens,
    [ref]$errors
  )

  if($errors -and @($errors).Count -gt 0){
    $e=@($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

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

  foreach($b in $hash){
    [void]$sb.AppendFormat("{0:x2}",$b)
  }

  return $sb.ToString()
}

function RelPath([string]$Base,[string]$Full){
  $b=(Resolve-Path -LiteralPath $Base).Path.TrimEnd([char]92,[char]47)
  $f=(Resolve-Path -LiteralPath $Full).Path

  if($f.Substring(0,$b.Length) -ne $b){
    Die ("REL_OUTSIDE_BASE: " + $Full)
  }

  return $f.Substring($b.Length).TrimStart([char]92,[char]47).Replace([char]92,[char]47)
}

function RunCapture {
  param(
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ExpectedToken,
    [Parameter(Mandatory=$true)][string]$OutDir
  )

  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){
    Die ("CAPTURE_MISSING_SCRIPT: " + $ScriptPath)
  }

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $stdout = Join-Path $OutDir ($Label + ".stdout.txt")
  $stderr = Join-Path $OutDir ($Label + ".stderr.txt")

  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $p = Start-Process `
    -FilePath $PSExe `
    -ArgumentList @(
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy","Bypass",
      "-File",$ScriptPath,
      "-RepoRoot",$RepoRoot
    ) `
    -Wait `
    -PassThru `
    -NoNewWindow `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr

  $out = ""
  $err = ""

  if(Test-Path -LiteralPath $stdout -PathType Leaf){
    $out = Get-Content -Raw -LiteralPath $stdout -Encoding UTF8
  }

  if(Test-Path -LiteralPath $stderr -PathType Leaf){
    $err = Get-Content -Raw -LiteralPath $stderr -Encoding UTF8
  }

  if($out){ [Console]::Out.Write($out) }
  if($err){ [Console]::Error.Write($err) }

  if([int]$p.ExitCode -ne 0){
    Die ("CAPTURE_FAIL[" + $Label + "]: " + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("CAPTURE_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ("CAPTURE_OK: " + $Label) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$WorkbenchPath = Join-Path $RepoRoot "workbench\recognition_runtime_workbench_snapshot_v1.html"
$ValidatorPath = Join-Path $RepoRoot "scripts\recognition_validate_runtime_workbench_v1.ps1"
$SealIndexPath = Join-Path $RepoRoot "proofs\seal_index\recognition_runtime_bridge_seal_index_v1.json"
$AttestVerifyPath = Join-Path $RepoRoot "scripts\recognition_verify_runtime_bridge_attestation_v1.ps1"
$SealVerifyPath = Join-Path $RepoRoot "scripts\_scratch\RUN_RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1.ps1"

foreach($p in @($WorkbenchPath,$ValidatorPath,$SealIndexPath,$AttestVerifyPath,$SealVerifyPath)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("FREEZE_REQUIRED_FILE_MISSING: " + $p)
  }
}

foreach($p in @($ValidatorPath,$AttestVerifyPath,$SealVerifyPath)){
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$FreezeRoot = Join-Path $RepoRoot "proofs\freeze\recognition_runtime_workbench_v1"
EnsureDir $FreezeRoot

$RunId = (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$Bundle = Join-Path $FreezeRoot $RunId

if(Test-Path -LiteralPath $Bundle -PathType Container){
  Remove-Item -LiteralPath $Bundle -Recurse -Force
}

EnsureDir $Bundle
EnsureDir (Join-Path $Bundle "transcripts")
EnsureDir (Join-Path $Bundle "scripts")
EnsureDir (Join-Path $Bundle "artifacts")

$TranscriptDir = Join-Path $Bundle "transcripts"

RunCapture `
  -Label "workbench_validator" `
  -ScriptPath $ValidatorPath `
  -ExpectedToken "RECOGNITION_RUNTIME_WORKBENCH_VALIDATE_V1_OK" `
  -OutDir $TranscriptDir

Copy-Item -LiteralPath $WorkbenchPath -Destination (Join-Path (Join-Path $Bundle "artifacts") "recognition_runtime_workbench_snapshot_v1.html") -Force
Copy-Item -LiteralPath $SealIndexPath -Destination (Join-Path (Join-Path $Bundle "artifacts") "recognition_runtime_bridge_seal_index_v1.json") -Force

Copy-Item -LiteralPath $ValidatorPath -Destination (Join-Path (Join-Path $Bundle "scripts") "recognition_validate_runtime_workbench_v1.ps1") -Force
Copy-Item -LiteralPath $AttestVerifyPath -Destination (Join-Path (Join-Path $Bundle "scripts") "recognition_verify_runtime_bridge_attestation_v1.ps1") -Force
Copy-Item -LiteralPath $SealVerifyPath -Destination (Join-Path (Join-Path $Bundle "scripts") "RUN_RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1.ps1") -Force

$AttestRoot = Join-Path $RepoRoot "proofs\attestations"

$latestAttest = @(
  Get-ChildItem -LiteralPath $AttestRoot -Directory -Force |
  Where-Object { $_.Name -like "recognition_runtime_bridge_attest_v1_*" } |
  Sort-Object Name |
  Select-Object -Last 1
)

if(@($latestAttest).Count -ne 1){
  Die "FREEZE_ATTESTATION_BUNDLE_NOT_FOUND"
}

$AttestationDir = $latestAttest[0].FullName
$AttestationJson = Join-Path $AttestationDir "attestation.json"
$AttestationSig = Join-Path $AttestationDir "attestation.sig"
$AttestationSums = Join-Path $AttestationDir "sha256sums.txt"

foreach($p in @($AttestationJson,$AttestationSig,$AttestationSums)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("FREEZE_ATTESTATION_FILE_MISSING: " + $p)
  }
}

Copy-Item -LiteralPath $AttestationJson -Destination (Join-Path (Join-Path $Bundle "artifacts") "attestation.json") -Force
Copy-Item -LiteralPath $AttestationSig -Destination (Join-Path (Join-Path $Bundle "artifacts") "attestation.sig") -Force
Copy-Item -LiteralPath $AttestationSums -Destination (Join-Path (Join-Path $Bundle "artifacts") "attestation.sha256sums.txt") -Force

$ManifestPath = Join-Path $Bundle "freeze_manifest.json"

$manifest = [ordered]@{
  schema = "recognition.runtime.workbench.freeze.v1"
  status = "GREEN"
  run_id = $RunId
  repo_root = $RepoRoot
  bundle = $Bundle
  validator_token = "RECOGNITION_RUNTIME_WORKBENCH_VALIDATE_V1_OK"
  workbench_snapshot = "artifacts/recognition_runtime_workbench_snapshot_v1.html"
  seal_index = "artifacts/recognition_runtime_bridge_seal_index_v1.json"
  attestation_json = "artifacts/attestation.json"
  hashes = [ordered]@{
    workbench_snapshot_sha256 = (Sha256HexFile (Join-Path (Join-Path $Bundle "artifacts") "recognition_runtime_workbench_snapshot_v1.html"))
    seal_index_sha256 = (Sha256HexFile (Join-Path (Join-Path $Bundle "artifacts") "recognition_runtime_bridge_seal_index_v1.json"))
    attestation_json_sha256 = (Sha256HexFile (Join-Path (Join-Path $Bundle "artifacts") "attestation.json"))
    attestation_sig_sha256 = (Sha256HexFile (Join-Path (Join-Path $Bundle "artifacts") "attestation.sig"))
  }
}

WriteUtf8NoBomLf $ManifestPath ($manifest | ConvertTo-Json -Depth 20)

$ShaPath = Join-Path $Bundle "sha256sums.txt"

if(Test-Path -LiteralPath $ShaPath -PathType Leaf){
  Remove-Item -LiteralPath $ShaPath -Force
}

$files = @(
  Get-ChildItem -LiteralPath $Bundle -Recurse -File -Force |
  Where-Object { $_.FullName -ne $ShaPath } |
  Sort-Object FullName
)

$lines = New-Object System.Collections.Generic.List[string]

foreach($f in @($files)){
  [void]$lines.Add(("{0}  {1}" -f (Sha256HexFile $f.FullName),(RelPath $Bundle $f.FullName)))
}

WriteUtf8NoBomLf $ShaPath ((@($lines) -join "`n") + "`n")

Write-Host ("WORKBENCH_FREEZE_BUNDLE_OK: " + $Bundle) -ForegroundColor Green
Write-Host "FREEZE_RECOGNITION_RUNTIME_WORKBENCH_V1_OK" -ForegroundColor Green
