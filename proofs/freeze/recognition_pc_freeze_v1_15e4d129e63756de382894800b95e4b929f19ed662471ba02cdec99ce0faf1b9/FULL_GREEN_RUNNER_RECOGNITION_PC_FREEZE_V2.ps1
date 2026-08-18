param([Parameter(Mandatory=$true)][string]$RepoRoot)

$ThisRunnerPath = $MyInvocation.MyCommand.Path

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){
    $x=$e[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
}

function Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("SHA256_MISSING_FILE: " + $Path) }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try{
    $fs = [System.IO.File]::OpenRead($Path)
    try{
      $hash = $sha.ComputeHash($fs)
    } finally {
      $fs.Dispose()
    }
  } finally {
    $sha.Dispose()
  }
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}", $b) }
  $sb.ToString()
}

function Invoke-ChildCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$false)][string[]]$Args,
    [Parameter(Mandatory=$true)][string]$StdoutPath,
    [Parameter(Mandatory=$true)][string]$StderrPath
  )

  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("CHILD_SCRIPT_MISSING: " + $ScriptPath) }

  $argList = New-Object System.Collections.Generic.List[string]
  [void]$argList.Add("-NoProfile")
  [void]$argList.Add("-NonInteractive")
  [void]$argList.Add("-ExecutionPolicy")
  [void]$argList.Add("Bypass")
  [void]$argList.Add("-File")
  [void]$argList.Add($ScriptPath)
  if($Args){
    foreach($a in $Args){ [void]$argList.Add([string]$a) }
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $psExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true

  $quoted = New-Object System.Collections.Generic.List[string]
  foreach($a in $argList){
    $s = [string]$a
    if($s -match '\s|"'){
      [void]$quoted.Add('"' + $s.Replace('"','\"') + '"')
    } else {
      [void]$quoted.Add($s)
    }
  }
  $psi.Arguments = (@($quoted) -join " ")

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  WriteUtf8NoBomLf $StdoutPath $stdout
  WriteUtf8NoBomLf $StderrPath $stderr

  if($stdout){ [Console]::Out.Write($stdout) }
  if($stderr){ [Console]::Error.Write($stderr) }

  if($p.ExitCode -ne 0){
    Die ("CHILD_FAIL(" + $p.ExitCode + "): " + $ScriptPath)
  }
}

function Get-LastExistingDirFromText([string]$Text){
  $lines = @($Text -split "`r?`n")
  for($i = $lines.Count - 1; $i -ge 0; $i--){
    $candidate = $lines[$i].Trim()
    if([string]::IsNullOrWhiteSpace($candidate)){ continue }
    if(Test-Path -LiteralPath $candidate -PathType Container){ return $candidate }
  }
  return $null
}

function Write-Sha256Sums([string]$RootDir,[string]$OutPath){
  $files = @(Get-ChildItem -LiteralPath $RootDir -Recurse -File -Force | Sort-Object FullName)
  $lines = New-Object System.Collections.Generic.List[string]
  foreach($f in $files){
    $full = $f.FullName
    if($full -ieq $OutPath){ continue }
    $rel = $full.Substring($RootDir.Length).TrimStart('\','/')
    $rel = $rel.Replace([char]92,[char]47)
    $h = Sha256HexFile $full
    [void]$lines.Add(("{0}  {1}" -f $h,$rel))
  }
  WriteUtf8NoBomLf $OutPath ((@($lines) -join "`n") + "`n")
}

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
$ScratchDir = Join-Path $ScriptsDir "_scratch"
$ProofsDir  = Join-Path $RepoRoot "proofs"
$ReceiptsDir = Join-Path $ProofsDir "receipts"
$FreezeDirRoot = Join-Path $ProofsDir "freeze"

EnsureDir $ScratchDir
EnsureDir $ReceiptsDir
EnsureDir $FreezeDirRoot

$LibPath      = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$ReceiptLib   = Join-Path $ScriptsDir "_lib_recognition_receipts_v1.ps1"
$BuildPath    = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$VerifyPath   = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$SelftestPath = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$ExportPath   = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"
$NegPath      = Join-Path $ScratchDir "RUN_RECOGNITION_PC_NEGATIVE_VECTORS_V3.ps1"

foreach($p in @($LibPath,$ReceiptLib,$BuildPath,$VerifyPath,$SelftestPath,$ExportPath,$NegPath)){
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$PayloadDir = Join-Path $RepoRoot "payload\session_export"
$OutDir     = Join-Path $RepoRoot "packets\outbox"
EnsureDir $PayloadDir
EnsureDir $OutDir

# positive selftest
$SelfOut = Join-Path $ScratchDir "recognition_pc_freeze_selftest.stdout.log"
$SelfErr = Join-Path $ScratchDir "recognition_pc_freeze_selftest.stderr.log"
Invoke-ChildCapture -ScriptPath $SelftestPath -Args @("-RepoRoot",$RepoRoot) -StdoutPath $SelfOut -StderrPath $SelfErr

# export
$ExpOut = Join-Path $ScratchDir "recognition_pc_freeze_export.stdout.log"
$ExpErr = Join-Path $ScratchDir "recognition_pc_freeze_export.stderr.log"
Invoke-ChildCapture -ScriptPath $ExportPath -Args @("-RepoRoot",$RepoRoot,"-SessionExportDir",$PayloadDir,"-OutDir",$OutDir,"-PacketName","recognition_session_export") -StdoutPath $ExpOut -StderrPath $ExpErr

$expText = Get-Content -Raw -LiteralPath $ExpOut -Encoding UTF8
$packetDir = Get-LastExistingDirFromText $expText
if([string]::IsNullOrWhiteSpace($packetDir)){ Die "EXPORT_PACKET_DIR_NOT_FOUND_IN_STDOUT" }

# verify exported packet
$VerOut = Join-Path $ScratchDir "recognition_pc_freeze_verify.stdout.log"
$VerErr = Join-Path $ScratchDir "recognition_pc_freeze_verify.stderr.log"
Invoke-ChildCapture -ScriptPath $VerifyPath -Args @("-PacketDir",$packetDir) -StdoutPath $VerOut -StderrPath $VerErr

# negative vectors
$NegOut = Join-Path $ScratchDir "recognition_pc_freeze_negative.stdout.log"
$NegErr = Join-Path $ScratchDir "recognition_pc_freeze_negative.stderr.log"
Invoke-ChildCapture -ScriptPath $NegPath -Args @("-RepoRoot",$RepoRoot) -StdoutPath $NegOut -StderrPath $NegErr

# reconcile receipt-path drift into repo-scoped receipt location
$RepoReceipt  = Join-Path $ReceiptsDir "recognition.packet_constitution.v1.ndjson"
$DriftReceipt = "C:\dev\recognition\proofs\receipts\recognition.packet_constitution.v1.ndjson"

if(Test-Path -LiteralPath $DriftReceipt -PathType Leaf){
  if(-not (Test-Path -LiteralPath $RepoReceipt -PathType Leaf)){
    Copy-Item -LiteralPath $DriftReceipt -Destination $RepoReceipt -Force
  } else {
    $repoHash  = Sha256HexFile $RepoReceipt
    $driftHash = Sha256HexFile $DriftReceipt
    if($repoHash -ne $driftHash){
      $repoBak  = $RepoReceipt  + ".bak_reconcile_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
      $driftBak = $DriftReceipt + ".bak_reconcile_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
      Copy-Item -LiteralPath $RepoReceipt  -Destination $repoBak  -Force
      Copy-Item -LiteralPath $DriftReceipt -Destination $driftBak -Force

      $repoLines  = @()
      $driftLines = @()

      $repoRaw = Get-Content -Raw -LiteralPath $RepoReceipt -Encoding UTF8
      if(-not [string]::IsNullOrWhiteSpace($repoRaw)){
        $repoLines = @($repoRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      }

      $driftRaw = Get-Content -Raw -LiteralPath $DriftReceipt -Encoding UTF8
      if(-not [string]::IsNullOrWhiteSpace($driftRaw)){
        $driftLines = @($driftRaw -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
      }

      $seen = New-Object 'System.Collections.Generic.HashSet[string]'
      $merged = New-Object System.Collections.Generic.List[string]

      foreach($ln in @($repoLines + $driftLines)){
        if($seen.Add([string]$ln)){
          [void]$merged.Add([string]$ln)
        }
      }

      WriteUtf8NoBomLf $RepoReceipt  ((@($merged) -join "`n") + "`n")
      WriteUtf8NoBomLf $DriftReceipt ((@($merged) -join "`n") + "`n")
      Write-Host ("RECEIPT_RECONCILE_OK: " + $RepoReceipt) -ForegroundColor Yellow
    }
  }
}

if(-not (Test-Path -LiteralPath $RepoReceipt -PathType Leaf)){
  Die ("MISSING_REPO_RECEIPT: " + $RepoReceipt)
}

$packetId = Split-Path -Leaf $packetDir
$FreezeDir = Join-Path $FreezeDirRoot ("recognition_pc_freeze_v1_" + $packetId)
if(Test-Path -LiteralPath $FreezeDir){
  Remove-Item -LiteralPath $FreezeDir -Recurse -Force
}
EnsureDir $FreezeDir

# freeze bundle
Copy-Item -LiteralPath $LibPath      -Destination (Join-Path $FreezeDir "_lib_packet_constitution_v1.ps1") -Force
Copy-Item -LiteralPath $ReceiptLib   -Destination (Join-Path $FreezeDir "_lib_recognition_receipts_v1.ps1") -Force
Copy-Item -LiteralPath $BuildPath    -Destination (Join-Path $FreezeDir "pc_build_packet_optionA_v1.ps1") -Force
Copy-Item -LiteralPath $VerifyPath   -Destination (Join-Path $FreezeDir "pc_verify_packet_optionA_v1.ps1") -Force
Copy-Item -LiteralPath $SelftestPath -Destination (Join-Path $FreezeDir "_selftest_packet_constitution_v1.ps1") -Force
Copy-Item -LiteralPath $ExportPath   -Destination (Join-Path $FreezeDir "recognition_export_session_packet_v1.ps1") -Force
Copy-Item -LiteralPath $NegPath      -Destination (Join-Path $FreezeDir "RUN_RECOGNITION_PC_NEGATIVE_VECTORS_V3.ps1") -Force
Copy-Item -LiteralPath $ThisRunnerPath   -Destination (Join-Path $FreezeDir "FULL_GREEN_RUNNER_RECOGNITION_PC_FREEZE_V2.ps1") -Force

$FreezePacketDir = Join-Path $FreezeDir "packet"
Copy-Item -LiteralPath $packetDir -Destination $FreezePacketDir -Recurse -Force

$FreezeTvDir = Join-Path $FreezeDir "test_vectors"
EnsureDir $FreezeTvDir
Copy-Item -LiteralPath (Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_minimal_optionA") -Destination (Join-Path $FreezeTvDir "v1_minimal_optionA") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_negative_vectors") -Destination (Join-Path $FreezeTvDir "v1_negative_vectors") -Recurse -Force

$FreezeLogs = Join-Path $FreezeDir "logs"
EnsureDir $FreezeLogs
foreach($p in @($SelfOut,$SelfErr,$ExpOut,$ExpErr,$VerOut,$VerErr,$NegOut,$NegErr)){
  Copy-Item -LiteralPath $p -Destination (Join-Path $FreezeLogs (Split-Path -Leaf $p)) -Force
}

Copy-Item -LiteralPath $RepoReceipt -Destination (Join-Path $FreezeDir "recognition.packet_constitution.v1.ndjson") -Force

$Summary = @(
  '{'
  '  "freeze_schema": "recognition.packet_constitution.freeze.v1",'
  ('  "repo_root": "' + ($RepoRoot.Replace('\','\\')) + '",')
  ('  "packet_id": "' + $packetId + '",')
  ('  "packet_dir": "' + ($packetDir.Replace('\','\\')) + '",')
  ('  "repo_receipt": "' + ($RepoReceipt.Replace('\','\\')) + '",')
  '  "positive_runner": "FULL_GREEN_RUNNER_RECOGNITION_PC_FREEZE_V2",'
  '  "negative_runner": "RUN_RECOGNITION_PC_NEGATIVE_VECTORS_V3",'
  '  "status": "GREEN"'
  '}'
)
WriteUtf8NoBomLf (Join-Path $FreezeDir "freeze_summary.json") ((@($Summary) -join "`n") + "`n")

$FreezeSha = Join-Path $FreezeDir "sha256sums.txt"
Write-Sha256Sums -RootDir $FreezeDir -OutPath $FreezeSha

Write-Host ("FULL_GREEN_RUNNER_RECOGNITION_PC_FREEZE_V2_OK: " + $packetDir) -ForegroundColor Green
Write-Host ("FREEZE_BUNDLE_OK: " + $FreezeDir) -ForegroundColor Green
