param([Parameter(Mandatory=$true)][string]$RepoRoot)

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

function Invoke-ChildCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$false)][string[]]$Args,
    [Parameter(Mandatory=$true)][string]$StdoutPath,
    [Parameter(Mandatory=$true)][string]$StderrPath
  )

  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("MISSING_CHILD_SCRIPT: " + $ScriptPath) }

  $argList = New-Object System.Collections.Generic.List[string]
  [void]$argList.Add("-NoProfile")
  [void]$argList.Add("-NonInteractive")
  [void]$argList.Add("-ExecutionPolicy")
  [void]$argList.Add("Bypass")
  [void]$argList.Add("-File")
  [void]$argList.Add($ScriptPath)

  if($Args){
    foreach($a in $Args){
      [void]$argList.Add([string]$a)
    }
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $psExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true

  $quoted = @()
  foreach($s in $argList){
    $v = [string]$s
    if($v -match '[\s"]'){
      $quoted += ('"' + $v.Replace('"','\"') + '"')
    } else {
      $quoted += $v
    }
  }
  $psi.Arguments = ($quoted -join " ")

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

  if([int]$p.ExitCode -ne 0){
    Die ("CHILD_FAIL(" + [int]$p.ExitCode + "): " + $ScriptPath)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
$ProofRoot  = Join-Path $RepoRoot "proofs\freeze\recognition_pc"
$RunId      = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$RunDir     = Join-Path $ProofRoot $RunId

EnsureDir $ScriptsDir
EnsureDir $RunDir

$LibPath     = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$RcptLibPath = Join-Path $ScriptsDir "_lib_recognition_receipts_v1.ps1"
$BuildPath   = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$VerifyPath  = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$SelfPath    = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$ExportPath  = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"

foreach($p in @($LibPath,$RcptLibPath,$BuildPath,$VerifyPath,$SelfPath,$ExportPath)){
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$SelfOut = Join-Path $RunDir "selftest.stdout.log"
$SelfErr = Join-Path $RunDir "selftest.stderr.log"
Invoke-ChildCapture -ScriptPath $SelfPath -Args @("-RepoRoot",$RepoRoot) -StdoutPath $SelfOut -StderrPath $SelfErr

$PayloadDir = Join-Path $RepoRoot "payload\session_export"
$OutDir     = Join-Path $RepoRoot "packets\outbox"

$ExpOut = Join-Path $RunDir "export.stdout.log"
$ExpErr = Join-Path $RunDir "export.stderr.log"
Invoke-ChildCapture -ScriptPath $ExportPath -Args @("-RepoRoot",$RepoRoot,"-SessionExportDir",$PayloadDir,"-OutDir",$OutDir,"-PacketName","recognition_session_export") -StdoutPath $ExpOut -StderrPath $ExpErr

$packetDir = $null
$expStdout = Get-Content -Raw -LiteralPath $ExpOut -Encoding UTF8
$matches = [regex]::Matches($expStdout,'[0-9a-f]{64}')
if($matches.Count -gt 0){
  $packetId = $matches[$matches.Count - 1].Value
  $packetDir = Join-Path $OutDir $packetId
}
if([string]::IsNullOrWhiteSpace($packetDir) -or -not (Test-Path -LiteralPath $packetDir -PathType Container)){
  Die ("FREEZE_PACKET_DIR_NOT_FOUND: " + $ExpOut)
}

$VerOut = Join-Path $RunDir "verify.stdout.log"
$VerErr = Join-Path $RunDir "verify.stderr.log"
Invoke-ChildCapture -ScriptPath $VerifyPath -Args @("-PacketDir",$packetDir) -StdoutPath $VerOut -StderrPath $VerErr

$SummaryPath = Join-Path $RunDir "summary.txt"
$summary = @(
  ("repo_root=" + $RepoRoot),
  ("run_dir=" + $RunDir),
  ("packet_dir=" + $packetDir),
  ("selftest_stdout=" + $SelfOut),
  ("selftest_stderr=" + $SelfErr),
  ("export_stdout=" + $ExpOut),
  ("export_stderr=" + $ExpErr),
  ("verify_stdout=" + $VerOut),
  ("verify_stderr=" + $VerErr)
) -join "`n"
WriteUtf8NoBomLf $SummaryPath $summary

Write-Host ("FULL_GREEN_RUNNER_RECOGNITION_PC_FREEZE_V1_OK: " + $packetDir) -ForegroundColor Green
