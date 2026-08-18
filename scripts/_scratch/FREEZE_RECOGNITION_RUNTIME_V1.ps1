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
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){
    Die ("PARSE_GATE_MISSING: " + $Path)
  }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("SHA256_MISSING_FILE: " + $Path) }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hash = $sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}", $b) }
  $sb.ToString()
}

function RelPath([string]$Base,[string]$Full){
  $b = (Resolve-Path -LiteralPath $Base).Path.TrimEnd([char]92,[char]47)
  $f = (Resolve-Path -LiteralPath $Full).Path
  if($f.Substring(0,$b.Length) -ne $b){ Die ("REL_OUTSIDE_BASE: " + $Full) }
  $rel = $f.Substring($b.Length).TrimStart([char]92,[char]47)
  $rel.Replace([char]92,[char]47)
}

function RunCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string[]]$Args,
    [Parameter(Mandatory=$true)][string]$StdoutPath,
    [Parameter(Mandatory=$true)][string]$StderrPath
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("CAPTURE_MISSING_SCRIPT: " + $ScriptPath) }

  $argList = New-Object System.Collections.Generic.List[string]
  [void]$argList.Add("-NoProfile")
  [void]$argList.Add("-NonInteractive")
  [void]$argList.Add("-ExecutionPolicy")
  [void]$argList.Add("Bypass")
  [void]$argList.Add("-File")
  [void]$argList.Add($ScriptPath)
  foreach($a in @($Args)){ [void]$argList.Add([string]$a) }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $PSExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $psi.Arguments = (@($argList) | ForEach-Object {
    $s = [string]$_
    if($s -match '[\s"]'){ '"' + $s.Replace('"','\"') + '"' } else { $s }
  }) -join " "

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
    Die ("CAPTURE_CHILD_FAIL(" + [int]$p.ExitCode + "): " + $ScriptPath)
  }

  return $stdout
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$FullGreen = Join-Path $RepoRoot "scripts\_scratch\FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1.ps1"
$NegRunner = Join-Path $RepoRoot "scripts\_scratch\RUN_RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1.ps1"

foreach($p in @($FullGreen,$NegRunner)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("MISSING_RUNNER: " + $p) }
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$FreezeRoot = Join-Path $RepoRoot "proofs\freeze"
EnsureDir $FreezeRoot

$RunId = "recognition_runtime_v1_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$Bundle = Join-Path $FreezeRoot $RunId
if(Test-Path -LiteralPath $Bundle -PathType Container){
  Remove-Item -LiteralPath $Bundle -Recurse -Force
}
EnsureDir $Bundle
EnsureDir (Join-Path $Bundle "transcripts")
EnsureDir (Join-Path $Bundle "receipts")
EnsureDir (Join-Path $Bundle "artifacts")
EnsureDir (Join-Path $Bundle "scripts")

$FullOut = Join-Path $Bundle "transcripts\full_green.stdout.txt"
$FullErr = Join-Path $Bundle "transcripts\full_green.stderr.txt"
$NegOut  = Join-Path $Bundle "transcripts\replay_negative.stdout.txt"
$NegErr  = Join-Path $Bundle "transcripts\replay_negative.stderr.txt"

$fullText = RunCapture -ScriptPath $FullGreen -Args @("-RepoRoot",$RepoRoot) -StdoutPath $FullOut -StderrPath $FullErr
if($fullText -notmatch "FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1_OK"){
  Die "FREEZE_FULL_GREEN_TOKEN_MISSING"
}

$negText = RunCapture -ScriptPath $NegRunner -Args @("-RepoRoot",$RepoRoot) -StdoutPath $NegOut -StderrPath $NegErr
if($negText -notmatch "RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1_OK"){
  Die "FREEZE_NEGATIVE_TOKEN_MISSING"
}

$RuntimeReceipt = Join-Path $RepoRoot "proofs\receipts\recognition.runtime.v1.ndjson"
$PacketReceipt  = Join-Path $RepoRoot "proofs\receipts\recognition.packet_constitution.v1.ndjson"

foreach($r in @($RuntimeReceipt,$PacketReceipt)){
  if(Test-Path -LiteralPath $r -PathType Leaf){
    Copy-Item -LiteralPath $r -Destination (Join-Path (Join-Path $Bundle "receipts") (Split-Path -Leaf $r)) -Force
  }
}

$PayloadDir = Join-Path $RepoRoot "payload\session_export"
$ReplayOut  = Join-Path $RepoRoot "runtime\replay\session_replay.json"

foreach($a in @(
  (Join-Path $PayloadDir "session.json"),
  (Join-Path $PayloadDir "tabs.json"),
  (Join-Path $PayloadDir "events.ndjson"),
  (Join-Path $PayloadDir "policy_state.json"),
  (Join-Path $PayloadDir "trust_context.json"),
  (Join-Path $PayloadDir "vpn_state.json"),
  (Join-Path $PayloadDir "export_manifest.json"),
  $ReplayOut
)){
  if(Test-Path -LiteralPath $a -PathType Leaf){
    Copy-Item -LiteralPath $a -Destination (Join-Path (Join-Path $Bundle "artifacts") (Split-Path -Leaf $a)) -Force
  } else {
    Die ("FREEZE_MISSING_ARTIFACT: " + $a)
  }
}

foreach($s in @(
  "recognition_runtime_session_open_v1.ps1",
  "recognition_runtime_tab_open_v1.ps1",
  "recognition_runtime_navigation_commit_v1.ps1",
  "recognition_runtime_export_from_runtime_v1.ps1",
  "recognition_runtime_replay_from_events_v1.ps1",
  "_lib_recognition_runtime_receipts_v1.ps1",
  "recognition_export_session_packet_v1.ps1",
  "pc_verify_packet_optionA_v1.ps1"
)){
  $src = Join-Path (Join-Path $RepoRoot "scripts") $s
  if(Test-Path -LiteralPath $src -PathType Leaf){
    Copy-Item -LiteralPath $src -Destination (Join-Path (Join-Path $Bundle "scripts") $s) -Force
  } else {
    Die ("FREEZE_MISSING_SCRIPT: " + $src)
  }
}

$SummaryPath = Join-Path $Bundle "FREEZE_SUMMARY.txt"
$summary = @(
  "schema=recognition.runtime.freeze.v1",
  ("repo_root=" + $RepoRoot),
  ("bundle=" + $Bundle),
  "full_green_token=FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1_OK",
  "negative_token=RECOGNITION_RUNTIME_REPLAY_NEGATIVE_V1_OK",
  "runtime_receipts=proofs/receipts/recognition.runtime.v1.ndjson",
  "packet_receipts=proofs/receipts/recognition.packet_constitution.v1.ndjson"
) -join "`n"
WriteUtf8NoBomLf $SummaryPath $summary

$ShaPath = Join-Path $Bundle "sha256sums.txt"
if(Test-Path -LiteralPath $ShaPath -PathType Leaf){
  Remove-Item -LiteralPath $ShaPath -Force
}

$files = @(Get-ChildItem -LiteralPath $Bundle -Recurse -File -Force | Where-Object { $_.FullName -ne $ShaPath } | Sort-Object FullName)
$lines = New-Object System.Collections.Generic.List[string]
foreach($f in @($files)){
  $rel = RelPath $Bundle $f.FullName
  $h = Sha256HexFile $f.FullName
  [void]$lines.Add(("{0}  {1}" -f $h,$rel))
}
WriteUtf8NoBomLf $ShaPath ((@($lines) -join "`n") + "`n")

Write-Host ("FREEZE_BUNDLE_OK: " + $Bundle) -ForegroundColor Green
Write-Host "FREEZE_RECOGNITION_RUNTIME_V1_OK" -ForegroundColor Green
