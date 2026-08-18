param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function Run-ChildCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$false)][string[]]$Args = @()
  )

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("CHILD_MISSING_SCRIPT: " + $ScriptPath) }

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

  if($stdout){ [Console]::Out.Write($stdout) }
  if($stderr){ [Console]::Error.Write($stderr) }

  if([int]$p.ExitCode -ne 0){
    Die ("CHILD_FAIL(" + [int]$p.ExitCode + "): " + $ScriptPath)
  }

  return $stdout
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$SessionOpenPath   = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpenPath       = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$NavPath           = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"
$RuntimeExportPath = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"
$ReplayPath        = Join-Path $RepoRoot "scripts\recognition_runtime_replay_from_events_v1.ps1"
$ExportPath        = Join-Path $RepoRoot "scripts\recognition_export_session_packet_v1.ps1"
$VerifyPath        = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"

foreach($p in @($SessionOpenPath,$TabOpenPath,$NavPath,$RuntimeExportPath,$ReplayPath,$ExportPath,$VerifyPath)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("MISSING_SCRIPT: " + $p) }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $p,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$RuntimeRoot = Join-Path $RepoRoot "runtime"
$PayloadDir  = Join-Path $RepoRoot "payload\session_export"
$OutDir      = Join-Path $RepoRoot "packets\outbox"
$ReplayOut   = Join-Path $RepoRoot "runtime\replay\session_replay.json"

if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}
if(Test-Path -LiteralPath $PayloadDir -PathType Container){
  Remove-Item -LiteralPath $PayloadDir -Recurse -Force
}

Run-ChildCapture -ScriptPath $SessionOpenPath -Args @("-RepoRoot",$RepoRoot,"-SessionId","recognition-runtime-full-green-v1","-StartedUtc","2026-03-31T13:00:00.000Z","-Mode","standard") | Out-Null
Run-ChildCapture -ScriptPath $TabOpenPath -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-001","-Index","0","-Url","https://example.com/","-Title","Example Domain","-OpenedUtc","2026-03-31T13:00:05.000Z","-IsActive","1") | Out-Null
Run-ChildCapture -ScriptPath $NavPath -Args @("-RepoRoot",$RepoRoot,"-TabId","tab-001","-Url","https://example.com/docs","-Title","Example Docs","-CommittedUtc","2026-03-31T13:00:10.000Z") | Out-Null
Run-ChildCapture -ScriptPath $RuntimeExportPath -Args @("-RepoRoot",$RepoRoot,"-SessionExportDir",$PayloadDir) | Out-Null
Run-ChildCapture -ScriptPath $ReplayPath -Args @("-RepoRoot",$RepoRoot,"-OutPath",$ReplayOut) | Out-Null

foreach($p in @(
  (Join-Path $PayloadDir "session.json"),
  (Join-Path $PayloadDir "tabs.json"),
  (Join-Path $PayloadDir "events.ndjson"),
  (Join-Path $PayloadDir "policy_state.json"),
  (Join-Path $PayloadDir "trust_context.json"),
  (Join-Path $PayloadDir "vpn_state.json"),
  (Join-Path $PayloadDir "export_manifest.json"),
  $ReplayOut
)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("MISSING_OUTPUT: " + $p)
  }
  Write-Host ("OUTPUT_OK: " + $p) -ForegroundColor Green
}

$exportStdout = Run-ChildCapture -ScriptPath $ExportPath -Args @("-RepoRoot",$RepoRoot,"-SessionExportDir",$PayloadDir,"-OutDir",$OutDir,"-PacketName","recognition_runtime_full_green")
$packetDirs = @(@(Get-ChildItem -LiteralPath $OutDir -Directory -Force | Sort-Object LastWriteTimeUtc))
if($packetDirs.Count -lt 1){ Die ("PACKET_OUTBOX_EMPTY: " + $OutDir) }
$packetDir = $packetDirs[-1].FullName

Run-ChildCapture -ScriptPath $VerifyPath -Args @("-PacketDir",$packetDir) | Out-Null

Write-Host ("FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1_OK: " + $packetDir) -ForegroundColor Green
