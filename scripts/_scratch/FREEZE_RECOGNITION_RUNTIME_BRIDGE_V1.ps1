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
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tokens=$null
  $errors=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e=@($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

function Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("SHA256_MISSING_FILE: " + $Path) }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try{
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hash = $sha.ComputeHash($bytes)
  } finally {
    $sha.Dispose()
  }
  $sb = New-Object System.Text.StringBuilder
  foreach($b in $hash){ [void]$sb.AppendFormat("{0:x2}", $b) }
  return $sb.ToString()
}

function RelPath([string]$Base,[string]$Full){
  $b = (Resolve-Path -LiteralPath $Base).Path.TrimEnd([char]92,[char]47)
  $f = (Resolve-Path -LiteralPath $Full).Path
  if($f.Substring(0,$b.Length) -ne $b){ Die ("REL_OUTSIDE_BASE: " + $Full) }
  return $f.Substring($b.Length).TrimStart([char]92,[char]47).Replace([char]92,[char]47)
}

function RunCapture {
  param(
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$ExpectedToken,
    [Parameter(Mandatory=$true)][string]$OutDir
  )

  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("CAPTURE_MISSING_SCRIPT: " + $ScriptPath) }

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
    Die ("CAPTURE_FAIL[" + $Label + "] exit=" + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("CAPTURE_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ("CAPTURE_OK: " + $Label) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$BridgeHarness = Join-Path $RepoRoot "scripts\_scratch\RUN_bridge_failhard_validate_v1.ps1"
$RuntimeFreeze  = Join-Path $RepoRoot "scripts\_scratch\FREEZE_RECOGNITION_RUNTIME_V1.ps1"

foreach($p in @($BridgeHarness,$RuntimeFreeze)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("FREEZE_REQUIRED_RUNNER_MISSING: " + $p)
  }
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$FreezeRoot = Join-Path $RepoRoot "proofs\freeze"
EnsureDir $FreezeRoot

$RunId  = "recognition_runtime_bridge_v1_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$Bundle = Join-Path $FreezeRoot $RunId

if(Test-Path -LiteralPath $Bundle -PathType Container){
  Remove-Item -LiteralPath $Bundle -Recurse -Force
}

EnsureDir $Bundle
EnsureDir (Join-Path $Bundle "transcripts")
EnsureDir (Join-Path $Bundle "receipts")
EnsureDir (Join-Path $Bundle "scripts")
EnsureDir (Join-Path $Bundle "artifacts")

$Transcripts = Join-Path $Bundle "transcripts"

RunCapture `
  -Label "bridge_failhard" `
  -ScriptPath $BridgeHarness `
  -ExpectedToken "RECOGNITION_RUNTIME_BRIDGE_FAILHARD_GREEN" `
  -OutDir $Transcripts

RunCapture `
  -Label "runtime_freeze" `
  -ScriptPath $RuntimeFreeze `
  -ExpectedToken "FREEZE_RECOGNITION_RUNTIME_V1_OK" `
  -OutDir $Transcripts

$receiptNames = @(
  "recognition.runtime.v1.ndjson",
  "recognition.runtime.bridge.v1.ndjson",
  "recognition.packet_constitution.v1.ndjson"
)

foreach($name in $receiptNames){
  $src = Join-Path (Join-Path $RepoRoot "proofs\receipts") $name
  if(Test-Path -LiteralPath $src -PathType Leaf){
    Copy-Item -LiteralPath $src -Destination (Join-Path (Join-Path $Bundle "receipts") $name) -Force
  } else {
    Die ("FREEZE_RECEIPT_MISSING: " + $src)
  }
}

$scriptNames = @(
  "recognition_runtime_bridge_event_v1.ps1",
  "recognition_runtime_session_open_v1.ps1",
  "recognition_runtime_tab_open_v1.ps1",
  "recognition_runtime_navigation_commit_v1.ps1",
  "recognition_runtime_export_from_runtime_v1.ps1",
  "recognition_runtime_replay_from_events_v1.ps1",
  "_selftest_recognition_runtime_bridge_v1.ps1",
  "_lib_recognition_runtime_receipts_v1.ps1",
  "recognition_export_session_packet_v1.ps1",
  "pc_verify_packet_optionA_v1.ps1"
)

foreach($name in $scriptNames){
  $src = Join-Path (Join-Path $RepoRoot "scripts") $name
  if(Test-Path -LiteralPath $src -PathType Leaf){
    Copy-Item -LiteralPath $src -Destination (Join-Path (Join-Path $Bundle "scripts") $name) -Force
  } else {
    Die ("FREEZE_SCRIPT_MISSING: " + $src)
  }
}

$artifactPaths = @(
  (Join-Path $RepoRoot "runtime\replay\bridge_replay.json"),
  (Join-Path $RepoRoot "runtime\replay\session_replay.json"),
  (Join-Path $RepoRoot "payload\session_export\session.json"),
  (Join-Path $RepoRoot "payload\session_export\tabs.json"),
  (Join-Path $RepoRoot "payload\session_export\events.ndjson"),
  (Join-Path $RepoRoot "payload\session_export\policy_state.json"),
  (Join-Path $RepoRoot "payload\session_export\trust_context.json"),
  (Join-Path $RepoRoot "payload\session_export\vpn_state.json"),
  (Join-Path $RepoRoot "payload\session_export\export_manifest.json")
)

foreach($src in $artifactPaths){
  if(Test-Path -LiteralPath $src -PathType Leaf){
    Copy-Item -LiteralPath $src -Destination (Join-Path (Join-Path $Bundle "artifacts") (Split-Path -Leaf $src)) -Force
  }
}

$summary = @(
  "schema=recognition.runtime.bridge.freeze.v1",
  ("repo_root=" + $RepoRoot),
  ("bundle=" + $Bundle),
  "runtime_token=FREEZE_RECOGNITION_RUNTIME_V1_OK",
  "bridge_token=RECOGNITION_RUNTIME_BRIDGE_FAILHARD_GREEN",
  "bridge_positive=SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK",
  "bridge_negative=RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1_OK"
) -join "`n"

WriteUtf8NoBomLf (Join-Path $Bundle "FREEZE_SUMMARY.txt") $summary

$shaPath = Join-Path $Bundle "sha256sums.txt"
if(Test-Path -LiteralPath $shaPath -PathType Leaf){
  Remove-Item -LiteralPath $shaPath -Force
}

$files = @(Get-ChildItem -LiteralPath $Bundle -Recurse -File -Force | Where-Object { $_.FullName -ne $shaPath } | Sort-Object FullName)
$lines = New-Object System.Collections.Generic.List[string]

foreach($f in @($files)){
  [void]$lines.Add(("{0}  {1}" -f (Sha256HexFile $f.FullName),(RelPath $Bundle $f.FullName)))
}

WriteUtf8NoBomLf $shaPath ((@($lines) -join "`n") + "`n")

Write-Host ("FREEZE_BUNDLE_OK: " + $Bundle) -ForegroundColor Green
Write-Host "FREEZE_RECOGNITION_RUNTIME_BRIDGE_V1_OK" -ForegroundColor Green
