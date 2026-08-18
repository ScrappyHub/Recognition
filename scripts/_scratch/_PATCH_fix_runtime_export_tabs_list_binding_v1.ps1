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

function Write-Utf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function Parse-GateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Target   = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"
if(-not (Test-Path -LiteralPath $Target -PathType Leaf)){ Die ("MISSING_TARGET: " + $Target) }

$raw = Get-Content -Raw -LiteralPath $Target -Encoding UTF8
$new = $raw

$old1 = '  tabs   = @($tabs)'
$new1 = '  tabs   = @($tabs.ToArray())'
if($new.Contains($old1)){
  $new = $new.Replace($old1,$new1)
}

if($new -eq $raw){
  Die "PATCH_FAIL: tabs list binding target not found"
}

Write-Utf8NoBomLf $Target $new
Parse-GateFile $Target
Write-Host ("PATCH_OK: " + $Target) -ForegroundColor Green

$PSExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
$PayloadDir = Join-Path $RepoRoot "payload\session_export"

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File $Target `
  -RepoRoot $RepoRoot `
  -SessionExportDir $PayloadDir | Out-Host

foreach($p in @(
  (Join-Path $PayloadDir "session.json"),
  (Join-Path $PayloadDir "tabs.json"),
  (Join-Path $PayloadDir "events.ndjson"),
  (Join-Path $PayloadDir "policy_state.json"),
  (Join-Path $PayloadDir "trust_context.json"),
  (Join-Path $PayloadDir "vpn_state.json"),
  (Join-Path $PayloadDir "export_manifest.json")
)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    Die ("EXPORT_MISSING_FILE: " + $p)
  }
  Write-Host ("EXPORT_FILE_OK: " + $p) -ForegroundColor Green
}

$ExportPath = Join-Path $RepoRoot "scripts\recognition_export_session_packet_v1.ps1"
$VerifyPath = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"
$OutDir     = Join-Path $RepoRoot "packets\outbox"

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File $ExportPath `
  -RepoRoot $RepoRoot `
  -SessionExportDir $PayloadDir `
  -OutDir $OutDir `
  -PacketName "recognition_runtime_export" | Out-Host

$dirs = @(@(Get-ChildItem -LiteralPath $OutDir -Directory -Force | Sort-Object LastWriteTimeUtc))
if($dirs.Count -lt 1){ Die ("PACKET_OUTBOX_EMPTY: " + $OutDir) }
$last = $dirs[-1].FullName

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File $VerifyPath `
  -PacketDir $last | Out-Host

Write-Host ("RUNTIME_EXPORT_PACKET_VERIFY_GREEN: " + $last) -ForegroundColor Green
