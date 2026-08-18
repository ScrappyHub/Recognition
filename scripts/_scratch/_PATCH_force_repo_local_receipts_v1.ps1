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
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$Candidates = @(
  (Join-Path $RepoRoot "scripts\_lib_recognition_receipts_v1.ps1"),
  (Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"),
  (Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"),
  (Join-Path $RepoRoot "scripts\recognition_export_session_packet_v1.ps1")
)

$changed = 0

foreach($Target in @($Candidates)){
  if(-not (Test-Path -LiteralPath $Target -PathType Leaf)){ continue }

  $raw = Get-Content -Raw -LiteralPath $Target -Encoding UTF8
  $new = $raw

  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) "proofs\receipts"', 'Join-Path $RepoRoot "proofs\receipts"')
  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) ''proofs\receipts''', 'Join-Path $RepoRoot ''proofs\receipts''')
  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) "proofs/receipts"', 'Join-Path $RepoRoot "proofs\receipts"')
  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) ''proofs/receipts''', 'Join-Path $RepoRoot ''proofs\receipts''')

  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) "proofs"', 'Join-Path $RepoRoot "proofs"')
  $new = $new.Replace('Join-Path (Split-Path -Parent $RepoRoot) ''proofs''', 'Join-Path $RepoRoot ''proofs''')

  $new = $new.Replace('C:\dev\proofs\receipts', 'C:\dev\recognition\proofs\receipts')
  $new = $new.Replace('C:/dev/proofs/receipts', 'C:/dev/recognition/proofs/receipts')

  if($new -ne $raw){
    $bak = $Target + ".bak_receiptpath_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
    Copy-Item -LiteralPath $Target -Destination $bak -Force
    WriteUtf8NoBomLf $Target $new
    ParseGateFile $Target
    Write-Host ("PATCHED_RECEIPT_PATH: " + $Target) -ForegroundColor Green
    Write-Host ("BACKUP: " + $bak) -ForegroundColor DarkGray
    $changed++
  } else {
    ParseGateFile $Target
    Write-Host ("NO_CHANGE_PARSE_OK: " + $Target) -ForegroundColor DarkGray
  }
}

if($changed -lt 1){
  Write-Host "NO_DIRECT_RECEIPT_PATH_PATCHES_APPLIED" -ForegroundColor Yellow
}

$Runner = Join-Path $RepoRoot "scripts\_scratch\FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1.ps1"
if(-not (Test-Path -LiteralPath $Runner -PathType Leaf)){ Die ("MISSING_RUNNER: " + $Runner) }
ParseGateFile $Runner

$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$out = & $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Runner -RepoRoot $RepoRoot 2>&1
$out | Out-Host

$text = ($out | Out-String)
if($text -match 'C:\\dev\\proofs\\receipts'){
  Die "RECEIPT_PATH_DRIFT_STILL_PRESENT"
}
if($text -notmatch 'FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1_OK'){
  Die "FULL_GREEN_TOKEN_MISSING"
}

Write-Host "RECEIPT_PATH_REPO_LOCAL_GREEN" -ForegroundColor Green
