param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ProfileId,
  [Parameter(Mandatory=$true)][string]$Passphrase,
  [Parameter(Mandatory=$false)][string]$Mode = "clean-browser"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function QuoteArg([string]$s){
  if($null -eq $s){ return '""' }
  if($s.Length -eq 0){ return '""' }
  return '"' + $s.Replace('"','\"') + '"'
}

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

function RunCapture {
  param(
    [Parameter(Mandatory=$true)][string]$Label,
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string[]]$Args,
    [Parameter(Mandatory=$true)][string]$ExpectedToken,
    [Parameter(Mandatory=$true)][string]$RunDir
  )

  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){
    Die ("STARTUP_SCRIPT_MISSING: " + $ScriptPath)
  }

  EnsureDir $RunDir

  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $stdout = Join-Path $RunDir ($Label + ".stdout.txt")
  $stderr = Join-Path $RunDir ($Label + ".stderr.txt")

  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $argv = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy","Bypass",
    "-File",$ScriptPath
  ) + @($Args)

  $argLine = (@($argv) | ForEach-Object { QuoteArg ([string]$_) }) -join " "

  $p = Start-Process `
    -FilePath $PSExe `
    -ArgumentList $argLine `
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
    Die ("STARTUP_CAPTURE_FAIL[" + $Label + "]: " + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("STARTUP_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }

  Write-Host ("STARTUP_CAPTURE_OK: " + $Label) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$ProfileScript = Join-Path $RepoRoot "scripts\recognition_encrypted_profile_v1.ps1"
$SealVerify = Join-Path $RepoRoot "scripts\_scratch\RUN_RECOGNITION_RUNTIME_BRIDGE_SEAL_VERIFY_V1.ps1"

$RunId = "recognition_locked_startup_v1_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$RunDir = Join-Path $RepoRoot ("proofs\runs\" + $RunId)
EnsureDir $RunDir

RunCapture `
  -Label "encrypted_profile_verify" `
  -ScriptPath $ProfileScript `
  -Args @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","verify","-Passphrase",$Passphrase) `
  -ExpectedToken "ENCRYPTED_PROFILE_VERIFY_OK" `
  -RunDir $RunDir

RunCapture `
  -Label "sealed_stack_verify" `
  -ScriptPath $SealVerify `
  -Args @("-RepoRoot",$RepoRoot) `
  -ExpectedToken "RECOGNITION_RUNTIME_FULL_SEALED_WORKBENCH_V1_OK" `
  -RunDir $RunDir

$startup = [ordered]@{
  schema = "recognition.locked_startup.v1"
  status = "GREEN"
  profile_id = $ProfileId
  mode = $Mode
  encrypted_profile = "verified"
  sealed_stack = "verified"
  run_dir = $RunDir
  ts_utc = (Get-Date).ToUniversalTime().ToString("o")
  tokens = @(
    "ENCRYPTED_PROFILE_VERIFY_OK",
    "RECOGNITION_RUNTIME_FULL_SEALED_WORKBENCH_V1_OK",
    "RECOGNITION_LOCKED_STARTUP_V1_OK"
  )
}

WriteUtf8NoBomLf (Join-Path $RunDir "startup_receipt.json") ($startup | ConvertTo-Json -Depth 20)

Write-Host ("RECOGNITION_LOCKED_STARTUP_RUN_OK: " + $RunDir) -ForegroundColor Green
Write-Host "RECOGNITION_LOCKED_STARTUP_V1_OK" -ForegroundColor Green
