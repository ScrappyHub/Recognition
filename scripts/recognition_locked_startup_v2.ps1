# Recognition Locked Startup v2
# Differences from v1:
#   - Passphrase via RECOGNITION_PASSPHRASE env var, never on argv (fixes audit F3).
#   - Uses encrypted profile v2 (AES-256-GCM key hierarchy, fixes F2).
#   - Seal verify promoted out of scripts\_scratch (fixes F7).
# Requires pwsh 7.2+. The sealed v1 stack still runs under Windows PowerShell 5.1.
# Green token: RECOGNITION_LOCKED_STARTUP_V2_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ProfileId,
  [Parameter(Mandatory=$false)][string]$Mode = "clean-browser",
  [Parameter(Mandatory=$false)][switch]$SkipSealVerify
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_crypto_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$null = RC2-GetPassphrase   # fail fast if env passphrase missing

$RunId = "recognition_locked_startup_v2_" + (Get-Date).ToUniversalTime().ToString("yyyyMMdd_HHmmssZ")
$RunDir = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "runs") $RunId
RC2-EnsureDir $RunDir

function RunChild([string]$Label,[string]$Exe,[string[]]$ChildArgs,[string]$ExpectedToken){
  $stdout = Join-Path $RunDir ($Label + ".stdout.txt")
  $stderr = Join-Path $RunDir ($Label + ".stderr.txt")

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  foreach($a in $ChildArgs){ [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  # Environment (incl. RECOGNITION_PASSPHRASE) is inherited by the child; nothing on argv.

  $p = [System.Diagnostics.Process]::Start($psi)
  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  # Never persist GET value lines into run logs.
  $safeOut = ($out -split "`n" | Where-Object { $_ -notmatch 'GET_VALUE_B64' }) -join "`n"
  [System.IO.File]::WriteAllText($stdout,$safeOut,(New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText($stderr,$err,(New-Object System.Text.UTF8Encoding($false)))

  if($out){ [Console]::Out.Write($safeOut) }
  if($err){ [Console]::Error.Write($err) }

  if($p.ExitCode -ne 0){ RC2-Die ("STARTUP_CHILD_FAIL[" + $Label + "]: exit=" + [string]$p.ExitCode) }
  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    RC2-Die ("STARTUP_TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken)
  }
  Write-Host ("STARTUP_CAPTURE_OK: " + $Label) -ForegroundColor Green
}

$PwshExe = [System.Environment]::ProcessPath
$ProfileScript = Join-Path (Join-Path $RepoRoot "scripts") "recognition_encrypted_profile_v2.ps1"

RunChild "encrypted_profile_v2_verify" $PwshExe @(
  "-NoProfile","-NonInteractive","-File",$ProfileScript,
  "-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","verify"
) "ENCRYPTED_PROFILE_V2_VERIFY_OK"

$sealVerified = $false
if(-not $SkipSealVerify){
  $SealVerify = Join-Path (Join-Path $RepoRoot "scripts") "recognition_seal_verify_v1.ps1"
  $Ps51 = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  RunChild "sealed_stack_verify" $Ps51 @(
    "-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",$SealVerify,
    "-RepoRoot",$RepoRoot
  ) "RECOGNITION_RUNTIME_FULL_SEALED_WORKBENCH_V1_OK"
  $sealVerified = $true
}

$tokens = New-Object System.Collections.Generic.List[string]
[void]$tokens.Add("ENCRYPTED_PROFILE_V2_VERIFY_OK")
if($sealVerified){ [void]$tokens.Add("RECOGNITION_RUNTIME_FULL_SEALED_WORKBENCH_V1_OK") }
[void]$tokens.Add("RECOGNITION_LOCKED_STARTUP_V2_OK")

$sealState = "skipped"
if($sealVerified){ $sealState = "verified" }

$startup = [ordered]@{
  schema = "recognition.locked_startup.v2"
  status = "GREEN"
  profile_id = $ProfileId
  mode = $Mode
  encrypted_profile = "verified"
  sealed_stack = $sealState
  passphrase_source = "env"
  run_dir = $RunDir
  ts_utc = RC2-NowUtc
  tokens = @($tokens.ToArray())
}

RC2-WriteUtf8NoBomLf (Join-Path $RunDir "startup_receipt.json") ($startup | ConvertTo-Json -Depth 20)
RC2-AppendUtf8NoBomLfLine (Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.locked_startup.v2.ndjson") (($startup | ConvertTo-Json -Depth 20 -Compress))

Write-Host ("RECOGNITION_LOCKED_STARTUP_RUN_OK: " + $RunDir) -ForegroundColor Green
Write-Host "RECOGNITION_LOCKED_STARTUP_V2_OK" -ForegroundColor Green
