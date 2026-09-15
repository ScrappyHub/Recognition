param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function QuoteArg([string]$s){
  if($null -eq $s){ return '""' }
  if($s.Length -eq 0){ return '""' }
  return '"' + $s.Replace('"','\"') + '"'
}

function RunChecked([string]$Script,[string[]]$ChildArgs,[string]$ExpectedToken){
  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $RunDir = Join-Path $RepoRoot "proofs\runs\locked_startup_selftest_v1"

  if(-not (Test-Path -LiteralPath $RunDir -PathType Container)){
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
  }

  $safe = $ExpectedToken.Replace(":","_").Replace("\","_").Replace("/","_")
  $stdout = Join-Path $RunDir ($safe + ".stdout.txt")
  $stderr = Join-Path $RunDir ($safe + ".stderr.txt")
  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $argv = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy","Bypass",
    "-File",$Script
  ) + @($ChildArgs)

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $PSExe
  $psi.Arguments = (@($argv) | ForEach-Object { QuoteArg ([string]$_) }) -join " "
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()

  $out = $p.StandardOutput.ReadToEnd()
  $err = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  [System.IO.File]::WriteAllText($stdout,$out,(New-Object System.Text.UTF8Encoding($false)))
  [System.IO.File]::WriteAllText($stderr,$err,(New-Object System.Text.UTF8Encoding($false)))

  if($out){ [Console]::Out.Write($out) }
  if($err){ [Console]::Error.Write($err) }

  if([int]$p.ExitCode -ne 0){
    Die ("SELFTEST_CHILD_FAIL: " + $ExpectedToken + " exit=" + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("SELFTEST_TOKEN_MISSING: " + $ExpectedToken)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$ProfileScript = Join-Path $RepoRoot "scripts\recognition_encrypted_profile_v1.ps1"
$StartupScript = Join-Path $RepoRoot "scripts\recognition_locked_startup_v1.ps1"

$ProfileId = "locked-startup-selftest-v1"
# Ephemeral, per-run test passphrase (never a real credential; not committed as a literal)
$Passphrase = "selftest-" + [Guid]::NewGuid().ToString("N")

$ProfileDir = Join-Path $RepoRoot ("profiles\" + $ProfileId)
if(Test-Path -LiteralPath $ProfileDir -PathType Container){
  Remove-Item -LiteralPath $ProfileDir -Recurse -Force
}

RunChecked $ProfileScript @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","init","-Passphrase",$Passphrase) "ENCRYPTED_PROFILE_INIT_OK"
RunChecked $ProfileScript @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","put","-Passphrase",$Passphrase,"-Key","startup.mode","-Value","clean-browser") "ENCRYPTED_PROFILE_PUT_OK"
RunChecked $StartupScript @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Passphrase",$Passphrase,"-Mode","clean-browser") "RECOGNITION_LOCKED_STARTUP_V1_OK"

Write-Host "SELFTEST_RECOGNITION_LOCKED_STARTUP_V1_OK" -ForegroundColor Green
