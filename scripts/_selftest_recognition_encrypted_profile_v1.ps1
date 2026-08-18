param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function QuoteArg([string]$s){
  if($null -eq $s){ return '""' }
  if($s.Length -eq 0){ return '""' }
  return '"' + $s.Replace('"','\"') + '"'
}

function RunChecked([string[]]$ChildArgs,[string]$Token){
  $RunDir = Join-Path $RepoRoot "proofs\runs\encrypted_profile_selftest_v1"
  if(-not (Test-Path -LiteralPath $RunDir -PathType Container)){
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
  }

  $safe = $Token.Replace(":","_").Replace("\","_").Replace("/","_")
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
    Die ("SELFTEST_CHILD_FAIL: " + $Token + " exit=" + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($Token)){
    Die ("SELFTEST_TOKEN_MISSING: " + $Token)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$Script = Join-Path $RepoRoot "scripts\recognition_encrypted_profile_v1.ps1"

$ProfileId = "selftest-profile-v1"
$ProfileDir = Join-Path $RepoRoot ("profiles\" + $ProfileId)
if(Test-Path -LiteralPath $ProfileDir -PathType Container){
  Remove-Item -LiteralPath $ProfileDir -Recurse -Force
}

$Passphrase = "recognition-selftest-passphrase-v1"
$OutPath = Join-Path $RepoRoot "runtime\encrypted_profile_selftest_value.txt"

RunChecked @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","init","-Passphrase",$Passphrase) "ENCRYPTED_PROFILE_INIT_OK"
RunChecked @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","put","-Passphrase",$Passphrase,"-Key","runtime.mode","-Value","clean-browser") "ENCRYPTED_PROFILE_PUT_OK"
RunChecked @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","verify","-Passphrase",$Passphrase) "ENCRYPTED_PROFILE_VERIFY_OK"
RunChecked @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","get","-Passphrase",$Passphrase,"-Key","runtime.mode","-OutPath",$OutPath) "ENCRYPTED_PROFILE_GET_OK"

$value = (Get-Content -Raw -LiteralPath $OutPath -Encoding UTF8).Trim()
if($value -ne "clean-browser"){ Die ("SELFTEST_VALUE_MISMATCH: " + $value) }

$Store = Join-Path $ProfileDir "encrypted.store.json"
$storeText = Get-Content -Raw -LiteralPath $Store -Encoding UTF8
if($storeText -match "clean-browser"){ Die "SELFTEST_PLAINTEXT_LEAK_IN_STORE" }

Write-Host "SELFTEST_RECOGNITION_ENCRYPTED_PROFILE_V1_OK" -ForegroundColor Green
