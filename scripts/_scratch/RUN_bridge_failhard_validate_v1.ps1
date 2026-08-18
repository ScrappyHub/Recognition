param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
function Die([string]$m){ throw $m }
$RepoRoot=(Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe=Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$SelfPath=Join-Path $RepoRoot "scripts\_selftest_recognition_runtime_bridge_v1.ps1"
$NegPath=Join-Path $RepoRoot "scripts\_scratch\RUN_RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1.ps1"
$ProofDir=Join-Path $RepoRoot "proofs\runs\bridge_failhard_validate_v1"
if(-not (Test-Path -LiteralPath $ProofDir -PathType Container)){ New-Item -ItemType Directory -Force -Path $ProofDir | Out-Null }
function RunCapture([string]$Label,[string]$ScriptPath,[string]$ExpectedToken){
  $stdout=Join-Path $script:ProofDir ($Label + ".stdout.txt")
  $stderr=Join-Path $script:ProofDir ($Label + ".stderr.txt")
  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
  $args=@("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",$ScriptPath,"-RepoRoot",$script:RepoRoot)
  $p=Start-Process -FilePath $script:PSExe -ArgumentList $args -Wait -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr
  $out=""; $err=""
  if(Test-Path -LiteralPath $stdout){ $out=Get-Content -Raw -LiteralPath $stdout -Encoding UTF8 }
  if(Test-Path -LiteralPath $stderr){ $err=Get-Content -Raw -LiteralPath $stderr -Encoding UTF8 }
  if($out){ [Console]::Out.Write($out) }
  if($err){ [Console]::Error.Write($err) }
  if([int]$p.ExitCode -ne 0){ Die ("CAPTURE_FAIL[" + $Label + "] exit=" + [string]$p.ExitCode) }
  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){ Die ("TOKEN_MISSING[" + $Label + "]: " + $ExpectedToken) }
  Write-Host ("CAPTURE_OK: " + $Label) -ForegroundColor Green
}
RunCapture "bridge_selftest" $SelfPath "SELFTEST_RECOGNITION_RUNTIME_BRIDGE_V1_OK"
RunCapture "bridge_negative" $NegPath "RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1_OK"
Write-Host "RECOGNITION_RUNTIME_BRIDGE_FAILHARD_GREEN" -ForegroundColor Green
