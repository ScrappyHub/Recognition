param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$ProfileId,
  [Parameter(Mandatory=$true)][string]$Passphrase,
  [Parameter(Mandatory=$false)][string]$SessionId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

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

function QuoteArg([string]$s){
  if($null -eq $s){ return '""' }
  if($s.Length -eq 0){ return '""' }
  return '"' + $s.Replace('"','\"') + '"'
}

function AppendReceipt([string]$RepoRoot,[object]$Obj){
  $path = Join-Path $RepoRoot "proofs\receipts\recognition.clean_browser.v1.ndjson"
  EnsureDir (Split-Path -Parent $path)
  $line = ($Obj | ConvertTo-Json -Depth 40 -Compress) + "`n"
  [System.IO.File]::AppendAllText($path,$line,(New-Object System.Text.UTF8Encoding($false)))
  Write-Host ("CLEAN_BROWSER_RECEIPT_OK: " + $path) -ForegroundColor Green
}

function RunChecked([string]$Script,[string[]]$ChildArgs,[string]$ExpectedToken){
  $PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
  $RunDir = Join-Path $RepoRoot "proofs\runs\clean_browser_session_v1"
  EnsureDir $RunDir

  $safe = $ExpectedToken.Replace(":","_").Replace("\","_").Replace("/","_")
  $stdout = Join-Path $RunDir ($safe + ".stdout.txt")
  $stderr = Join-Path $RunDir ($safe + ".stderr.txt")
  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue

  $argv = @("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",$Script) + @($ChildArgs)

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
    Die ("CLEAN_BROWSER_CHILD_FAIL: " + $ExpectedToken + " exit=" + [string]$p.ExitCode)
  }

  if(($out + "`n" + $err) -notmatch [regex]::Escape($ExpectedToken)){
    Die ("CLEAN_BROWSER_TOKEN_MISSING: " + $ExpectedToken)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($SessionId)){
  $SessionId = "clean-browser-" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
}

$ProfileScript = Join-Path $RepoRoot "scripts\recognition_encrypted_profile_v1.ps1"
$StartupScript = Join-Path $RepoRoot "scripts\recognition_locked_startup_v1.ps1"
$TimelineScript = Join-Path $RepoRoot "scripts\recognition_runtime_timeline_materialize_v1.ps1"
$TimelineVerify = Join-Path $RepoRoot "scripts\recognition_verify_runtime_timeline_v1.ps1"

RunChecked $StartupScript @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Passphrase",$Passphrase,"-Mode","clean-browser") "RECOGNITION_LOCKED_STARTUP_V1_OK"

$TempRoot = Join-Path $RepoRoot ("tmp\clean_browser\" + $SessionId)
$SessionRoot = Join-Path $TempRoot "runtime"
$EventsPath = Join-Path $SessionRoot "events.ndjson"
$TimelineDir = Join-Path $TempRoot "timeline"

if(Test-Path -LiteralPath $TempRoot -PathType Container){
  Remove-Item -LiteralPath $TempRoot -Recurse -Force
}

EnsureDir $SessionRoot

$line1 = '{"schema":"recognition.event.v1","event_id":"clean-evt-0001","seq":1,"ts_utc":"2026-06-07T16:00:00.000Z","type":"session.started","tab_id":null,"data":{"mode":"clean-browser","session_id":"' + $SessionId + '"}}'
$line2 = '{"schema":"recognition.event.v1","event_id":"clean-evt-0002","seq":2,"ts_utc":"2026-06-07T16:00:05.000Z","type":"tab.opened","tab_id":"clean-tab-001","data":{"url":"about:clean","title":"Clean Browser Start","index":0}}'
$line3 = '{"schema":"recognition.event.v1","event_id":"clean-evt-0003","seq":3,"ts_utc":"2026-06-07T16:00:10.000Z","type":"navigation.committed","tab_id":"clean-tab-001","data":{"url":"https://example.com/private","title":"Private Example"}}'

WriteUtf8NoBomLf $EventsPath ([string]::Join("`n", [string[]]@($line1,$line2,$line3)))
RunChecked $TimelineScript @("-RepoRoot",$RepoRoot,"-EventsPath",$EventsPath,"-OutDir",$TimelineDir) "RECOGNITION_RUNTIME_TIMELINE_MATERIALIZE_V1_OK"
RunChecked $TimelineVerify @("-RepoRoot",$RepoRoot,"-TimelineDir",$TimelineDir) "RECOGNITION_RUNTIME_TIMELINE_VERIFY_V1_OK"

$SummaryPath = Join-Path $TimelineDir "session_summary.json"
$Summary = Get-Content -Raw -LiteralPath $SummaryPath -Encoding UTF8

RunChecked $ProfileScript @("-RepoRoot",$RepoRoot,"-ProfileId",$ProfileId,"-Action","put","-Passphrase",$Passphrase,"-Key",("clean_session." + $SessionId + ".summary"),"-Value",$Summary) "ENCRYPTED_PROFILE_PUT_OK"

Remove-Item -LiteralPath $TempRoot -Recurse -Force

if(Test-Path -LiteralPath $TempRoot -PathType Container){
  Die ("CLEAN_BROWSER_WIPE_FAILED: " + $TempRoot)
}

AppendReceipt $RepoRoot ([ordered]@{
  schema = "recognition.clean_browser.receipt.v1"
  action = "session.run_ephemeral"
  profile_id = $ProfileId
  session_id = $SessionId
  encrypted_summary_written = $true
  plaintext_workspace_wiped = $true
  ts_utc = (Get-Date).ToUniversalTime().ToString("o")
})

Write-Host ("CLEAN_BROWSER_SESSION_WIPE_OK: " + $TempRoot) -ForegroundColor Green
Write-Host "RECOGNITION_CLEAN_BROWSER_SESSION_V1_OK" -ForegroundColor Green
