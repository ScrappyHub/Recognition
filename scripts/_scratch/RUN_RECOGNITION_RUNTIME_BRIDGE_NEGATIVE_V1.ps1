param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$BridgePath = Join-Path $RepoRoot "scripts\recognition_runtime_bridge_event_v1.ps1"
$RuntimeRoot = Join-Path $RepoRoot "runtime"
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

if(Test-Path -LiteralPath $RuntimeRoot -PathType Container){
  Remove-Item -LiteralPath $RuntimeRoot -Recurse -Force
}

$tmp = Join-Path $env:TEMP ("recognition_bridge_neg_" + [guid]::NewGuid().ToString("N"))
$stdout = $tmp + ".stdout.txt"
$stderr = $tmp + ".stderr.txt"

try {
  $p = Start-Process `
    -FilePath $PSExe `
    -ArgumentList @(
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy","Bypass",
      "-File",$BridgePath,
      "-RepoRoot",$RepoRoot,
      "-EventType","tab.open",
      "-TabId","tab-neg-001",
      "-Index","0",
      "-Url","https://neg.invalid/",
      "-Title","NEG"
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

  $text = $out + "`n" + $err

  if([int]$p.ExitCode -eq 0){
    throw "NEGATIVE_EXPECTED_FAILURE_MISSING"
  }

  if($text -notmatch "OPEN_TAB_WITHOUT_SESSION"){
    throw ("NEGATIVE_TOKEN_MISSING: " + $text)
  }

  Write-Host "NEG_OPEN_TAB_WITHOUT_SESSION_OK" -ForegroundColor Green
  Write-Host "RECOGNITION_RUNTIME_BRIDGE_NEGATIVE_V1_OK" -ForegroundColor Green
}
finally {
  Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
}
