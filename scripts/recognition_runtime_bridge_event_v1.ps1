param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][ValidateSet("session.open","tab.open","navigation.commit")][string]$EventType,

  [string]$Utc = "2026-04-24T00:00:00.000Z",

  [string]$SessionId = "recognition-bridge-session-v1",
  [string]$StartedUtc,
  [string]$Mode = "standard",

  [string]$TabId = "tab-001",
  [string]$Url = "about:blank",
  [string]$Title = "",
  [string]$OpenedUtc,
  [string]$CommittedUtc,

  [int]$Index = 0,
  [int]$IsActive = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function Quote-Arg([string]$s){
  if($null -eq $s){ return '""' }
  if($s -match '[\s"]'){
    return '"' + $s.Replace('"','\"') + '"'
  }
  return $s
}

function Run-Child {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string[]]$ChildArgs
  )

  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){
    Die ("BRIDGE_CHILD_MISSING: " + $ScriptPath)
  }

  $tmpOut = [System.IO.Path]::GetTempFileName()
  $tmpErr = [System.IO.Path]::GetTempFileName()

  try {
    $argv = New-Object System.Collections.Generic.List[string]
    foreach($a in @("-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",$ScriptPath)){
      [void]$argv.Add([string]$a)
    }
    foreach($a in @($ChildArgs)){
      [void]$argv.Add([string]$a)
    }

    $joined = (@($argv) | ForEach-Object { Quote-Arg ([string]$_) }) -join " "

    $p = Start-Process `
      -FilePath $script:PSExe `
      -ArgumentList $joined `
      -Wait `
      -PassThru `
      -NoNewWindow `
      -RedirectStandardOutput $tmpOut `
      -RedirectStandardError $tmpErr

    $stdout = ""
    $stderr = ""

    if(Test-Path -LiteralPath $tmpOut -PathType Leaf){
      $stdout = Get-Content -Raw -LiteralPath $tmpOut -Encoding UTF8
    }

    if(Test-Path -LiteralPath $tmpErr -PathType Leaf){
      $stderr = Get-Content -Raw -LiteralPath $tmpErr -Encoding UTF8
    }

    if($stdout){ [Console]::Out.Write($stdout) }
    if($stderr){ [Console]::Error.Write($stderr) }

    if([int]$p.ExitCode -ne 0){
      Die ("BRIDGE_CHILD_FAIL(" + [string]$p.ExitCode + "): " + $ScriptPath)
    }
  }
  finally {
    Remove-Item -LiteralPath $tmpOut,$tmpErr -Force -ErrorAction SilentlyContinue
  }
}

function Write-BridgeReceipt {
  param(
    [string]$ReceiptEventType,
    [string]$ReceiptSessionId,
    [string]$ReceiptTabId,
    [string]$ReceiptUrl,
    [string]$ReceiptTitle,
    [string]$ReceiptUtc
  )

  $ReceiptPath = Join-Path (Join-Path $RepoRoot "proofs\receipts") "recognition.runtime.bridge.v1.ndjson"
  $dir = Split-Path -Parent $ReceiptPath

  if(-not (Test-Path -LiteralPath $dir -PathType Container)){
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
  }

  $obj = [ordered]@{
    schema     = "recognition.runtime.bridge.receipt.v1"
    event_type = $ReceiptEventType
    session_id = $ReceiptSessionId
    tab_id     = $ReceiptTabId
    url        = $ReceiptUrl
    title      = $ReceiptTitle
    ts_utc     = $ReceiptUtc
    source     = "recognition_runtime_bridge_event_v1"
  }

  $json = $obj | ConvertTo-Json -Compress -Depth 20
  $enc = New-Object System.Text.UTF8Encoding($false)
  $line = ($json -replace "`r`n","`n") -replace "`r","`n"
  if(-not $line.EndsWith("`n")){ $line += "`n" }

  [System.IO.File]::AppendAllText($ReceiptPath,$line,$enc)
  Write-Host ("BRIDGE_RECEIPT_OK: " + $ReceiptPath) -ForegroundColor Green
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($StartedUtc)){ $StartedUtc = $Utc }
if([string]::IsNullOrWhiteSpace($OpenedUtc)){ $OpenedUtc = $Utc }
if([string]::IsNullOrWhiteSpace($CommittedUtc)){ $CommittedUtc = $Utc }
if([string]::IsNullOrWhiteSpace($Mode)){ $Mode = "standard" }

$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

$SessionOpenPath = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpenPath     = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$NavPath         = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"

if($EventType -eq "session.open"){
  Run-Child -ScriptPath $SessionOpenPath -ChildArgs @(
    "-RepoRoot", $RepoRoot,
    "-SessionId", $SessionId,
    "-StartedUtc", $StartedUtc,
    "-Mode", $Mode
  )

  Write-BridgeReceipt `
    -ReceiptEventType "session.open" `
    -ReceiptSessionId $SessionId `
    -ReceiptTabId "" `
    -ReceiptUrl "" `
    -ReceiptTitle "" `
    -ReceiptUtc $StartedUtc

  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: session.open " + $SessionId) -ForegroundColor Green
  return
}

if($EventType -eq "tab.open"){

  $SessionPath = Join-Path `
    $RepoRoot `
    "runtime\session\session_state.json"

  if(-not (Test-Path -LiteralPath $SessionPath -PathType Leaf)){
    Die "OPEN_TAB_WITHOUT_SESSION"
  }

  Run-Child -ScriptPath $TabOpenPath -ChildArgs @(
    "-RepoRoot", $RepoRoot,
    "-TabId", $TabId,
    "-Index", ([string]$Index),
    "-Url", $Url,
    "-Title", $Title,
    "-OpenedUtc", $OpenedUtc,
    "-IsActive", ([string]$IsActive)
  )

  Write-BridgeReceipt `
    -ReceiptEventType "tab.open" `
    -ReceiptSessionId $SessionId `
    -ReceiptTabId $TabId `
    -ReceiptUrl $Url `
    -ReceiptTitle $Title `
    -ReceiptUtc $OpenedUtc

  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: tab.open " + $TabId) -ForegroundColor Green
  return
}

if($EventType -eq "navigation.commit"){
  Run-Child -ScriptPath $NavPath -ChildArgs @(
    "-RepoRoot", $RepoRoot,
    "-TabId", $TabId,
    "-Url", $Url,
    "-Title", $Title,
    "-CommittedUtc", $CommittedUtc
  )

  Write-BridgeReceipt `
    -ReceiptEventType "navigation.commit" `
    -ReceiptSessionId $SessionId `
    -ReceiptTabId $TabId `
    -ReceiptUrl $Url `
    -ReceiptTitle $Title `
    -ReceiptUtc $CommittedUtc

  Write-Host ("RUNTIME_BRIDGE_EVENT_OK: navigation.commit " + $TabId) -ForegroundColor Green
  return
}

Die ("UNKNOWN_EVENT_TYPE: " + $EventType)
