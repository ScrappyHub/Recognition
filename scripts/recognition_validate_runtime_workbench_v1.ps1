param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$WorkbenchPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($WorkbenchPath)){
  $WorkbenchPath = Join-Path $RepoRoot "workbench\recognition_runtime_workbench_snapshot_v1.html"
}

if(-not (Test-Path -LiteralPath $WorkbenchPath -PathType Leaf)){
  Die ("WORKBENCH_MISSING: " + $WorkbenchPath)
}

$raw = Get-Content -Raw -LiteralPath $WorkbenchPath -Encoding UTF8

$required = @(
  "Recognition Runtime Workbench v1",
  "WORKBENCH_SNAPSHOT_LOAD_OK",
  "Evidence Summary",
  "SEAL",
  "ATTESTATION",
  "VERIFY",
  "LOCAL SNAPSHOT",
  "Timeline",
  "Tabs",
  "Navigation",
  "Graph",
  "Raw",
  "Event Inspector",
  "Copy Event JSON",
  "Copy Visible JSON",
  "Download Visible JSON",
  "recognition.runtime.timeline.v1",
  "recognition.runtime.tabs_timeline.v1",
  "recognition.runtime.navigation_chain.v1",
  "recognition.runtime.session_summary.v1",
  "recognition.workbench.visible.timeline.v1",
  "recognition.workbench.visible.tabs.v1",
  "recognition.workbench.visible.navigation.v1",
  "recognition.workbench.visible.graph.v1"
)

foreach($token in @($required)){
  if($raw.IndexOf($token,[StringComparison]::Ordinal) -lt 0){
    Die ("WORKBENCH_REQUIRED_TOKEN_MISSING: " + $token)
  }
}

$embeddedCount = 0
foreach($id in @("embeddedTimeline","embeddedTabs","embeddedNav","embeddedSummary")){
  if($raw.IndexOf(('id="' + $id + '"'),[StringComparison]::Ordinal) -lt 0){
    Die ("WORKBENCH_EMBEDDED_JSON_MISSING: " + $id)
  }
  $embeddedCount++
}

if($embeddedCount -ne 4){
  Die ("WORKBENCH_EMBEDDED_COUNT_BAD: " + [string]$embeddedCount)
}

Write-Host ("WORKBENCH_VALIDATE_OK: " + $WorkbenchPath) -ForegroundColor Green
Write-Host "RECOGNITION_RUNTIME_WORKBENCH_VALIDATE_V1_OK" -ForegroundColor Green
