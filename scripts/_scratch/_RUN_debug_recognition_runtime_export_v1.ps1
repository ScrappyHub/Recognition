param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function D([string]$m){ throw $m }

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Target   = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"
$Payload  = Join-Path $RepoRoot "payload\session_export"

if(-not (Test-Path -LiteralPath $Target -PathType Leaf)){ D ("MISSING_TARGET: " + $Target) }

Write-Host ("DEBUG_TARGET: " + $Target) -ForegroundColor Cyan

$raw = Get-Content -Raw -LiteralPath $Target -Encoding UTF8
$lines = @($raw -split "`n")

for($i=0; $i -lt $lines.Count; $i++){
  $n = $i + 1
  Write-Host ("{0:d3}: {1}" -f $n, $lines[$i])
}

Write-Host "DEBUG_RUN_START" -ForegroundColor Yellow
& $Target -RepoRoot $RepoRoot -SessionExportDir $Payload | Out-Host
Write-Host "DEBUG_RUN_END" -ForegroundColor Green
