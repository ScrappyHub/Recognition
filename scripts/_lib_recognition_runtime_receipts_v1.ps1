Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function RRT-EnsureDir([string]$p){
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function RRT-ReceiptPath([string]$RepoRoot){
  Join-Path (Join-Path $RepoRoot "proofs\receipts") "recognition.runtime.v1.ndjson"
}

function Write-RecognitionRuntimeReceipt {
  param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [Parameter(Mandatory=$true)][string]$Action,
    [Parameter(Mandatory=$true)][string]$Status,
    [Parameter()][hashtable]$Data
  )

  if($null -eq $Data){ $Data = @{} }

  $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
  $path = RRT-ReceiptPath $RepoRoot

  RRT-EnsureDir (Split-Path -Parent $path)

  $obj = [ordered]@{
    schema = "recognition.runtime.receipt.v1"
    action = $Action
    status = $Status
    data   = $Data
  }

  $json = $obj | ConvertTo-Json -Depth 10
  $enc  = New-Object System.Text.UTF8Encoding($false)

  $line = ($json -replace "`r`n","`n") -replace "`r","`n"
  if(-not $line.EndsWith("`n")){ $line += "`n" }

  [System.IO.File]::AppendAllText($path,$line,$enc)

  Write-Host ("RUNTIME_RECEIPT_OK: " + $path) -ForegroundColor Green
}
