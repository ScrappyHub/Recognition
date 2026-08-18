param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){
    $x=$e[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
$ReceiptsDir = Join-Path $RepoRoot "proofs\receipts"
EnsureDir $ReceiptsDir

$LibPath    = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$Builder    = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$Verifier   = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$Selftest   = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$Exporter   = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"

foreach($p in @($LibPath,$Builder,$Verifier,$Selftest,$Exporter)){
  ParseGateFile $p
  Write-Host ("PARSE_OK: " + $p) -ForegroundColor Green
}

$PayloadDir = Join-Path $RepoRoot "payload\session_export"
$OutDir     = Join-Path $RepoRoot "packets\outbox"
EnsureDir $PayloadDir
EnsureDir $OutDir

$runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")

# positive selftest
& $Selftest -RepoRoot $RepoRoot | Out-Host

# export
$pktDir = & $Exporter -RepoRoot $RepoRoot -SessionExportDir $PayloadDir -OutDir $OutDir -PacketName "recognition_session_export"
if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){
  Die ("EXPORT_BUILD_FAIL: " + $pktDir)
}

# verify exported packet
& $Verifier -PacketDir $pktDir | Out-Host

$packetId = Split-Path -Leaf $pktDir

$exportReceipt = @{
  schema       = "recognition.export.receipt.v1"
  run_id       = $runId
  action       = "export"
  packet_dir   = $pktDir
  packet_id    = $packetId
  status       = "ok"
  token        = "EXPORT_OK"
  timestamp_utc= (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
} | ConvertTo-Json -Compress

$verifyReceipt = @{
  schema       = "recognition.verify.receipt.v1"
  run_id       = $runId
  action       = "verify"
  packet_dir   = $pktDir
  packet_id    = $packetId
  status       = "ok"
  token        = "VERIFY_OK"
  timestamp_utc= (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
} | ConvertTo-Json -Compress

Add-Content -LiteralPath (Join-Path $ReceiptsDir "recognition_export.ndjson") -Value $exportReceipt -Encoding UTF8
Add-Content -LiteralPath (Join-Path $ReceiptsDir "recognition_verify.ndjson") -Value $verifyReceipt -Encoding UTF8

Write-Host ("FULL_GREEN_RUNNER_RECOGNITION_PC_V1_OK: " + $pktDir) -ForegroundColor Green
