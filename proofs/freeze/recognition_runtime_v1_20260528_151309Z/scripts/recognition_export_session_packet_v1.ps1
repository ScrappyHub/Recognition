param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$SessionExportDir,
  [Parameter(Mandatory=$false)][string]$OutDir,
  [Parameter(Mandatory=$false)][string]$PacketName = "recognition_session_export"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")
. (Join-Path $PSScriptRoot "_lib_recognition_receipts_v1.ps1")

if([string]::IsNullOrWhiteSpace($SessionExportDir)){ $SessionExportDir = Join-Path $RepoRoot "payload\session_export" }
if([string]::IsNullOrWhiteSpace($OutDir)){ $OutDir = Join-Path $RepoRoot "packets\outbox" }

PC-EnsureDir $SessionExportDir
PC-EnsureDir $OutDir

$builder = Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"
if(-not (Test-Path -LiteralPath $builder -PathType Leaf)){ PC-Die ("MISSING_BUILDER: " + $builder) }

$pktDir = & $builder -RepoRoot $RepoRoot -PayloadDir $SessionExportDir -OutDir $OutDir -PacketName $PacketName
if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ PC-Die ("EXPORT_BUILD_FAIL: " + $pktDir) }

$packetIdPath = Join-Path $pktDir "packet_id.txt"
if(-not (Test-Path -LiteralPath $packetIdPath -PathType Leaf)){ PC-Die ("EXPORT_MISSING_PACKET_ID: " + $packetIdPath) }
$packetId = (Get-Content -Raw -LiteralPath $packetIdPath -Encoding UTF8).Trim()

$receipt = @{
  schema = "recognition.receipt.v1"
  event = "recognition.packet.export"
  timestamp_utc = REC-NowUtc
  session_export_dir = $SessionExportDir
  out_dir = $OutDir
  packet_name = $PacketName
  packet_dir = $pktDir
  packet_id = $packetId
  status = "ok"
}
$receiptPath = REC-AppendReceipt $RepoRoot $receipt

Write-Host ("EXPORT_OK: " + $pktDir) -ForegroundColor Green
Write-Host ("RECEIPT_OK: " + $receiptPath) -ForegroundColor Green
Write-Output $pktDir
