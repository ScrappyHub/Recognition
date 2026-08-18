param([Parameter(Mandatory=$true)][string]$PacketDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")
. (Join-Path $PSScriptRoot "_lib_recognition_receipts_v1.ps1")

if(-not (Test-Path -LiteralPath $PacketDir -PathType Container)){ PC-Die ("MISSING_PACKET_DIR: " + $PacketDir) }

$packetDirName = Split-Path -Leaf $PacketDir
$manifestPath  = Join-Path $PacketDir "manifest.json"
$packetIdPath  = Join-Path $PacketDir "packet_id.txt"
$sumPath       = Join-Path $PacketDir "sha256sums.txt"

foreach($p in @($manifestPath,$packetIdPath,$sumPath)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ PC-Die ("MISSING_REQUIRED_FILE: " + $p) }
}

$raw = Get-Content -Raw -LiteralPath $sumPath -Encoding UTF8
$lines = @(@($raw -split "`n") | Where-Object { $_ -and $_.Trim().Length -gt 0 })

foreach($ln in @($lines)){
  $mm = [regex]::Match($ln, "^(?<h>[0-9a-f]{64})\s\s(?<p>.+)$")
  if(-not $mm.Success){ PC-Die ("BAD_SHA256SUMS_LINE: " + $ln) }

  $h      = $mm.Groups["h"].Value
  $rel    = $mm.Groups["p"].Value
  $winRel = $rel.Replace([char]47,[char]92)
  $full   = Join-Path $PacketDir $winRel

  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ PC-Die ("MISSING_FILE_LISTED_IN_SHA256SUMS: " + $rel) }

  $hh = PC-Sha256HexFile $full
  if($hh -ne $h){ PC-Die ("SHA256_MISMATCH: " + $rel + " expected=" + $h + " got=" + $hh) }
}

$packetId = (Get-Content -Raw -LiteralPath $packetIdPath -Encoding UTF8).Trim()
$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8
$manifestCanon = ($manifestRaw -replace "`r`n","`n") -replace "`r","`n"
$expected = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanon

if($expected -ne $packetId){ PC-Die ("PACKET_ID_MISMATCH: expected=" + $expected + " file=" + $packetId) }
if($packetDirName -ne $packetId){ PC-Die ("PACKET_DIRNAME_MISMATCH: dir=" + $packetDirName + " pid=" + $packetId) }

$repoRoot = Split-Path -Parent $PSScriptRoot
$receipt = @{
  schema = "recognition.receipt.v1"
  event = "recognition.packet.verify"
  timestamp_utc = REC-NowUtc
  packet_dir = $PacketDir
  packet_id = $packetId
  status = "ok"
}
$receiptPath = REC-AppendReceipt $repoRoot $receipt

Write-Host ("VERIFY_OK: " + $PacketDir) -ForegroundColor Green
Write-Host ("RECEIPT_OK: " + $receiptPath) -ForegroundColor Green
