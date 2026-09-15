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

$listed = @{}   # rel -> $true, for the completeness check below
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

  $listed[$rel] = $true
}

# Completeness (fixes an integrity hole: an ADDED file not listed in
# sha256sums previously passed verification). Every file physically present in
# the packet must be covered by sha256sums; only sha256sums.txt itself is exempt
# (it cannot list its own hash).
$actual = @(PC-ListFilesRec $PacketDir)
foreach($f in @($actual)){
  $arel = PC-RelPath $PacketDir $f.FullName
  if($arel -ieq "sha256sums.txt"){ continue }
  if(-not $listed.ContainsKey($arel)){ PC-Die ("UNLISTED_FILE_IN_PACKET: " + $arel) }
}

$packetId = (Get-Content -Raw -LiteralPath $packetIdPath -Encoding UTF8).Trim()
$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8
$manifestCanon = ($manifestRaw -replace "`r`n","`n") -replace "`r","`n"
$expected = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanon

if($expected -ne $packetId){ PC-Die ("PACKET_ID_MISMATCH: expected=" + $expected + " file=" + $packetId) }
if($packetDirName -ne $packetId){ PC-Die ("PACKET_DIRNAME_MISMATCH: dir=" + $packetDirName + " pid=" + $packetId) }

# --- manifest-anchored verification (authoritative) --------------------------
# packet_id pins manifest.json, so manifest.files is the trusted file list.
# sha256sums.txt is NOT pinned by anything and therefore cannot be the source of
# truth (an attacker can delete a payload file AND its sums line while leaving
# the pinned manifest intact — the sha256sums-only check would pass). Validate
# the packet against manifest.files: every declared file present with matching
# size+hash, and no payload file exists that the manifest does not declare.
$man = $manifestRaw | ConvertFrom-Json
if($null -eq $man.files){ PC-Die "MANIFEST_NO_FILES" }

$declared = @{}
foreach($e in @($man.files)){
  $dp = [string]$e.path
  if([string]::IsNullOrWhiteSpace($dp)){ PC-Die "MANIFEST_EMPTY_PATH" }
  $declared[$dp] = $true
  $full = Join-Path $PacketDir ($dp.Replace([char]47,[char]92))
  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ PC-Die ("MANIFEST_FILE_MISSING: " + $dp) }
  $fi = Get-Item -LiteralPath $full
  if([int64]$fi.Length -ne [int64]$e.bytes){ PC-Die ("MANIFEST_FILE_SIZE_MISMATCH: " + $dp) }
  $hh = PC-Sha256HexFile $full
  if($hh -ne ([string]$e.sha256)){ PC-Die ("MANIFEST_FILE_SHA_MISMATCH: " + $dp + " expected=" + ([string]$e.sha256) + " got=" + $hh) }
}

# every payload file physically present must be declared by the manifest
foreach($f in @(PC-ListFilesRec $PacketDir)){
  $arel = PC-RelPath $PacketDir $f.FullName
  if($arel.StartsWith("payload/") -and -not $declared.ContainsKey($arel)){
    PC-Die ("PAYLOAD_FILE_NOT_IN_MANIFEST: " + $arel)
  }
}

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
