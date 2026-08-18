param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$PayloadDir,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$false)][string]$PacketName = "packet"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")

if(-not (Test-Path -LiteralPath $PayloadDir -PathType Container)){ PC-Die ("MISSING_PAYLOAD_DIR: " + $PayloadDir) }
PC-EnsureDir $OutDir

$work = Join-Path $OutDir ($PacketName + "_work")
if(Test-Path -LiteralPath $work){
  Remove-Item -LiteralPath $work -Recurse -Force
}
PC-EnsureDir $work

# 1) payload/**
$pktPayload = Join-Path $work "payload"
PC-EnsureDir $pktPayload

$children = @(Get-ChildItem -LiteralPath $PayloadDir -Force | Sort-Object FullName)
foreach($c in $children){
  if($c.PSIsContainer){
    Copy-Item -LiteralPath $c.FullName -Destination $pktPayload -Recurse -Force
  } else {
    Copy-Item -LiteralPath $c.FullName -Destination $pktPayload -Force
  }
}

# 2) manifest.json without id
$files = @()
$all = @(PC-ListFilesRec $work)

foreach($f in $all){
  $rel = PC-RelPath $work $f.FullName
  if($rel -ieq "manifest.json"){ continue }
  if($rel -ieq "packet_id.txt"){ continue }
  if($rel -ieq "sha256sums.txt"){ continue }

  $files += @{
    path   = $rel
    bytes  = [int64]$f.Length
    sha256 = (PC-Sha256HexFile $f.FullName)
  }
}

$m = @{
  schema = "packet.manifest.v1"
  option = "A"
  files  = @($files)
}

$manifestCanonNoId = PC-ToCanonJson $m
$manifestPath = Join-Path $work "manifest.json"
PC-WriteUtf8NoBomLf $manifestPath $manifestCanonNoId

# 3) signatures dir exists by law
PC-EnsureDir (Join-Path $work "signatures")

# 4) PacketId = SHA256(canonical manifest bytes)
$packetId = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanonNoId

# 5) packet_id.txt
$pidPath = Join-Path $work "packet_id.txt"
PC-WriteUtf8NoBomLf $pidPath $packetId

# 6) sha256sums last
$lines = @()
$all2 = @(PC-ListFilesRec $work)
foreach($f in $all2){
  $rel = PC-RelPath $work $f.FullName
  if($rel -ieq "sha256sums.txt"){ continue }
  $h = PC-Sha256HexFile $f.FullName
  $lines += ("{0}  {1}" -f $h,$rel)
}
$sumPath = Join-Path $work "sha256sums.txt"
PC-WriteUtf8NoBomLf $sumPath (($lines -join "`n") + "`n")

# 7) finalize
$final = Join-Path $OutDir $packetId
if(Test-Path -LiteralPath $final){
  Remove-Item -LiteralPath $final -Recurse -Force
}
Move-Item -LiteralPath $work -Destination $final

Write-Output $final
