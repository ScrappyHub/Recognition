param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){ $x=$e[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message) }
}

$ScriptsDir = Join-Path $RepoRoot "scripts"
$builderPath = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
if(-not (Test-Path -LiteralPath $builderPath -PathType Leaf)){ Die ("MISSING_BUILDER_TO_PATCH: " + $builderPath) }

# Overwrite builder with fixed payload copy (no LiteralPath wildcards)
$builder = @'
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
if(Test-Path -LiteralPath $work){ Remove-Item -LiteralPath $work -Recurse -Force }
PC-EnsureDir $work

# 1) payload/** (copy children deterministically; no wildcard LiteralPath)
$pktPayload = Join-Path $work "payload"
PC-EnsureDir $pktPayload
$children = @(@(Get-ChildItem -LiteralPath $PayloadDir -Force))
foreach($c in $children){
  Copy-Item -LiteralPath $c.FullName -Destination $pktPayload -Recurse -Force
}

# 2) manifest.json without id (canonical JSON bytes)
$files = New-Object System.Collections.Generic.List[object]
$all = PC-ListFilesRec $work
foreach($f in @($all)){
  $rel = PC-RelPath $work $f.FullName
  if($rel -ieq "manifest.json"){ continue }
  if($rel -ieq "packet_id.txt"){ continue }
  if($rel -ieq "sha256sums.txt"){ continue }
  $h = PC-Sha256HexFile $f.FullName
  $o = @{}
  $o["path"]  = $rel
  $o["bytes"] = [int64]$f.Length
  $o["sha256"]= $h
  [void]$files.Add($o)
}

$m = @{}
$m["schema"]      = "packet.manifest.v1"
$m["option"]      = "A"
$m["created_utc"] = PC-NowUtc
$m["files"]       = @($files)

$manifestCanonNoId = PC-ToCanonJson $m
$manifestPath = Join-Path $work "manifest.json"
PC-WriteUtf8NoBomLf $manifestPath $manifestCanonNoId

# 3) signatures dir exists by law
PC-EnsureDir (Join-Path $work "signatures")

# 4) PacketId = SHA256(canon_bytes(manifest-without-id))
$packetId = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanonNoId

# 5) persist PacketId (Option A): packet_id.txt
$pidPath = Join-Path $work "packet_id.txt"
PC-WriteUtf8NoBomLf $pidPath ($packetId + "`n")

# 6) sha256sums last over final bytes (excluding sha256sums itself)
$all2 = PC-ListFilesRec $work
$lines = New-Object System.Collections.Generic.List[string]
foreach($f in @($all2)){
  $rel = PC-RelPath $work $f.FullName
  if($rel -ieq "sha256sums.txt"){ continue }
  $h = PC-Sha256HexFile $f.FullName
  [void]$lines.Add(("{0}  {1}" -f $h,$rel))
}
$sumPath = Join-Path $work "sha256sums.txt"
PC-WriteUtf8NoBomLf $sumPath ((@($lines) -join "`n") + "`n")

# 7) finalize: move work -> folder named by PacketId
$final = Join-Path $OutDir $packetId
if(Test-Path -LiteralPath $final){ Remove-Item -LiteralPath $final -Recurse -Force }
Move-Item -LiteralPath $work -Destination $final
Write-Output $final
'@

# Write builder (use lib PC-WriteUtf8NoBomLf if available; else raw file write)
try{ . (Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"); PC-WriteUtf8NoBomLf $builderPath $builder } catch {
  $enc = New-Object System.Text.UTF8Encoding($false)
  $t = ($builder -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::WriteAllText($builderPath,$t,$enc)
}
ParseGateFile $builderPath

# Re-run selftest in-process (must pass)
$self = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
if(-not (Test-Path -LiteralPath $self -PathType Leaf)){ Die ("MISSING_SELFTEST: " + $self) }
ParseGateFile $self
& $self -RepoRoot $RepoRoot | Out-Host
Write-Host "FIX_OK: builder copy repaired + selftest passed." -ForegroundColor Green
