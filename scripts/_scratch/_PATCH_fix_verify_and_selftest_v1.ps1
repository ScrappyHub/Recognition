param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  EnsureDir (Split-Path -Parent $Path)
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){ $x=$e[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message) }
}

$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir

# ---------------- overwrite scripts/pc_verify_packet_optionA_v1.ps1 ----------------
$verPath = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$ver = @'
param([Parameter(Mandatory=$true)][string]$PacketDir)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")

if(-not (Test-Path -LiteralPath $PacketDir -PathType Container)){ PC-Die ("MISSING_PACKET_DIR: " + $PacketDir) }

$packetDirName = Split-Path -Leaf $PacketDir
$manifestPath = Join-Path $PacketDir "manifest.json"
$pidPath      = Join-Path $PacketDir "packet_id.txt"
$sumPath      = Join-Path $PacketDir "sha256sums.txt"
foreach($p in @($manifestPath,$pidPath,$sumPath)){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ PC-Die ("MISSING_REQUIRED_FILE: " + $p) } }

# 1) verify sha256sums
$raw = Get-Content -Raw -LiteralPath $sumPath -Encoding UTF8
$lines = @(@($raw -split "`n") | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ -and $_.Trim().Length -gt 0 })
foreach($ln in @($lines)){
  $m = [regex]::Match($ln, "^(?<h>[0-9a-f]{64})\s\s(?<p>.+)$")
  if(-not $m.Success){ PC-Die ("BAD_SHA256SUMS_LINE: " + $ln) }
  $h   = $m.Groups["h"].Value
  $rel = $m.Groups["p"].Value
  $full = Join-Path $PacketDir ($rel -replace "/","\")
  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ PC-Die ("MISSING_FILE_LISTED_IN_SHA256SUMS: " + $rel) }
  $hh = PC-Sha256HexFile $full
  if($hh -ne $h){ PC-Die ("SHA256_MISMATCH: " + $rel + " expected=" + $h + " got=" + $hh) }
}

# 2) verify PacketId rule (Option A)
$pid = (Get-Content -Raw -LiteralPath $pidPath -Encoding UTF8).Trim()
$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8
$manifestCanon = ($manifestRaw -replace "`r`n","`n") -replace "`r","`n"
$expected = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanon
if($expected -ne $pid){ PC-Die ("PACKET_ID_MISMATCH: expected=" + $expected + " file=" + $pid) }
if($packetDirName -ne $pid){ PC-Die ("PACKET_DIRNAME_MISMATCH: dir=" + $packetDirName + " pid=" + $pid) }

Write-Host ("VERIFY_OK: " + $PacketDir) -ForegroundColor Green
'@
WriteUtf8NoBomLf $verPath $ver
ParseGateFile $verPath

# ---------------- overwrite scripts/_selftest_packet_constitution_v1.ps1 ----------------
$selfPath = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$self = @'
param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")

$tv      = Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_minimal_optionA"
$payload = Join-Path $tv "payload"
$out     = Join-Path $tv "out"
$gold    = Join-Path $tv "golden"
PC-EnsureDir $tv; PC-EnsureDir $payload; PC-EnsureDir $out; PC-EnsureDir $gold

PC-WriteUtf8NoBomLf (Join-Path $payload "hello.txt") ("hello`n")
$metaCanon = PC-ToCanonJson (@{ schema="recognition.payload.meta.v1"; note="minimal"; n=1 })
PC-WriteUtf8NoBomLf (Join-Path $payload "meta.json") $metaCanon

$builder = Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"
$ver     = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"
if(-not (Test-Path -LiteralPath $builder -PathType Leaf)){ PC-Die ("MISSING_BUILDER: " + $builder) }
if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ PC-Die ("MISSING_VERIFIER: " + $ver) }

# Run builder + verifier IN-PROCESS so errors throw and stop
$pktDir = & $builder -RepoRoot $RepoRoot -PayloadDir $payload -OutDir $out -PacketName "tv"
if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ PC-Die ("SELFTEST_BUILD_FAIL: " + $pktDir) }
& $ver -PacketDir $pktDir | Out-Host

Copy-Item -LiteralPath (Join-Path $pktDir "manifest.json")  -Destination (Join-Path $gold "manifest_without_id.canon.json") -Force
Copy-Item -LiteralPath (Join-Path $pktDir "packet_id.txt")  -Destination (Join-Path $gold "packet_id.txt") -Force
Copy-Item -LiteralPath (Join-Path $pktDir "sha256sums.txt") -Destination (Join-Path $gold "sha256sums.txt") -Force

$gm = Get-Content -Raw -LiteralPath (Join-Path $gold "manifest_without_id.canon.json") -Encoding UTF8
$gp = (Get-Content -Raw -LiteralPath (Join-Path $gold "packet_id.txt") -Encoding UTF8).Trim()
$ep = PC-ComputePacketIdFromManifestNoIdCanon $gm
if($ep -ne $gp){ PC-Die ("GOLDEN_PACKET_ID_MISMATCH: expected=" + $ep + " golden=" + $gp) }

Write-Host ("SELFTEST_OK: Packet Constitution v1 Option A minimal vector -> " + $tv) -ForegroundColor Green
'@
WriteUtf8NoBomLf $selfPath $self
ParseGateFile $selfPath

# Parse-gate exporter too (must exist)
$exp = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"
if(-not (Test-Path -LiteralPath $exp -PathType Leaf)){ Die ("MISSING_EXPORTER: " + $exp) }
ParseGateFile $exp

# Run selftest IN-PROCESS (no false OK possible)
& $selfPath -RepoRoot $RepoRoot | Out-Host
Write-Host ("FIX_OK: verifier + selftest repaired; exporter -> " + (Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1")) -ForegroundColor Green
