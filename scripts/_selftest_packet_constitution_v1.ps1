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
