# RUN_PACKAGE_DIST_V1 — WBS 7.3 packaging / distribution
#
# Builds a self-contained distributable and wraps the WHOLE distribution in a
# governed Packet Constitution packet (the installer output is itself a
# deterministic, verifiable evidence artifact — dogfooding the export law).
#
# Steps: publish the browser (self-contained win-x64 single file) -> assemble
# dist\recognition\ (browser + scripts + schemas + policies + config + docs +
# trust root) -> build a packet of dist\ -> verify it.
#
#   pwsh -File scripts\RUN_PACKAGE_DIST_V1.ps1 -RepoRoot .
# Final token: RECOGNITION_PACKAGE_DIST_V1_OK   (needs .NET 8 SDK)

param([Parameter(Mandatory=$true)][string]$RepoRoot,[string]$Configuration="Release")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$S = Join-Path $RepoRoot "scripts"
function Die([string]$m){ Write-Host ("PACKAGE_FAIL: " + $m) -ForegroundColor Red; exit 1 }

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if(-not $dotnet){ Die ".NET SDK not found — install .NET 8 SDK to package the browser." }

# 1) publish the browser (self-contained, single file)
$proj = Join-Path $RepoRoot "browser\Recognition.Browser.csproj"
if(-not (Test-Path -LiteralPath $proj)){ Die ("browser project missing: " + $proj) }
Write-Host "=== dotnet publish (self-contained win-x64) ===" -ForegroundColor Cyan
& dotnet publish $proj -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true
if($LASTEXITCODE -ne 0){ Die "dotnet publish failed" }
$pub = Join-Path $RepoRoot ("browser\bin\" + $Configuration + "\net8.0-windows\win-x64\publish")
if(-not (Test-Path -LiteralPath $pub -PathType Container)){ Die ("publish output not found: " + $pub) }

# 2) assemble dist\recognition\
$dist = Join-Path $RepoRoot "dist\recognition"
if(Test-Path -LiteralPath $dist){ Remove-Item -LiteralPath $dist -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dist | Out-Null
function CopyInto([string]$srcRel,[string]$dstName){
  $src = Join-Path $RepoRoot $srcRel
  if(Test-Path -LiteralPath $src){
    $dst = Join-Path $dist $dstName
    Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force
  }
}
Copy-Item -LiteralPath $pub -Destination (Join-Path $dist "browser") -Recurse -Force
CopyInto "scripts"      "scripts"
CopyInto "schemas"      "schemas"
CopyInto "policies"     "policies"
CopyInto "config"       "config"
CopyInto "docs"         "docs"
CopyInto "branding"     "branding"
CopyInto "installer"    "installer"
# Trust root must sit at proofs\trust\ so the runtime scripts resolve it against the
# install root (RepoRoot). locked-startup checks proofs\trust\allowed_signers.
New-Item -ItemType Directory -Force -Path (Join-Path $dist "proofs") | Out-Null
CopyInto "proofs\trust" "proofs\trust"
# drop scratch + any stray key material from the packaged scripts
$scratch = Join-Path (Join-Path $dist "scripts") "_scratch"
if(Test-Path -LiteralPath $scratch){ Remove-Item -LiteralPath $scratch -Recurse -Force }

# 3) wrap the distribution in a governed packet + verify it
Write-Host "=== packaging dist as a governed packet ===" -ForegroundColor Cyan
$outbox = Join-Path $RepoRoot "packets\outbox"
$builder = Join-Path $S "pc_build_packet_optionA_v1.ps1"
$verifier = Join-Path $S "pc_verify_packet_optionA_v1.ps1"
$pkt = & $builder -RepoRoot $RepoRoot -PayloadDir $dist -OutDir $outbox -PacketName "recognition_dist"
$pkt = ([string]$pkt).Trim()
if(-not (Test-Path -LiteralPath $pkt -PathType Container)){ Die ("packet build failed: " + $pkt) }
$vout = & $verifier -PacketDir $pkt *>&1 | Out-String
Write-Host $vout
if($vout -notmatch "VERIFY_OK"){ Die "distribution packet failed verification" }

# 4) produce the downloadable zip (the standalone, self-contained distribution)
$zip = Join-Path $RepoRoot "dist\Recognition-win-x64.zip"
if(Test-Path -LiteralPath $zip){ Remove-Item -LiteralPath $zip -Force }
Write-Host "=== zipping standalone distribution ===" -ForegroundColor Cyan
Compress-Archive -Path (Join-Path $dist "*") -DestinationPath $zip -Force
$zipMB = [math]::Round((Get-Item -LiteralPath $zip).Length / 1MB, 1)

Write-Host ""
Write-Host ("Distribution assembled: " + $dist)
Write-Host ("Governed dist packet  : " + $pkt)
Write-Host ("Downloadable zip      : " + $zip + "  (" + $zipMB + " MB)")
Write-Host ""
Write-Host "To install from the zip: extract it, then run"
Write-Host "  pwsh -File installer\RECOGNITION_INSTALL_V1.ps1"
Write-Host "RECOGNITION_PACKAGE_DIST_V1_OK" -ForegroundColor Green
