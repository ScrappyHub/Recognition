# Selftest — Packet Constitution v1 Option A NEGATIVE vectors (WBS 7.2)
#
# Proves the verifier REJECTS every tamper class. Guards the completeness fix
# (an added file that is not listed in sha256sums must be rejected — this was a
# real hole the adversarial audit found and closed).
#
# A valid packet must verify OK; each of the following must be rejected:
#   tampered payload, tampered manifest, tampered packet_id, removed file,
#   ADDED rogue file.
#
# Windows PowerShell 5.1 compatible.
# Token: SELFTEST_PACKET_NEGATIVE_V1_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$S        = Join-Path $RepoRoot "scripts"
$builder  = Join-Path $S "pc_build_packet_optionA_v1.ps1"
$ver      = Join-Path $S "pc_verify_packet_optionA_v1.ps1"
foreach($p in @($builder,$ver)){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ PC-Die ("MISSING: " + $p) } }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pktneg_" + [Guid]::NewGuid().ToString("N"))
PC-EnsureDir $tmp
$payload = Join-Path $tmp "payload"
PC-EnsureDir $payload
PC-WriteUtf8NoBomLf (Join-Path $payload "hello.txt") "hello`n"
PC-WriteUtf8NoBomLf (Join-Path $payload "meta.json") (PC-ToCanonJson (@{ schema="recognition.payload.meta.v1"; note="minimal"; n=1 }))

$script:pass = 0; $script:fail = 0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }

function BuildFresh(){
  $o = Join-Path $tmp ("out_" + [Guid]::NewGuid().ToString("N"))
  PC-EnsureDir $o
  $d = & $builder -RepoRoot $RepoRoot -PayloadDir $payload -OutDir $o -PacketName "nv"
  return ([string]$d).Trim()
}
function ShouldReject([string]$PktDir,[string]$Label){
  $threw = $false; $out = ""
  try { $out = & $ver -PacketDir $PktDir *>&1 | Out-String } catch { $threw = $true }
  Check ($threw -or ($out -notmatch "VERIFY_OK")) $Label
}

try {
  # baseline: a valid packet must verify OK (completeness fix must not false-reject)
  $base = BuildFresh
  $bout = & $ver -PacketDir $base *>&1 | Out-String
  Check ($bout -match "VERIFY_OK") "baseline valid packet verifies OK"

  $p = BuildFresh; PC-WriteUtf8NoBomLf (Join-Path $p "payload\hello.txt") "HACKED`n"
  ShouldReject $p "tampered payload -> rejected"

  $p = BuildFresh; [System.IO.File]::AppendAllText((Join-Path $p "manifest.json")," ")
  ShouldReject $p "tampered manifest -> rejected"

  $p = BuildFresh; PC-WriteUtf8NoBomLf (Join-Path $p "packet_id.txt") ("0" * 64)
  ShouldReject $p "tampered packet_id -> rejected"

  $p = BuildFresh; Remove-Item -LiteralPath (Join-Path $p "payload\meta.json") -Force
  ShouldReject $p "removed file (sums line intact) -> rejected"

  $p = BuildFresh; PC-WriteUtf8NoBomLf (Join-Path $p "payload\evil.txt") "rogue`n"
  ShouldReject $p "ADDED rogue file -> rejected (completeness fix)"

  # deeper attack: delete a payload file AND its sha256sums line, leave the
  # packet_id-pinned manifest intact. Only the manifest-anchored check catches this.
  $p = BuildFresh
  Remove-Item -LiteralPath (Join-Path $p "payload\meta.json") -Force
  $sumsPath = Join-Path $p "sha256sums.txt"
  $kept = @(Get-Content -LiteralPath $sumsPath -Encoding UTF8 | Where-Object { $_ -and ($_ -notmatch "payload/meta\.json") })
  PC-WriteUtf8NoBomLf $sumsPath (($kept -join "`n") + "`n")
  ShouldReject $p "removed file + scrubbed sums line, manifest intact -> rejected (manifest-anchored)"

  # added rogue file WITH a matching sha256sums line (defeats sums-only completeness)
  $p = BuildFresh
  PC-WriteUtf8NoBomLf (Join-Path $p "payload\evil.txt") "rogue`n"
  $evilHash = PC-Sha256HexFile (Join-Path $p "payload\evil.txt")
  Add-Content -LiteralPath (Join-Path $p "sha256sums.txt") -Value ("{0}  payload/evil.txt" -f $evilHash) -Encoding UTF8
  ShouldReject $p "added rogue file + matching sums line, manifest intact -> rejected (manifest-anchored)"
}
finally {
  try { Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ PC-Die ("PACKET_NEGATIVE_SELFTEST_FAIL: " + $script:fail) }
Write-Host "SELFTEST_PACKET_NEGATIVE_V1_OK" -ForegroundColor Green
