# Selftest — Recognition Universal Extension Adapter v1 (§6/§22)
# Proves the invariant the browser's adapter depends on: repackaging a governed
# extension as a .zip or a .crx (CRX3) must NOT change its governed identity —
# otherwise every zip/unzip would silently break governance and force
# re-registration. Builds a synthetic extension, registers + allows it via the
# ALREADY-PROVEN governance CLI, then:
#   - zips it and re-extracts -> byte-identical files, same extension_id, still
#     passes the load gate (verify).
#   - wraps the same zip bytes in a synthetic CRX3 container, strips the header
#     using the EXACT byte-offset formula the C# adapter uses (12 + headerLen),
#     unzips the recovered payload -> byte-identical files, same extension_id.
#   - tampering a file after extraction still fails the load gate (governance
#     is keyed on CURRENT bytes, not on how they arrived).
# This does not execute the C# adapter itself (no .NET runtime here); it proves
# the CRX offset math and the zip/identity invariant the C# code relies on.
# Token: SELFTEST_RECOGNITION_EXTENSION_ADAPTER_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($RepoRoot)){ $RepoRoot = (Get-Location).Path }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
. (Join-Path $RepoRoot "scripts\_lib_recognition_extension_governance_v1.ps1")

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("extadapt_" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }

function DirFileHashes([string]$dir){
  $root = (Resolve-Path -LiteralPath $dir).Path
  $map = @{}
  foreach($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)){
    $rel = ($f.FullName.Substring($root.Length).TrimStart('\','/')) -replace '\\','/'
    $h = [System.Security.Cryptography.SHA256]::HashData([System.IO.File]::ReadAllBytes($f.FullName))
    $map[$rel] = -join ($h | ForEach-Object { $_.ToString("x2") })
  }
  return $map
}
function SameHashes($a,$b){
  $ak = @($a.Keys | Sort-Object); $bk = @($b.Keys | Sort-Object)
  if(($ak -join ",") -ne ($bk -join ",")){ return $false }
  foreach($k in $ak){ if($a[$k] -ne $b[$k]){ return $false } }
  return $true
}

# Reproduces the C# adapter's CRX3 offset formula exactly: magic(4) version(4)
# headerLen(4) header(headerLen) ZIP... -> zip starts at 12+headerLen.
function BuildSyntheticCrx3([byte[]]$zipBytes,[byte[]]$headerBytes){
  $magic = [byte[]]([byte][char]'C',[byte][char]'r',[byte][char]'2',[byte][char]'4')
  $version = [BitConverter]::GetBytes([uint32]3)
  $headerLen = [BitConverter]::GetBytes([uint32]$headerBytes.Length)
  $out = New-Object System.Collections.Generic.List[byte]
  $out.AddRange($magic); $out.AddRange($version); $out.AddRange($headerLen); $out.AddRange($headerBytes); $out.AddRange($zipBytes)
  return ,$out.ToArray()
}
function StripCrx3Header([byte[]]$crxBytes){
  if($crxBytes.Length -lt 16 -or [char]$crxBytes[0] -ne 'C' -or [char]$crxBytes[1] -ne 'r' -or [char]$crxBytes[2] -ne '2' -or [char]$crxBytes[3] -ne '4'){
    throw "bad CRX magic"
  }
  $version = [BitConverter]::ToUInt32($crxBytes, 4)
  if($version -ne 3){ throw "expected CRX3 in this test" }
  $headerLen = [BitConverter]::ToUInt32($crxBytes, 8)
  $zipStart = 12 + [int]$headerLen
  $zip = New-Object byte[] ($crxBytes.Length - $zipStart)
  [Array]::Copy($crxBytes, $zipStart, $zip, 0, $zip.Length)
  return ,$zip
}

try {
  # --- build a tiny synthetic MV3 extension, allowed by the default policy ---
  $extDir = Join-Path $TempRoot "ext-src"
  New-Item -ItemType Directory -Force -Path $extDir | Out-Null
  Set-Content -LiteralPath (Join-Path $extDir "manifest.json") -NoNewline -Encoding utf8 -Value (
    '{"name":"selftest-ext","version":"1.0","manifest_version":3,"permissions":["storage"]}'
  )
  Set-Content -LiteralPath (Join-Path $extDir "background.js") -NoNewline -Encoding utf8 -Value "// noop`n"

  $policyPath = Join-Path $RepoRoot "config\extension_policy.v1.json"
  $ledger = Join-Path $TempRoot "ledger.ndjson"

  $idInfo = RG-ComputeIdentity $extDir
  $manifest = RG-ReadManifest $extDir
  $policy = RG-LoadPolicy $policyPath
  $decision = RG-Decide $manifest $idInfo.extension_id $policy
  Check ($decision.decision -eq "allow") "synthetic extension (storage only) decides 'allow' under the real policy"
  $tail = RG-LedgerTailHash $ledger
  $rec = RG-BuildRecord ([int]$tail.seq + 1) $idInfo.extension_id $manifest $idInfo.files $decision ([string]$tail.head)
  RCE-AppendLine $ledger (RCE-CanonJson $rec)

  $origId = $idInfo.extension_id
  $origHashes = DirFileHashes $extDir

  # --- zip round-trip: identity and content must be unchanged ---
  $zipPath = Join-Path $TempRoot "ext.zip"
  Compress-Archive -Path (Join-Path $extDir "*") -DestinationPath $zipPath -Force
  $unzipDir = Join-Path $TempRoot "ext-from-zip"
  Expand-Archive -LiteralPath $zipPath -DestinationPath $unzipDir -Force
  $zipHashes = DirFileHashes $unzipDir
  Check (SameHashes $origHashes $zipHashes) "zip round-trip reproduces byte-identical files"
  $zipIdInfo = RG-ComputeIdentity $unzipDir
  Check ($zipIdInfo.extension_id -eq $origId) "zip round-trip does not change the governed extension_id"
  $verifyRec = RG-LatestDecision $ledger $zipIdInfo.extension_id
  Check ($null -ne $verifyRec -and [string](RG-Get $verifyRec "policy_decision") -eq "allow") "load gate allows the zip-extracted copy under the SAME ledger record (no re-registration needed)"

  # --- CRX3 round-trip: strip header using the exact C# offset formula, then unzip ---
  $zipBytes = [System.IO.File]::ReadAllBytes($zipPath)
  $fakeHeader = [System.Text.Encoding]::UTF8.GetBytes("not-a-real-protobuf-header-just-bytes")
  $crxBytes = BuildSyntheticCrx3 $zipBytes $fakeHeader
  $recoveredZip = StripCrx3Header $crxBytes
  Check (($recoveredZip.Length -eq $zipBytes.Length) -and (-not (Compare-Object $recoveredZip $zipBytes -SyncWindow 0))) "CRX3 header-strip (12+headerLen) recovers the exact original zip bytes"

  $crxZipPath = Join-Path $TempRoot "from-crx.zip"
  [System.IO.File]::WriteAllBytes($crxZipPath, $recoveredZip)
  $crxUnzipDir = Join-Path $TempRoot "ext-from-crx"
  Expand-Archive -LiteralPath $crxZipPath -DestinationPath $crxUnzipDir -Force
  $crxHashes = DirFileHashes $crxUnzipDir
  Check (SameHashes $origHashes $crxHashes) "CRX3 round-trip reproduces byte-identical files"
  $crxIdInfo = RG-ComputeIdentity $crxUnzipDir
  Check ($crxIdInfo.extension_id -eq $origId) "CRX3 round-trip does not change the governed extension_id"

  # --- negative: tamper after extraction still refuses ---
  Add-Content -LiteralPath (Join-Path $crxUnzipDir "background.js") -Value "// injected" -Encoding utf8
  $tamperedIdInfo = RG-ComputeIdentity $crxUnzipDir
  Check ($tamperedIdInfo.extension_id -ne $origId) "tampering the extracted copy changes its extension_id"
  $tamperedRec = RG-LatestDecision $ledger $tamperedIdInfo.extension_id
  Check ($null -eq $tamperedRec) "tampered copy has no ledger record — load gate would refuse it"
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("EXTENSION_ADAPTER_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_EXTENSION_ADAPTER_V1_OK" -ForegroundColor Green
