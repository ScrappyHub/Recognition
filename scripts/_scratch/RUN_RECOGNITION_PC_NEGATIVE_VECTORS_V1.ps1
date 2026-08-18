param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){
    $x=$e[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
}

function Copy-Dir([string]$Src,[string]$Dst){
  if(Test-Path -LiteralPath $Dst){ Remove-Item -LiteralPath $Dst -Recurse -Force }
  New-Item -ItemType Directory -Force -Path $Dst | Out-Null
  Copy-Item -LiteralPath (Join-Path $Src '*') -Destination $Dst -Recurse -Force
}

function Expect-FailToken([scriptblock]$Action,[string]$Needle,[string]$Label){
  $ok = $false
  try {
    & $Action | Out-Host
    $ok = $false
  } catch {
    $msg = $_ | Out-String
    if($msg -match [regex]::Escape($Needle)){
      Write-Host ($Label + ": " + $Needle) -ForegroundColor Green
      $ok = $true
    } else {
      throw ("UNEXPECTED_FAIL_TOKEN[" + $Label + "]: " + $msg)
    }
  }
  if(-not $ok){
    throw ("NEGATIVE_EXPECTED_FAILURE_BUT_PASSED: " + $Label)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"

$Builder  = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$Verifier = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$Selftest = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$Exporter = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"

foreach($p in @($Builder,$Verifier,$Selftest,$Exporter)){
  ParseGateFile $p
}

# Start from known good state
& $Selftest -RepoRoot $RepoRoot | Out-Host

$tvRoot   = Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_negative_vectors"
$payload  = Join-Path $tvRoot "payload"
$out      = Join-Path $tvRoot "out"
$work     = Join-Path $tvRoot "work"

EnsureDir $tvRoot
EnsureDir $payload
EnsureDir $out
EnsureDir $work

WriteUtf8NoBomLf (Join-Path $payload "hello.txt") "hello`n"
WriteUtf8NoBomLf (Join-Path $payload "meta.json") '{"schema":"recognition.payload.meta.v1","note":"negative","n":1}' 

$goodPkt = & $Builder -RepoRoot $RepoRoot -PayloadDir $payload -OutDir $out -PacketName "negbase"
if(-not (Test-Path -LiteralPath $goodPkt -PathType Container)){
  Die ("NEG_BASE_BUILD_FAIL: " + $goodPkt)
}
& $Verifier -PacketDir $goodPkt | Out-Host

# 1) tampered packet_id.txt
$pkt1 = Join-Path $work "tampered_packet_id"
Copy-Dir $goodPkt $pkt1
WriteUtf8NoBomLf (Join-Path $pkt1 "packet_id.txt") ("0" * 64)
Expect-FailToken { & $Verifier -PacketDir $pkt1 } "PACKET_ID_MISMATCH" "NEG_PACKET_ID"

# 2) tampered manifest.json
$pkt2 = Join-Path $work "tampered_manifest"
Copy-Dir $goodPkt $pkt2
Add-Content -LiteralPath (Join-Path $pkt2 "manifest.json") -Value " " -Encoding UTF8
Expect-FailToken { & $Verifier -PacketDir $pkt2 } "SHA256_MISMATCH: manifest.json" "NEG_MANIFEST"

# 3) tampered payload file
$pkt3 = Join-Path $work "tampered_payload"
Copy-Dir $goodPkt $pkt3
Add-Content -LiteralPath (Join-Path $pkt3 "payload\hello.txt") -Value "tamper" -Encoding UTF8
Expect-FailToken { & $Verifier -PacketDir $pkt3 } "SHA256_MISMATCH: payload/hello.txt" "NEG_PAYLOAD"

Write-Host "RECOGNITION_PC_NEGATIVE_VECTORS_V1_OK" -ForegroundColor Green
