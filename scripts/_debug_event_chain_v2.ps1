param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "_lib_recognition_event_chain_v2.ps1")

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

# 1. direct parser probes
foreach($probe in @('{"a":1}','{}','{"mode":"selftest","session_id":"sid-1"}','{"url":"about:blank","index":0}')){
  try {
    $r = RCE-ParseJson $probe
    $keys = "-"
    if($r -is [System.Collections.IDictionary]){ $keys = (@($r.Keys) -join ",") }
    Write-Output ("PROBE_OK: <" + $probe + "> keys=" + $keys + " recanon=<" + (RCE-CanonJson $r) + ">")
  } catch {
    Write-Output ("PROBE_ERR: <" + $probe + "> " + $_.Exception.Message)
  }
}

# 2. append script invoked exactly like the selftest does
$tmp = Join-Path $RepoRoot (Join-Path "tmp" "debug_chain_v2")
if(Test-Path -LiteralPath $tmp){ Remove-Item -LiteralPath $tmp -Recurse -Force }
RCE-EnsureDir $tmp
$chain = Join-Path $tmp "events.v2.ndjson"
$AppendScript = Join-Path $PSScriptRoot "recognition_event_append_v2.ps1"
$common = @{ RepoRoot=$RepoRoot; ChainPath=$chain; SessionId="dbg-session"; ProfileId="dbg-profile"; DeviceId="dbg-device" }

try {
  $out = & $AppendScript @common -Type "session.started" -DataJson '{"mode":"dbg","session_id":"dbg-session"}' *>&1 | Out-String
  Write-Output ("APPEND1: " + $out.Trim())
} catch {
  Write-Output ("APPEND1_ERR: " + $_.Exception.Message)
}

try {
  $out = & $AppendScript @common -Type "tab.opened" -TabId "tab-1" -DataJson '{"url":"about:blank","index":0}' *>&1 | Out-String
  Write-Output ("APPEND2: " + $out.Trim())
} catch {
  Write-Output ("APPEND2_ERR: " + $_.Exception.Message)
}

try {
  $v = RCE-VerifyChain $chain
  Write-Output ("VERIFY_COUNT: " + $v.event_count + " HEAD: " + $v.head_hash)
} catch {
  Write-Output ("VERIFY_ERR: " + $_.Exception.Message)
}

if(Test-Path -LiteralPath $tmp){ Remove-Item -LiteralPath $tmp -Recurse -Force }
Write-Output "DEBUG_CHAIN_OK"
