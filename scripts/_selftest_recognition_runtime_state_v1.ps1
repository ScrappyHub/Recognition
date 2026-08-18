param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$PSExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source

$SessionOpenPath   = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"
$TabOpenPath       = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"
$NavPath           = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"
$RuntimeExportPath = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"
$ExportPath        = Join-Path $RepoRoot "scripts\recognition_export_session_packet_v1.ps1"
$VerifyPath        = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"

$RuntimeRoot = Join-Path $RepoRoot "runtime"
$PayloadDir  = Join-Path $RepoRoot "payload\session_export"
$OutDir      = Join-Path $RepoRoot "test_vectors\recognition_runtime_state_v1\packet_out"

foreach($p in @($RuntimeRoot,$PayloadDir,$OutDir)){
  if(Test-Path -LiteralPath $p -PathType Container){
    Remove-Item -LiteralPath $p -Recurse -Force
  }
}

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpenPath -RepoRoot $RepoRoot -SessionId "recognition-runtime-selftest-v1" -StartedUtc "2026-03-31T12:00:00.000Z" -Mode "standard" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpenPath -RepoRoot $RepoRoot -TabId "tab-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -OpenedUtc "2026-03-31T12:00:05.000Z" -IsActive 1 | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavPath -RepoRoot $RepoRoot -TabId "tab-001" -Url "https://example.com/" -Title "Example Domain" -CommittedUtc "2026-03-31T12:00:10.000Z" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RuntimeExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir | Out-Host

foreach($p in @(
  (Join-Path $PayloadDir "session.json"),
  (Join-Path $PayloadDir "tabs.json"),
  (Join-Path $PayloadDir "events.ndjson"),
  (Join-Path $PayloadDir "policy_state.json"),
  (Join-Path $PayloadDir "trust_context.json"),
  (Join-Path $PayloadDir "vpn_state.json"),
  (Join-Path $PayloadDir "export_manifest.json")
)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){
    throw ("SELFTEST_RUNTIME_EXPORT_MISSING_FILE: " + $p)
  }
}

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir -OutDir $OutDir -PacketName "recognition_runtime_export" | Out-Host

$packetDirs = @(@(Get-ChildItem -LiteralPath $OutDir -Directory -Force | Sort-Object Name))
if($packetDirs.Count -ne 1){
  throw ("SELFTEST_RUNTIME_PACKET_COUNT_BAD: " + $packetDirs.Count)
}
$pktDir = $packetDirs[0].FullName

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $VerifyPath -PacketDir $pktDir | Out-Host
Write-Host ("SELFTEST_RECOGNITION_RUNTIME_STATE_V1_OK: " + $pktDir) -ForegroundColor Green
