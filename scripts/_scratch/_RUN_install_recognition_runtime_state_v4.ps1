param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}
function Write-Utf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function Parse-GateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and $errors.Count -gt 0){
    $e = $errors[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}
function Run-ChildChecked {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$false)][string[]]$Args = @()
  )
  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ Die ("CHILD_MISSING_SCRIPT: " + $ScriptPath) }
  $alist = New-Object System.Collections.Generic.List[string]
  [void]$alist.Add("-NoProfile")
  [void]$alist.Add("-NonInteractive")
  [void]$alist.Add("-ExecutionPolicy")
  [void]$alist.Add("Bypass")
  [void]$alist.Add("-File")
  [void]$alist.Add($ScriptPath)
  foreach($a in @($Args)){ [void]$alist.Add([string]$a) }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $psExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $q = New-Object System.Collections.Generic.List[string]
  foreach($item in @($alist)){
    $s = [string]$item
    if($s.Contains(" ") -or $s.Contains([char]34)){
      [void]$q.Add(([char]34 + $s.Replace([string][char]34, [string]([char]92) + [char]34) + [char]34))
    } else {
      [void]$q.Add($s)
    }
  }
  $psi.Arguments = (@($q) -join " ")
  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()
  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()
  if($stdout){ [Console]::Out.Write($stdout) }
  if($stderr){ [Console]::Error.Write($stderr) }
  if([int]$p.ExitCode -ne 0){ Die ("CHILD_FAIL(" + [int]$p.ExitCode + "): " + $ScriptPath) }
}
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir

$LibPath = Join-Path $ScriptsDir "_lib_recognition_runtime_state_v1.ps1"
$L = New-Object System.Collections.Generic.List[string]
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference = "Stop"')
[void]$L.Add('')
[void]$L.Add('function RR-Die([string]$m){ throw ("RR_FAIL: " + $m) }')
[void]$L.Add('function RR-EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ RR-Die "ENSUREDIR_EMPTY" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }')
[void]$L.Add('function RR-WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc = New-Object System.Text.UTF8Encoding($false); $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; $dir = Split-Path -Parent $Path; if($dir){ RR-EnsureDir $dir }; [System.IO.File]::WriteAllText($Path,$lf,$enc) }')
[void]$L.Add('function RR-ReadUtf8([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ RR-Die ("MISSING_FILE: " + $Path) }; Get-Content -Raw -LiteralPath $Path -Encoding UTF8 }')
[void]$L.Add('function RR-CanonJson([object]$obj){ $pc = Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1"; if(-not (Test-Path -LiteralPath $pc -PathType Leaf)){ RR-Die ("MISSING_PC_LIB: " + $pc) }; . $pc; PC-ToCanonJson $obj }')
[void]$L.Add('function RR-RuntimeRoot([string]$RepoRoot){ Join-Path $RepoRoot "runtime" }')
[void]$L.Add('function RR-SessionDir([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "session" }')
[void]$L.Add('function RR-TabsDir([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "tabs" }')
[void]$L.Add('function RR-EventsPath([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "events.ndjson" }')
[void]$L.Add('function RR-SessionStatePath([string]$RepoRoot){ Join-Path (RR-SessionDir $RepoRoot) "session_state.json" }')
[void]$L.Add('function RR-TabStatePath([string]$RepoRoot,[string]$TabId){ Join-Path (RR-TabsDir $RepoRoot) ($TabId + ".json") }')
[void]$L.Add('function RR-EnsureRuntimeLayout([string]$RepoRoot){ RR-EnsureDir (RR-RuntimeRoot $RepoRoot); RR-EnsureDir (RR-SessionDir $RepoRoot); RR-EnsureDir (RR-TabsDir $RepoRoot); $eventsPath = RR-EventsPath $RepoRoot; if(-not (Test-Path -LiteralPath $eventsPath -PathType Leaf)){ RR-WriteUtf8NoBomLf $eventsPath "" } }')
[void]$L.Add('function RR-ReadJsonObject([string]$Path){ $raw = RR-ReadUtf8 $Path; if([string]::IsNullOrWhiteSpace($raw)){ return $null }; $raw | ConvertFrom-Json }')
[void]$L.Add('function RR-ReadSessionState([string]$RepoRoot){ $p = RR-SessionStatePath $RepoRoot; if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ return $null }; RR-ReadJsonObject $p }')
[void]$L.Add('function RR-WriteSessionState([string]$RepoRoot,[hashtable]$State){ RR-EnsureRuntimeLayout $RepoRoot; RR-WriteUtf8NoBomLf (RR-SessionStatePath $RepoRoot) (RR-CanonJson $State) }')
[void]$L.Add('function RR-ReadTabState([string]$RepoRoot,[string]$TabId){ $p = RR-TabStatePath $RepoRoot $TabId; if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ return $null }; RR-ReadJsonObject $p }')
[void]$L.Add('function RR-WriteTabState([string]$RepoRoot,[string]$TabId,[hashtable]$State){ RR-EnsureRuntimeLayout $RepoRoot; RR-WriteUtf8NoBomLf (RR-TabStatePath $RepoRoot $TabId) (RR-CanonJson $State) }')
[void]$L.Add('function RR-GetNextSeq([string]$RepoRoot){ RR-EnsureRuntimeLayout $RepoRoot; $raw = RR-ReadUtf8 (RR-EventsPath $RepoRoot); if([string]::IsNullOrWhiteSpace($raw)){ return 1 }; $lines = @(@($raw -split "`n") | Where-Object { $_ -and $_.Trim().Length -gt 0 }); if($lines.Count -eq 0){ return 1 }; $last = $lines[-1] | ConvertFrom-Json; return ([int]$last.seq + 1) }')
[void]$L.Add('function RR-AppendEvent([string]$RepoRoot,[hashtable]$Event){ RR-EnsureRuntimeLayout $RepoRoot; $canon = RR-CanonJson $Event; $path = RR-EventsPath $RepoRoot; $enc = New-Object System.Text.UTF8Encoding($false); $text = ($canon -replace "`r`n","`n") -replace "`r","`n"; if(-not $text.EndsWith("`n")){ $text += "`n" }; [System.IO.File]::AppendAllText($path,$text,$enc) }')
[void]$L.Add('function RR-ExportRuntimeToSessionPayload([string]$RepoRoot,[string]$OutDir){ RR-EnsureRuntimeLayout $RepoRoot; RR-EnsureDir $OutDir; $session = RR-ReadSessionState $RepoRoot; if($null -eq $session){ RR-Die "SESSION_STATE_MISSING" }; $tabFiles = @(@(Get-ChildItem -LiteralPath (RR-TabsDir $RepoRoot) -File -Force | Sort-Object FullName)); $tabs = New-Object System.Collections.Generic.List[object]; foreach($f in $tabFiles){ $raw = RR-ReadUtf8 $f.FullName; if([string]::IsNullOrWhiteSpace($raw)){ continue }; [void]$tabs.Add(($raw | ConvertFrom-Json)) }; $sessionObj = @{ schema="recognition.session.v1"; session_id=[string]$session.session_id; started_utc=[string]$session.started_utc; ended_utc=$session.ended_utc; mode=[string]$session.mode; runtime=@{ platform=[string]$session.platform; surface=[string]$session.surface; recognition_version=[string]$session.recognition_version } }; $tabsObj = @{ schema="recognition.tabs.v1"; tabs=@($tabs) }; $policyObj = @{ schema="recognition.policy_state.v1"; policy_pack_id="recognition.standard.v1"; policy_pack_version=1; mode=[string]$session.mode; effective_rules=@(); default_network_policy="allow"; default_storage_policy="allow" }; $trustObj = @{ schema="recognition.trust_context.v1"; trust_bundle_present=(Test-Path -LiteralPath (Join-Path $RepoRoot "proofs\trust\trust_bundle.json") -PathType Leaf); trust_bundle_path="proofs/trust/trust_bundle.json"; allowed_signers_path="proofs/trust/allowed_signers"; active_principal=$null }; $vpnObj = @{ schema="recognition.vpn_state.v1"; vpn_mode="off"; vpn_connected=$false; kill_switch_enabled=$false; provider_id=$null }; $exportManifestObj = @{ schema="recognition.session_export_manifest.v1"; session_schema="recognition.session.v1"; tabs_schema="recognition.tabs.v1"; events_schema="recognition.event.v1"; policy_state_schema="recognition.policy_state.v1"; trust_context_schema="recognition.trust_context.v1"; vpn_state_schema="recognition.vpn_state.v1" }; RR-WriteUtf8NoBomLf (Join-Path $OutDir "session.json") (RR-CanonJson $sessionObj); RR-WriteUtf8NoBomLf (Join-Path $OutDir "tabs.json") (RR-CanonJson $tabsObj); RR-WriteUtf8NoBomLf (Join-Path $OutDir "policy_state.json") (RR-CanonJson $policyObj); RR-WriteUtf8NoBomLf (Join-Path $OutDir "trust_context.json") (RR-CanonJson $trustObj); RR-WriteUtf8NoBomLf (Join-Path $OutDir "vpn_state.json") (RR-CanonJson $vpnObj); RR-WriteUtf8NoBomLf (Join-Path $OutDir "export_manifest.json") (RR-CanonJson $exportManifestObj); $eventsRaw = RR-ReadUtf8 (RR-EventsPath $RepoRoot); RR-WriteUtf8NoBomLf (Join-Path $OutDir "events.ndjson") $eventsRaw }')
Write-Utf8NoBomLf $LibPath ((@($L) -join "`n") + "`n")
Parse-GateFile $LibPath
Write-Host ("PARSE_OK: " + $LibPath) -ForegroundColor Green

$OpenPath = Join-Path $ScriptsDir "recognition_runtime_session_open_v1.ps1"
$open = @'
param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$false)][string]$SessionId = "recognition-session-v1",[Parameter(Mandatory=$false)][string]$StartedUtc = "2026-03-31T12:00:00.000Z",[Parameter(Mandatory=$false)][string]$Mode = "standard")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
RR-EnsureRuntimeLayout $RepoRoot
$state = @{ schema="recognition.runtime.session_state.v1"; session_id=$SessionId; started_utc=$StartedUtc; ended_utc=$null; mode=$Mode; platform="windows"; surface="webview2"; recognition_version="runtime_state.v1" }
RR-WriteSessionState $RepoRoot $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$StartedUtc; type="session.started"; tab_id=$null; data=@{ mode=$Mode; session_id=$SessionId } }
RR-AppendEvent $RepoRoot $event
Write-Host ("RUNTIME_SESSION_OPEN_OK: " + $SessionId) -ForegroundColor Green
'@
Write-Utf8NoBomLf $OpenPath $open
Parse-GateFile $OpenPath
Write-Host ("PARSE_OK: " + $OpenPath) -ForegroundColor Green

$TabOpenPath = Join-Path $ScriptsDir "recognition_runtime_tab_open_v1.ps1"
$tabOpen = @'
param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][int]$Index,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$OpenedUtc = "2026-03-31T12:00:05.000Z",[Parameter(Mandatory=$false)][int]$IsActive = 0)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$session = RR-ReadSessionState $RepoRoot
if($null -eq $session){ RR-Die "OPEN_TAB_WITHOUT_SESSION" }
$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=$TabId; index=$Index; url=$Url; title=$Title; is_active=($IsActive -ne 0); is_pinned=$false; opened_utc=$OpenedUtc; last_committed_navigation_utc=$OpenedUtc }
RR-WriteTabState $RepoRoot $TabId $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$OpenedUtc; type="tab.opened"; tab_id=$TabId; data=@{ url=$Url; title=$Title; index=$Index } }
RR-AppendEvent $RepoRoot $event
Write-Host ("RUNTIME_TAB_OPEN_OK: " + $TabId) -ForegroundColor Green
'@
Write-Utf8NoBomLf $TabOpenPath $tabOpen
Parse-GateFile $TabOpenPath
Write-Host ("PARSE_OK: " + $TabOpenPath) -ForegroundColor Green

$NavPath = Join-Path $ScriptsDir "recognition_runtime_navigation_commit_v1.ps1"
$nav = @'
param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$CommittedUtc = "2026-03-31T12:00:10.000Z")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$tab = RR-ReadTabState $RepoRoot $TabId
if($null -eq $tab){ RR-Die ("NAV_WITHOUT_TAB: " + $TabId) }
$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=[string]$tab.tab_id; index=[int]$tab.index; url=$Url; title=$Title; is_active=[bool]$tab.is_active; is_pinned=[bool]$tab.is_pinned; opened_utc=[string]$tab.opened_utc; last_committed_navigation_utc=$CommittedUtc }
RR-WriteTabState $RepoRoot $TabId $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$CommittedUtc; type="navigation.committed"; tab_id=$TabId; data=@{ url=$Url; title=$Title } }
RR-AppendEvent $RepoRoot $event
Write-Host ("RUNTIME_NAV_COMMIT_OK: " + $TabId) -ForegroundColor Green
'@
Write-Utf8NoBomLf $NavPath $nav
Parse-GateFile $NavPath
Write-Host ("PARSE_OK: " + $NavPath) -ForegroundColor Green

$RuntimeExportPath = Join-Path $ScriptsDir "recognition_runtime_export_from_runtime_v1.ps1"
$rexp = @'
param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$false)][string]$SessionExportDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($SessionExportDir)){ $SessionExportDir = Join-Path $RepoRoot "payload\session_export" }
RR-ExportRuntimeToSessionPayload $RepoRoot $SessionExportDir
Write-Host ("RUNTIME_EXPORT_OK: " + $SessionExportDir) -ForegroundColor Green
'@
Write-Utf8NoBomLf $RuntimeExportPath $rexp
Parse-GateFile $RuntimeExportPath
Write-Host ("PARSE_OK: " + $RuntimeExportPath) -ForegroundColor Green

$SelfPath = Join-Path $ScriptsDir "_selftest_recognition_runtime_state_v1.ps1"
$self = @'
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
foreach($p in @($RuntimeRoot,$PayloadDir,$OutDir)){ if(Test-Path -LiteralPath $p -PathType Container){ Remove-Item -LiteralPath $p -Recurse -Force } }
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpenPath -RepoRoot $RepoRoot -SessionId "recognition-runtime-selftest-v1" -StartedUtc "2026-03-31T12:00:00.000Z" -Mode "standard" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpenPath -RepoRoot $RepoRoot -TabId "tab-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -OpenedUtc "2026-03-31T12:00:05.000Z" -IsActive 1 | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavPath -RepoRoot $RepoRoot -TabId "tab-001" -Url "https://example.com/" -Title "Example Domain" -CommittedUtc "2026-03-31T12:00:10.000Z" | Out-Host
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RuntimeExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir | Out-Host
foreach($p in @((Join-Path $PayloadDir "session.json"),(Join-Path $PayloadDir "tabs.json"),(Join-Path $PayloadDir "events.ndjson"),(Join-Path $PayloadDir "policy_state.json"),(Join-Path $PayloadDir "trust_context.json"),(Join-Path $PayloadDir "vpn_state.json"),(Join-Path $PayloadDir "export_manifest.json"))){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ throw ("SELFTEST_RUNTIME_EXPORT_MISSING_FILE: " + $p) } }
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir -OutDir $OutDir -PacketName "recognition_runtime_export" | Out-Host
$packetDirs = @(@(Get-ChildItem -LiteralPath $OutDir -Directory -Force | Sort-Object Name))
if($packetDirs.Count -ne 1){ throw ("SELFTEST_RUNTIME_PACKET_COUNT_BAD: " + $packetDirs.Count) }
$pktDir = $packetDirs[0].FullName
& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $VerifyPath -PacketDir $pktDir | Out-Host
Write-Host ("SELFTEST_RECOGNITION_RUNTIME_STATE_V1_OK: " + $pktDir) -ForegroundColor Green
'@
Write-Utf8NoBomLf $SelfPath $self
Parse-GateFile $SelfPath
Write-Host ("PARSE_OK: " + $SelfPath) -ForegroundColor Green

Run-ChildChecked -ScriptPath $SelfPath -Args @("-RepoRoot",$RepoRoot)
Write-Host ("RECOGNITION_RUNTIME_STATE_V1_INSTALL_OK: " + $RepoRoot) -ForegroundColor Green
