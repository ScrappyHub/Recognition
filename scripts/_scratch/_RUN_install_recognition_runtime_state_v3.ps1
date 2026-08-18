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
  $argList = New-Object System.Collections.Generic.List[string]
  [void]$argList.Add("-NoProfile")
  [void]$argList.Add("-NonInteractive")
  [void]$argList.Add("-ExecutionPolicy")
  [void]$argList.Add("Bypass")
  [void]$argList.Add("-File")
  [void]$argList.Add($ScriptPath)
  foreach($a in @($Args)){ [void]$argList.Add([string]$a) }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $psExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $quoted = New-Object System.Collections.Generic.List[string]
  foreach($item in @($argList)){
    $s = [string]$item
    if($s.Contains(" ") -or $s.Contains([char]34)){
      [void]$quoted.Add(([char]34 + $s.Replace([string][char]34, [string]([char]92) + [char]34) + [char]34))
    } else {
      [void]$quoted.Add($s)
    }
  }
  $psi.Arguments = (@($quoted) -join " ")
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

$RepoRoot   = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir

$LibPath = Join-Path $ScriptsDir "_lib_recognition_runtime_state_v1.ps1"
$L = New-Object System.Collections.Generic.List[string]
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference = "Stop"')
[void]$L.Add('')
[void]$L.Add('function RR-Die([string]$m){ throw ("RR_FAIL: " + $m) }')
[void]$L.Add('function RR-EnsureDir([string]$p){')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($p)){ RR-Die "ENSUREDIR_EMPTY" }')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }')
[void]$L.Add('}')
[void]$L.Add('function RR-WriteUtf8NoBomLf([string]$Path,[string]$Text){')
[void]$L.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$L.Add('  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"')
[void]$L.Add('  if(-not $lf.EndsWith("`n")){ $lf += "`n" }')
[void]$L.Add('  $dir = Split-Path -Parent $Path')
[void]$L.Add('  if($dir){ RR-EnsureDir $dir }')
[void]$L.Add('  [System.IO.File]::WriteAllText($Path,$lf,$enc)')
[void]$L.Add('}')
[void]$L.Add('function RR-ReadUtf8([string]$Path){')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ RR-Die ("MISSING_FILE: " + $Path) }')
[void]$L.Add('  Get-Content -Raw -LiteralPath $Path -Encoding UTF8')
[void]$L.Add('}')
[void]$L.Add('function RR-CanonJson([object]$obj){')
[void]$L.Add('  $pc = Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1"')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $pc -PathType Leaf)){ RR-Die ("MISSING_PC_LIB: " + $pc) }')
[void]$L.Add('  . $pc')
[void]$L.Add('  PC-ToCanonJson $obj')
[void]$L.Add('}')
[void]$L.Add('function RR-RuntimeRoot([string]$RepoRoot){ Join-Path $RepoRoot "runtime" }')
[void]$L.Add('function RR-SessionDir([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "session" }')
[void]$L.Add('function RR-TabsDir([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "tabs" }')
[void]$L.Add('function RR-EventsPath([string]$RepoRoot){ Join-Path (RR-RuntimeRoot $RepoRoot) "events.ndjson" }')
[void]$L.Add('function RR-SessionStatePath([string]$RepoRoot){ Join-Path (RR-SessionDir $RepoRoot) "session_state.json" }')
[void]$L.Add('function RR-TabStatePath([string]$RepoRoot,[string]$TabId){ Join-Path (RR-TabsDir $RepoRoot) ($TabId + ".json") }')
[void]$L.Add('function RR-EnsureRuntimeLayout([string]$RepoRoot){')
[void]$L.Add('  RR-EnsureDir (RR-RuntimeRoot $RepoRoot)')
[void]$L.Add('  RR-EnsureDir (RR-SessionDir $RepoRoot)')
[void]$L.Add('  RR-EnsureDir (RR-TabsDir $RepoRoot)')
[void]$L.Add('  $eventsPath = RR-EventsPath $RepoRoot')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $eventsPath -PathType Leaf)){ RR-WriteUtf8NoBomLf $eventsPath "" }')
[void]$L.Add('}')
[void]$L.Add('function RR-ReadSessionState([string]$RepoRoot){')
[void]$L.Add('  $p = RR-SessionStatePath $RepoRoot')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ return $null }')
[void]$L.Add('  $raw = RR-ReadUtf8 $p')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($raw)){ return $null }')
[void]$L.Add('  $raw | ConvertFrom-Json -Depth 100')
[void]$L.Add('}')
[void]$L.Add('function RR-WriteSessionState([string]$RepoRoot,[hashtable]$State){')
[void]$L.Add('  RR-EnsureRuntimeLayout $RepoRoot')
[void]$L.Add('  RR-WriteUtf8NoBomLf (RR-SessionStatePath $RepoRoot) (RR-CanonJson $State)')
[void]$L.Add('}')
[void]$L.Add('function RR-ReadTabState([string]$RepoRoot,[string]$TabId){')
[void]$L.Add('  $p = RR-TabStatePath $RepoRoot $TabId')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ return $null }')
[void]$L.Add('  $raw = RR-ReadUtf8 $p')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($raw)){ return $null }')
[void]$L.Add('  $raw | ConvertFrom-Json -Depth 100')
[void]$L.Add('}')
[void]$L.Add('function RR-WriteTabState([string]$RepoRoot,[string]$TabId,[hashtable]$State){')
[void]$L.Add('  RR-EnsureRuntimeLayout $RepoRoot')
[void]$L.Add('  RR-WriteUtf8NoBomLf (RR-TabStatePath $RepoRoot $TabId) (RR-CanonJson $State)')
[void]$L.Add('}')
[void]$L.Add('function RR-GetNextSeq([string]$RepoRoot){')
[void]$L.Add('  RR-EnsureRuntimeLayout $RepoRoot')
[void]$L.Add('  $raw = RR-ReadUtf8 (RR-EventsPath $RepoRoot)')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($raw)){ return 1 }')
[void]$L.Add('  $lines = @(@($raw -split "`n") | Where-Object { $_ -and $_.Trim().Length -gt 0 })')
[void]$L.Add('  if($lines.Count -eq 0){ return 1 }')
[void]$L.Add('  $last = $lines[-1] | ConvertFrom-Json -Depth 100')
[void]$L.Add('  return ([int]$last.seq + 1)')
[void]$L.Add('}')
[void]$L.Add('function RR-AppendEvent([string]$RepoRoot,[hashtable]$Event){')
[void]$L.Add('  RR-EnsureRuntimeLayout $RepoRoot')
[void]$L.Add('  $canon = RR-CanonJson $Event')
[void]$L.Add('  $path = RR-EventsPath $RepoRoot')
[void]$L.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$L.Add('  $text = ($canon -replace "`r`n","`n") -replace "`r","`n"')
[void]$L.Add('  if(-not $text.EndsWith("`n")){ $text += "`n" }')
[void]$L.Add('  [System.IO.File]::AppendAllText($path,$text,$enc)')
[void]$L.Add('}')
[void]$L.Add('function RR-ExportRuntimeToSessionPayload([string]$RepoRoot,[string]$OutDir){')
[void]$L.Add('  RR-EnsureRuntimeLayout $RepoRoot')
[void]$L.Add('  RR-EnsureDir $OutDir')
[void]$L.Add('  $session = RR-ReadSessionState $RepoRoot')
[void]$L.Add('  if($null -eq $session){ RR-Die "SESSION_STATE_MISSING" }')
[void]$L.Add('  $tabFiles = @(@(Get-ChildItem -LiteralPath (RR-TabsDir $RepoRoot) -File -Force | Sort-Object FullName))')
[void]$L.Add('  $tabs = New-Object System.Collections.Generic.List[object]')
[void]$L.Add('  foreach($f in $tabFiles){')
[void]$L.Add('    $raw = RR-ReadUtf8 $f.FullName')
[void]$L.Add('    if([string]::IsNullOrWhiteSpace($raw)){ continue }')
[void]$L.Add('    [void]$tabs.Add(($raw | ConvertFrom-Json -Depth 100))')
[void]$L.Add('  }')
[void]$L.Add('  $sessionObj = @{ schema="recognition.session.v1"; session_id=[string]$session.session_id; started_utc=[string]$session.started_utc; ended_utc=$session.ended_utc; mode=[string]$session.mode; runtime=@{ platform=[string]$session.platform; surface=[string]$session.surface; recognition_version=[string]$session.recognition_version } }')
[void]$L.Add('  $tabsObj = @{ schema="recognition.tabs.v1"; tabs=@($tabs) }')
[void]$L.Add('  $policyObj = @{ schema="recognition.policy_state.v1"; policy_pack_id="recognition.standard.v1"; policy_pack_version=1; mode=[string]$session.mode; effective_rules=@(); default_network_policy="allow"; default_storage_policy="allow" }')
[void]$L.Add('  $trustObj = @{ schema="recognition.trust_context.v1"; trust_bundle_present=(Test-Path -LiteralPath (Join-Path $RepoRoot "proofs\trust\trust_bundle.json") -PathType Leaf); trust_bundle_path="proofs/trust/trust_bundle.json"; allowed_signers_path="proofs/trust/allowed_signers"; active_principal=$null }')
[void]$L.Add('  $vpnObj = @{ schema="recognition.vpn_state.v1"; vpn_mode="off"; vpn_connected=$false; kill_switch_enabled=$false; provider_id=$null }')
[void]$L.Add('  $exportManifestObj = @{ schema="recognition.session_export_manifest.v1"; session_schema="recognition.session.v1"; tabs_schema="recognition.tabs.v1"; events_schema="recognition.event.v1"; policy_state_schema="recognition.policy_state.v1"; trust_context_schema="recognition.trust_context.v1"; vpn_state_schema="recognition.vpn_state.v1" }')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "session.json") (RR-CanonJson $sessionObj)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "tabs.json") (RR-CanonJson $tabsObj)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "policy_state.json") (RR-CanonJson $policyObj)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "trust_context.json") (RR-CanonJson $trustObj)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "vpn_state.json") (RR-CanonJson $vpnObj)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "export_manifest.json") (RR-CanonJson $exportManifestObj)')
[void]$L.Add('  $eventsRaw = RR-ReadUtf8 (RR-EventsPath $RepoRoot)')
[void]$L.Add('  RR-WriteUtf8NoBomLf (Join-Path $OutDir "events.ndjson") $eventsRaw')
[void]$L.Add('}')
Write-Utf8NoBomLf $LibPath ((@($L) -join "`n") + "`n")
Parse-GateFile $LibPath
Write-Host ("PARSE_OK: " + $LibPath) -ForegroundColor Green

$OpenPath = Join-Path $ScriptsDir "recognition_runtime_session_open_v1.ps1"
$O = New-Object System.Collections.Generic.List[string]
[void]$O.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$false)][string]$SessionId = "recognition-session-v1",[Parameter(Mandatory=$false)][string]$StartedUtc = "2026-03-31T12:00:00.000Z",[Parameter(Mandatory=$false)][string]$Mode = "standard")')
[void]$O.Add('Set-StrictMode -Version Latest')
[void]$O.Add('$ErrorActionPreference = "Stop"')
[void]$O.Add('$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"')
[void]$O.Add('if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }')
[void]$O.Add('. $LibPath')
[void]$O.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$O.Add('RR-EnsureRuntimeLayout $RepoRoot')
[void]$O.Add('$state = @{ schema="recognition.runtime.session_state.v1"; session_id=$SessionId; started_utc=$StartedUtc; ended_utc=$null; mode=$Mode; platform="windows"; surface="webview2"; recognition_version="runtime_state.v1" }')
[void]$O.Add('RR-WriteSessionState $RepoRoot $state')
[void]$O.Add('$seq = RR-GetNextSeq $RepoRoot')
[void]$O.Add('$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$StartedUtc; type="session.started"; tab_id=$null; data=@{ mode=$Mode; session_id=$SessionId } }')
[void]$O.Add('RR-AppendEvent $RepoRoot $event')
[void]$O.Add('Write-Host ("RUNTIME_SESSION_OPEN_OK: " + $SessionId) -ForegroundColor Green')
Write-Utf8NoBomLf $OpenPath ((@($O) -join "`n") + "`n")
Parse-GateFile $OpenPath
Write-Host ("PARSE_OK: " + $OpenPath) -ForegroundColor Green

$TabOpenPath = Join-Path $ScriptsDir "recognition_runtime_tab_open_v1.ps1"
$T = New-Object System.Collections.Generic.List[string]
[void]$T.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][int]$Index,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$OpenedUtc = "2026-03-31T12:00:05.000Z",[Parameter(Mandatory=$false)][int]$IsActive = 0)' )
[void]$T.Add('Set-StrictMode -Version Latest')
[void]$T.Add('$ErrorActionPreference = "Stop"')
[void]$T.Add('$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"')
[void]$T.Add('if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }')
[void]$T.Add('. $LibPath')
[void]$T.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$T.Add('$session = RR-ReadSessionState $RepoRoot')
[void]$T.Add('if($null -eq $session){ RR-Die "OPEN_TAB_WITHOUT_SESSION" }')
[void]$T.Add('$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=$TabId; index=$Index; url=$Url; title=$Title; is_active=($IsActive -ne 0); is_pinned=$false; opened_utc=$OpenedUtc; last_committed_navigation_utc=$OpenedUtc }')
[void]$T.Add('RR-WriteTabState $RepoRoot $TabId $state')
[void]$T.Add('$seq = RR-GetNextSeq $RepoRoot')
[void]$T.Add('$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$OpenedUtc; type="tab.opened"; tab_id=$TabId; data=@{ url=$Url; title=$Title; index=$Index } }')
[void]$T.Add('RR-AppendEvent $RepoRoot $event')
[void]$T.Add('Write-Host ("RUNTIME_TAB_OPEN_OK: " + $TabId) -ForegroundColor Green')
Write-Utf8NoBomLf $TabOpenPath ((@($T) -join "`n") + "`n")
Parse-GateFile $TabOpenPath
Write-Host ("PARSE_OK: " + $TabOpenPath) -ForegroundColor Green

$NavPath = Join-Path $ScriptsDir "recognition_runtime_navigation_commit_v1.ps1"
$N = New-Object System.Collections.Generic.List[string]
[void]$N.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$CommittedUtc = "2026-03-31T12:00:10.000Z")')
[void]$N.Add('Set-StrictMode -Version Latest')
[void]$N.Add('$ErrorActionPreference = "Stop"')
[void]$N.Add('$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"')
[void]$N.Add('if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }')
[void]$N.Add('. $LibPath')
[void]$N.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$N.Add('$tab = RR-ReadTabState $RepoRoot $TabId')
[void]$N.Add('if($null -eq $tab){ RR-Die ("NAV_WITHOUT_TAB: " + $TabId) }')
[void]$N.Add('$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=[string]$tab.tab_id; index=[int]$tab.index; url=$Url; title=$Title; is_active=[bool]$tab.is_active; is_pinned=[bool]$tab.is_pinned; opened_utc=[string]$tab.opened_utc; last_committed_navigation_utc=$CommittedUtc }')
[void]$N.Add('RR-WriteTabState $RepoRoot $TabId $state')
[void]$N.Add('$seq = RR-GetNextSeq $RepoRoot')
[void]$N.Add('$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$CommittedUtc; type="navigation.committed"; tab_id=$TabId; data=@{ url=$Url; title=$Title } }')
[void]$N.Add('RR-AppendEvent $RepoRoot $event')
[void]$N.Add('Write-Host ("RUNTIME_NAV_COMMIT_OK: " + $TabId) -ForegroundColor Green')
Write-Utf8NoBomLf $NavPath ((@($N) -join "`n") + "`n")
Parse-GateFile $NavPath
Write-Host ("PARSE_OK: " + $NavPath) -ForegroundColor Green

$RuntimeExportPath = Join-Path $ScriptsDir "recognition_runtime_export_from_runtime_v1.ps1"
$E = New-Object System.Collections.Generic.List[string]
[void]$E.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$false)][string]$SessionExportDir)' )
[void]$E.Add('Set-StrictMode -Version Latest')
[void]$E.Add('$ErrorActionPreference = "Stop"')
[void]$E.Add('$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"')
[void]$E.Add('if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }')
[void]$E.Add('. $LibPath')
[void]$E.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$E.Add('if([string]::IsNullOrWhiteSpace($SessionExportDir)){ $SessionExportDir = Join-Path $RepoRoot "payload\session_export" }')
[void]$E.Add('RR-ExportRuntimeToSessionPayload $RepoRoot $SessionExportDir')
[void]$E.Add('Write-Host ("RUNTIME_EXPORT_OK: " + $SessionExportDir) -ForegroundColor Green')
Write-Utf8NoBomLf $RuntimeExportPath ((@($E) -join "`n") + "`n")
Parse-GateFile $RuntimeExportPath
Write-Host ("PARSE_OK: " + $RuntimeExportPath) -ForegroundColor Green

$SelfPath = Join-Path $ScriptsDir "_selftest_recognition_runtime_state_v1.ps1"
$S = New-Object System.Collections.Generic.List[string]
[void]$S.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)')
[void]$S.Add('Set-StrictMode -Version Latest')
[void]$S.Add('$ErrorActionPreference = "Stop"')
[void]$S.Add('$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path')
[void]$S.Add('$PSExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source')
[void]$S.Add('$SessionOpenPath   = Join-Path $RepoRoot "scripts\recognition_runtime_session_open_v1.ps1"')
[void]$S.Add('$TabOpenPath       = Join-Path $RepoRoot "scripts\recognition_runtime_tab_open_v1.ps1"')
[void]$S.Add('$NavPath           = Join-Path $RepoRoot "scripts\recognition_runtime_navigation_commit_v1.ps1"')
[void]$S.Add('$RuntimeExportPath = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"')
[void]$S.Add('$ExportPath        = Join-Path $RepoRoot "scripts\recognition_export_session_packet_v1.ps1"')
[void]$S.Add('$VerifyPath        = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"')
[void]$S.Add('$RuntimeRoot = Join-Path $RepoRoot "runtime"')
[void]$S.Add('$PayloadDir  = Join-Path $RepoRoot "payload\session_export"')
[void]$S.Add('$OutDir      = Join-Path $RepoRoot "test_vectors\recognition_runtime_state_v1\packet_out"')
[void]$S.Add('foreach($p in @($RuntimeRoot,$PayloadDir,$OutDir)){ if(Test-Path -LiteralPath $p -PathType Container){ Remove-Item -LiteralPath $p -Recurse -Force } }')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $SessionOpenPath -RepoRoot $RepoRoot -SessionId "recognition-runtime-selftest-v1" -StartedUtc "2026-03-31T12:00:00.000Z" -Mode "standard" | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $TabOpenPath -RepoRoot $RepoRoot -TabId "tab-001" -Index 0 -Url "https://example.com/" -Title "Example Domain" -OpenedUtc "2026-03-31T12:00:05.000Z" -IsActive 1 | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $NavPath -RepoRoot $RepoRoot -TabId "tab-001" -Url "https://example.com/" -Title "Example Domain" -CommittedUtc "2026-03-31T12:00:10.000Z" | Out-Host')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $RuntimeExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir | Out-Host')
[void]$S.Add('foreach($p in @((Join-Path $PayloadDir "session.json"),(Join-Path $PayloadDir "tabs.json"),(Join-Path $PayloadDir "events.ndjson"),(Join-Path $PayloadDir "policy_state.json"),(Join-Path $PayloadDir "trust_context.json"),(Join-Path $PayloadDir "vpn_state.json"),(Join-Path $PayloadDir "export_manifest.json"))){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ throw ("SELFTEST_RUNTIME_EXPORT_MISSING_FILE: " + $p) } }')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ExportPath -RepoRoot $RepoRoot -SessionExportDir $PayloadDir -OutDir $OutDir -PacketName "recognition_runtime_export" | Out-Host')
[void]$S.Add('$packetDirs = @(@(Get-ChildItem -LiteralPath $OutDir -Directory -Force | Sort-Object Name))')
[void]$S.Add('if($packetDirs.Count -ne 1){ throw ("SELFTEST_RUNTIME_PACKET_COUNT_BAD: " + $packetDirs.Count) }')
[void]$S.Add('$pktDir = $packetDirs[0].FullName')
[void]$S.Add('& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $VerifyPath -PacketDir $pktDir | Out-Host')
[void]$S.Add('Write-Host ("SELFTEST_RECOGNITION_RUNTIME_STATE_V1_OK: " + $pktDir) -ForegroundColor Green')
Write-Utf8NoBomLf $SelfPath ((@($S) -join "`n") + "`n")
Parse-GateFile $SelfPath
Write-Host ("PARSE_OK: " + $SelfPath) -ForegroundColor Green

Run-ChildChecked -ScriptPath $SelfPath -Args @("-RepoRoot",$RepoRoot)
Write-Host ("RECOGNITION_RUNTIME_STATE_V1_INSTALL_OK: " + $RepoRoot) -ForegroundColor Green
