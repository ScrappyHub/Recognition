# (Also executes the real AppearanceSettings class: validated colours / allowlisted fonts only.)
# Selftest — executes the browser's REAL GovernedActions C# class (browser.tests project; the same
# browser\GovernedActions.cs source the browser compiles) against golden + negative vectors.
# This closes the "PowerShell mirror only" gap for the governance ledger used by action receipts,
# cookies, site policy and certificate trust. Requires the .NET 8 SDK (same as the browser build).
# Token: SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK

param([string]$RepoRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($RepoRoot)){ $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if(-not $dotnet){ Write-Host "BROWSER_TESTS_FAIL: .NET SDK not found (needed to execute the C# governance tests)" -ForegroundColor Red; exit 1 }

$proj = Join-Path (Join-Path $RepoRoot "browser.tests") "Recognition.Browser.Tests.csproj"
if(-not (Test-Path -LiteralPath $proj -PathType Leaf)){ Write-Host ("BROWSER_TESTS_FAIL: missing " + $proj) -ForegroundColor Red; exit 1 }

# Static source invariants for the password vault + setup snapshot (the parts the C# tests cannot execute: WPF glue).
$bdir = Join-Path $RepoRoot "browser"
$pwGlue = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Passwords.cs") -Raw
$setupGlue = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Setup.cs") -Raw
$setupCore = Get-Content -LiteralPath (Join-Path $bdir "SetupSnapshot.cs") -Raw
$bad = @()
foreach($m in [regex]::Matches($pwGlue, '_actions\?\.Append\([^;]*;')){ if($m.Value -match '(?i)\.Password|\bpw\b|secret'){ $bad += ("receipt carries a secret: " + $m.Value) } }
foreach($m in [regex]::Matches($setupGlue, '_actions\?\.Append\([^;]*;')){ if($m.Value -match '(?i)\bcode\b|\bblob\b|\bpayload\b'){ $bad += ("setup receipt carries code/blob: " + $m.Value) } }
if($setupGlue -match '_vault|PasswordVault|VaultEntry' -or $setupCore -match '_vault|PasswordVault|VaultEntry'){ $bad += "setup snapshot code must never reference the password vault" }
if($pwGlue -notmatch 'PasswordRules\.MayFill'){ $bad += "Fill must be gated by PasswordRules.MayFill" }
if(([regex]::Matches($pwGlue, 'MayFill')).Count -lt 2){ $bad += "Fill must re-check the origin at injection time" }
if($pwGlue -match 'NavigationCompleted|DOMContentLoaded|WebResourceRequested'){ $bad += "vault must not auto-fill on page events" }
# Local-only invariant: the privacy/tools/viewer/vault/setup modules must not open sockets, spawn processes or load code.
foreach($f in @("PdfTools.cs","ImageMath.cs","CodeHighlighter.cs","PrivacyRules.cs","PasswordVault.cs","SetupSnapshot.cs","MainWindow.Tools.cs","MainWindow.Passwords.cs","MainWindow.Setup.cs")){
  $p = Join-Path $bdir $f
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ $bad += ("missing source file: " + $f); continue }
  $src = Get-Content -LiteralPath $p -Raw
  if($src -match 'HttpClient|WebClient|WebRequest|TcpClient|UdpClient|Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create'){ $bad += ($f + " must stay local-only (no network clients, process launch or dynamic code loading)") }
}
$toolsGlue = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Tools.cs") -Raw
if(([regex]::Matches($toolsGlue, 'would overwrite the original')).Count -lt 2){ $bad += "PDF and image tools must refuse to overwrite the original file" }
foreach($m in [regex]::Matches($toolsGlue, '_actions\?\.Append\([^;]*;')){ if($m.Value -match '(?i)\btext\b|\bhtml\b|\bdata\b\s*\)'){ $bad += ("tools receipt must carry names/hashes only: " + $m.Value) } }
$navGlue = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.xaml.cs") -Raw
$iGate = $navGlue.IndexOf('MessageGate.Classify(tab.IsInternal')
$iOpen = $navGlue.IndexOf('msg.StartsWith("open:")')
$iSite = $navGlue.IndexOf('msg.StartsWith("site-perm:")')
if($iGate -lt 0){ $bad += "OnWebMessage must gate every message with MessageGate.Classify(tab.IsInternal, source, msg) (web pages can call window.chrome.webview.postMessage)" }
elseif(($iOpen -gt 0 -and $iGate -gt $iOpen) -or ($iSite -gt 0 -and $iGate -gt $iSite)){ $bad += "the MessageGate check must run BEFORE any command handler" }
if($navGlue -notmatch 'DownloadRules\.Assess'){ $bad += "downloads must be assessed with DownloadRules.Assess" }
if($navGlue -notmatch 'isTrusted'){ $bad += "keyboard shortcut script must ignore synthetic (untrusted) events" }
if($navGlue -notmatch 'PrivacyRules\.HttpsUpgrade'){ $bad += "navigation must use PrivacyRules.HttpsUpgrade (parsed-host loopback check)" }
if($navGlue -match 'StartsWith\("http://localhost"|StartsWith\("http://127\.0\.0\.1"'){ $bad += "regression: prefix-based localhost exemption (http://localhost.evil.com bypass) is back" }
# Shield + filter engine invariants.
$fe = Get-Content -LiteralPath (Join-Path $bdir "FilterEngine.cs") -Raw
$fg = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Filters.cs") -Raw
$sj = Get-Content -LiteralPath (Join-Path $bdir "shield\fingerprint_shield.js") -Raw
# SoteriaVault link: optional, read-only, no secrets, no processes, no network (docs\proposals\SOTERIA_INTEGRATION_V1.md).
$sb = Get-Content -LiteralPath (Join-Path $bdir "SoteriaBridge.cs") -Raw
$sw = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Soteria.cs") -Raw
if($sb -match 'HttpClient|WebClient|WebRequest|TcpClient|UdpClient|Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create|System\.Text\.RegularExpressions|File\.Write|File\.Delete|Directory\.Delete'){ $bad += "SoteriaBridge.cs must stay pure: no network, processes, writes, deletes or regex" }
if($sw -match 'HttpClient|WebClient|WebRequest|Process\.Start|ProcessStartInfo|File\.Write|File\.Delete|Directory\.Delete|File\.Copy|File\.Move|PasswordVault|Decrypt|Unprotect'){ $bad += "MainWindow.Soteria.cs may only read the two contract files: no processes, writes, network or secret handling" }
if($sb -notmatch 'secret_release_to_external_runtime' -or $sb -notmatch 'hard_runtime_dependency' -or $sb -notmatch 'must_not_fail_if_absent'){ $bad += "the SoteriaVault link must refuse a contract that allows secret release or hard dependencies" }
if($sw -notmatch 'soteria\.check'){ $bad += "SoteriaVault checks must be receipted (soteria.check)" }
if($sw -notmatch 'IsSafeRoot'){ $bad += "the SoteriaVault folder must pass SoteriaBridge.IsSafeRoot before use" }
if($fe -match 'HttpClient|WebClient|WebRequest|TcpClient|UdpClient|Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create|System\.Text\.RegularExpressions'){ $bad += "FilterEngine.cs must stay local-only and regex-free (no network, processes, dynamic code, or backtracking regex on hostile lists)" }
if($fg -match 'Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create|TcpClient|UdpClient|WebClient'){ $bad += "MainWindow.Filters.cs may only use HttpClient for the list updater" }
if(([regex]::Matches($fg, 'new HttpClient\(')).Count -ne 1){ $bad += "exactly one HttpClient (the user-initiated list updater) is allowed in MainWindow.Filters.cs" }
if($fg -notmatch 'Scheme != Uri\.UriSchemeHttps'){ $bad += "list updater must refuse non-https URLs" }
if($fg -notmatch 'MaxListBytes'){ $bad += "list updater must cap download size" }
if($fg -notmatch 'filters\.update'){ $bad += "list updates must be receipted (filters.update with SHA-256)" }
if($sj -match '(?m)^[^/\r\n]*postMessage\('){ $bad += "fingerprint_shield.js must not use postMessage (the host refuses commands from web content)" }
if($sj -match '\beval\s*\(|new Function|document\.write'){ $bad += "fingerprint_shield.js must not use eval/new Function/document.write" }
$pk = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Passkeys.cs") -Raw
$pg = Get-Content -LiteralPath (Join-Path $bdir "shield\passkey_guard.js") -Raw
if($pk -match 'HttpClient|WebClient|WebRequest|Assembly\.Load|Activator\.Create'){ $bad += "MainWindow.Passkeys.cs must not make outbound requests or load code" }
if(([regex]::Matches($pk, 'Prefixes\.Add\(')).Count -ne 1 -or $pk -notmatch 'Prefixes\.Add\("http://localhost:"'){ $bad += "the passkey test server must listen on exactly one http://localhost:<port>/ prefix" }
if($pk -match 'http://\+|http://\*|0\.0\.0\.0|IPAddress\.Any'){ $bad += "the passkey test server must never bind beyond loopback" }
if($pk -notmatch 'UserHostName'){ $bad += "the passkey test server must check the Host header (DNS rebinding)" }
if($pk -notmatch 'RandomNumberGenerator'){ $bad += "the passkey test path must contain an unguessable token" }
if($pg -match '(?m)^[^/\r\n]*postMessage\(' -or $pg -match '\beval\s*\(|new Function'){ $bad += "passkey_guard.js must not use postMessage/eval" }
if($pk -match '_actions\?\.Append\([^;]*(challenge|rawId|credential|signature)'){ $bad += "passkey receipts must never carry credential data" }
$eg = Get-Content -LiteralPath (Join-Path $bdir "ExtensionGovernance.cs") -Raw
$ex = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Extensions.cs") -Raw
if($eg -match 'HttpClient|WebClient|WebRequest|TcpClient|Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create'){ $bad += "ExtensionGovernance.cs must stay local-only" }
if($ex -match 'Process\.Start|ProcessStartInfo|Assembly\.Load|Activator\.Create|TcpClient|WebClient'){ $bad += "MainWindow.Extensions.cs must not spawn processes or load code" }
if(([regex]::Matches($ex, 'new HttpClient\(')).Count -ne 1 -or $ex -notmatch 'Scheme != Uri\.UriSchemeHttps' -or $ex -notmatch 'MaxExtDownloadBytes'){ $bad += "extension download must be one https-only, size-capped HttpClient" }
if(([regex]::Matches($ex, 'AddBrowserExtensionAsync\(')).Count -ne 3){ $bad += "AddBrowserExtensionAsync may only be called by the gated loader, the gated enable path, and the isolated test profile" }
if($navGlue -match 'AddBrowserExtensionAsync'){ $bad += "MainWindow.xaml.cs must not register extensions itself" }
if(([regex]::Matches($ex, 'GateDirectory\(')).Count -lt 4){ $bad += "every extension load path must pass GateDirectory (identity recomputed + ledger allow)" }
$iDeny = $ex.IndexOf('decision == "deny"'); $iCopy = $ex.IndexOf('CopyDirectory(p.Root, dst)')
if($iDeny -lt 0 -or $iCopy -lt 0 -or $iDeny -gt $iCopy){ $bad += "a policy-denied extension must be refused before anything is copied into runtime\extensions" }
if($ex -notmatch 'user_approved_review' -or $ex -notmatch 'ExtGovernance\.Record\('){ $bad += "installs and approvals must be recorded in the governance ledger" }
if($ex -notmatch 'removed_unapproved'){ $bad += "extensions the browser did not approve must be removed from the engine profile at startup" }
$hd = Get-Content -LiteralPath (Join-Path $bdir "MainWindow.Hardening.cs") -Raw
if($hd -notmatch 'PopupRules\.Decide' -or $hd -notmatch 'LaunchingExternalUriScheme' -or $hd -notmatch 'ExternalUriRules\.Allowed'){ $bad += "pop-up and external-program rules must be wired in MainWindow.Hardening.cs" }
if($hd -notmatch 'origin\?\.Private'){ $bad += "a pop-up opened from a private tab must stay private" }
if($navGlue -match 'private void OnNewWindowRequested'){ $bad += "the old unconditional pop-up handler must not return" }
if($navGlue -notmatch "Content-Security-Policy"){ $bad += "internal pages must carry a Content-Security-Policy" }
if($navGlue -notmatch '_filters\.Match\('){ $bad += "OnResourceRequested must use the filter engine" }
if($navGlue -notmatch 'RegisterShieldAsync'){ $bad += "every tab must register the fingerprint shield" }
if($bad.Count -gt 0){ $bad | ForEach-Object { Write-Host ("BROWSER_TESTS_FAIL: " + $_) -ForegroundColor Red }; exit 1 }
Write-Host "  ok  - static: filter engine is local-only and regex-free; list updater is https-only, size-capped, receipted; shield never uses postMessage"
Write-Host "  ok  - static: receipts carry no secrets; setup never touches the vault; Fill is origin-gated twice and never event-driven"
Write-Host "  ok  - static: privacy/tools/viewer/vault/setup modules are local-only; tools never overwrite originals; no prefix-based localhost exemption"

# Fingerprint shield maths run under node when it is installed (they are JavaScript, not C#).
$node = Get-Command node -ErrorAction SilentlyContinue
if($node){
  $shieldOut = & node (Join-Path $RepoRoot "browser.tests\shield\shield.test.js") 2>&1 | Out-String
  Write-Host $shieldOut
  if($LASTEXITCODE -ne 0){ Write-Host "BROWSER_TESTS_FAIL: fingerprint shield tests failed" -ForegroundColor Red; exit 1 }
  $pkOut = & node (Join-Path $RepoRoot "browser.tests\shield\passkey.test.js") 2>&1 | Out-String
  Write-Host $pkOut
  if($LASTEXITCODE -ne 0){ Write-Host "BROWSER_TESTS_FAIL: passkey guard/test-page tests failed" -ForegroundColor Red; exit 1 }
} else { Write-Host "  note - node not installed: fingerprint shield JS tests were skipped (install Node.js to run them)" -ForegroundColor Yellow }

$out = & dotnet run --project $proj -c Release 2>&1 | Out-String
Write-Host $out
if($LASTEXITCODE -ne 0){ Write-Host "BROWSER_TESTS_FAIL: dotnet run exited with code $LASTEXITCODE" -ForegroundColor Red; exit 1 }
if($out -notmatch "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK"){ Write-Host "BROWSER_TESTS_FAIL: success token not emitted" -ForegroundColor Red; exit 1 }
Write-Host "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK" -ForegroundColor Green
