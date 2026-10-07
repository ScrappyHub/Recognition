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
if($bad.Count -gt 0){ $bad | ForEach-Object { Write-Host ("BROWSER_TESTS_FAIL: " + $_) -ForegroundColor Red }; exit 1 }
Write-Host "  ok  - static: receipts carry no secrets; setup never touches the vault; Fill is origin-gated twice and never event-driven"
Write-Host "  ok  - static: privacy/tools/viewer/vault/setup modules are local-only; tools never overwrite originals; no prefix-based localhost exemption"

$out = & dotnet run --project $proj -c Release 2>&1 | Out-String
Write-Host $out
if($LASTEXITCODE -ne 0){ Write-Host "BROWSER_TESTS_FAIL: dotnet run exited with code $LASTEXITCODE" -ForegroundColor Red; exit 1 }
if($out -notmatch "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK"){ Write-Host "BROWSER_TESTS_FAIL: success token not emitted" -ForegroundColor Red; exit 1 }
Write-Host "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK" -ForegroundColor Green
