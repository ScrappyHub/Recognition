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

$out = & dotnet run --project $proj -c Release 2>&1 | Out-String
Write-Host $out
if($LASTEXITCODE -ne 0){ Write-Host "BROWSER_TESTS_FAIL: dotnet run exited with code $LASTEXITCODE" -ForegroundColor Red; exit 1 }
if($out -notmatch "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK"){ Write-Host "BROWSER_TESTS_FAIL: success token not emitted" -ForegroundColor Red; exit 1 }
Write-Host "SELFTEST_RECOGNITION_BROWSER_GOVERNED_ACTIONS_V1_OK" -ForegroundColor Green
