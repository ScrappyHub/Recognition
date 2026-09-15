# Build the Recognition governed browser shell (WBS 5.1).
# Requires: .NET 8 SDK, and the Evergreen WebView2 Runtime (preinstalled on Win11).
#   pwsh -File browser\build.ps1            # build
#   pwsh -File browser\build.ps1 -Run       # build + launch
param([string]$Configuration = "Release", [switch]$Run)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$proj = Join-Path $here "Recognition.Browser.csproj"

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if(-not $dotnet){
  Write-Host "RECOGNITION_BROWSER_BUILD_FAIL: .NET SDK not found. Install .NET 8 SDK (https://dotnet.microsoft.com/download)." -ForegroundColor Red
  exit 1
}

# A still-open prior instance locks the output exe (build can't overwrite it) and
# holds the WebView2 profile (runtime\browser_profile) so a second process hangs on
# init. Stop stale instances BEFORE building.
$stale = Get-Process -Name "RecognitionBrowser" -ErrorAction SilentlyContinue
if($stale){
  Write-Host ("Stopping " + @($stale).Count + " stale RecognitionBrowser instance(s) (exe/profile lock)...") -ForegroundColor Yellow
  $stale | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 800
}

Write-Host ("dotnet " + (& dotnet --version))
& dotnet build $proj -c $Configuration
if($LASTEXITCODE -ne 0){ Write-Host "RECOGNITION_BROWSER_BUILD_FAIL: build error" -ForegroundColor Red; exit 1 }

Write-Host "RECOGNITION_BROWSER_BUILD_OK" -ForegroundColor Green

$exe = Join-Path $here ("bin\" + $Configuration + "\net8.0-windows\RecognitionBrowser.exe")
Write-Host ("Run with:  " + $exe)

if($Run){
  if(-not (Test-Path -LiteralPath $exe)){
    Write-Host ("RECOGNITION_BROWSER_RUN_FAIL: built exe not found at " + $exe) -ForegroundColor Red; exit 1
  }
  # Launch the built exe detached so the console returns; the browser is a windowed
  # WPF app (it does NOT block this shell). Close the window to end the session.
  Start-Process -FilePath $exe -WorkingDirectory $here
  Write-Host "RECOGNITION_BROWSER_LAUNCHED" -ForegroundColor Green
}
