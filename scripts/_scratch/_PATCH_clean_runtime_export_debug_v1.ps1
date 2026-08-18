param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }

function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $tokens = $null
  $errors = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors)
  if($errors -and @($errors).Count -gt 0){
    $e = @($errors)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$e.Extent.StartLineNumber,$e.Extent.StartColumnNumber,$e.Message)
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$Target   = Join-Path $RepoRoot "scripts\recognition_runtime_export_from_runtime_v1.ps1"
$Runner   = Join-Path $RepoRoot "scripts\_scratch\FULL_GREEN_RUNNER_RECOGNITION_RUNTIME_V1.ps1"

if(-not (Test-Path -LiteralPath $Target -PathType Leaf)){ Die ("MISSING_TARGET: " + $Target) }
if(-not (Test-Path -LiteralPath $Runner -PathType Leaf)){ Die ("MISSING_RUNNER: " + $Runner) }

$raw = Get-Content -Raw -LiteralPath $Target -Encoding UTF8
$lines = New-Object System.Collections.Generic.List[string]

foreach($line in @($raw -split "`n")){
  $clean = $line.TrimEnd("`r")
  if($clean -match '^\s*Write-Host\s+"STEP:'){ continue }
  if($clean -match '^\s*Write-Host\s+\("STEP:'){ continue }
  [void]$lines.Add($clean)
}

$new = (@($lines) -join "`n") + "`n"
if($new -eq $raw){ Die "PATCH_FAIL:NO_DEBUG_LINES_REMOVED" }

WriteUtf8NoBomLf $Target $new
ParseGateFile $Target
Write-Host ("DEBUG_CLEAN_OK: " + $Target) -ForegroundColor Green

ParseGateFile $Runner
$PSExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

& $PSExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Runner -RepoRoot $RepoRoot | Out-Host
