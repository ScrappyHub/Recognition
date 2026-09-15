param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $raw=Get-Content -Raw -LiteralPath $Path -Encoding UTF8; $null=[ScriptBlock]::Create($raw) }

$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir

$libPath = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$lib = New-Object System.Collections.Generic.List[string]
WriteUtf8NoBomLf $libPath ((@($lib) -join "`n") + "`n")
ParseGateFile $libPath

$builderPath = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$b = New-Object System.Collections.Generic.List[string]
WriteUtf8NoBomLf $builderPath ((@($b) -join "`n") + "`n")
ParseGateFile $builderPath

$verPath = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$v = New-Object System.Collections.Generic.List[string]
WriteUtf8NoBomLf $verPath ((@($v) -join "`n") + "`n")
ParseGateFile $verPath

$selfPath = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$s = New-Object System.Collections.Generic.List[string]
WriteUtf8NoBomLf $selfPath ((@($s) -join "`n") + "`n")
ParseGateFile $selfPath

& (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe") -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $selfPath -RepoRoot $RepoRoot | Out-Host
Write-Host "OK: Packet Constitution v1 Option A installed (standalone) in Recognition." -ForegroundColor Green
