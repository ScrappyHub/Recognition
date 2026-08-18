param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $raw=Get-Content -Raw -LiteralPath $Path -Encoding UTF8; $null=[ScriptBlock]::Create($raw) }

$ScriptsDir = Join-Path $RepoRoot "scripts"
$Target = Join-Path $ScriptsDir "recognition_bootstrap_v1.ps1"
EnsureDir $ScriptsDir

$boot = New-Object System.Collections.Generic.List[string]

function WriteUtf8NoBomLf_Local([string]$Path,[string]$Text){ WriteUtf8NoBomLf $Path $Text }
$txt = (@($boot) -join "`n") + "`n"
WriteUtf8NoBomLf $Target $txt
ParseGateFile $Target
Write-Host ("PATCH_OK: rewrote bootstrap -> " + $Target) -ForegroundColor Green
