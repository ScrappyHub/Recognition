param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

# Canonical helper: emit a line that contains a literal $var name without caller interpolation
function EmitLiteral([string]$s){ return ($s -replace "\$","`$") }

Write-Host "LOCK_OK: Use backtick-dollar (``$) when generating patch text that must contain literal `$var names." -ForegroundColor Green
