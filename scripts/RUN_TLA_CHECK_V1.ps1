# Recognition — formal verification runner (TLA+ / TLC).
#
# Model-checks the specs in formal\ with TLC. Requires Java. Fetches tla2tools.jar into
# formal\ if it is not already present (or set $env:TLA2TOOLS to a local jar).
# Cross-platform (pwsh 7 on Windows/Linux). Token: RECOGNITION_TLA_CHECK_V1_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$formal = Join-Path $RepoRoot "formal"
function Die([string]$m){ Write-Host ("TLA_CHECK_FAIL: " + $m) -ForegroundColor Red; exit 1 }

$java = Get-Command java -ErrorAction SilentlyContinue
if(-not $java){ Die "Java not found — install a JRE/JDK (e.g. Temurin 17) to run TLC." }

$jar = if($env:TLA2TOOLS -and (Test-Path -LiteralPath $env:TLA2TOOLS)){ $env:TLA2TOOLS } else { Join-Path $formal "tla2tools.jar" }
if(-not (Test-Path -LiteralPath $jar)){
  $url = "https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar"
  Write-Host ("fetching TLC: " + $url)
  try { Invoke-WebRequest -Uri $url -OutFile $jar -UseBasicParsing } catch { Die ("could not download tla2tools.jar: " + $_.Exception.Message + " — download it into formal\ manually.") }
}

$specs = @("EvidenceChain", "LockedStartup")
$allOk = $true
foreach($s in $specs){
  Write-Host ("=== TLC: " + $s + " ===") -ForegroundColor Cyan
  Push-Location $formal
  try {
    $out = & $java.Source "-XX:+UseParallelGC" "-cp" $jar "tlc2.TLC" "-config" ($s + ".cfg") ($s + ".tla") 2>&1 | Out-String
  } finally { Pop-Location }
  Write-Host $out
  if($out -match "Model checking completed. No error has been found" -or $out -match "No error has been found"){
    Write-Host ("TLC OK: " + $s) -ForegroundColor Green
  } else {
    Write-Host ("TLC FAILED: " + $s) -ForegroundColor Red
    $allOk = $false
  }
}

if(-not $allOk){ Die "one or more specs did not verify" }

$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.formal.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
$rec = [ordered]@{ schema="recognition.formal.verify.receipt.v1"; ts_utc=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ"); specs=$specs; verified=$true }
[System.IO.File]::AppendAllText($rp, (($rec | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "RECOGNITION_TLA_CHECK_V1_OK" -ForegroundColor Green
