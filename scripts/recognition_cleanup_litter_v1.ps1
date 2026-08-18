#requires -Version 5.1
<#
  recognition_cleanup_litter_v1.ps1

  Removes non-authoritative litter from the repo:
    - backup files: *.bak, *.bak_*, *.ps1.bak_*  (already .gitignore'd)
    - broken-script artifact directories at repo root whose name contains '$'
      (e.g. the "$Path,$lf,$enc)'" dir left by the literal-dollar-rule patch)

  Safe by design:
    - DRY-RUN by default. Prints a plan and exits. Pass -Execute to delete.
    - Refuses to delete anything git currently tracks (when git is available).
    - Computes SHA-256 of each removed file BEFORE deletion and records it in
      an append-only receipt, so the cleanup itself is provable.

  Conventions:
    - Green path prints RECOGNITION_CLEANUP_LITTER_V1_OK (or _PLAN_OK on dry-run).
    - Receipt: proofs/receipts/recognition.cleanup.v1.ndjson (UTF-8 no BOM, LF, append).
#>
[CmdletBinding()]
param(
  [string]$RepoRoot = ".",
  [switch]$Execute,
  [switch]$NoReceipt
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $RepoRoot).Path

function Die([string]$m){ Write-Error $m; exit 1 }

# --- git tracked-set guard ---------------------------------------------------
$tracked = @{}
$gitOk = $false
try {
  Push-Location $root
  $lsfiles = & git ls-files 2>$null
  if($LASTEXITCODE -eq 0){
    $gitOk = $true
    foreach($f in $lsfiles){ $tracked[[IO.Path]::GetFullPath((Join-Path $root $f))] = $true }
  }
} catch { } finally { Pop-Location }

# --- enumerate litter --------------------------------------------------------
$targets = New-Object System.Collections.Generic.List[object]

# 1) backup files anywhere except .git
Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
  Where-Object { $_.Name -like '*.bak' -or $_.Name -like '*.bak_*' -or $_.Name -like '*.ps1.bak_*' } |
  ForEach-Object { $targets.Add([pscustomobject]@{ Kind='file'; Path=$_.FullName }) }

# 2) broken artifact directories at repo root whose name contains '$'
Get-ChildItem -LiteralPath $root -Force -Directory -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -notlike '.git' -and $_.Name.Contains('$') } |
  ForEach-Object { $targets.Add([pscustomobject]@{ Kind='dir'; Path=$_.FullName }) }

if($targets.Count -eq 0){
  Write-Host "No litter found. Nothing to do."
  Write-Host "RECOGNITION_CLEANUP_LITTER_V1_OK"
  exit 0
}

# --- plan + tracked-set safety ----------------------------------------------
$plan = New-Object System.Collections.Generic.List[object]
foreach($t in $targets){
  $full = [IO.Path]::GetFullPath($t.Path)
  if($gitOk -and $tracked.ContainsKey($full)){
    Die ("REFUSING: target is git-tracked (not litter): " + $t.Path)
  }
  $sha = ""
  if($t.Kind -eq 'file'){
    try { $sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $t.Path).Hash.ToLower() } catch { $sha = "UNREADABLE" }
  }
  $plan.Add([pscustomobject]@{ kind=$t.Kind; path=$full; sha256=$sha })
}

Write-Host ("Litter found: {0} item(s)  (git-guard: {1})" -f $plan.Count, ($(if($gitOk){"on"}else{"off"})))
$plan | ForEach-Object { Write-Host ("  [{0}] {1}{2}" -f $_.kind, $_.path, $(if($_.sha256){" sha256="+$_.sha256.Substring(0,12)+"..."}else{""})) }

if(-not $Execute){
  Write-Host ""
  Write-Host "DRY-RUN. Re-run with -Execute to delete the items above."
  Write-Host "RECOGNITION_CLEANUP_LITTER_V1_PLAN_OK"
  exit 0
}

# --- execute -----------------------------------------------------------------
foreach($p in $plan){
  Remove-Item -LiteralPath $p.path -Recurse -Force -ErrorAction Stop
  if(Test-Path -LiteralPath $p.path){ Die ("DELETE_VERIFY_FAILED: " + $p.path) }
  Write-Host ("removed: " + $p.path)
}

# --- receipt (append-only, UTF-8 no BOM, LF) ---------------------------------
if(-not $NoReceipt){
  $receiptDir = Join-Path (Join-Path $root "proofs") "receipts"
  New-Item -ItemType Directory -Force -Path $receiptDir | Out-Null
  $receipt = Join-Path $receiptDir "recognition.cleanup.v1.ndjson"
  $stampUtc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ")
  $record = [ordered]@{
    receipt      = "recognition.cleanup.v1"
    ts_utc       = $stampUtc
    action       = "litter_removed"
    removed_count= $plan.Count
    removed      = @($plan | ForEach-Object { [ordered]@{ kind=$_.kind; path=$_.path; sha256=$_.sha256 } })
    git_guard    = $gitOk
  }
  $json = ($record | ConvertTo-Json -Depth 6 -Compress)
  $enc  = New-Object System.Text.UTF8Encoding($false)
  $line = $json + "`n"
  [System.IO.File]::AppendAllText($receipt, $line, $enc)
  Write-Host ("receipt appended: " + $receipt)
}

Write-Host "RECOGNITION_CLEANUP_LITTER_V1_OK"
