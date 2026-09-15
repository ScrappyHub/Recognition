# Recognition — single entry point (daily workflow)
#
# Wraps the individual scripts into one tool.
#
#   pwsh -File recognition_v1.ps1 up        # govern installed extensions -> launch plan -> prove
#   pwsh -File recognition_v1.ps1 govern    # govern your installed extensions
#   pwsh -File recognition_v1.ps1 plan      # emit the governed launch manifest (no browser launched)
#   pwsh -File recognition_v1.ps1 prove     # run every verifier -> proof-of-health receipt
#   pwsh -File recognition_v1.ps1 seal      # encrypt runtime/ state into the vault (destroys plaintext)
#   pwsh -File recognition_v1.ps1 restore   # restore runtime/ from the vault
#   pwsh -File recognition_v1.ps1 capture   # snapshot a running Chrome's tabs into the evidence chain
#   pwsh -File recognition_v1.ps1 status    # what's governed / proven right now
#
# Most actions need $env:RECOGNITION_PASSPHRASE.

param(
  [Parameter(Mandatory=$true)][ValidateSet("up","govern","plan","prove","seal","restore","capture","status")][string]$Action,
  [string]$RepoRoot = ".",
  [string]$Browser = "chrome"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$S = Join-Path $RepoRoot "scripts"

function Step([string]$Script,[hashtable]$Params,[string]$Token){
  # hashtable splatting binds by parameter NAME (array splatting misaligns args
  # in this environment, e.g. -RepoRoot getting treated as a value).
  $path = Join-Path $S $Script
  Write-Host ("==> " + $Script + " " + (($Params.GetEnumerator() | ForEach-Object { "-" + $_.Key + " " + $_.Value }) -join " ")) -ForegroundColor Cyan
  $out = & $path @Params *>&1 | Out-String
  Write-Host $out
  if(-not [string]::IsNullOrWhiteSpace($Token) -and ($out -notmatch [regex]::Escape($Token))){
    throw ("STEP_FAILED: " + $Script + " did not report " + $Token)
  }
}

function Ensure-Vault(){
  $ks = Join-Path (Join-Path (Join-Path (Join-Path $RepoRoot "vault") "runtime")) "keystore.v2.json"
  if(-not (Test-Path -LiteralPath $ks -PathType Leaf)){
    Step "recognition_vault_v1.ps1" @{ RepoRoot=$RepoRoot; VaultId="runtime"; Action="init" } "RECOGNITION_VAULT_V1_INIT_OK"
  }
}

switch($Action){
  "govern"  { Step "recognition_govern_installed_v1.ps1" @{ RepoRoot=$RepoRoot; Browser=$Browser } "RECOGNITION_GOVERN_INSTALLED_V1_OK" }
  "plan"    { Step "recognition_launch_governed_v1.ps1"  @{ RepoRoot=$RepoRoot } "" }
  "prove"   { Step "recognition_prove_all_v1.ps1"        @{ RepoRoot=$RepoRoot } "RECOGNITION_PROVE_ALL_V1_OK" }
  "seal"    { Ensure-Vault; Step "recognition_runtime_seal_v1.ps1" @{ RepoRoot=$RepoRoot; Action="seal" } "" }
  "restore" { Step "recognition_runtime_seal_v1.ps1"     @{ RepoRoot=$RepoRoot; Action="restore" } "" }
  "capture" { Step "recognition_cdp_capture_v1.ps1"      @{ RepoRoot=$RepoRoot } "" }
  "up" {
    Step "recognition_govern_installed_v1.ps1" @{ RepoRoot=$RepoRoot; Browser=$Browser } "RECOGNITION_GOVERN_INSTALLED_V1_OK"
    Step "recognition_launch_governed_v1.ps1"  @{ RepoRoot=$RepoRoot } ""
    Step "recognition_prove_all_v1.ps1"        @{ RepoRoot=$RepoRoot } "RECOGNITION_PROVE_ALL_V1_OK"
    Write-Host "RECOGNITION_UP_OK" -ForegroundColor Green
  }
  "status" {
    Write-Host "=== governed extensions ===" -ForegroundColor Cyan
    Step "recognition_extension_governance_v1.ps1" @{ RepoRoot=$RepoRoot; Action="list" } ""
    $pr = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.prove_all.v1.ndjson"
    if(Test-Path -LiteralPath $pr -PathType Leaf){
      $last = (Get-Content -LiteralPath $pr -Encoding UTF8 | Where-Object { $_ -ne "" } | Select-Object -Last 1)
      if($last){
        $o = $last | ConvertFrom-Json
        Write-Host ("last proof: verdict=" + $o.verdict + " at " + $o.ts_utc + " hash=" + $o.proof_hash)
      }
    } else { Write-Host "no proof receipt yet — run: recognition_v1.ps1 prove" }
    Write-Host "RECOGNITION_STATUS_OK" -ForegroundColor Green
  }
}
