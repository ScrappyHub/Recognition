# Recognition Runtime Seal v1 — root fix for audit F1 (plaintext at rest)
#
# The canonical flow ends "... -> Encrypt -> Destroy Plaintext -> Exit"
# (Handoff §30) and the law is "Nothing plaintext after shutdown" (§7).
# Today runtime/ holds plaintext session/tab/timeline state and event streams,
# including URLs. This tool moves that state INTO the vault as AES-256-GCM
# objects and then destroys the plaintext, leaving runtime/ empty. `restore`
# reconstitutes the working tree from the vault for the next session.
#
# Passphrase from RECOGNITION_PASSPHRASE only. The vault must already exist
# (run: recognition_vault_v1.ps1 -Action init).
#
# Actions:
#   seal    [-DryRun]   encrypt every runtime/ file into the vault, then wipe
#   restore            decrypt sealed runtime state back onto disk
#
# Secure-delete caveat: plaintext is overwritten once with random bytes then
# unlinked. On copy-on-write / SSD / journaled filesystems this is best-effort,
# not a guarantee. The durable guarantee is that the authoritative copy is the
# encrypted vault object; the plaintext is transient working state.

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$true)][string]$Action,
  [string]$VaultId = "runtime",
  [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_vault_v1.ps1")

$P = RV1-Paths $RepoRoot $VaultId
$RuntimeDir = Join-Path $P.Repo "runtime"
$ReceiptPath = Join-Path (Join-Path (Join-Path $P.Repo "proofs") "receipts") "recognition.runtime_seal.v1.ndjson"
$INDEX_NAME = "runtime/_sealed_index.v1"

function Receipt([hashtable]$Fields){
  $obj = [ordered]@{ schema = "recognition.runtime_seal.receipt.v1"; vault_id = $VaultId }
  foreach($k in $Fields.Keys){ $obj[$k] = $Fields[$k] }
  $obj["ts_utc"] = RC2-NowUtc
  RC2-AppendUtf8NoBomLfLine $ReceiptPath (($obj | ConvertTo-Json -Depth 20 -Compress))
}

function RelName([string]$FullPath){
  $rel = $FullPath.Substring($P.Repo.Length).TrimStart('\','/')
  return ($rel -replace '\\','/')
}

function SecureWipe([string]$FullPath){
  try {
    $len = (Get-Item -LiteralPath $FullPath).Length
    if($len -gt 0){
      $rnd = RC2-RandomBytes ([int]$len)
      [System.IO.File]::WriteAllBytes($FullPath, $rnd)
    }
  } catch { }
  Remove-Item -LiteralPath $FullPath -Force
}

if($Action -eq "seal"){
  if(-not (Test-Path -LiteralPath $RuntimeDir -PathType Container)){
    Write-Host "RECOGNITION_RUNTIME_SEAL_V1_OK: runtime/ absent, nothing to seal" -ForegroundColor Green
    exit 0
  }
  if(-not (Test-Path -LiteralPath $P.Keystore -PathType Leaf)){
    RV1-Die ("VAULT_MISSING: init the vault first -> recognition_vault_v1.ps1 -RepoRoot . -VaultId " + $VaultId + " -Action init")
  }

  $files = @(Get-ChildItem -LiteralPath $RuntimeDir -Recurse -File -Force -ErrorAction SilentlyContinue |
             Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })
  if($files.Count -eq 0){
    Write-Host "RECOGNITION_RUNTIME_SEAL_V1_OK: no runtime files present" -ForegroundColor Green
    exit 0
  }

  Write-Host ("Runtime files to seal: " + $files.Count)
  $entries = @()
  foreach($f in $files){
    $rel = RelName $f.FullName
    $sha = RV1-Sha256Hex ([System.IO.File]::ReadAllBytes($f.FullName))
    $entries += [ordered]@{ rel = $rel; size = $f.Length; sha256 = $sha }
    Write-Host ("  seal <- " + $rel + " (" + $f.Length + " bytes)")
  }

  if($DryRun){
    Write-Host "DRY-RUN. Re-run without -DryRun to encrypt and wipe."
    Write-Host "RECOGNITION_RUNTIME_SEAL_V1_PLAN_OK"
    exit 0
  }

  $master = RV1-OpenMaster $P
  $sealed = @()
  try {
    foreach($f in $files){
      $rel = RelName $f.FullName
      $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
      try {
        $res = RV1-PutBytes $P $master $rel $bytes "runtime-state"
        $sealed += [ordered]@{ rel = $rel; name_hmac = $res.name_hmac; size = $res.size; sha256 = $res.sha256 }
      } finally { RC2-ZeroBytes $bytes }
    }
    # store the recovery index so `restore` knows the logical names
    $indexJson = ([ordered]@{
      schema = "recognition.runtime_seal.index.v1"; sealed_utc = RC2-NowUtc; entries = $sealed
    } | ConvertTo-Json -Depth 20)
    $null = RV1-PutBytes $P $master $INDEX_NAME (RC2-Utf8Bytes $indexJson) "runtime-index"
  } finally { RC2-ZeroBytes $master }

  # destroy plaintext
  foreach($f in $files){ SecureWipe $f.FullName }
  # remove now-empty runtime subdirectories (keep the runtime/ root)
  Get-ChildItem -LiteralPath $RuntimeDir -Recurse -Directory -Force -ErrorAction SilentlyContinue |
    Sort-Object { $_.FullName.Length } -Descending |
    ForEach-Object {
      if(@(Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0){
        Remove-Item -LiteralPath $_.FullName -Force
      }
    }

  Receipt @{ action = "seal"; sealed_count = $sealed.Count; objects = $sealed; plaintext_wiped = $true }
  Write-Host ("RECOGNITION_RUNTIME_SEAL_V1_OK: sealed=" + $sealed.Count + " (plaintext wiped)") -ForegroundColor Green
  exit 0
}

if($Action -eq "restore"){
  if(-not (Test-Path -LiteralPath $P.Keystore -PathType Leaf)){ RV1-Die "VAULT_MISSING" }
  $master = RV1-OpenMaster $P
  $restored = @()
  try {
    $indexBytes = RV1-GetBytes $P $master $INDEX_NAME
    $index = (New-Object System.Text.UTF8Encoding($false)).GetString($indexBytes) | ConvertFrom-Json -AsHashtable
    foreach($e in $index.entries){
      $rel = [string]$e.rel
      $bytes = RV1-GetBytes $P $master $rel
      try {
        $dest = Join-Path $P.Repo ($rel -replace '/','\')
        $dir = Split-Path -Parent $dest
        if($dir){ RC2-EnsureDir $dir }
        [System.IO.File]::WriteAllBytes($dest, $bytes)
        $restored += $rel
        Write-Host ("  restore -> " + $rel)
      } finally { RC2-ZeroBytes $bytes }
    }
  } finally { RC2-ZeroBytes $master }

  Receipt @{ action = "restore"; restored_count = $restored.Count; plaintext_persisted = $true }
  Write-Host ("RECOGNITION_RUNTIME_SEAL_V1_RESTORE_OK: restored=" + $restored.Count) -ForegroundColor Green
  exit 0
}

RV1-Die ("RUNTIME_SEAL_UNKNOWN_ACTION: " + $Action)
