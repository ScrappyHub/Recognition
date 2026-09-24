# Recognition Portable Backup / Recovery v1 — CLI (§21)
#
# Actions:
#   export -RepoRoot . -OutFile <path.rbackup>   -> passphrase-encrypted portable bundle
#   verify -InFile <path.rbackup>                 -> decrypt-only inspection, no writes
#   import -RepoRoot . -InFile <path.rbackup> [-Force] -> restore identity + stores
#
# Passphrase from $env:RECOGNITION_PASSPHRASE only (never argv). The SAME
# passphrase used to export must be supplied to verify/import.

param(
  [Parameter(Mandatory=$true)][ValidateSet("export","verify","import")][string]$Action,
  [string]$RepoRoot = "",
  [string]$OutFile = "",
  [string]$InFile = "",
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_backup_v1.ps1")

if($Action -eq "export"){
  if([string]::IsNullOrWhiteSpace($RepoRoot)){ RBK-Die "EXPORT_REQUIRES_REPOROOT" }
  if([string]::IsNullOrWhiteSpace($OutFile)){ RBK-Die "EXPORT_REQUIRES_OUTFILE" }
  $r = RBK-Export $RepoRoot $OutFile
  Write-Host ("stores included: " + (($r.stores_included) -join ", "))
  Write-Host ("recognition_identity_id: " + $r.recognition_identity_id)
  Write-Host ("RECOGNITION_BACKUP_V1_EXPORT_OK: " + $r.out_file) -ForegroundColor Green
  exit 0
}

if($Action -eq "verify"){
  if([string]::IsNullOrWhiteSpace($InFile)){ RBK-Die "VERIFY_REQUIRES_INFILE" }
  $r = RBK-Verify $InFile
  Write-Host ("recognition_identity_id: " + $r.recognition_identity_id)
  Write-Host ("exported_utc: " + $r.exported_utc)
  Write-Host ("stores present: " + (($r.stores_present) -join ", "))
  Write-Host "RECOGNITION_BACKUP_V1_VERIFY_OK" -ForegroundColor Green
  exit 0
}

if($Action -eq "import"){
  if([string]::IsNullOrWhiteSpace($RepoRoot)){ RBK-Die "IMPORT_REQUIRES_REPOROOT" }
  if([string]::IsNullOrWhiteSpace($InFile)){ RBK-Die "IMPORT_REQUIRES_INFILE" }
  $r = RBK-Import $RepoRoot $InFile -Force:$Force
  Write-Host ("stores restored: " + (($r.stores_restored) -join ", "))
  Write-Host ("recognition_identity_id: " + $r.recognition_identity_id)
  Write-Host "RECOGNITION_BACKUP_V1_IMPORT_OK" -ForegroundColor Green
  exit 0
}
