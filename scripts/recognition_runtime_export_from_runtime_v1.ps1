param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [Parameter(Mandatory=$false)][string]$SessionExportDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReceiptLib = Join-Path $PSScriptRoot "_lib_recognition_runtime_receipts_v1.ps1"
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RUNTIME_RECEIPT_LIB: " + $ReceiptLib) }
. $ReceiptLib

function RRDie([string]$m){ throw ("RR_FAIL: " + $m) }

function RREnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ RRDie "ENSUREDIR_EMPTY" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}

function RRWriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  $dir = Split-Path -Parent $Path
  if($dir){ RREnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}

function RRReadUtf8([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ RRDie ("MISSING_FILE: " + $Path) }
  Get-Content -Raw -LiteralPath $Path -Encoding UTF8
}

function RRCanonJsonText([object]$obj){
  $PcLib = Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1"
  if(-not (Test-Path -LiteralPath $PcLib -PathType Leaf)){ RRDie ("MISSING_PC_LIB: " + $PcLib) }
  . $PcLib

  $canon = PC-ToCanonJson $obj
  if($null -eq $canon){ RRDie "CANONJSON_NULL" }

  if($canon -is [byte[]]){
    $enc = New-Object System.Text.UTF8Encoding($false)
    return $enc.GetString($canon)
  }

  return [string]$canon
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if([string]::IsNullOrWhiteSpace($SessionExportDir)){
  $SessionExportDir = Join-Path $RepoRoot "payload\session_export"
}

$RuntimeRoot      = Join-Path $RepoRoot "runtime"
$SessionStatePath = Join-Path $RuntimeRoot "session\session_state.json"
$TabsDir          = Join-Path $RuntimeRoot "tabs"
$EventsPath       = Join-Path $RuntimeRoot "events.ndjson"

if(-not (Test-Path -LiteralPath $SessionStatePath -PathType Leaf)){ RRDie ("MISSING_RUNTIME_SESSION_STATE: " + $SessionStatePath) }
if(-not (Test-Path -LiteralPath $TabsDir -PathType Container)){ RRDie ("MISSING_RUNTIME_TABS_DIR: " + $TabsDir) }
if(-not (Test-Path -LiteralPath $EventsPath -PathType Leaf)){ RRDie ("MISSING_RUNTIME_EVENTS: " + $EventsPath) }

RREnsureDir $SessionExportDir

$session = (RRReadUtf8 $SessionStatePath) | ConvertFrom-Json

$tabFiles = @(@(Get-ChildItem -LiteralPath $TabsDir -File -Force | Sort-Object FullName))
$tabs = New-Object System.Collections.Generic.List[object]
foreach($f in @($tabFiles)){
  $raw = RRReadUtf8 $f.FullName
  if([string]::IsNullOrWhiteSpace($raw)){ continue }
  [void]$tabs.Add(($raw | ConvertFrom-Json))
}

$sessionObj = @{
  schema      = "recognition.session.v1"
  session_id  = [string]$session.session_id
  started_utc = [string]$session.started_utc
  ended_utc   = $session.ended_utc
  mode        = [string]$session.mode
  runtime     = @{
    platform            = [string]$session.platform
    surface             = [string]$session.surface
    recognition_version = [string]$session.recognition_version
  }
}

$tabsObj = @{
  schema = "recognition.tabs.v1"
  tabs   = @($tabs.ToArray())
}

$policyObj = @{
  schema                 = "recognition.policy_state.v1"
  policy_pack_id         = "recognition.standard.v1"
  policy_pack_version    = 1
  mode                   = [string]$session.mode
  effective_rules        = @()
  default_network_policy = "allow"
  default_storage_policy = "allow"
}

$trustObj = @{
  schema               = "recognition.trust_context.v1"
  trust_bundle_present = (Test-Path -LiteralPath (Join-Path $RepoRoot "proofs\trust\trust_bundle.json") -PathType Leaf)
  trust_bundle_path    = "proofs/trust/trust_bundle.json"
  allowed_signers_path = "proofs/trust/allowed_signers"
  active_principal     = $null
}

$vpnObj = @{
  schema              = "recognition.vpn_state.v1"
  vpn_mode            = "off"
  vpn_connected       = $false
  kill_switch_enabled = $false
  provider_id         = $null
}

$exportManifestObj = @{
  schema               = "recognition.session_export_manifest.v1"
  session_schema       = "recognition.session.v1"
  tabs_schema          = "recognition.tabs.v1"
  events_schema        = "recognition.event.v1"
  policy_state_schema  = "recognition.policy_state.v1"
  trust_context_schema = "recognition.trust_context.v1"
  vpn_state_schema     = "recognition.vpn_state.v1"
}

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "session.json") (RRCanonJsonText $sessionObj)

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "tabs.json") (RRCanonJsonText $tabsObj)

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "policy_state.json") (RRCanonJsonText $policyObj)

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "trust_context.json") (RRCanonJsonText $trustObj)

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "vpn_state.json") (RRCanonJsonText $vpnObj)

RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "export_manifest.json") (RRCanonJsonText $exportManifestObj)

$eventsRaw = RRReadUtf8 $EventsPath
RRWriteUtf8NoBomLf (Join-Path $SessionExportDir "events.ndjson") $eventsRaw

Write-RecognitionRuntimeReceipt -RepoRoot $RepoRoot -Action "runtime.export" -Status "ok" -Data @{
  session_export_dir = $SessionExportDir
}
Write-Host ("RUNTIME_EXPORT_OK: " + $SessionExportDir) -ForegroundColor Green

