param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$false)][string]$SessionId = "recognition-session-v1",[Parameter(Mandatory=$false)][string]$StartedUtc = "2026-03-31T12:00:00.000Z",[Parameter(Mandatory=$false)][string]$Mode = "standard")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReceiptLib = Join-Path $PSScriptRoot "_lib_recognition_runtime_receipts_v1.ps1"
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RUNTIME_RECEIPT_LIB: " + $ReceiptLib) }
. $ReceiptLib
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
RR-EnsureRuntimeLayout $RepoRoot
$state = @{ schema="recognition.runtime.session_state.v1"; session_id=$SessionId; started_utc=$StartedUtc; ended_utc=$null; mode=$Mode; platform="windows"; surface="webview2"; recognition_version="runtime_state.v1" }
RR-WriteSessionState $RepoRoot $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$StartedUtc; type="session.started"; tab_id=$null; data=@{ mode=$Mode; session_id=$SessionId } }
RR-AppendEvent $RepoRoot $event
Write-RecognitionRuntimeReceipt -RepoRoot $RepoRoot -Action "runtime.session.open" -Status "ok" -Data @{
  session_id  = $SessionId
  started_utc = $StartedUtc
  mode        = $Mode
}
Write-Host ("RUNTIME_SESSION_OPEN_OK: " + $SessionId) -ForegroundColor Green
