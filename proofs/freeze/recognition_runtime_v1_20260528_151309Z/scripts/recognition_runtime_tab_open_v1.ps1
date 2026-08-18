param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][int]$Index,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$OpenedUtc = "2026-03-31T12:00:05.000Z",[Parameter(Mandatory=$false)][int]$IsActive = 0)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReceiptLib = Join-Path $PSScriptRoot "_lib_recognition_runtime_receipts_v1.ps1"
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RUNTIME_RECEIPT_LIB: " + $ReceiptLib) }
. $ReceiptLib
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$session = RR-ReadSessionState $RepoRoot
if($null -eq $session){ RR-Die "OPEN_TAB_WITHOUT_SESSION" }
$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=$TabId; index=$Index; url=$Url; title=$Title; is_active=($IsActive -ne 0); is_pinned=$false; opened_utc=$OpenedUtc; last_committed_navigation_utc=$OpenedUtc }
RR-WriteTabState $RepoRoot $TabId $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$OpenedUtc; type="tab.opened"; tab_id=$TabId; data=@{ url=$Url; title=$Title; index=$Index } }
RR-AppendEvent $RepoRoot $event
Write-RecognitionRuntimeReceipt -RepoRoot $RepoRoot -Action "runtime.tab.open" -Status "ok" -Data @{
  tab_id     = $TabId
  index      = $Index
  url        = $Url
  title      = $Title
  opened_utc = $OpenedUtc
  is_active  = ($IsActive -ne 0)
}
Write-Host ("RUNTIME_TAB_OPEN_OK: " + $TabId) -ForegroundColor Green
