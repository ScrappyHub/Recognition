param([Parameter(Mandatory=$true)][string]$RepoRoot,[Parameter(Mandatory=$true)][string]$TabId,[Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Title,[Parameter(Mandatory=$false)][string]$CommittedUtc = "2026-03-31T12:00:10.000Z")
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ReceiptLib = Join-Path $PSScriptRoot "_lib_recognition_runtime_receipts_v1.ps1"
if(-not (Test-Path -LiteralPath $ReceiptLib -PathType Leaf)){ throw ("MISSING_RUNTIME_RECEIPT_LIB: " + $ReceiptLib) }
. $ReceiptLib
$LibPath = Join-Path $PSScriptRoot "_lib_recognition_runtime_state_v1.ps1"
if(-not (Test-Path -LiteralPath $LibPath -PathType Leaf)){ throw ("MISSING_RUNTIME_LIB: " + $LibPath) }
. $LibPath
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$tab = RR-ReadTabState $RepoRoot $TabId
if($null -eq $tab){ RR-Die ("NAV_WITHOUT_TAB: " + $TabId) }
$state = @{ schema="recognition.runtime.tab_state.v1"; tab_id=[string]$tab.tab_id; index=[int]$tab.index; url=$Url; title=$Title; is_active=[bool]$tab.is_active; is_pinned=[bool]$tab.is_pinned; opened_utc=[string]$tab.opened_utc; last_committed_navigation_utc=$CommittedUtc }
RR-WriteTabState $RepoRoot $TabId $state
$seq = RR-GetNextSeq $RepoRoot
$event = @{ schema="recognition.event.v1"; event_id=("evt-" + ("{0:d4}" -f $seq)); seq=$seq; ts_utc=$CommittedUtc; type="navigation.committed"; tab_id=$TabId; data=@{ url=$Url; title=$Title } }
RR-AppendEvent $RepoRoot $event
Write-RecognitionRuntimeReceipt -RepoRoot $RepoRoot -Action "runtime.navigation.commit" -Status "ok" -Data @{
  tab_id        = $TabId
  url           = $Url
  title         = $Title
  committed_utc = $CommittedUtc
}
Write-Host ("RUNTIME_NAV_COMMIT_OK: " + $TabId) -ForegroundColor Green
