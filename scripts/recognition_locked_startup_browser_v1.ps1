# Recognition Locked Startup (browser) v1 — Handoff §5, §20
#
# Runtime is never trusted; it is always verified BEFORE the browser opens.
# This preflight enforces the launch gate for the WebView2 shell:
#   identity verified -> policy present -> trust root pinned -> evidence chain
#   initialized (session.started receipt appended).
# Emits a single token; the browser opens the web view only on OK.
#
#   pwsh -File recognition_locked_startup_browser_v1.ps1 -RepoRoot .
# Tokens: RECOGNITION_LOCKED_STARTUP_OK | RECOGNITION_LOCKED_STARTUP_BLOCKED

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_identity_v1.ps1")   # RID-* (+ RCE-*)

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

function Blocked([string]$why){
  Write-Host ("locked startup BLOCKED: " + $why) -ForegroundColor Red
  Write-Host "RECOGNITION_LOCKED_STARTUP_BLOCKED" -ForegroundColor Red
  exit 1
}

# 1) Identity verified (established on first run; chain intact thereafter)
try {
  $desc = RID-EnsureIdentity $RepoRoot
  $rid  = [string](RID-Get $desc "recognition_identity_id")
  if($rid -notmatch '^[0-9a-f]{64}$'){ Blocked "identity id invalid" }
  $iv = RID-Verify $RepoRoot
  Write-Host ("identity verified: " + $rid + " (receipts=" + $iv.event_count + ")")
} catch { Blocked ("identity verify failed: " + $_.Exception.Message) }

# 2) Policy present + parses
$policy = Join-Path (Join-Path $RepoRoot "config") "extension_policy.v1.json"
$canon  = Join-Path (Join-Path $RepoRoot "policies") "canonical.policy.v1.json"
foreach($p in @($policy,$canon)){
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Blocked ("policy missing: " + $p) }
  try { [void](Get-Content -Raw -LiteralPath $p -Encoding UTF8 | ConvertFrom-Json) } catch { Blocked ("policy unparseable: " + $p) }
}
Write-Host "policy present and parseable"

# 3) Trust root pinned
$trust = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "trust") "allowed_signers"
if(-not (Test-Path -LiteralPath $trust -PathType Leaf)){ Blocked "trust root missing (proofs/trust/allowed_signers)" }
Write-Host "trust root pinned"

# 4) Evidence chain initialized — record the governed session start
try {
  $evt = RID-Event $RepoRoot "session.started" ([ordered]@{ surface = "browser"; locked_startup = $true })
  Write-Host ("session.started receipt appended: seq=" + [string]$evt.seq)
} catch { Blocked ("could not append session.started receipt: " + $_.Exception.Message) }

Write-Host "RECOGNITION_LOCKED_STARTUP_OK" -ForegroundColor Green
exit 0
