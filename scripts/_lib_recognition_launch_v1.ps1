# Recognition Governed Launch PLAN v1 — Canonical Handoff §20 + §22
#
# PLAN ONLY — Recognition does not launch or drive a browser. This computes the
# governed launch manifest: every configured extension is checked against the
# governance ledger, and only extensions whose CURRENT bytes match a recorded
# 'allow' decision are eligible for the manifest's --load-extension set. Any
# unregistered, modified (id-flipped), or review/deny extension causes a REFUSE
# and no runnable manifest is produced. The intended browser path and argument
# list are recorded as evidence; they are never executed here.
#
# Reuses the extension-governance lib (identity + ledger) and the event-chain
# canonicalizer beneath it.
#
# Requires pwsh 7.2+.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot "_lib_recognition_extension_governance_v1.ps1")  # RG-ComputeIdentity / RG-LatestDecision / RG-Get / RG-GetArr / RCE-ParseJson

function RGL-Die([string]$m){ throw ("RGL_FAIL: " + $m) }

# Evaluate each configured extension against the ledger. Returns one row per
# extension: { path, extension_id, decision, gate(permit|refuse), reason }.
function RGL-EvaluateExtensions([string]$LedgerPath,$ExtPaths){
  $rows = New-Object System.Collections.Generic.List[object]
  foreach($p in @($ExtPaths)){
    $ps = [string]$p
    # pscustomobject (not [ordered]) so callers can index/read rows without the
    # OrderedDictionary "Argument types do not match" quirk on this pwsh build.
    $row = [pscustomobject]@{ path = $ps; extension_id = ""; decision = "unregistered"; gate = "refuse"; reason = "" }
    try {
      $idInfo = RG-ComputeIdentity $ps
      $row.extension_id = $idInfo.extension_id
      $rec = RG-LatestDecision $LedgerPath $idInfo.extension_id
      if($null -eq $rec){
        $row.decision = "unregistered"; $row.gate = "refuse"
        $row.reason = "no governance record for current bytes (never registered, or modified since)"
      } else {
        $d = [string](RG-Get $rec "policy_decision")
        $row.decision = $d
        if($d -eq "allow"){ $row.gate = "permit"; $row.reason = "governed allow" }
        else { $row.gate = "refuse"; $row.reason = ("policy decision = " + $d) }
      }
    } catch {
      $row.gate = "refuse"; $row.reason = ("error: " + $_.Exception.Message)
    }
    [void]$rows.Add($row)
  }
  return ,($rows.ToArray())
}

# Locate a Chromium-family browser. Explicit path wins; otherwise probe the
# usual Chrome / Chromium / Edge locations. Returns "" if none found.
function RGL-FindChromium([string]$Preferred){
  if(-not [string]::IsNullOrWhiteSpace($Preferred)){
    if(Test-Path -LiteralPath $Preferred -PathType Leaf){ return $Preferred }
    RGL-Die ("CHROMIUM_NOT_FOUND_AT: " + $Preferred)
  }
  $pf   = [string]$env:ProgramFiles
  $pfx  = [string]${env:ProgramFiles(x86)}
  $lad  = [string]$env:LOCALAPPDATA
  $cands = @(
    (Join-Path $pf  "Google\Chrome\Application\chrome.exe"),
    (Join-Path $pfx "Google\Chrome\Application\chrome.exe"),
    (Join-Path $lad "Google\Chrome\Application\chrome.exe"),
    (Join-Path $pf  "Chromium\Application\chrome.exe"),
    (Join-Path $pf  "Microsoft\Edge\Application\msedge.exe"),
    (Join-Path $pfx "Microsoft\Edge\Application\msedge.exe")
  )
  foreach($c in $cands){ if(-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path -LiteralPath $c -PathType Leaf)){ return $c } }
  return ""
}

# Build the Chromium argument list. (Not named $args — that shadows the
# automatic $args and breaks argument passing.)
function RGL-BuildArgs([string]$UserDataDir,$AllowPaths){
  $cliArgs = New-Object System.Collections.Generic.List[string]
  $cliArgs.Add("--user-data-dir=" + $UserDataDir)
  $cliArgs.Add("--no-first-run")
  $cliArgs.Add("--no-default-browser-check")
  $loadList = (@($AllowPaths) -join ",")
  if(-not [string]::IsNullOrWhiteSpace($loadList)){ $cliArgs.Add("--load-extension=" + $loadList) }
  return ,($cliArgs.ToArray())
}
