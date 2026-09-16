# Recognition — governed BYO WireGuard tunnel (§5.3).
#
# Recognition operates NO exit servers. You bring your own WireGuard .conf (self-hosted
# or a provider). This script brings that tunnel up/down via the official wireguard.exe
# service, reports status, and appends a governed receipt. Elevation is required to
# install/remove a tunnel service.
#
#   pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action status
#   pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action up   -Config C:\path\my.conf   (admin)
#   pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action down -Config C:\path\my.conf   (admin)
# Token: RECOGNITION_VPN_WIREGUARD_V1_OK

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [ValidateSet("up","down","status")][string]$Action = "status",
  [string]$Config = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

function Wg(){
  $c = Get-Command wireguard.exe -ErrorAction SilentlyContinue
  if($c){ return $c.Source }
  $def = "C:\Program Files\WireGuard\wireguard.exe"
  if(Test-Path -LiteralPath $def){ return $def }
  return $null
}
function TunnelName([string]$cfg){ return [System.IO.Path]::GetFileNameWithoutExtension($cfg) }
function Receipt([hashtable]$o){
  $rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.network.v1.ndjson"
  $rd = Split-Path -Parent $rp
  if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
  $rec = [ordered]@{ schema="recognition.network.receipt.v1"; ts_utc=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
  foreach($k in $o.Keys){ $rec[$k]=$o[$k] }
  [System.IO.File]::AppendAllText($rp, (($rec | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))
}
function StatusOf([string]$name){
  if(-not $name){ return "unknown" }
  $svc = Get-Service -Name ("WireGuardTunnel`$" + $name) -ErrorAction SilentlyContinue
  if($svc){ return [string]$svc.Status }
  return "not-installed"
}

$wg = Wg
if(-not $wg -and $Action -ne "status"){ Write-Host "VPN_WG_FAIL: wireguard.exe not found — install WireGuard for Windows." -ForegroundColor Red; exit 1 }

switch($Action){
  "up" {
    if(-not $Config -or -not (Test-Path -LiteralPath $Config -PathType Leaf)){ Write-Host "VPN_WG_FAIL: -Config <path to .conf> required for 'up'." -ForegroundColor Red; exit 1 }
    $name = TunnelName $Config
    & $wg /installtunnelservice $Config | Out-Host
    Start-Sleep -Milliseconds 800
    $st = StatusOf $name
    Receipt @{ action="up"; tunnel=$name; status=$st }
    Write-Host ("tunnel '" + $name + "' status: " + $st)
  }
  "down" {
    if(-not $Config){ Write-Host "VPN_WG_FAIL: -Config (or the tunnel name) required for 'down'." -ForegroundColor Red; exit 1 }
    $name = TunnelName $Config
    & $wg /uninstalltunnelservice $name | Out-Host
    Receipt @{ action="down"; tunnel=$name; status=(StatusOf $name) }
    Write-Host ("tunnel '" + $name + "' brought down")
  }
  default {
    $name = if($Config){ TunnelName $Config } else { "" }
    $st = StatusOf $name
    Receipt @{ action="status"; tunnel=$name; status=$st; wireguard_present=[bool]$wg }
    Write-Host ("wireguard present: " + [bool]$wg + "   tunnel: " + ($(if($name){$name}else{"(none specified)"})) + "   status: " + $st)
  }
}

Write-Host "RECOGNITION_VPN_WIREGUARD_V1_OK" -ForegroundColor Green
