# Recognition — detect & attest active tunnels/VPN adapters (§5.3, §29).
#
# Read-only. Enumerates network interfaces and flags tunnel/VPN adapters (WireGuard,
# WinTun, OpenVPN/TAP, generic Tunnel type), then appends a governed receipt so the
# host's network posture is recorded, never hidden.
#
#   pwsh -File scripts\recognition_vpn_detect_v1.ps1 -RepoRoot .
# Token: RECOGNITION_VPN_DETECT_V1_OK

param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

$nics = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
$tunnels = @()
foreach($n in $nics){
  if($n.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up){ continue }
  $desc = [string]$n.Description
  $isTunnelType = ($n.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel)
  $looksVpn = ($desc -match "(?i)wireguard|wintun|openvpn|tap-|tunnel|nordlynx|wg\b")
  if($isTunnelType -or $looksVpn){
    $tunnels += [pscustomobject]@{ name=[string]$n.Name; description=$desc; type=[string]$n.NetworkInterfaceType }
  }
}

$active = @($tunnels).Count -gt 0
Write-Host ("active tunnel/VPN adapters: " + @($tunnels).Count)
foreach($t in $tunnels){ Write-Host ("  - " + $t.name + "  [" + $t.type + "]  " + $t.description) }

$rp = Join-Path (Join-Path (Join-Path $RepoRoot "proofs") "receipts") "recognition.network.v1.ndjson"
$rd = Split-Path -Parent $rp
if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
$rec = [ordered]@{
  schema  = "recognition.network.detect.receipt.v1"
  ts_utc  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  tunnel_active = $active
  count   = @($tunnels).Count
  adapters = @($tunnels | ForEach-Object { $_.name + " [" + $_.type + "]" })
}
[System.IO.File]::AppendAllText($rp, (($rec | ConvertTo-Json -Depth 8 -Compress) + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Host "RECOGNITION_VPN_DETECT_V1_OK" -ForegroundColor Green
