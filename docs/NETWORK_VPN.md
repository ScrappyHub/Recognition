# Recognition — network / VPN (§5.3, §29)

Recognition operates **no exit servers** and makes no hidden network calls. Its job is to
**route the browser through a tunnel you control and attest that state** — never to be a
VPN provider. Network posture is declared in the UI and written into the governed session
export; nothing is silent.

Configuration lives in `config/network.v1.json` (schema: `schemas/recognition.network.v1.schema.json`):

```json
{ "schema": "recognition.network.v1", "mode": "off",
  "proxy": "", "exit_region": "", "exit_check_url": "", "wireguard_config": "" }
```

`mode` is one of:

## `proxy` — route the browser through a proxy (built-in)
Set `proxy` to a `scheme://host:port` (e.g. `socks5://127.0.0.1:9050` for Tor, or an
HTTP/SOCKS proxy backed by your VPN). Recognition passes `--proxy-server` to the browser
engine at startup, so **all** browser traffic goes through it. Settings → Network shows the
mode/proxy/exit region; the exported `vpn_state.json` records `connected/mode/proxy_configured/exit_region`.
Click **Verify exit IP** (only fires when you click) to open your `exit_check_url` and see the
egress address.

## `wireguard` — bring-your-own WireGuard tunnel
Recognition manages a real WireGuard tunnel from a `.conf` you supply (self-hosted or a
provider), via the official `wireguard.exe` service:

```powershell
pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action up   -Config C:\path\my.conf   # admin
pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action status -Config C:\path\my.conf
pwsh -File scripts\recognition_vpn_wireguard_v1.ps1 -RepoRoot . -Action down -Config C:\path\my.conf   # admin
```

Each action appends a receipt to `proofs/receipts/recognition.network.v1.ndjson`. Pair with
`mode: "proxy"` only if your WireGuard setup also exposes a local proxy; otherwise WireGuard
tunnels the whole machine and the browser follows.

## `system` — detect & attest an existing tunnel
Don't route anything ourselves; record whatever tunnel/VPN adapter the OS already has up:

```powershell
pwsh -File scripts\recognition_vpn_detect_v1.ps1 -RepoRoot .   # read-only, receipted
```

## Honesty notes
- Recognition is a browser, not a VPN network. It routes/attests; it does not provide exits.
- `proxy` mode is browser-scoped (only the browser). `wireguard` mode tunnels per your config.
- No exit or IP check is performed automatically — only on your explicit **Verify exit IP**.
