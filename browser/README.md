# Recognition — Governed Browser Shell (WBS 5.0)

A standalone, Windows-first browser built on **WebView2** (the OS Chromium
runtime — Recognition is not a Chromium fork; it governs and records, per Handoff
§1). This is the browser front-end for the deterministic evidence platform: what
you browse can be exported, on demand, as a governed, verifiable packet.

## What it does

- **Windowing + navigation** (5.1): address bar, back/forward/reload, WebView2 view.
- **Privacy defaults** (5.2): HTTPS-first (bare `http://` is upgraded, loopback
  excepted), no password autosave, no general autofill, no telemetry from the shell.
- **Governed profile**: the browser profile lives under `runtime\browser_profile`
  (gitignored, and sealable into the vault via `recognition_runtime_seal_v1`).
- **Session export** (5.4): the **Export Session** button writes
  `payload\session_export\{session.json,tabs.json,events.ndjson}` with **URLs
  hashed** (`url_sha256`, no cleartext targets), then invokes the packet export law
  (`scripts\recognition_export_session_packet_v1.ps1`) to produce a deterministic,
  verifiable evidence packet in `packets\outbox\<packet_id>`. That packet verifies
  with `pc_verify_packet_optionA_v1.ps1` and is now anti-tamper hardened
  (manifest-anchored) per audit v2.

## Prerequisites

- Windows 10/11
- .NET 8 SDK — https://dotnet.microsoft.com/download
- Evergreen WebView2 Runtime (preinstalled on Windows 11; else install from Microsoft)

## Build / run

```powershell
pwsh -File browser\build.ps1            # build  -> RECOGNITION_BROWSER_BUILD_OK
pwsh -File browser\build.ps1 -Run       # build + launch
# or:
dotnet run --project browser\Recognition.Browser.csproj -c Release
```

## Flow (Handoff §30, evidence half)

Launch → browse (governed profile, HTTPS-first) → **Export Session** →
`payload\session_export` (hashed) → packet export law → `packets\outbox\<id>` →
`pc_verify_packet_optionA_v1.ps1` verifies it. Every export is a receipted,
deterministic, independently verifiable artifact.

## Not yet wired (next WBS)

- 5.3 VPN state / policy integration points.
- Multi-tab (current shell is single-view); the export schema already carries a
  `tabs` array for when multi-tab lands.
- Locked-startup gating in front of launch (identity/vault/policy) — §20.
