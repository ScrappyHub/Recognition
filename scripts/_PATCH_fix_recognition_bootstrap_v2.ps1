Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

param([Parameter(Mandatory=$true)][string]$RepoRoot)

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){
    New-Item -ItemType Directory -Force -Path $p | Out-Null
  }
}
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  EnsureDir (Split-Path -Parent $Path)
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8
  $null = [ScriptBlock]::Create($raw)
}
function WriteLines([string]$RepoRoot,[string]$Rel,[string[]]$Lines){
  $p = Join-Path $RepoRoot $Rel
  $txt = (@($Lines) -join "`n") + "`n"
  WriteUtf8NoBomLf $p $txt
}

$ScriptsDir = Join-Path $RepoRoot "scripts"
$Target = Join-Path $ScriptsDir "recognition_bootstrap_v1.ps1"
EnsureDir $ScriptsDir

# Rewrite bootstrap: ONLY single-quoted strings for content lines (safe for JSON quotes)
$L = New-Object System.Collections.Generic.List[string]
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference = "Stop"')
[void]$L.Add('')
[void]$L.Add('function Die([string]$m){ throw $m }')
[void]$L.Add('function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }')
[void]$L.Add('function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }')
[void]$L.Add('function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8; $null = [ScriptBlock]::Create($raw) }')
[void]$L.Add('function WriteLines([string]$Rel,[string[]]$Lines){ $p = Join-Path $RepoRoot $Rel; $txt = (@($Lines) -join "`n") + "`n"; WriteUtf8NoBomLf $p $txt }')
[void]$L.Add('')
[void]$L.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)')
[void]$L.Add('')
[void]$L.Add('$dirs = @("docs","schemas","policy/canonical","policy/overlay","proofs/keys","proofs/trust","proofs/receipts","packets/outbox","packets/inbox","packets/quarantine","packets/receipts","scripts","src","test_vectors/packet_constitution_v1","test_vectors/recognition_policy_v1")')
[void]$L.Add('foreach($d in @($dirs)){ EnsureDir (Join-Path $RepoRoot $d) }')
[void]$L.Add('')

# README (ASCII-only: "-" not em dash)
[void]$L.Add('WriteLines "README.md" @(')
[void]$L.Add('  "# Recognition",')
[void]$L.Add('  "",')
[void]$L.Add('  "Recognition is a lightweight Windows-first browser (WebView2) that is strong like Opera, safe like Brave, and protected like DuckDuckGo - but governed and exportable under the ecosystem laws.",')
[void]$L.Add('  "",')
[void]$L.Add('  "## Canonical Laws",')
[void]$L.Add('  "- NFL duplication is non-optional for defined events (install/update/policy/trust/vpn/session export).",')
[void]$L.Add('  "- NeverLost v1 identity + deterministic receipts.",')
[void]$L.Add('  "- Packet Constitution v1 for exportable directory-bundle packets.",')
[void]$L.Add('  "- WatchTower verification compatible; Covenant Gate policy gating later.",')
[void]$L.Add('  "",')
[void]$L.Add('  "## Repo Layout",')
[void]$L.Add('  "- `schemas/`: canonical event schemas",')
[void]$L.Add('  "- `policy/`: policy packs (canonical + overlay)",')
[void]$L.Add('  "- `proofs/`: trust bundles + receipts",')
[void]$L.Add('  "- `packets/`: outbox/inbox/quarantine + receipts",')
[void]$L.Add('  "- `scripts/`: deterministic tooling (bootstrap/export/dup/selftests)"')
[void]$L.Add(')')

# SPEC (short but parse-safe)
[void]$L.Add('')
[void]$L.Add('WriteLines "SPEC_Recognition_v1.md" @(')
[void]$L.Add('  "# Recognition v1 Specification (Canonical)",')
[void]$L.Add('  "",')
[void]$L.Add('  "Non-negotiables:",')
[void]$L.Add('  "- NFL duplication is mandatory for install/update/policy/trust/vpn/session export.",')
[void]$L.Add('  "- Standalone privacy + VPN; AnchorMark integration optional.",')
[void]$L.Add('  "- Packet Constitution v1 session export packets."')
[void]$L.Add(')')

# Trust placeholders (the exact lines that previously broke)
[void]$L.Add('')
[void]$L.Add('WriteLines "proofs/trust/trust_bundle.json" @(')
[void]$L.Add('  "{",')
[void]$L.Add('  "  ""schema"": ""neverlost.trust_bundle.v1"",",')
[void]$L.Add('  "  ""note"": ""Bootstrap placeholder. Replace with real trust bundle and derive allowed_signers deterministically.""',)
[void]$L.Add('  "}"')
[void]$L.Add(')')

# NOTE: above line has a trailing comma INSIDE the string list - that is allowed in PowerShell arrays only when it is a separate token.
# Fix by writing the trust bundle using a simpler 3-line method instead:
[void]$L.Add('')
[void]$L.Add('$tb = Join-Path $RepoRoot "proofs/trust/trust_bundle.json"')
[void]$L.Add('WriteUtf8NoBomLf $tb ("{`n  ""schema"": ""neverlost.trust_bundle.v1"",`n  ""note"": ""Bootstrap placeholder. Replace with real trust bundle and derive allowed_signers deterministically.""`n}`n")')
[void]$L.Add('WriteLines "proofs/trust/allowed_signers" @("# allowed_signers (placeholder)","","# Derive from trust_bundle.json via scripts/make_allowed_signers_v1.ps1")')
[void]$L.Add('WriteLines "proofs/receipts/neverlost.ndjson" @()')

# Minimal policy pack (valid JSON, tiny)
[void]$L.Add('')
[void]$L.Add('WriteLines "policy/canonical/policy_pack_recognition_standard_v1.json" @(')
[void]$L.Add('  "{",')
[void]$L.Add('  "  ""schema"": ""recognition.policy_pack.v1"",",')
[void]$L.Add('  "  ""pack_id"": ""recognition.standard.v1"",",')
[void]$L.Add('  "  ""pack_version"": 1,",')
[void]$L.Add('  "  ""defaults"": { ""protection"": { ""tracker_blocking"": true, ""https_first"": true }, ""capabilities"": { ""js"": ""allow"", ""cookies"": ""allow"" } },",')
[void]$L.Add('  "  ""rules"": []",')
[void]$L.Add('  "}"')
[void]$L.Add(')')

# Parse gate the bootstrap itself at the end
[void]$L.Add('')
[void]$L.Add('ParseGateFile $MyInvocation.MyCommand.Path')
[void]$L.Add('Write-Host ("OK: Bootstrap script written; now writing files -> " + $RepoRoot) -ForegroundColor Cyan')

# Write the bootstrap file
WriteUtf8NoBomLf $Target ((@($L) -join "`n") + "`n")
ParseGateFile $Target
Write-Host ("PATCH_OK: rewrote bootstrap -> " + $Target) -ForegroundColor Green
