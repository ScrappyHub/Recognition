Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
param([Parameter(Mandatory=$true)][string]$RepoRoot)

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $raw = Get-Content -Raw -LiteralPath $Path -Encoding UTF8; $null = [ScriptBlock]::Create($raw) }
function WriteLines([string]$RepoRoot,[string]$Rel,[string[]]$Lines){ $p = Join-Path $RepoRoot $Rel; $txt = (@($Lines) -join "`n") + "`n"; WriteUtf8NoBomLf $p $txt }

$ScriptsDir = Join-Path $RepoRoot "scripts"
$Target = Join-Path $ScriptsDir "recognition_bootstrap_v1.ps1"
EnsureDir $ScriptsDir

$B = New-Object System.Collections.Generic.List[string]
[void]$B.Add('Set-StrictMode -Version Latest')
[void]$B.Add('$ErrorActionPreference = "Stop"' )
[void]$B.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)' )
[void]$B.Add('')
[void]$B.Add('function Die([string]$m){ throw $m }')
[void]$B.Add('function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }')
[void]$B.Add('function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }')
[void]$B.Add('function WriteLines([string]$Rel,[string[]]$Lines){ $p = Join-Path $RepoRoot $Rel; $txt = (@($Lines) -join "`n") + "`n"; WriteUtf8NoBomLf $p $txt }')
[void]$B.Add('')
[void]$B.Add('$dirs = @("docs","schemas","policy/canonical","policy/overlay","proofs/keys","proofs/trust","proofs/receipts","packets/outbox","packets/inbox","packets/quarantine","packets/receipts","scripts","src","test_vectors/packet_constitution_v1","test_vectors/recognition_policy_v1")' )
[void]$B.Add('foreach($d in @($dirs)){ EnsureDir (Join-Path $RepoRoot $d) }' )
[void]$B.Add('')
[void]$B.Add('WriteLines "README.md" @(')
[void]$B.Add('  "# Recognition",')
[void]$B.Add('  "",')
[void]$B.Add('  "Recognition is a lightweight Windows-first browser (WebView2) that is strong like Opera, safe like Brave, and protected like DuckDuckGo - governed and exportable under ecosystem laws.",')
[void]$B.Add('  "",')
[void]$B.Add('  "Canonical Laws:",')
[void]$B.Add('  "- NFL duplication is non-optional.",')
[void]$B.Add('  "- NeverLost v1 identity + deterministic receipts.",')
[void]$B.Add('  "- Packet Constitution v1 export packets.",')
[void]$B.Add('  "- WatchTower compatible; Covenant Gate gating later."')
[void]$B.Add(')')
[void]$B.Add('')
[void]$B.Add('WriteLines "SPEC_Recognition_v1.md" @(')
[void]$B.Add('  "# Recognition v1 Specification (Canonical)",')
[void]$B.Add('  "",')
[void]$B.Add('  "- NFL duplication mandatory for install/update/policy/trust/vpn/session export.",')
[void]$B.Add('  "- Standalone privacy + VPN; AnchorMark integration optional.",')
[void]$B.Add('  "- Session export uses Packet Constitution v1."')
[void]$B.Add(')')
[void]$B.Add('')
[void]$B.Add('$tb = Join-Path $RepoRoot "proofs/trust/trust_bundle.json"' )
[void]$B.Add('$tbJson = "{`n  ""schema"": ""neverlost.trust_bundle.v1"",`n  ""note"": ""Bootstrap placeholder. Replace with real trust bundle and derive allowed_signers deterministically.""`n}`n"' )
[void]$B.Add('WriteUtf8NoBomLf $tb $tbJson' )
[void]$B.Add('WriteLines "proofs/trust/allowed_signers" @("# allowed_signers (placeholder)","","# Derive from trust_bundle.json via scripts/make_allowed_signers_v1.ps1")' )
[void]$B.Add('WriteLines "proofs/receipts/neverlost.ndjson" @()' )
[void]$B.Add('')
[void]$B.Add('WriteLines "policy/canonical/policy_pack_recognition_standard_v1.json" @(')
[void]$B.Add('  "{",')
[void]$B.Add('  "  ""schema"": ""recognition.policy_pack.v1"",')
[void]$B.Add('  "  ""pack_id"": ""recognition.standard.v1"",')
[void]$B.Add('  "  ""pack_version"": 1",')
[void]$B.Add('  "}"')
[void]$B.Add(')')

WriteUtf8NoBomLf $Target ((@($B) -join "`n") + "`n")
ParseGateFile $Target
Write-Host ("PATCH_OK: rewrote bootstrap -> " + $Target) -ForegroundColor Green
