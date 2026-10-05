# Selftest — Recognition Certificate Manager v1 (§54)
# Proves the two governed TLS decisions the browser's ServerCertificateErrorDetected /
# ClientCertificateRequested handlers make:
#   1. Server certificate errors are refused (fail-closed) by default, and trust is
#      PINNED to the exact certificate fingerprint (subject|issuer|validFrom|validTo),
#      not just the host — so a different certificate later presented for the SAME
#      host does NOT inherit an earlier trust decision (the core anti-substitution
#      property this exists to provide).
#   2. Mutual-TLS client certificate requests are unconditionally refused — verified
#      by STATICALLY checking the shipped C# source (no .NET runtime here): the
#      OnClientCertificateRequested method must set Cancel=true and must contain no
#      code path that ever sets Cancel=false.
# Reuses the SAME GovernedActions-format ledger + replay semantics already proven by
# _selftest_recognition_site_policy_v1.ps1 — certificate trust records share that exact
# ledger/encoding (key "cert.<fingerprint>"), so this selftest focuses on what's NEW:
# the fingerprint formula and the pin-does-not-transfer property.
# Token: SELFTEST_RECOGNITION_CERTIFICATE_MANAGER_V1_OK

param([string]$RepoRoot = "", [string]$TempRoot = "")

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if([string]::IsNullOrWhiteSpace($RepoRoot)){ $RepoRoot = (Get-Location).Path }
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path

if([string]::IsNullOrWhiteSpace($TempRoot)){
  $TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("certmgr_" + [Guid]::NewGuid().ToString("N"))
}
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

$script:pass=0; $script:fail=0
function Check([bool]$c,[string]$l){ if($c){ $script:pass++; Write-Host ("  ok  - " + $l) -ForegroundColor Green } else { $script:fail++; Write-Host ("  FAIL- " + $l) -ForegroundColor Red } }
function WriteLines([string]$p,[string[]]$lines){ [System.IO.File]::WriteAllText($p, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false))) }

$Enc = New-Object System.Text.UTF8Encoding($false)
$Sha = [System.Security.Cryptography.SHA256]::Create()
function Sha256Hex([string]$s){
  $b = $Sha.ComputeHash($Enc.GetBytes([string]$s))
  -join ($b | ForEach-Object { $_.ToString("x2") })
}
function JJ([string]$s){ '"' + ([string]$s).Replace('\','\\').Replace('"','\"') + '"' }

# Mirrors C# CertFingerprint exactly: sha256hex(subject|issuer|validFrom_o|validTo_o), first 16 hex chars.
function CertFingerprint([string]$subject,[string]$issuer,[string]$validFrom,[string]$validTo){
  # metadata FALLBACK fingerprint (used by the browser only if DER bytes can't be obtained)
  $s = $subject + "|" + $issuer + "|" + $validFrom + "|" + $validTo
  "meta-" + (Sha256Hex $s)
}
# Mirrors the browser's PRIMARY fingerprint: "der-" + SHA-256(raw DER bytes of the certificate).
function DerFingerprint([System.Security.Cryptography.X509Certificates.X509Certificate2]$cert){
  "der-" + (-join ([System.Security.Cryptography.SHA256]::HashData($cert.RawData) | ForEach-Object { $_.ToString("x2") }))
}
function NewSelfSigned([string]$subject,[datetime]$nb,[datetime]$na){
  $key = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
  $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($subject, $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
  $req.CreateSelfSigned([System.DateTimeOffset]$nb, [System.DateTimeOffset]$na)
}

function New-Receipt([int]$seq,[string]$ts,[string]$action,[string]$detail,[string]$prev){
  $dsha = if([string]::IsNullOrEmpty($detail)){ "" } else { Sha256Hex $detail }
  $body = "{" + (JJ "seq") + ":" + $seq + "," + (JJ "ts_utc") + ":" + (JJ $ts) + "," +
          (JJ "action") + ":" + (JJ $action) + "," + (JJ "detail_sha256") + ":" + (JJ $dsha) + "," +
          (JJ "prev_hash") + ":" + (JJ $prev) + "}"
  $hash = Sha256Hex $body
  $line = $body.Substring(0, $body.Length - 1) + "," + (JJ "hash") + ":" + (JJ $hash) + "}"
  @{ line=$line; hash=$hash }
}
function Verify-Chain([string]$path){
  $lines = @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ -ne "" })
  $prev = ("0" * 64); $expect = 1; $count = 0
  $marker = "," + (JJ "hash") + ":"
  foreach($line in $lines){
    $r = $line | ConvertFrom-Json
    if([int]$r.seq -ne $expect){ throw "SEQ_BREAK at $expect" }
    if([string]$r.prev_hash -ne $prev){ throw "PREV_BREAK at $expect" }
    $h = [string]$r.hash
    $idx = $line.LastIndexOf($marker)
    if($idx -lt 0){ throw "MALFORMED at $expect" }
    $body = $line.Substring(0, $idx) + "}"
    if((Sha256Hex $body) -ne $h){ throw "HASH_BREAK at $expect" }
    $prev = $h; $expect++; $count++
  }
  @{ count=$count; head=$prev }
}
function ShouldThrow([scriptblock]$b,[string]$l){ $t=$false; try { & $b | Out-Null } catch { $t=$true }; Check $t $l }

function Replay-SitePolicy([string]$path){
  $state = @{}
  $lines = @(Get-Content -LiteralPath $path -Encoding UTF8 | Where-Object { $_ -ne "" })
  foreach($line in $lines){
    $r = $line | ConvertFrom-Json
    $a = [string]$r.action
    if(-not $a.StartsWith("site_policy.set|")){ continue }
    $parts = $a.Split('|')
    if($parts.Count -ne 4){ continue }
    $state[$parts[1] + "|" + $parts[2].ToLowerInvariant()] = $parts[3]
  }
  $state
}
function Get-SitePolicy($state,[string]$origin,[string]$key,[string]$def){
  $k = $key + "|" + $origin.ToLowerInvariant()
  if($state.ContainsKey($k)){ return [string]$state[$k] }
  return $def
}

try {
  # --- fingerprint determinism / sensitivity ---
  $fpA  = CertFingerprint "CN=bank.example" "CN=Example CA" "2026-01-01T00:00:00.000Z" "2027-01-01T00:00:00.000Z"
  $fpA2 = CertFingerprint "CN=bank.example" "CN=Example CA" "2026-01-01T00:00:00.000Z" "2027-01-01T00:00:00.000Z"
  $fpB  = CertFingerprint "CN=bank.example" "CN=Example CA" "2026-06-01T00:00:00.000Z" "2027-06-01T00:00:00.000Z"   # same subject/issuer, different validity (e.g. renewed/substituted cert)
  Check ($fpA -eq $fpA2) "fingerprint is deterministic for identical certificate metadata"
  Check ($fpA -ne $fpB) "fingerprint changes when only the validity window differs (catches a substituted certificate)"
  Check ($fpA -match '^meta-[0-9a-f]{64}$') "metadata fallback fingerprint has the expected 'meta-' + 64 hex form"

  # --- DER pinning: the gap the metadata fingerprint could not close ---
  $nb = [datetime]::new(2026,1,1,0,0,0,[System.DateTimeKind]::Utc); $na = [datetime]::new(2027,1,1,0,0,0,[System.DateTimeKind]::Utc)
  $c1 = NewSelfSigned "CN=bank.example" $nb $na
  $c2 = NewSelfSigned "CN=bank.example" $nb $na      # SAME subject, issuer (self) and validity, DIFFERENT key
  Check ($c1.Subject -eq $c2.Subject -and $c1.Issuer -eq $c2.Issuer -and $c1.NotBefore -eq $c2.NotBefore -and $c1.NotAfter -eq $c2.NotAfter) "forged lookalike has identical subject/issuer/validity metadata"
  $mfp1 = CertFingerprint $c1.Subject $c1.Issuer $c1.NotBefore.ToString("o") $c1.NotAfter.ToString("o")
  $mfp2 = CertFingerprint $c2.Subject $c2.Issuer $c2.NotBefore.ToString("o") $c2.NotAfter.ToString("o")
  Check ($mfp1 -eq $mfp2) "metadata fingerprint CANNOT tell the lookalike apart (the documented weakness)"
  $d1 = DerFingerprint $c1; $d2 = DerFingerprint $c2; $d1b = DerFingerprint $c1
  Check ($d1 -match '^der-[0-9a-f]{64}$') "DER fingerprint has the expected 'der-' + 64 hex form"
  Check ($d1 -eq $d1b) "DER fingerprint is deterministic for the same certificate"
  Check ($d1 -ne $d2) "SECURITY: DER fingerprint DOES distinguish a same-metadata, different-key lookalike"
  Check ($d1 -ne $mfp1) "der- and meta- fingerprints can never collide (distinct prefixes)"
  Check (($d1 + $mfp1) -notmatch '[:|]') "fingerprints contain no ':' or '|' (safe inside web messages and ledger records)"
  $c1.Dispose(); $c2.Dispose()

  # --- build a ledger: explicitly trust fpA for bank.example ---
  $chain = Join-Path $TempRoot "site_policy.v1.ndjson"
  $head = ("0" * 64)
  $r1 = New-Receipt 1 "2026-01-01T00:00:00.001Z" ("site_policy.set|cert." + $fpA + "|bank.example|allow") "" $head; $head = $r1.hash
  WriteLines $chain @($r1.line)

  $v = Verify-Chain $chain
  Check ($v.count -eq 1) "1 certificate-trust receipt verifies as a valid chain"

  $state = Replay-SitePolicy $chain
  Check ((Get-SitePolicy $state "bank.example" ("cert." + $fpA) "deny") -eq "allow") "replay: explicitly trusted certificate (fpA) decides allow"
  Check ((Get-SitePolicy $state "bank.example" ("cert." + $fpB) "deny") -eq "deny") "SECURITY: a DIFFERENT certificate (fpB) for the SAME host does NOT inherit trust — pin does not transfer"
  Check ((Get-SitePolicy $state "evil.example" ("cert." + $fpA) "deny") -eq "deny") "trust does not transfer to a different host either, even with the identical certificate fingerprint"
  Check ((Get-SitePolicy $state "bank.example" ("cert." + $fpA) "deny") -ne "allow-everything") "sanity: decision values are exact strings, not truthy-anything"

  # --- negative: tamper the trust record, chain breaks ---
  $lines = @(Get-Content -LiteralPath $chain -Encoding UTF8 | Where-Object { $_ -ne "" })
  $t1 = @($lines); $t1[0] = $t1[0].Replace("|allow","|ALLOW_EVERYTHING")
  WriteLines $chain $t1
  ShouldThrow { Verify-Chain $chain } "tampering the trust record breaks chain verification"

  # --- static check: client certificates are unconditionally refused in the shipped source ---
  $srcPath = Join-Path $RepoRoot "browser\MainWindow.xaml.cs"
  Check (Test-Path -LiteralPath $srcPath -PathType Leaf) "browser source file found for static verification"
  $src = Get-Content -Raw -LiteralPath $srcPath
  $m = [regex]::Match($src, 'private void OnClientCertificateRequested\(.*?\)\s*\{(?<body>.*?)\n        \}', 'Singleline')
  Check $m.Success "OnClientCertificateRequested method located in shipped source"
  $fpm = [regex]::Match($src, 'private static string CertFingerprint\(.*?\n        \}\n', 'Singleline')
  Check ($fpm.Success -and $fpm.Value -match 'ToX509Certificate2' -and $fpm.Value -match 'RawData' -and $fpm.Value -match '"der-"') "shipped CertFingerprint pins on SHA-256 of the raw DER bytes (ToX509Certificate2().RawData)"
  if($m.Success){
    $body = $m.Groups["body"].Value
    Check ($body -match 'Cancel\s*=\s*true') "OnClientCertificateRequested sets Cancel = true"
    Check ($body -notmatch 'Cancel\s*=\s*false') "OnClientCertificateRequested contains no code path that sets Cancel = false (never auto-presents a client certificate)"
  }
}
catch {
  Write-Host ""
  Write-Host ("SELFTEST_ERROR: " + $_.Exception.Message) -ForegroundColor Red
  Write-Host ($_.InvocationInfo.PositionMessage) -ForegroundColor Red
  throw
}
finally {
  try { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue } catch {}
}

Write-Host ""
Write-Host ("checks passed: " + $script:pass + "  failed: " + $script:fail)
if($script:fail -gt 0){ Write-Error ("CERTIFICATE_MANAGER_SELFTEST_FAIL: " + $script:fail); exit 1 }
Write-Host "SELFTEST_RECOGNITION_CERTIFICATE_MANAGER_V1_OK" -ForegroundColor Green
