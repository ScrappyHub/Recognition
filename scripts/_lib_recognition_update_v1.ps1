# Recognition — Governed Updater library v1 (§54, Updater)
#
# An update package is a folder:
#   update_manifest.json   canonical signed record (version, channel, payload_id, files[])
#   update_manifest.sig    Ed25519 SSH signature over the manifest bytes (ssh-keygen -Y)
#   payload\...            the files listed in the manifest
#
# Authenticity = signature checked against the PINNED trust root
# (proofs/trust/allowed_signers) — the same mechanism as SoftwareID/attestation, no
# central authority. Nothing is applied unless EVERY check passes:
#   signature valid, schema/namespace right, every listed file's sha256+size matches,
#   no unlisted file in the payload, no path escaping the install root, no write into
#   protected locations (runtime\, proofs\trust\, proofs\software\), payload_id matches,
#   and the version is STRICTLY greater than the installed one (no downgrade/replay).
#
# This library does no network I/O: delivery of the package is out of scope (a package
# fetched over an untrusted channel is just as safe, because it is verified end-to-end).

Set-StrictMode -Version Latest

$script:RU_Namespace = "recognition/update"
$script:RU_Principal = "recognition-runtime-bridge"
$script:RU_Enc = New-Object System.Text.UTF8Encoding($false)

function RU-Sha256Hex([byte[]]$Bytes){
  $h = [System.Security.Cryptography.SHA256]::HashData($Bytes)
  -join ($h | ForEach-Object { $_.ToString("x2") })
}
function RU-Sha256File([string]$Path){ RU-Sha256Hex ([System.IO.File]::ReadAllBytes($Path)) }

function RU-FindSshKeygen(){
  foreach($cand in @((Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'), (Join-Path ${env:ProgramFiles} 'Git\usr\bin\ssh-keygen.exe'))){
    if($cand -and (Test-Path -LiteralPath $cand)){ return $cand }
  }
  return (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source
}

function RU-RunSsh([string[]]$SshArgs,[string]$StdinText = "",[int]$TimeoutMs = 20000){
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = (RU-FindSshKeygen)
  foreach($a in $SshArgs){ [void]$psi.ArgumentList.Add($a) }
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  if($StdinText){ $p.StandardInput.Write($StdinText) }
  try { $p.StandardInput.Close() } catch {}
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit($TimeoutMs)){ try { $p.Kill() } catch {}; return @{ ExitCode=124; Err="TIMEOUT" } }
  return @{ ExitCode=$p.ExitCode; Out=$o.Result; Err=$e.Result }
}

function RU-NormRel([string]$Rel){ ($Rel -replace '\\','/').TrimStart('/') }

# Returns $null if the relative path is safe, else a reason string.
function RU-PathProblem([string]$Rel){
  if([string]::IsNullOrWhiteSpace($Rel)){ return "empty path" }
  if([System.IO.Path]::IsPathRooted($Rel) -or $Rel -match '^[A-Za-z]:' -or $Rel.StartsWith("/") -or $Rel.StartsWith("\")){ return "rooted path" }
  $n = RU-NormRel $Rel
  foreach($seg in ($n -split '/')){
    if($seg -eq ".." -or $seg -eq "." -or $seg -eq ""){ return "path traversal / empty segment" }
  }
  $low = $n.ToLowerInvariant()
  foreach($prot in @("runtime/","proofs/trust/","proofs/software/")){
    if($low.StartsWith($prot) -or $low -eq $prot.TrimEnd('/')){ return ("protected location (" + $prot + ")") }
  }
  return $null
}

# payload_id = SHA-256 over "path:sha256:size\n" lines, sorted by path (ordinal).
function RU-ComputePayloadId($Files){
  $lines = @($Files | Sort-Object { [string]$_.path } -CaseSensitive | ForEach-Object { ([string]$_.path) + ":" + ([string]$_.sha256) + ":" + ([string]$_.size) })
  RU-Sha256Hex ($script:RU_Enc.GetBytes(($lines -join "`n") + "`n"))
}

function RU-GetInstalledVersion([string]$InstallRoot){
  $p = Join-Path (Join-Path $InstallRoot "config") "version.v1.json"
  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ return [version]"0.0.0" }
  try { return [version]([string]((Get-Content -Raw -LiteralPath $p -Encoding UTF8 | ConvertFrom-Json).version)) }
  catch { return [version]"0.0.0" }
}

# BUILD: package a payload directory, sign the manifest with a private key held OUTSIDE the repo.
function RU-Build([string]$PayloadDir,[string]$OutDir,[string]$Version,[string]$KeyPath,[string]$Channel = "stable",[string]$RepoRoot = ""){
  $PayloadDir = (Resolve-Path -LiteralPath $PayloadDir).Path
  [void][version]$Version   # throws on a malformed version
  $keyFull = [System.IO.Path]::GetFullPath($KeyPath)
  if($RepoRoot){
    $rr = (Resolve-Path -LiteralPath $RepoRoot).Path
    if($keyFull.StartsWith($rr,[System.StringComparison]::OrdinalIgnoreCase)){ throw "KEYPATH_INSIDE_REPO: keep the private key outside the repo" }
  }
  if(-not (Test-Path -LiteralPath $keyFull -PathType Leaf)){ throw ("SIGNING_KEY_MISSING: " + $keyFull) }

  if(Test-Path -LiteralPath $OutDir){ throw ("OUTDIR_EXISTS: " + $OutDir) }
  New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "payload") | Out-Null

  $files = New-Object System.Collections.Generic.List[object]
  foreach($f in @(Get-ChildItem -LiteralPath $PayloadDir -Recurse -File -Force)){
    $rel = RU-NormRel ($f.FullName.Substring($PayloadDir.Length))
    $prob = RU-PathProblem $rel
    if($prob){ throw ("PAYLOAD_PATH_REFUSED: " + $rel + " — " + $prob) }
    $dest = Join-Path (Join-Path $OutDir "payload") ($rel -replace '/','\')
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item -LiteralPath $f.FullName -Destination $dest -Force
    $files.Add([ordered]@{ path=$rel; sha256=(RU-Sha256File $dest); size=[int64]$f.Length })
  }
  if($files.Count -eq 0){ throw "EMPTY_PAYLOAD" }
  $sorted = @($files | Sort-Object { [string]$_.path } -CaseSensitive)

  $manifest = [ordered]@{
    schema     = "recognition.update.v1"
    version    = $Version
    channel    = $Channel
    payload_id = (RU-ComputePayloadId $sorted)
    files      = $sorted
    principal  = $script:RU_Principal
    namespace  = $script:RU_Namespace
    signed_utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  }
  $json = (($manifest | ConvertTo-Json -Depth 8) -replace "`r`n","`n")
  if(-not $json.EndsWith("`n")){ $json += "`n" }
  $manPath = Join-Path $OutDir "update_manifest.json"
  [System.IO.File]::WriteAllText($manPath, $json, $script:RU_Enc)

  $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("upd_" + [Guid]::NewGuid().ToString("N"))
  Copy-Item -LiteralPath $manPath -Destination $tmp -Force
  try {
    $sg = RU-RunSsh @("-Y","sign","-f",$keyFull,"-n",$script:RU_Namespace,$tmp)
    if($sg.ExitCode -ne 0){ throw ("SIGN_FAILED: " + ([string]$sg.Err).Trim()) }
    Move-Item -LiteralPath ($tmp + ".sig") -Destination (Join-Path $OutDir "update_manifest.sig") -Force
  } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
  return @{ version=$Version; payload_id=$manifest.payload_id; file_count=$sorted.Count; out=$OutDir }
}

# VERIFY: every check must pass. Returns @{ ok; reason; version; payload_id; manifest } — never throws on a
# bad package (returns ok=$false with the reason), so callers can fail closed deterministically.
function RU-Verify([string]$PackageDir,[string]$InstallRoot,[string]$TrustRoot){
  function Fail([string]$why){ return @{ ok=$false; reason=$why } }
  try {
    $manPath = Join-Path $PackageDir "update_manifest.json"
    $sigPath = Join-Path $PackageDir "update_manifest.sig"
    $payload = Join-Path $PackageDir "payload"
    if(-not (Test-Path -LiteralPath $manPath -PathType Leaf)){ return Fail "manifest missing" }
    if(-not (Test-Path -LiteralPath $sigPath -PathType Leaf)){ return Fail "signature missing" }
    if(-not (Test-Path -LiteralPath $TrustRoot -PathType Leaf)){ return Fail "trust root missing" }
    if(-not (Test-Path -LiteralPath $payload -PathType Container)){ return Fail "payload directory missing" }

    # 1. authenticity — signature over the exact manifest bytes, against the pinned trust root
    $raw = Get-Content -Raw -LiteralPath $manPath -Encoding UTF8
    $sv = RU-RunSsh @("-Y","verify","-f",$TrustRoot,"-I",$script:RU_Principal,"-n",$script:RU_Namespace,"-s",$sigPath) $raw
    if($sv.ExitCode -ne 0){ return Fail ("signature invalid against pinned trust root: " + ([string]$sv.Err).Trim()) }

    $m = $raw | ConvertFrom-Json
    if([string]$m.schema -ne "recognition.update.v1"){ return Fail "wrong schema" }
    if([string]$m.namespace -ne $script:RU_Namespace){ return Fail "wrong namespace" }
    $newVer = $null
    try { $newVer = [version][string]$m.version } catch { return Fail "unparseable version" }

    # 2. anti-downgrade / anti-replay
    $cur = RU-GetInstalledVersion $InstallRoot
    if($newVer -le $cur){ return Fail ("not newer than installed (" + $newVer + " <= " + $cur + ") — downgrade/replay refused") }

    # 3. file list: safe paths, hashes, sizes, payload_id
    $listed = @($m.files)
    if($listed.Count -eq 0){ return Fail "empty file list" }
    $seen = @{}
    foreach($f in $listed){
      $rel = RU-NormRel ([string]$f.path)
      $prob = RU-PathProblem $rel
      if($prob){ return Fail ("unsafe path '" + $rel + "': " + $prob) }
      if($seen.ContainsKey($rel.ToLowerInvariant())){ return Fail ("duplicate path '" + $rel + "'") }
      $seen[$rel.ToLowerInvariant()] = $true
      $fp = Join-Path $payload ($rel -replace '/','\')
      if(-not (Test-Path -LiteralPath $fp -PathType Leaf)){ return Fail ("listed file missing from payload: " + $rel) }
      if((Get-Item -LiteralPath $fp).Length -ne [int64]$f.size){ return Fail ("size mismatch: " + $rel) }
      if((RU-Sha256File $fp) -ne ([string]$f.sha256).ToLowerInvariant()){ return Fail ("hash mismatch: " + $rel) }
    }
    if((RU-ComputePayloadId $listed) -ne [string]$m.payload_id){ return Fail "payload_id does not match file list" }

    # 4. nothing unlisted may ride along in the payload
    $root = (Resolve-Path -LiteralPath $payload).Path
    foreach($f in @(Get-ChildItem -LiteralPath $root -Recurse -File -Force)){
      $rel = (RU-NormRel ($f.FullName.Substring($root.Length))).ToLowerInvariant()
      if(-not $seen.ContainsKey($rel)){ return Fail ("unlisted file in payload: " + $rel) }
    }
    return @{ ok=$true; reason=""; version=[string]$newVer; payload_id=[string]$m.payload_id; manifest=$m }
  } catch { return Fail ("verification error: " + $_.Exception.Message) }
}

function RU-AppendReceipt([string]$InstallRoot,$Obj){
  $rp = Join-Path (Join-Path (Join-Path $InstallRoot "proofs") "receipts") "recognition.update.v1.ndjson"
  $rd = Split-Path -Parent $rp
  if(-not (Test-Path -LiteralPath $rd)){ New-Item -ItemType Directory -Force -Path $rd | Out-Null }
  [System.IO.File]::AppendAllText($rp, (($Obj | ConvertTo-Json -Depth 8 -Compress) + "`n"), $script:RU_Enc)
}

# APPLY: verify first (fail closed), back up every replaced file, copy, re-verify installed bytes, and roll
# back automatically on any failure. A refused/failed update leaves the install byte-identical.
function RU-Apply([string]$PackageDir,[string]$InstallRoot,[string]$TrustRoot){
  $v = RU-Verify $PackageDir $InstallRoot $TrustRoot
  $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  if(-not $v.ok){
    RU-AppendReceipt $InstallRoot ([ordered]@{ schema="recognition.update.receipt.v1"; ts_utc=$ts; outcome="refused"; reason=$v.reason })
    return @{ ok=$false; reason=$v.reason }
  }
  $m = $v.manifest
  $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
  $backup = Join-Path (Join-Path (Join-Path $InstallRoot "runtime") "update_backup") ($v.version + "_" + $stamp)
  New-Item -ItemType Directory -Force -Path $backup | Out-Null
  $touched = New-Object System.Collections.Generic.List[object]   # @{ rel; had }
  $verPath = Join-Path (Join-Path $InstallRoot "config") "version.v1.json"
  $hadVer = Test-Path -LiteralPath $verPath -PathType Leaf
  $verBackedUp = $false
  try {
    # back up the version marker FIRST so a failure at any later point can restore it
    if($hadVer){ Copy-Item -LiteralPath $verPath -Destination (Join-Path $backup "__version.v1.json") -Force; $verBackedUp = $true }
    foreach($f in @($m.files)){
      $rel = RU-NormRel ([string]$f.path)
      $dest = Join-Path $InstallRoot ($rel -replace '/','\')
      $had = Test-Path -LiteralPath $dest -PathType Leaf
      if($had){
        $b = Join-Path $backup ($rel -replace '/','\')
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $b) | Out-Null
        Copy-Item -LiteralPath $dest -Destination $b -Force
      }
      $touched.Add(@{ rel=$rel; had=$had })
      New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
      Copy-Item -LiteralPath (Join-Path (Join-Path $PackageDir "payload") ($rel -replace '/','\')) -Destination $dest -Force
    }
    # re-verify installed bytes against the signed manifest
    foreach($f in @($m.files)){
      $dest = Join-Path $InstallRoot ((RU-NormRel ([string]$f.path)) -replace '/','\')
      if((RU-Sha256File $dest) -ne ([string]$f.sha256).ToLowerInvariant()){ throw ("post-apply hash mismatch: " + $f.path) }
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $verPath) | Out-Null
    [System.IO.File]::WriteAllText($verPath, ((([ordered]@{ schema="recognition.version.v1"; version=$v.version }) | ConvertTo-Json -Compress) + "`n"), $script:RU_Enc)
    RU-AppendReceipt $InstallRoot ([ordered]@{ schema="recognition.update.receipt.v1"; ts_utc=$ts; outcome="applied"; version=$v.version; payload_id=$v.payload_id; file_count=@($m.files).Count })
    return @{ ok=$true; version=$v.version; payload_id=$v.payload_id; backup=$backup }
  } catch {
    $why = $_.Exception.Message
    foreach($t in $touched){
      $dest = Join-Path $InstallRoot ($t.rel -replace '/','\')
      if($t.had){ Copy-Item -LiteralPath (Join-Path $backup ($t.rel -replace '/','\')) -Destination $dest -Force }
      else { Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue }
    }
    if($verBackedUp){ Copy-Item -LiteralPath (Join-Path $backup "__version.v1.json") -Destination $verPath -Force }
    RU-AppendReceipt $InstallRoot ([ordered]@{ schema="recognition.update.receipt.v1"; ts_utc=$ts; outcome="rolled_back"; reason=$why })
    return @{ ok=$false; reason=("apply failed, rolled back: " + $why) }
  }
}
