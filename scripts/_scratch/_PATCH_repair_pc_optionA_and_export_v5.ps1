param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  EnsureDir (Split-Path -Parent $Path)
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){ $x=$e[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message) }
}

$ScriptsDir = Join-Path $RepoRoot "scripts"
$ScratchDir = Join-Path $ScriptsDir "_scratch"
EnsureDir $ScriptsDir; EnsureDir $ScratchDir

# ---------------- scripts/_lib_packet_constitution_v1.ps1 (REWRITE CLEAN) ----------------
$libPath = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$lib = @'
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function PC-Die([string]$m){ throw $m }
function PC-EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ PC-Die "PC-EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function PC-WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  PC-EnsureDir (Split-Path -Parent $Path)
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function PC-Sha256HexBytes([byte[]]$Bytes){
  if($null -eq $Bytes){ PC-Die "PC-Sha256HexBytes: null bytes" }
  $sha=[System.Security.Cryptography.SHA256]::Create()
  try{ $h=$sha.ComputeHash($Bytes) } finally{ $sha.Dispose() }
  $sb=New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }
  $sb.ToString()
}
function PC-Sha256HexFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ PC-Die ("MISSING_FILE: " + $Path) }
  $sha=[System.Security.Cryptography.SHA256]::Create()
  try{
    $fs=[System.IO.File]::OpenRead($Path)
    try{ $h=$sha.ComputeHash($fs) } finally{ $fs.Dispose() }
  } finally{ $sha.Dispose() }
  $sb=New-Object System.Text.StringBuilder
  foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }
  $sb.ToString()
}
function PC-NowUtc(){ (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }

# Canonical JSON: stable ordering; no whitespace; stable escaping
function PC-EscapeJsonString([string]$s){
  if($null -eq $s){ return "" }
  $sb = New-Object System.Text.StringBuilder
  for($i=0;$i -lt $s.Length;$i++){
    $code = [int][char]$s[$i]
    if($code -eq 8){  [void]$sb.Append([char]92); [void]$sb.Append("b"); continue }
    if($code -eq 9){  [void]$sb.Append([char]92); [void]$sb.Append("t"); continue }
    if($code -eq 10){ [void]$sb.Append([char]92); [void]$sb.Append("n"); continue }
    if($code -eq 12){ [void]$sb.Append([char]92); [void]$sb.Append("f"); continue }
    if($code -eq 13){ [void]$sb.Append([char]92); [void]$sb.Append("r"); continue }
    if($code -eq 34){ [void]$sb.Append([char]92); [void]$sb.Append([char]34); continue }  # \"
    if($code -eq 92){ [void]$sb.Append([char]92); [void]$sb.Append([char]92); continue }  # \\
    if($code -lt 32){
      [void]$sb.Append([char]92); [void]$sb.Append("u")
      [void]$sb.Append(("{0:x4}" -f $code))
      continue
    }
    [void]$sb.Append([char]$code)
  }
  $sb.ToString()
}
function PC-ToCanonJson($v){
  if($null -eq $v){ return "null" }
  if($v -is [string]){ return ("""" + (PC-EscapeJsonString $v) + """") }
  if($v -is [bool]){ return ($(if($v){"true"}else{"false"})) }
  if($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]){
    return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,"{0}",$v)).ToLowerInvariant()
  }
  if($v -is [hashtable] -or $v -is [System.Collections.IDictionary]){
    $keys = @(@($v.Keys) | ForEach-Object { [string]$_ } | Sort-Object)
    $parts = New-Object System.Collections.Generic.List[string]
    foreach($kk in @($keys)){
      $k = [string]$kk
      $vv = $v[$k]
      [void]$parts.Add( ("""" + (PC-EscapeJsonString $k) + """:" + (PC-ToCanonJson $vv)) )
    }
    return ("{" + (@($parts) -join ",") + "}")
  }
  if($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){
    $parts = New-Object System.Collections.Generic.List[string]
    foreach($it in @($v)){ [void]$parts.Add((PC-ToCanonJson $it)) }
    return ("[" + (@($parts) -join ",") + "]")
  }
  return ("""" + (PC-EscapeJsonString ([string]$v)) + """")
}
function PC-CanonBytesFromCanonJson([string]$canon){
  $t = ($canon -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  $enc = New-Object System.Text.UTF8Encoding($false)
  $enc.GetBytes($t)
}
function PC-ComputePacketIdFromManifestNoIdCanon([string]$manifestCanonNoId){
  PC-Sha256HexBytes (PC-CanonBytesFromCanonJson $manifestCanonNoId)
}
function PC-RelPath([string]$Root,[string]$Full){
  $r=[System.IO.Path]::GetFullPath($Root)
  $f=[System.IO.Path]::GetFullPath($Full)
  if(-not $f.StartsWith($r,[System.StringComparison]::OrdinalIgnoreCase)){ PC-Die ("PC-RelPath: not under root: " + $Full) }
  $rel=$f.Substring($r.Length).TrimStart("\","/")
  ($rel -replace "\","/")
}
function PC-ListFilesRec([string]$Dir){
  if(-not (Test-Path -LiteralPath $Dir -PathType Container)){ PC-Die ("MISSING_DIR: " + $Dir) }
  @(@(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force | Sort-Object FullName))
}
'@
WriteUtf8NoBomLf $libPath $lib
ParseGateFile $libPath

# Re-parse-gate existing scripts (builder/verifier/selftest/exporter) that you already wrote
$paths = @(
  (Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"),
  (Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"),
  (Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"),
  (Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1")
)
foreach($p in @($paths)){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ Die ("MISSING_SCRIPT: " + $p) }; ParseGateFile $p }

# Run selftest (must pass or we throw)
$ps = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1") -RepoRoot $RepoRoot | Out-Host
Write-Host ("REPAIR_OK: Packet Constitution v1 Option A repaired + selftest passed; exporter -> " + (Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1")) -ForegroundColor Green
