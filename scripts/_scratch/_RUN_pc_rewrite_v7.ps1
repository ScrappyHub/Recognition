param([Parameter(Mandatory=$true)][string]$RepoRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){
  if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }
  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }
}
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $enc = New-Object System.Text.UTF8Encoding($false)
  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $lf.EndsWith("`n")){ $lf += "`n" }
  EnsureDir (Split-Path -Parent $Path)
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and @($e).Count -gt 0){
    $x=@($e)[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
}
function FailIfBadReplace([string]$Path){
  $hits = @(Select-String -LiteralPath $Path -Pattern '\-replace\s+["'']\\["'']' -ErrorAction Stop)
  if(@($hits).Count -gt 0){
    $h = @($hits)[0]
    Die ("BAD_REGEX_BACKSLASH_REPLACE: {0}:{1}: {2}" -f $Path,$h.LineNumber,$h.Line.Trim())
  }
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir
EnsureDir (Join-Path $ScriptsDir "_scratch")

# =========================================================
# scripts/_lib_packet_constitution_v1.ps1
# - fixes IEnumerable handling deterministically (materialize to object[])
# =========================================================
$libPath = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$L = New-Object System.Collections.Generic.List[string]

[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference = "Stop"')
[void]$L.Add('')
[void]$L.Add('function PC-Die([string]$m){ throw $m }')
[void]$L.Add('function PC-EnsureDir([string]$p){')
[void]$L.Add('  if([string]::IsNullOrWhiteSpace($p)){ PC-Die "PC-EnsureDir: empty path" }')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null }')
[void]$L.Add('}')
[void]$L.Add('function PC-WriteUtf8NoBomLf([string]$Path,[string]$Text){')
[void]$L.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$L.Add('  $lf  = ($Text -replace "`r`n","`n") -replace "`r","`n"')
[void]$L.Add('  if(-not $lf.EndsWith("`n")){ $lf += "`n" }')
[void]$L.Add('  PC-EnsureDir (Split-Path -Parent $Path)')
[void]$L.Add('  [System.IO.File]::WriteAllText($Path,$lf,$enc)')
[void]$L.Add('}')
[void]$L.Add('')
[void]$L.Add('function PC-Sha256HexBytes([byte[]]$Bytes){')
[void]$L.Add('  if($null -eq $Bytes){ PC-Die "PC-Sha256HexBytes: null bytes" }')
[void]$L.Add('  $sha=[System.Security.Cryptography.SHA256]::Create()')
[void]$L.Add('  try{ $h=$sha.ComputeHash($Bytes) } finally{ $sha.Dispose() }')
[void]$L.Add('  $sb=New-Object System.Text.StringBuilder')
[void]$L.Add('  foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }')
[void]$L.Add('  $sb.ToString()')
[void]$L.Add('}')
[void]$L.Add('function PC-Sha256HexFile([string]$Path){')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ PC-Die ("MISSING_FILE: " + $Path) }')
[void]$L.Add('  $sha=[System.Security.Cryptography.SHA256]::Create()')
[void]$L.Add('  try{')
[void]$L.Add('    $fs=[System.IO.File]::OpenRead($Path)')
[void]$L.Add('    try{ $h=$sha.ComputeHash($fs) } finally{ $fs.Dispose() }')
[void]$L.Add('  } finally{ $sha.Dispose() }')
[void]$L.Add('  $sb=New-Object System.Text.StringBuilder')
[void]$L.Add('  foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }')
[void]$L.Add('  $sb.ToString()')
[void]$L.Add('}')
[void]$L.Add('')
[void]$L.Add('function PC-EscapeJsonString([string]$s){')
[void]$L.Add('  if($null -eq $s){ return "" }')
[void]$L.Add('  $sb = New-Object System.Text.StringBuilder')
[void]$L.Add('  for($i=0;$i -lt $s.Length;$i++){')
[void]$L.Add('    $code = [int][char]$s[$i]')
[void]$L.Add('    if($code -eq 8){  [void]$sb.Append("\b"); continue }')
[void]$L.Add('    if($code -eq 9){  [void]$sb.Append("\t"); continue }')
[void]$L.Add('    if($code -eq 10){ [void]$sb.Append("\n"); continue }')
[void]$L.Add('    if($code -eq 12){ [void]$sb.Append("\f"); continue }')
[void]$L.Add('    if($code -eq 13){ [void]$sb.Append("\r"); continue }')
[void]$L.Add('    if($code -eq 34){ [void]$sb.Append("\\\""); continue }')
[void]$L.Add('    if($code -eq 92){ [void]$sb.Append("\\\\"); continue }')
[void]$L.Add('    if($code -lt 32){ [void]$sb.Append( ("\\u{0:x4}" -f $code) ); continue }')
[void]$L.Add('    [void]$sb.Append([char]$code)')
[void]$L.Add('  }')
[void]$L.Add('  $sb.ToString()')
[void]$L.Add('}')
[void]$L.Add('function PC-ToCanonJson($v){')
[void]$L.Add('  if($null -eq $v){ return "null" }')
[void]$L.Add('  if($v -is [string]){ return (''"'' + (PC-EscapeJsonString $v) + ''"'') }')
[void]$L.Add('  if($v -is [bool]){ return ($(if($v){"true"}else{"false"})) }')
[void]$L.Add('  if($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]){')
[void]$L.Add('    return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,"{0}",$v)).ToLowerInvariant()')
[void]$L.Add('  }')
[void]$L.Add('  if($v -is [hashtable] -or $v -is [System.Collections.IDictionary]){')
[void]$L.Add('    $keys = @(@($v.Keys) | ForEach-Object { [string]$_ } | Sort-Object)')
[void]$L.Add('    $parts = New-Object System.Collections.Generic.List[string]')
[void]$L.Add('    foreach($kk in @($keys)){')
[void]$L.Add('      $k = [string]$kk')
[void]$L.Add('      $vv = $v[$k]')
[void]$L.Add('      [void]$parts.Add( (''"'' + (PC-EscapeJsonString $k) + ''":'' + (PC-ToCanonJson $vv)) )')
[void]$L.Add('    }')
[void]$L.Add('    return ("{" + (@($parts) -join ",") + "}")')
[void]$L.Add('  }')
[void]$L.Add('  if($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){')
[void]$L.Add('    $items = @()')
[void]$L.Add('    if($v -is [System.Array]){')
[void]$L.Add('      $items = @($v)')
[void]$L.Add('    } else {')
[void]$L.Add('      $tmp = New-Object System.Collections.Generic.List[object]')
[void]$L.Add('      foreach($it in $v){ [void]$tmp.Add($it) }')
[void]$L.Add('      $items = @($tmp.ToArray())')
[void]$L.Add('    }')
[void]$L.Add('    $parts = New-Object System.Collections.Generic.List[string]')
[void]$L.Add('    foreach($it in @($items)){ [void]$parts.Add((PC-ToCanonJson $it)) }')
[void]$L.Add('    return ("[" + (@($parts) -join ",") + "]")')
[void]$L.Add('  }')
[void]$L.Add('  return (''"'' + (PC-EscapeJsonString ([string]$v)) + ''"'')')
[void]$L.Add('}')
[void]$L.Add('function PC-CanonBytesFromCanonJson([string]$canon){')
[void]$L.Add('  $t = ($canon -replace "`r`n","`n") -replace "`r","`n"')
[void]$L.Add('  if(-not $t.EndsWith("`n")){ $t += "`n" }')
[void]$L.Add('  $enc = New-Object System.Text.UTF8Encoding($false)')
[void]$L.Add('  $enc.GetBytes($t)')
[void]$L.Add('}')
[void]$L.Add('function PC-ComputePacketIdFromManifestNoIdCanon([string]$manifestCanonNoId){')
[void]$L.Add('  PC-Sha256HexBytes (PC-CanonBytesFromCanonJson $manifestCanonNoId)')
[void]$L.Add('}')
[void]$L.Add('function PC-RelPath([string]$Root,[string]$Full){')
[void]$L.Add('  $r=[System.IO.Path]::GetFullPath($Root)')
[void]$L.Add('  $f=[System.IO.Path]::GetFullPath($Full)')
[void]$L.Add('  if(-not $f.StartsWith($r,[System.StringComparison]::OrdinalIgnoreCase)){ PC-Die ("PC-RelPath: not under root: " + $Full) }')
[void]$L.Add('  $rel=$f.Substring($r.Length).TrimStart([char]92,[char]47)')
[void]$L.Add('  $rel.Replace([char]92,[char]47)')
[void]$L.Add('}')
[void]$L.Add('function PC-ListFilesRec([string]$Dir){')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $Dir -PathType Container)){ PC-Die ("MISSING_DIR: " + $Dir) }')
[void]$L.Add('  @(@(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force | Sort-Object FullName))')
[void]$L.Add('}')

WriteUtf8NoBomLf $libPath ((@($L) -join "`n") + "`n")
ParseGateFile $libPath
FailIfBadReplace $libPath

# =========================================================
# scripts/pc_build_packet_optionA_v1.ps1
# - explicit dest per child prevents Copy-Item overload ambiguity
# =========================================================
$builderPath = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$B = New-Object System.Collections.Generic.List[string]
[void]$B.Add('param(')
[void]$B.Add('  [Parameter(Mandatory=$true)][string]$RepoRoot,')
[void]$B.Add('  [Parameter(Mandatory=$true)][string]$PayloadDir,')
[void]$B.Add('  [Parameter(Mandatory=$true)][string]$OutDir,')
[void]$B.Add('  [Parameter(Mandatory=$false)][string]$PacketName = "packet"')
[void]$B.Add(')')
[void]$B.Add('Set-StrictMode -Version Latest')
[void]$B.Add('$ErrorActionPreference = "Stop"')
[void]$B.Add('. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")')
[void]$B.Add('')
[void]$B.Add('if(-not (Test-Path -LiteralPath $PayloadDir -PathType Container)){ PC-Die ("MISSING_PAYLOAD_DIR: " + $PayloadDir) }')
[void]$B.Add('PC-EnsureDir $OutDir')
[void]$B.Add('')
[void]$B.Add('$work = Join-Path $OutDir ($PacketName + "_work")')
[void]$B.Add('if(Test-Path -LiteralPath $work){ Remove-Item -LiteralPath $work -Recurse -Force }')
[void]$B.Add('PC-EnsureDir $work')
[void]$B.Add('')
[void]$B.Add('# 1) payload/**')
[void]$B.Add('$pktPayload = Join-Path $work "payload"')
[void]$B.Add('PC-EnsureDir $pktPayload')
[void]$B.Add('$children = @(@(Get-ChildItem -LiteralPath $PayloadDir -Force | Sort-Object FullName))')
[void]$B.Add('foreach($c in @($children)){')
[void]$B.Add('  $dest = Join-Path $pktPayload $c.Name')
[void]$B.Add('  if(Test-Path -LiteralPath $c.FullName -PathType Container){')
[void]$B.Add('    Copy-Item -LiteralPath $c.FullName -Destination $dest -Recurse -Force')
[void]$B.Add('  } else {')
[void]$B.Add('    Copy-Item -LiteralPath $c.FullName -Destination $dest -Force')
[void]$B.Add('  }')
[void]$B.Add('}')
[void]$B.Add('')
[void]$B.Add('# 2) manifest.json without id')
[void]$B.Add('$files = New-Object System.Collections.Generic.List[object]')
[void]$B.Add('$all = PC-ListFilesRec $work')
[void]$B.Add('foreach($f in @($all)){')
[void]$B.Add('  $rel = PC-RelPath $work $f.FullName')
[void]$B.Add('  if($rel -ieq "manifest.json"){ continue }')
[void]$B.Add('  if($rel -ieq "packet_id.txt"){ continue }')
[void]$B.Add('  if($rel -ieq "sha256sums.txt"){ continue }')
[void]$B.Add('  $h = PC-Sha256HexFile $f.FullName')
[void]$B.Add('  $o = @{}')
[void]$B.Add('  $o["path"]  = $rel')
[void]$B.Add('  $o["bytes"] = [int64]$f.Length')
[void]$B.Add('  $o["sha256"]= $h')
[void]$B.Add('  [void]$files.Add($o)')
[void]$B.Add('}')
[void]$B.Add('')
[void]$B.Add('$m = @{}')
[void]$B.Add('$m["schema"] = "packet.manifest.v1"')
[void]$B.Add('$m["option"] = "A"')
[void]$B.Add('$m["files"]  = @($files.ToArray())')
[void]$B.Add('')
[void]$B.Add('$manifestCanonNoId = PC-ToCanonJson $m')
[void]$B.Add('$manifestPath = Join-Path $work "manifest.json"')
[void]$B.Add('PC-WriteUtf8NoBomLf $manifestPath $manifestCanonNoId')
[void]$B.Add('')
[void]$B.Add('# 3) signatures dir exists by law')
[void]$B.Add('PC-EnsureDir (Join-Path $work "signatures")')
[void]$B.Add('')
[void]$B.Add('# 4) PacketId = SHA256(canon_bytes(manifest-without-id))')
[void]$B.Add('$packetId = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanonNoId')
[void]$B.Add('')
[void]$B.Add('# 5) packet_id.txt')
[void]$B.Add('$pidPath = Join-Path $work "packet_id.txt"')
[void]$B.Add('PC-WriteUtf8NoBomLf $pidPath ($packetId + "`n")')
[void]$B.Add('')
[void]$B.Add('# 6) sha256sums last (exclude sha256sums itself)')
[void]$B.Add('$all2 = PC-ListFilesRec $work')
[void]$B.Add('$lines = New-Object System.Collections.Generic.List[string]')
[void]$B.Add('foreach($f in @($all2)){')
[void]$B.Add('  $rel = PC-RelPath $work $f.FullName')
[void]$B.Add('  if($rel -ieq "sha256sums.txt"){ continue }')
[void]$B.Add('  $h = PC-Sha256HexFile $f.FullName')
[void]$B.Add('  [void]$lines.Add(("{0}  {1}" -f $h,$rel))')
[void]$B.Add('}')
[void]$B.Add('$sumPath = Join-Path $work "sha256sums.txt"')
[void]$B.Add('PC-WriteUtf8NoBomLf $sumPath ((@($lines) -join "`n") + "`n")')
[void]$B.Add('')
[void]$B.Add('# 7) finalize folder named by PacketId')
[void]$B.Add('$final = Join-Path $OutDir $packetId')
[void]$B.Add('if(Test-Path -LiteralPath $final){ Remove-Item -LiteralPath $final -Recurse -Force }')
[void]$B.Add('Move-Item -LiteralPath $work -Destination $final')
[void]$B.Add('Write-Output $final')

WriteUtf8NoBomLf $builderPath ((@($B) -join "`n") + "`n")
ParseGateFile $builderPath
FailIfBadReplace $builderPath

# =========================================================
# scripts/pc_verify_packet_optionA_v1.ps1
# =========================================================
$verPath = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$V = New-Object System.Collections.Generic.List[string]
[void]$V.Add('param([Parameter(Mandatory=$true)][string]$PacketDir)')
[void]$V.Add('Set-StrictMode -Version Latest')
[void]$V.Add('$ErrorActionPreference = "Stop"')
[void]$V.Add('. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")')
[void]$V.Add('')
[void]$V.Add('if(-not (Test-Path -LiteralPath $PacketDir -PathType Container)){ PC-Die ("MISSING_PACKET_DIR: " + $PacketDir) }')
[void]$V.Add('$packetDirName = Split-Path -Leaf $PacketDir')
[void]$V.Add('$manifestPath  = Join-Path $PacketDir "manifest.json"')
[void]$V.Add('$pidPath       = Join-Path $PacketDir "packet_id.txt"')
[void]$V.Add('$sumPath       = Join-Path $PacketDir "sha256sums.txt"')
[void]$V.Add('foreach($p in @($manifestPath,$pidPath,$sumPath)){')
[void]$V.Add('  if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ PC-Die ("MISSING_REQUIRED_FILE: " + $p) }')
[void]$V.Add('}')
[void]$V.Add('')
[void]$V.Add('# 1) verify sha256sums')
[void]$V.Add('$raw = Get-Content -Raw -LiteralPath $sumPath -Encoding UTF8')
[void]$V.Add('$lines = @(@($raw -split "`n") | Where-Object { $_ -and $_.Trim().Length -gt 0 })')
[void]$V.Add('foreach($ln in @($lines)){')
[void]$V.Add('  $mm = [regex]::Match($ln, "^(?<h>[0-9a-f]{64})\s\s(?<p>.+)$")')
[void]$V.Add('  if(-not $mm.Success){ PC-Die ("BAD_SHA256SUMS_LINE: " + $ln) }')
[void]$V.Add('  $h   = $mm.Groups["h"].Value')
[void]$V.Add('  $rel = $mm.Groups["p"].Value')
[void]$V.Add('  $winRel = $rel.Replace([char]47,[char]92)')
[void]$V.Add('  $full = Join-Path $PacketDir $winRel')
[void]$V.Add('  if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ PC-Die ("MISSING_FILE_LISTED_IN_SHA256SUMS: " + $rel) }')
[void]$V.Add('  $hh = PC-Sha256HexFile $full')
[void]$V.Add('  if($hh -ne $h){ PC-Die ("SHA256_MISMATCH: " + $rel + " expected=" + $h + " got=" + $hh) }')
[void]$V.Add('}')
[void]$V.Add('')
[void]$V.Add('# 2) verify PacketId rule')
[void]$V.Add('$pid = (Get-Content -Raw -LiteralPath $pidPath -Encoding UTF8).Trim()')
[void]$V.Add('$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8')
[void]$V.Add('$manifestCanon = ($manifestRaw -replace "`r`n","`n") -replace "`r","`n"')
[void]$V.Add('$expected = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanon')
[void]$V.Add('if($expected -ne $pid){ PC-Die ("PACKET_ID_MISMATCH: expected=" + $expected + " file=" + $pid) }')
[void]$V.Add('if($packetDirName -ne $pid){ PC-Die ("PACKET_DIRNAME_MISMATCH: dir=" + $packetDirName + " pid=" + $pid) }')
[void]$V.Add('Write-Host ("VERIFY_OK: " + $PacketDir) -ForegroundColor Green')

WriteUtf8NoBomLf $verPath ((@($V) -join "`n") + "`n")
ParseGateFile $verPath
FailIfBadReplace $verPath

# =========================================================
# scripts/_selftest_packet_constitution_v1.ps1
# =========================================================
$selfPath = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$S = New-Object System.Collections.Generic.List[string]
[void]$S.Add('param([Parameter(Mandatory=$true)][string]$RepoRoot)')
[void]$S.Add('Set-StrictMode -Version Latest')
[void]$S.Add('$ErrorActionPreference = "Stop"')
[void]$S.Add('. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")')
[void]$S.Add('')
[void]$S.Add('$tv      = Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_minimal_optionA"')
[void]$S.Add('$payload = Join-Path $tv "payload"')
[void]$S.Add('$out     = Join-Path $tv "out"')
[void]$S.Add('$gold    = Join-Path $tv "golden"')
[void]$S.Add('PC-EnsureDir $tv; PC-EnsureDir $payload; PC-EnsureDir $out; PC-EnsureDir $gold')
[void]$S.Add('')
[void]$S.Add('PC-WriteUtf8NoBomLf (Join-Path $payload "hello.txt") ("hello`n")')
[void]$S.Add('$metaCanon = PC-ToCanonJson (@{ schema="recognition.payload.meta.v1"; note="minimal"; n=1 })')
[void]$S.Add('PC-WriteUtf8NoBomLf (Join-Path $payload "meta.json") $metaCanon')
[void]$S.Add('')
[void]$S.Add('$builder = Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"')
[void]$S.Add('$ver     = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"')
[void]$S.Add('if(-not (Test-Path -LiteralPath $builder -PathType Leaf)){ PC-Die ("MISSING_BUILDER: " + $builder) }')
[void]$S.Add('if(-not (Test-Path -LiteralPath $ver -PathType Leaf)){ PC-Die ("MISSING_VERIFIER: " + $ver) }')
[void]$S.Add('')
[void]$S.Add('$pktDir = & $builder -RepoRoot $RepoRoot -PayloadDir $payload -OutDir $out -PacketName "tv"')
[void]$S.Add('if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ PC-Die ("SELFTEST_BUILD_FAIL: " + $pktDir) }')
[void]$S.Add('& $ver -PacketDir $pktDir | Out-Host')
[void]$S.Add('')
[void]$S.Add('Copy-Item -LiteralPath (Join-Path $pktDir "manifest.json")  -Destination (Join-Path $gold "manifest_without_id.canon.json") -Force')
[void]$S.Add('Copy-Item -LiteralPath (Join-Path $pktDir "packet_id.txt")  -Destination (Join-Path $gold "packet_id.txt") -Force')
[void]$S.Add('Copy-Item -LiteralPath (Join-Path $pktDir "sha256sums.txt") -Destination (Join-Path $gold "sha256sums.txt") -Force')
[void]$S.Add('')
[void]$S.Add('$gm = Get-Content -Raw -LiteralPath (Join-Path $gold "manifest_without_id.canon.json") -Encoding UTF8')
[void]$S.Add('$gp = (Get-Content -Raw -LiteralPath (Join-Path $gold "packet_id.txt") -Encoding UTF8).Trim()')
[void]$S.Add('$ep = PC-ComputePacketIdFromManifestNoIdCanon $gm')
[void]$S.Add('if($ep -ne $gp){ PC-Die ("GOLDEN_PACKET_ID_MISMATCH: expected=" + $ep + " golden=" + $gp) }')
[void]$S.Add('Write-Host ("SELFTEST_OK: Packet Constitution v1 Option A minimal vector -> " + $tv) -ForegroundColor Green')

WriteUtf8NoBomLf $selfPath ((@($S) -join "`n") + "`n")
ParseGateFile $selfPath
FailIfBadReplace $selfPath

# =========================================================
# scripts/recognition_export_session_packet_v1.ps1
# =========================================================
$expPath = Join-Path $ScriptsDir "recognition_export_session_packet_v1.ps1"
$E = New-Object System.Collections.Generic.List[string]
[void]$E.Add('param(')
[void]$E.Add('  [Parameter(Mandatory=$true)][string]$RepoRoot,')
[void]$E.Add('  [Parameter(Mandatory=$false)][string]$SessionExportDir,')
[void]$E.Add('  [Parameter(Mandatory=$false)][string]$OutDir,')
[void]$E.Add('  [Parameter(Mandatory=$false)][string]$PacketName = "recognition_session_export"')
[void]$E.Add(')')
[void]$E.Add('Set-StrictMode -Version Latest')
[void]$E.Add('$ErrorActionPreference = "Stop"')
[void]$E.Add('. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")')
[void]$E.Add('')
[void]$E.Add('if([string]::IsNullOrWhiteSpace($SessionExportDir)){ $SessionExportDir = Join-Path $RepoRoot "payload\session_export" }')
[void]$E.Add('if([string]::IsNullOrWhiteSpace($OutDir)){ $OutDir = Join-Path $RepoRoot "packets\outbox" }')
[void]$E.Add('')
[void]$E.Add('PC-EnsureDir $SessionExportDir')
[void]$E.Add('PC-EnsureDir $OutDir')
[void]$E.Add('')
[void]$E.Add('$builder = Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"')
[void]$E.Add('if(-not (Test-Path -LiteralPath $builder -PathType Leaf)){ PC-Die ("MISSING_BUILDER: " + $builder) }')
[void]$E.Add('')
[void]$E.Add('$pktDir = & $builder -RepoRoot $RepoRoot -PayloadDir $SessionExportDir -OutDir $OutDir -PacketName $PacketName')
[void]$E.Add('if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ PC-Die ("EXPORT_BUILD_FAIL: " + $pktDir) }')
[void]$E.Add('Write-Host ("EXPORT_OK: " + $pktDir) -ForegroundColor Green')
[void]$E.Add('Write-Output $pktDir')

WriteUtf8NoBomLf $expPath ((@($E) -join "`n") + "`n")
ParseGateFile $expPath
FailIfBadReplace $expPath

# =========================================================
# Run selftest + exporter (must pass)
# =========================================================
& $selfPath -RepoRoot $RepoRoot | Out-Host
& $expPath  -RepoRoot $RepoRoot | Out-Host
Write-Host ("PC_V7_OK: lib/builder/verifier/selftest/exporter are GREEN -> " + $ScriptsDir) -ForegroundColor Green
