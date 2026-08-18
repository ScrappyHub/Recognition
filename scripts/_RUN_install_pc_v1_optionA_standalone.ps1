param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"

function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e); if($e -and $e.Count -gt 0){ $x=$e[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message) } }

$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir

$libPath = Join-Path $ScriptsDir "_lib_packet_constitution_v1.ps1"
$libTxt = @(
'Set-StrictMode -Version Latest'
'$ErrorActionPreference="Stop"'
''
'function PC-Die([string]$m){ throw $m }'
'function PC-EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ PC-Die "PC-EnsureDir: empty path" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }'
'function PC-WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf += "`n" }; PC-EnsureDir (Split-Path -Parent $Path); [System.IO.File]::WriteAllText($Path,$lf,$enc) }'
'function PC-ReadAllBytes([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ PC-Die ("MISSING_FILE: " + $Path) }; [System.IO.File]::ReadAllBytes($Path) }'
'function PC-Sha256HexBytes([byte[]]$Bytes){ if($null -eq $Bytes){ PC-Die "PC-Sha256HexBytes: null bytes" }; $sha=[System.Security.Cryptography.SHA256]::Create(); try{ $h=$sha.ComputeHash($Bytes) } finally{ $sha.Dispose() }; $sb=New-Object System.Text.StringBuilder; foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }; $sb.ToString() }'
'function PC-Sha256HexFile([string]$Path){ $sha=[System.Security.Cryptography.SHA256]::Create(); try{ $fs=[System.IO.File]::OpenRead($Path); try{ $h=$sha.ComputeHash($fs) } finally{ $fs.Dispose() } } finally{ $sha.Dispose() }; $sb=New-Object System.Text.StringBuilder; foreach($b in $h){ [void]$sb.Append($b.ToString("x2")) }; $sb.ToString() }'
'function PC-NowUtc(){ (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }'
''
'function PC-EscapeJsonString([string]$s){ if($null -eq $s){ return "" }; $sb=New-Object System.Text.StringBuilder; for($i=0;$i -lt $s.Length;$i++){ $c=[int][char]$s[$i]; switch($c){ 8{[void]$sb.Append("\b");continue};9{[void]$sb.Append("\t");continue};10{[void]$sb.Append("\n");continue};12{[void]$sb.Append("\f");continue};13{[void]$sb.Append("\r");continue};34{[void]$sb.Append("\\\"");continue};92{[void]$sb.Append("\\\\");continue}; default{ if($c -lt 32){ [void]$sb.Append(("\\u{0:x4}" -f $c)); continue }; [void]$sb.Append([char]$c) } } }; $sb.ToString() }'
'function PC-ToCanonJson($v){ if($null -eq $v){ return "null" }; if($v -is [string]){ return ("""" + (PC-EscapeJsonString $v) + """") }; if($v -is [bool]){ return ($(if($v){"true"}else{"false"})) }; if($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]){ return ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture,"{0}",$v)) }; if($v -is [hashtable] -or $v -is [System.Collections.IDictionary]){ $keys=@(@($v.Keys)|ForEach-Object{[string]$_}|Sort-Object); $parts=New-Object System.Collections.Generic.List[string]; foreach($k in $keys){ $kk=[string]$k; $vv=$v[$kk]; [void]$parts.Add(("""" + (PC-EscapeJsonString $kk) + """:" + (PC-ToCanonJson $vv))) }; return ("{" + (@($parts) -join ",") + "}") }; if($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])){ $parts=New-Object System.Collections.Generic.List[string]; foreach($it in @($v)){ [void]$parts.Add((PC-ToCanonJson $it)) }; return ("[" + (@($parts) -join ",") + "]") }; return ("""" + (PC-EscapeJsonString ([string]$v)) + """") }'
'function PC-CanonBytesFromCanonJson([string]$canon){ $t=($canon -replace "`r`n","`n") -replace "`r","`n"; if(-not $t.EndsWith("`n")){ $t += "`n" }; $enc=New-Object System.Text.UTF8Encoding($false); $enc.GetBytes($t) }'
'function PC-ComputePacketIdFromManifestNoIdCanon([string]$manifestCanonNoId){ PC-Sha256HexBytes (PC-CanonBytesFromCanonJson $manifestCanonNoId) }'
'function PC-RelPath([string]$Root,[string]$Full){ $r=[System.IO.Path]::GetFullPath($Root); $f=[System.IO.Path]::GetFullPath($Full); if(-not $f.StartsWith($r,[System.StringComparison]::OrdinalIgnoreCase)){ PC-Die ("PC-RelPath: not under root: " + $Full) }; $rel=$f.Substring($r.Length).TrimStart("\","/"); ($rel -replace "\","/") }'
'function PC-ListFilesRec([string]$Dir){ if(-not (Test-Path -LiteralPath $Dir -PathType Container)){ PC-Die ("MISSING_DIR: " + $Dir) }; @(@(Get-ChildItem -LiteralPath $Dir -Recurse -File -Force | Sort-Object FullName)) }'
) -join "`n"
WriteUtf8NoBomLf $libPath ($libTxt + "`n")
ParseGateFile $libPath

$builderPath = Join-Path $ScriptsDir "pc_build_packet_optionA_v1.ps1"
$builderTxt = @(
'param('
'  [Parameter(Mandatory=$true)][string]$RepoRoot,'
'  [Parameter(Mandatory=$true)][string]$PayloadDir,'
'  [Parameter(Mandatory=$true)][string]$OutDir,'
'  [Parameter(Mandatory=$false)][string]$PacketName = "packet"'
')'
'Set-StrictMode -Version Latest'
'$ErrorActionPreference="Stop"'
'. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")'
'if(-not (Test-Path -LiteralPath $PayloadDir -PathType Container)){ PC-Die ("MISSING_PAYLOAD_DIR: " + $PayloadDir) }'
'PC-EnsureDir $OutDir'
'$work = Join-Path $OutDir ($PacketName + "_work")'
'if(Test-Path -LiteralPath $work){ Remove-Item -LiteralPath $work -Recurse -Force }'
'PC-EnsureDir $work'
'$pktPayload = Join-Path $work "payload"; PC-EnsureDir $pktPayload'
'Copy-Item -LiteralPath (Join-Path $PayloadDir "*") -Destination $pktPayload -Recurse -Force'
'$files = New-Object System.Collections.Generic.List[object]'
'$all = PC-ListFilesRec $work'
'foreach($f in @($all)){ $rel = PC-RelPath $work $f.FullName; if($rel -ieq "manifest.json" -or $rel -ieq "packet_id.txt" -or $rel -ieq "sha256sums.txt"){ continue }; $h=PC-Sha256HexFile $f.FullName; $o=@{}; $o["path"]=$rel; $o["bytes"]=[int64]$f.Length; $o["sha256"]=$h; [void]$files.Add($o) }'
'$m=@{}; $m["schema"]="packet.manifest.v1"; $m["option"]="A"; $m["created_utc"]=PC-NowUtc; $m["files"]=@($files)'
'$manifestCanonNoId = PC-ToCanonJson $m'
'$manifestPath = Join-Path $work "manifest.json"; PC-WriteUtf8NoBomLf $manifestPath $manifestCanonNoId'
'PC-EnsureDir (Join-Path $work "signatures")'
'$packetId = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanonNoId'
'$pidPath = Join-Path $work "packet_id.txt"; PC-WriteUtf8NoBomLf $pidPath ($packetId + "`n")'
'$all2 = PC-ListFilesRec $work; $lines = New-Object System.Collections.Generic.List[string]'
'foreach($f in @($all2)){ $rel = PC-RelPath $work $f.FullName; if($rel -ieq "sha256sums.txt"){ continue }; $h=PC-Sha256HexFile $f.FullName; [void]$lines.Add(("{0}  {1}" -f $h,$rel)) }'
'$sumPath = Join-Path $work "sha256sums.txt"; PC-WriteUtf8NoBomLf $sumPath ((@($lines) -join "`n") + "`n")'
'$final = Join-Path $OutDir $packetId; if(Test-Path -LiteralPath $final){ Remove-Item -LiteralPath $final -Recurse -Force }'
'Move-Item -LiteralPath $work -Destination $final'
'Write-Output $final'
) -join "`n"
WriteUtf8NoBomLf $builderPath ($builderTxt + "`n")
ParseGateFile $builderPath

$verPath = Join-Path $ScriptsDir "pc_verify_packet_optionA_v1.ps1"
$verTxt = @(
'param([Parameter(Mandatory=$true)][string]$PacketDir)'
'Set-StrictMode -Version Latest'
'$ErrorActionPreference="Stop"'
'. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")'
'if(-not (Test-Path -LiteralPath $PacketDir -PathType Container)){ PC-Die ("MISSING_PACKET_DIR: " + $PacketDir) }'
'$packetDirName = Split-Path -Leaf $PacketDir'
'$manifestPath = Join-Path $PacketDir "manifest.json"; $pidPath = Join-Path $PacketDir "packet_id.txt"; $sumPath = Join-Path $PacketDir "sha256sums.txt"'
'foreach($p in @($manifestPath,$pidPath,$sumPath)){ if(-not (Test-Path -LiteralPath $p -PathType Leaf)){ PC-Die ("MISSING_REQUIRED_FILE: " + $p) } }'
'$raw = Get-Content -Raw -LiteralPath $sumPath -Encoding UTF8'
'$lines = @(@($raw -split "`n") | Where-Object { $_ -and $_.Trim().Length -gt 0 })'
'foreach($ln in @($lines)){ $m=[regex]::Match($ln,"^(?<h>[0-9a-f]{64})\s\s(?<p>.+)$"); if(-not $m.Success){ PC-Die ("BAD_SHA256SUMS_LINE: " + $ln) }; $h=$m.Groups["h"].Value; $rel=$m.Groups["p"].Value; $full=Join-Path $PacketDir ($rel -replace "/","\"); if(-not (Test-Path -LiteralPath $full -PathType Leaf)){ PC-Die ("MISSING_FILE_LISTED_IN_SHA256SUMS: " + $rel) }; $hh=PC-Sha256HexFile $full; if($hh -ne $h){ PC-Die ("SHA256_MISMATCH: " + $rel + " expected=" + $h + " got=" + $hh) } }'
'$pid = (Get-Content -Raw -LiteralPath $pidPath -Encoding UTF8).Trim()'
'$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath -Encoding UTF8'
'$manifestCanon = ($manifestRaw -replace "`r`n","`n") -replace "`r","`n"'
'$expected = PC-ComputePacketIdFromManifestNoIdCanon $manifestCanon'
'if($expected -ne $pid){ PC-Die ("PACKET_ID_MISMATCH: expected=" + $expected + " file=" + $pid) }'
'if($packetDirName -ne $pid){ PC-Die ("PACKET_DIRNAME_MISMATCH: dir=" + $packetDirName + " pid=" + $pid) }'
'Write-Host ("VERIFY_OK: " + $PacketDir) -ForegroundColor Green'
) -join "`n"
WriteUtf8NoBomLf $verPath ($verTxt + "`n")
ParseGateFile $verPath

$selfPath = Join-Path $ScriptsDir "_selftest_packet_constitution_v1.ps1"
$selfTxt = @(
'param([Parameter(Mandatory=$true)][string]$RepoRoot)'
'Set-StrictMode -Version Latest'
'$ErrorActionPreference="Stop"'
'. (Join-Path $PSScriptRoot "_lib_packet_constitution_v1.ps1")'
'$tv = Join-Path $RepoRoot "test_vectors\packet_constitution_v1\v1_minimal_optionA"'
'$payload = Join-Path $tv "payload"; $out = Join-Path $tv "out"; $gold = Join-Path $tv "golden"'
'PC-EnsureDir $tv; PC-EnsureDir $payload; PC-EnsureDir $out; PC-EnsureDir $gold'
'PC-WriteUtf8NoBomLf (Join-Path $payload "hello.txt") ("hello`n")'
'$metaCanon = PC-ToCanonJson (@{ schema="recognition.payload.meta.v1"; note="minimal"; n=1 })'
'PC-WriteUtf8NoBomLf (Join-Path $payload "meta.json") $metaCanon'
'$builder = Join-Path $RepoRoot "scripts\pc_build_packet_optionA_v1.ps1"'
'$ver = Join-Path $RepoRoot "scripts\pc_verify_packet_optionA_v1.ps1"'
'$ps = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"'
'$pktDir = & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $builder -RepoRoot $RepoRoot -PayloadDir $payload -OutDir $out -PacketName "tv"'
'if(-not (Test-Path -LiteralPath $pktDir -PathType Container)){ PC-Die ("SELFTEST_BUILD_FAIL: " + $pktDir) }'
'& $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ver -PacketDir $pktDir | Out-Host'
'Copy-Item -LiteralPath (Join-Path $pktDir "manifest.json") -Destination (Join-Path $gold "manifest_without_id.canon.json") -Force'
'Copy-Item -LiteralPath (Join-Path $pktDir "packet_id.txt") -Destination (Join-Path $gold "packet_id.txt") -Force'
'Copy-Item -LiteralPath (Join-Path $pktDir "sha256sums.txt") -Destination (Join-Path $gold "sha256sums.txt") -Force'
'$gm = Get-Content -Raw -LiteralPath (Join-Path $gold "manifest_without_id.canon.json") -Encoding UTF8'
'$gp = (Get-Content -Raw -LiteralPath (Join-Path $gold "packet_id.txt") -Encoding UTF8).Trim()'
'$ep = PC-ComputePacketIdFromManifestNoIdCanon $gm'
'if($ep -ne $gp){ PC-Die ("GOLDEN_PACKET_ID_MISMATCH: expected=" + $ep + " golden=" + $gp) }'
'Write-Host ("SELFTEST_OK: Packet Constitution v1 Option A minimal vector -> " + $tv) -ForegroundColor Green'
) -join "`n"
WriteUtf8NoBomLf $selfPath ($selfTxt + "`n")
ParseGateFile $selfPath

& (Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe") -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $selfPath -RepoRoot $RepoRoot | Out-Host
Write-Host "OK: Packet Constitution v1 Option A installed + selftested (standalone)." -ForegroundColor Green
