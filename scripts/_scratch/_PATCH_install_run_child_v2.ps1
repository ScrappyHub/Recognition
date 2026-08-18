param([Parameter(Mandatory=$true)][string]$RepoRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference="Stop"
function Die([string]$m){ throw $m }
function EnsureDir([string]$p){ if([string]::IsNullOrWhiteSpace($p)){ Die "EnsureDir: empty" }; if(-not (Test-Path -LiteralPath $p -PathType Container)){ New-Item -ItemType Directory -Force -Path $p | Out-Null } }
function WriteUtf8NoBomLf([string]$Path,[string]$Text){ $enc=New-Object System.Text.UTF8Encoding($false); $lf=($Text -replace "`r`n","`n") -replace "`r","`n"; if(-not $lf.EndsWith("`n")){ $lf+="`n" }; $dir=Split-Path -Parent $Path; if($dir){ EnsureDir $dir }; [System.IO.File]::WriteAllText($Path,$lf,$enc) }
function ParseGateFile([string]$Path){ if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }; $t=$null; $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e); if($e -and $e.Count -gt 0){ $x=$e[0]; Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message) } }
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir
$OutPath = Join-Path $ScriptsDir "run_child_v1.ps1"
$L = New-Object System.Collections.Generic.List[string]
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference="Stop"' )
[void]$L.Add('')
[void]$L.Add('function RC-Die([string]$m){ throw $m }')
[void]$L.Add('function RC-QuoteArg([string]$s){')
[void]$L.Add('  if($null -eq $s){ return "" }')
[void]$L.Add('  if($s -match '\s|"' ){ return ('"' + ($s.Replace('"','\"')) + '"') }')
[void]$L.Add('  return $s')
[void]$L.Add('}')
[void]$L.Add('')
[void]$L.Add('function Run-Child {' )
[void]$L.Add('  param([Parameter(Mandatory=$true)][string]$ScriptPath,[Parameter(Mandatory=$false)][hashtable]$ArgMap)' )
[void]$L.Add('  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source' )
[void]$L.Add('  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ RC-Die ("RUN_CHILD_MISSING_SCRIPT: " + $ScriptPath) }' )
[void]$L.Add('  $alist = New-Object System.Collections.Generic.List[string]' )
[void]$L.Add('  [void]$alist.Add("-NoProfile"); [void]$alist.Add("-NonInteractive"); [void]$alist.Add("-ExecutionPolicy"); [void]$alist.Add("Bypass"); [void]$alist.Add("-File"); [void]$alist.Add($ScriptPath)' )
[void]$L.Add('  if($null -ne $ArgMap){' )
[void]$L.Add('    foreach($k in @($ArgMap.Keys | Sort-Object)){' )
[void]$L.Add('      $name=[string]$k; if([string]::IsNullOrWhiteSpace($name)){ RC-Die "RUN_CHILD_EMPTY_ARG_KEY" }' )
[void]$L.Add('      [void]$alist.Add(("-" + $name))' )
[void]$L.Add('      $v=$ArgMap[$k]; if($null -eq $v){ [void]$alist.Add("") } else { [void]$alist.Add([string]$v) }' )
[void]$L.Add('    }' )
[void]$L.Add('  }' )
[void]$L.Add('  $psi = New-Object System.Diagnostics.ProcessStartInfo' )
[void]$L.Add('  $psi.FileName = $psExe' )
[void]$L.Add('  $psi.UseShellExecute = $false' )
[void]$L.Add('  $psi.RedirectStandardOutput = $true' )
[void]$L.Add('  $psi.RedirectStandardError  = $true' )
[void]$L.Add('  $psi.CreateNoWindow = $true' )
[void]$L.Add('  $psi.Arguments = (@($alist) | ForEach-Object { RC-QuoteArg ([string]$_) }) -join " "' )
[void]$L.Add('  $p = New-Object System.Diagnostics.Process' )
[void]$L.Add('  $p.StartInfo = $psi' )
[void]$L.Add('  [void]$p.Start()' )
[void]$L.Add('  $stdout = $p.StandardOutput.ReadToEnd()' )
[void]$L.Add('  $stderr = $p.StandardError.ReadToEnd()' )
[void]$L.Add('  $p.WaitForExit()' )
[void]$L.Add('  if($stdout){ [Console]::Out.Write($stdout) }' )
[void]$L.Add('  if($stderr){ [Console]::Error.Write($stderr) }' )
[void]$L.Add('  $code=[int]$p.ExitCode; if($code -ne 0){ RC-Die ("CHILD_FAIL(" + $code + "): " + $ScriptPath) }' )
[void]$L.Add('}' )
WriteUtf8NoBomLf $OutPath ((@($L) -join "`n") + "`n")
ParseGateFile $OutPath
Write-Host ("RUN_CHILD_INSTALLED_OK: " + $OutPath) -ForegroundColor Green
