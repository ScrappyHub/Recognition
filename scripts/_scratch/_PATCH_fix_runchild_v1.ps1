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
  $dir = Split-Path -Parent $Path
  if($dir){ EnsureDir $dir }
  [System.IO.File]::WriteAllText($Path,$lf,$enc)
}
function ParseGateFile([string]$Path){
  if(-not (Test-Path -LiteralPath $Path -PathType Leaf)){ Die ("PARSE_GATE_MISSING: " + $Path) }
  $t=$null; $e=$null
  [void][System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$t,[ref]$e)
  if($e -and $e.Count -gt 0){
    $x=$e[0]
    Die ("PARSE_GATE_FAIL: {0}:{1}:{2}: {3}" -f $Path,$x.Extent.StartLineNumber,$x.Extent.StartColumnNumber,$x.Message)
  }
}

# -------------------------------------------------------------------
# scripts\run_child_v1.ps1  (library-style helper)
# - NO Get-Command parameter introspection
# - Strict hashtable key/value -> "-Key" "Value" list
# - Child failures are fatal and surfaced deterministically
# -------------------------------------------------------------------
$ScriptsDir = Join-Path $RepoRoot "scripts"
EnsureDir $ScriptsDir
$OutPath = Join-Path $ScriptsDir "run_child_v1.ps1"

$L = New-Object System.Collections.Generic.List[string]
[void]$L.Add('Set-StrictMode -Version Latest')
[void]$L.Add('$ErrorActionPreference = "Stop"')
[void]$L.Add('')
[void]$L.Add('function RC-Die([string]$m){ throw $m }')
[void]$L.Add('')
[void]$L.Add('function Run-Child {')
[void]$L.Add('  param(')
[void]$L.Add('    [Parameter(Mandatory=$true)][string]$ScriptPath,')
[void]$L.Add('    [Parameter(Mandatory=$false)][hashtable]$ArgMap')
[void]$L.Add('  )')
[void]$L.Add('  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source')
[void]$L.Add('  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){ RC-Die ("RUN_CHILD_MISSING_SCRIPT: " + $ScriptPath) }')
[void]$L.Add('')
[void]$L.Add('  $alist = New-Object System.Collections.Generic.List[string]')
[void]$L.Add('  [void]$alist.Add("-NoProfile")')
[void]$L.Add('  [void]$alist.Add("-NonInteractive")')
[void]$L.Add('  [void]$alist.Add("-ExecutionPolicy")')
[void]$L.Add('  [void]$alist.Add("Bypass")')
[void]$L.Add('  [void]$alist.Add("-File")')
[void]$L.Add('  [void]$alist.Add($ScriptPath)')
[void]$L.Add('')
[void]$L.Add('  if($null -ne $ArgMap){')
[void]$L.Add('    foreach($k in @($ArgMap.Keys | Sort-Object)){')
[void]$L.Add('      $name = [string]$k')
[void]$L.Add('      if([string]::IsNullOrWhiteSpace($name)){ RC-Die "RUN_CHILD_EMPTY_ARG_KEY" }')
[void]$L.Add('      [void]$alist.Add(("-" + $name))')
[void]$L.Add('      $v = $ArgMap[$k]')
[void]$L.Add('      if($null -eq $v){ [void]$alist.Add("") } else { [void]$alist.Add([string]$v) }')
[void]$L.Add('    }')
[void]$L.Add('  }')
[void]$L.Add('')
[void]$L.Add('  $psi = New-Object System.Diagnostics.ProcessStartInfo')
[void]$L.Add('  $psi.FileName = $psExe')
[void]$L.Add('  $psi.UseShellExecute = $false')
[void]$L.Add('  $psi.RedirectStandardOutput = $true')
[void]$L.Add('  $psi.RedirectStandardError  = $true')
[void]$L.Add('  $psi.CreateNoWindow = $true')
[void]$L.Add('  $psi.Arguments = (@($alist) | ForEach-Object {')
[void]$L.Add('    $s = [string]$_')
[void]$L.Add('    if($s -match ''\s|\"''){ ''"'' + ($s.Replace(''"'',''\"'')) + ''"'' } else { $s }')
[void]$L.Add('  }) -join " "')
[void]$L.Add('')
[void]$L.Add('  $p = New-Object System.Diagnostics.Process')
[void]$L.Add('  $p.StartInfo = $psi')
[void]$L.Add('  [void]$p.Start()')
[void]$L.Add('  $stdout = $p.StandardOutput.ReadToEnd()')
[void]$L.Add('  $stderr = $p.StandardError.ReadToEnd()')
[void]$L.Add('  $p.WaitForExit()')
[void]$L.Add('  if($stdout){ [Console]::Out.Write($stdout) }')
[void]$L.Add('  if($stderr){ [Console]::Error.Write($stderr) }')
[void]$L.Add('  $code = [int]$p.ExitCode')
[void]$L.Add('  if($code -ne 0){ RC-Die ("CHILD_FAIL(" + $code + "): " + $ScriptPath) }')
[void]$L.Add('}')
')

WriteUtf8NoBomLf $OutPath ((@($L) -join "`n") + "`n")
ParseGateFile $OutPath
Write-Host ("RUN_CHILD_INSTALLED_OK: " + $OutPath) -ForegroundColor Green
