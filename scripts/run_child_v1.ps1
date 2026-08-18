Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function RC-Die([string]$m){ throw $m }

function RC-QuoteArg([string]$s){
  if($null -eq $s){ $s = "" }
  # Quote if whitespace or quotes present
  $needs = $false
  foreach($ch in $s.ToCharArray()){
    if($ch -eq [char]32 -or $ch -eq [char]9 -or $ch -eq [char]34){ $needs = $true; break }
  }
  if(-not $needs){ return $s }
  # Escape embedded quotes for Windows command line
  return ('"' + ($s -replace '"','\"') + '"')
}

function Run-Child {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$false)][hashtable]$ArgMap
  )

  $psExe = (Get-Command powershell.exe -CommandType Application -ErrorAction Stop).Source
  if(-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)){
    RC-Die ("RUN_CHILD_MISSING_SCRIPT: " + $ScriptPath)
  }

  $alist = New-Object System.Collections.Generic.List[string]
  [void]$alist.Add("-NoProfile")
  [void]$alist.Add("-NonInteractive")
  [void]$alist.Add("-ExecutionPolicy")
  [void]$alist.Add("Bypass")
  [void]$alist.Add("-File")
  [void]$alist.Add($ScriptPath)

  if($null -ne $ArgMap){
    foreach($k in @($ArgMap.Keys | Sort-Object)){
      $name = [string]$k
      if([string]::IsNullOrWhiteSpace($name)){ RC-Die "RUN_CHILD_EMPTY_ARG_KEY" }
      [void]$alist.Add(("-" + $name))
      $v = $ArgMap[$k]
      if($null -eq $v){ [void]$alist.Add("") } else { [void]$alist.Add([string]$v) }
    }
  }

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $psExe
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError  = $true
  $psi.CreateNoWindow = $true
  $psi.Arguments = (@($alist) | ForEach-Object { RC-QuoteArg ([string]$_) }) -join " "

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $psi
  [void]$p.Start()

  $stdout = $p.StandardOutput.ReadToEnd()
  $stderr = $p.StandardError.ReadToEnd()
  $p.WaitForExit()

  if($stdout){ [Console]::Out.Write($stdout) }
  if($stderr){ [Console]::Error.Write($stderr) }

  $code = [int]$p.ExitCode
  if($code -ne 0){ RC-Die ("CHILD_FAIL(" + $code + "): " + $ScriptPath) }
}
