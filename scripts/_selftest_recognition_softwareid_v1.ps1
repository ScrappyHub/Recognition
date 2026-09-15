# Self-test — SoftwareID seal + verify with negative vectors (self-contained).
# Uses an EPHEMERAL Ed25519 key in a temp dir; never touches the real repo/keys.
# Token: SELFTEST_RECOGNITION_SOFTWAREID_V1_OK

param([string]$RepoRoot = ".")   # accepted for prove_all uniformity; not used

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scripts = $PSScriptRoot
$seal    = Join-Path $scripts "recognition_seal_softwareid_v1.ps1"
$verify  = Join-Path $scripts "recognition_verify_softwareid_v1.ps1"
$ssh     = (Get-Command ssh-keygen -CommandType Application -ErrorAction Stop).Source

$fail = 0
function Assert([bool]$cond,[string]$msg){
  if($cond){ Write-Host ("  ok  - " + $msg) -ForegroundColor Green }
  else     { Write-Host ("  FAIL- " + $msg) -ForegroundColor Red; $script:fail++ }
}
function WriteUtf8NoBomLf([string]$Path,[string]$Text){
  $t = ($Text -replace "`r`n","`n") -replace "`r","`n"
  if(-not $t.EndsWith("`n")){ $t += "`n" }
  [System.IO.File]::WriteAllText($Path,$t,(New-Object System.Text.UTF8Encoding($false)))
}
function RunSsh([string[]]$SshArgs,[int]$TimeoutMs=20000){
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $ssh
  foreach($a in $SshArgs){ [void]$psi.ArgumentList.Add($a) }   # ArgumentList passes -N "" literally
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $p = [System.Diagnostics.Process]::Start($psi)
  try { $p.StandardInput.Close() } catch {}
  $o = $p.StandardOutput.ReadToEndAsync(); $e = $p.StandardError.ReadToEndAsync()
  if(-not $p.WaitForExit($TimeoutMs)){ try { $p.Kill() } catch {}; throw "SELFTEST_SSH_TIMEOUT" }
  return $p.ExitCode
}
function Vout { return (& $verify -RepoRoot $work -BinaryPath $bin *>&1 | Out-String) }
function PinKey([string]$pubPath){
  $pub = (Get-Content -Raw -LiteralPath $pubPath -Encoding UTF8).Trim()
  $parts = $pub -split '\s+'
  WriteUtf8NoBomLf $trust ("recognition-runtime-bridge " + $parts[0] + " " + $parts[1])
}

$work   = Join-Path ([System.IO.Path]::GetTempPath()) ("sid_repo_" + [Guid]::NewGuid().ToString("N"))
$keydir = Join-Path ([System.IO.Path]::GetTempPath()) ("sid_keys_" + [Guid]::NewGuid().ToString("N"))
try {
  New-Item -ItemType Directory -Force -Path (Join-Path $work "proofs\trust") | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $work "browser\bin\Release\net8.0-windows") | Out-Null
  New-Item -ItemType Directory -Force -Path $keydir | Out-Null
  $trust = Join-Path $work "proofs\trust\allowed_signers"
  $bin   = Join-Path $work "browser\bin\Release\net8.0-windows\RecognitionBrowser.dll"

  # fake binary bytes
  $orig = [byte[]]((1..2048) | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 })
  [System.IO.File]::WriteAllBytes($bin, $orig)

  # ephemeral signing key #1 + pin as trust root
  $key1 = Join-Path $keydir "k1"
  [void](RunSsh @("-t","ed25519","-f",$key1,"-N","","-C","recognition-runtime-bridge"))
  if(-not (Test-Path -LiteralPath ($key1 + ".pub"))){ throw "SELFTEST_KEYGEN_FAILED" }
  PinKey ($key1 + ".pub")

  Write-Host "=== softwareid selftest ===" -ForegroundColor Cyan

  # vector 0: unattested (no record)
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_UNATTESTED") "unsealed build reports UNATTESTED (advisory)"

  # vector 1: seal + verify OK
  $so = & $seal -RepoRoot $work -BinaryPath $bin -KeyPath $key1 *>&1 | Out-String
  Assert ($so -match "RECOGNITION_SEAL_SOFTWAREID_V1_OK") "seal signs the SoftwareID record"
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_OK") "sealed binary verifies authentic"

  # vector 2: tampered binary -> BLOCKED, then restore -> OK
  $t = New-Object System.Collections.Generic.List[byte]; $t.AddRange($orig); $t.Add(0x42)
  [System.IO.File]::WriteAllBytes($bin, $t.ToArray())
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_BLOCKED") "one modified byte in the binary -> BLOCKED"
  [System.IO.File]::WriteAllBytes($bin, $orig)
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_OK") "restoring the binary verifies again"

  # vector 3: tampered record (change the recorded size) -> signature invalid -> BLOCKED
  $recPath = Join-Path $work "proofs\software\software_id.json"
  $rawrec = Get-Content -Raw -LiteralPath $recPath -Encoding UTF8
  $bad = [regex]::Replace($rawrec, '"size":\s*\d+', '"size": 999999')
  if($bad -eq $rawrec){ $bad = $rawrec -replace '"algo":\s*"sha256"','"algo": "sha256 "' }  # ensure bytes change
  [System.IO.File]::WriteAllText($recPath, $bad, (New-Object System.Text.UTF8Encoding($false)))
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_BLOCKED") "modified signed record -> BLOCKED"

  # re-seal clean for the final vector
  & $seal -RepoRoot $work -BinaryPath $bin -KeyPath $key1 *>&1 | Out-Null
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_OK") "re-seal restores OK"

  # vector 4: different signer pinned -> signature no longer trusted -> BLOCKED
  $key2 = Join-Path $keydir "k2"
  [void](RunSsh @("-t","ed25519","-f",$key2,"-N","","-C","recognition-runtime-bridge"))
  PinKey ($key2 + ".pub")
  Assert ((Vout) -match "RECOGNITION_SOFTWAREID_BLOCKED") "signature from an untrusted key -> BLOCKED"

  Write-Host ""
  Write-Host ("checks passed: " + (8 - $fail) + "  failed: " + $fail)
  if($fail -ne 0){ throw ("SOFTWAREID_SELFTEST_FAILURES=" + $fail) }
  Write-Host "SELFTEST_RECOGNITION_SOFTWAREID_V1_OK" -ForegroundColor Green
}
finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $keydir -Recurse -Force -ErrorAction SilentlyContinue
}
