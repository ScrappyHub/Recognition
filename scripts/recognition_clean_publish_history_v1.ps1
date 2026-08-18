# Recognition — Clean Publish History v1  (finishes audit F10 remediation)
#
# The compromised signing key is present in an existing commit. Nothing has been
# pushed yet, so the safest way to guarantee the private key never reaches GitHub
# is to replace the branch with a single fresh root commit of the current working
# tree (secrets already untracked + .gitignore'd), preserving the old history in a
# local backup branch.
#
# DRY-RUN by default: prints the plan and the pre-flight secret check, changes
# nothing. Pass -Execute to perform the squash. Never pushes.
#
# Usage (pwsh 7+ or Windows PowerShell, git on PATH):
#   pwsh -File scripts/recognition_clean_publish_history_v1.ps1 -RepoRoot .
#   pwsh -File scripts/recognition_clean_publish_history_v1.ps1 -RepoRoot . -Execute

param(
  [Parameter(Mandatory=$true)][string]$RepoRoot,
  [string]$Branch    = "main",
  [string]$RemoteUrl = "https://github.com/ScrappyHub/Recognition.git",
  [switch]$Execute
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Die([string]$m){ Write-Error $m; exit 1 }
# NB: function is NOT named 'Git' — `& git` would resolve back to it (PowerShell
# is case-insensitive) and recurse forever. Call git.exe explicitly, and don't
# name the parameter $Args (shadows the automatic $args).
function RunGit([string[]]$GitArgs){
  $out = & git.exe @GitArgs 2>&1
  return @{ Code = $LASTEXITCODE; Out = ($out | Out-String) }
}
function RunGitOrDie([string[]]$GitArgs){
  $r = RunGit $GitArgs
  if($r.Code -ne 0){ Die ("GIT_FAIL [" + ($GitArgs -join ' ') + "]: " + $r.Out.Trim()) }
  return $r.Out
}

$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
Set-Location $RepoRoot

if((RunGit @("rev-parse","--is-inside-work-tree")).Code -ne 0){ Die "NOT_A_GIT_REPO" }

# --- pre-flight: no secret may be in the tracked set -------------------------
$tracked = (RunGitOrDie @("ls-files")) -split "`n" | Where-Object { $_ -ne "" }
$secretHits = $tracked | Where-Object {
  $_ -match '(^|/)proofs/keys/' -or $_ -match '\.ed25519$' -or $_ -match '\.pem$' -or $_ -match '_private'
}
if(@($secretHits).Count -gt 0){
  Write-Host "TRACKED SECRETS DETECTED — remove them before squashing:" -ForegroundColor Red
  $secretHits | ForEach-Object { Write-Host ("  " + $_) -ForegroundColor Red }
  Die "ABORT: run 'git rm --cached <file>' on the above (they stay on disk) and re-run."
}
# content-level check for private-key material anywhere in the tracked set
$grep = RunGit @("grep","-I","--cached","-l","BEGIN OPENSSH PRIVATE KEY")
if($grep.Code -eq 0 -and $grep.Out.Trim() -ne ""){
  Write-Host "PRIVATE KEY MATERIAL found in tracked content:" -ForegroundColor Red
  Write-Host $grep.Out
  Die "ABORT: purge the key from the tracked set first."
}
Write-Host "Pre-flight OK: no private key material in the tracked set." -ForegroundColor Green

$head = (RunGitOrDie @("rev-parse","--short","HEAD")).Trim()
$count = (RunGitOrDie @("rev-list","--count","HEAD")).Trim()
Write-Host ("Current branch HEAD " + $head + " has " + $count + " commit(s).")

if(-not $Execute){
  Write-Host ""
  Write-Host "PLAN (dry-run):"
  Write-Host ("  1. back up current history to branch  backup/pre-clean-<utc>")
  Write-Host ("  2. create a single fresh root commit of the working tree on '" + $Branch + "'")
  Write-Host ("  3. old history remains only in the backup branch (recoverable locally)")
  Write-Host ("  4. print the push command (this script never pushes)")
  Write-Host ""
  Write-Host "Re-run with -Execute to perform the squash."
  Write-Host "RECOGNITION_CLEAN_PUBLISH_HISTORY_V1_PLAN_OK"
  exit 0
}

# --- execute -----------------------------------------------------------------
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$backup = "backup/pre-clean-" + $stamp
RunGitOrDie @("branch",$backup) | Out-Null
Write-Host ("Backed up current history to " + $backup) -ForegroundColor Green

$orphan = "_recognition_clean_" + $stamp
RunGitOrDie @("checkout","--orphan",$orphan) | Out-Null
RunGitOrDie @("add","-A") | Out-Null

# final guard: nothing secret staged
$staged = (RunGitOrDie @("ls-files","--cached")) -split "`n" | Where-Object { $_ -ne "" }
$stagedSecret = $staged | Where-Object { $_ -match '(^|/)proofs/keys/' -or $_ -match '\.ed25519$' -or $_ -match '\.pem$' -or $_ -match '_private' }
if(@($stagedSecret).Count -gt 0){
  RunGitOrDie @("checkout","-f",$Branch) | Out-Null
  RunGitOrDie @("branch","-D",$orphan) | Out-Null
  Die ("ABORT: secret staged in orphan commit: " + ($stagedSecret -join ', '))
}

RunGitOrDie @("commit","-m","Recognition: clean publish snapshot (squashed history; secrets excluded)") | Out-Null
RunGitOrDie @("branch","-M",$Branch) | Out-Null

$newCount = (RunGitOrDie @("rev-list","--count","HEAD")).Trim()
Write-Host ("Branch '" + $Branch + "' now has " + $newCount + " commit (old history kept in " + $backup + ").") -ForegroundColor Green
Write-Host ""
Write-Host "Verify, then publish manually:" -ForegroundColor Cyan
Write-Host ("  git remote get-url origin   # expect " + $RemoteUrl)
Write-Host ("  git push -u origin " + $Branch + " --force")
Write-Host "  (force replaces the remote's placeholder README commit; re-add Contributing/Security after if you want them.)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "If anything looks wrong, restore with:  git checkout -B $Branch $backup" -ForegroundColor DarkGray
Write-Host "RECOGNITION_CLEAN_PUBLISH_HISTORY_V1_OK" -ForegroundColor Green
