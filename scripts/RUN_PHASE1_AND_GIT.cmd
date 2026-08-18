@echo off
rem Recognition Phase 1 green runner + Phase 0 git bootstrap (double-click or run)
rem Logs: proofs\runs\phase1_green_v2.log and proofs\runs\phase0_git_init.log
cd /d C:\dev\recognition
if not exist proofs\runs mkdir proofs\runs
echo RUN_STARTED > proofs\runs\phase1_green_v2.log
"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File scripts\RUN_PHASE1_GREEN_V2.ps1 -RepoRoot . >> proofs\runs\phase1_green_v2.log 2>&1
if errorlevel 1 (
  echo CMD_PHASE1_FAILED >> proofs\runs\phase1_green_v2.log
  exit
)
echo CMD_PHASE1_GREEN >> proofs\runs\phase1_green_v2.log
echo RUN_STARTED > proofs\runs\phase0_git_init.log
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\RUN_PHASE0_GIT_INIT.ps1 -RepoRoot . >> proofs\runs\phase0_git_init.log 2>&1
if errorlevel 1 (
  echo CMD_PHASE0_FAILED >> proofs\runs\phase0_git_init.log
  exit
)
echo CMD_PHASE0_GREEN >> proofs\runs\phase0_git_init.log
exit
