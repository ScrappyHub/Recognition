@echo off
cd /d C:\dev\recognition
"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File scripts\_debug_event_chain_v2.ps1 -RepoRoot . > proofs\runs\debug_chain.log 2>&1
exit
