@echo off
rem Recognition Phase 2+3 green runner; commits to git only when green.
rem Log: proofs\runs\phase2_green_v2.log
cd /d C:\dev\recognition
if not exist proofs\runs mkdir proofs\runs
echo RUN_STARTED > proofs\runs\phase2_green_v2.log
"C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -ExecutionPolicy Bypass -File scripts\RUN_PHASE2_GREEN_V2.ps1 -RepoRoot . >> proofs\runs\phase2_green_v2.log 2>&1
if errorlevel 1 (
  echo CMD_PHASE2_FAILED >> proofs\runs\phase2_green_v2.log
  exit
)
echo CMD_PHASE2_GREEN >> proofs\runs\phase2_green_v2.log
git add -A >> proofs\runs\phase2_green_v2.log 2>&1
git commit -m "Phase 2+3: event hash chain v2 + pinned trust root (audit F4, F5)" -m "Event chain v2: every event carries seq, ts, identity, prev_hash, event_hash (SHA256 over canonical JSON); append validates chain head; verifier proves nothing modified/missing/reordered/forged; v1 migration with provenance. Trust root pinned at proofs/trust/allowed_signers; attestation verify v2 checks signatures against the pinned root only and flags divergent bundle signers. Selftest: 6 negative vectors green." >> proofs\runs\phase2_green_v2.log 2>&1
echo CMD_COMMIT_DONE >> proofs\runs\phase2_green_v2.log
exit
