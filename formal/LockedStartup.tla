---------------------------- MODULE LockedStartup ----------------------------
(***************************************************************************)
(* Formal model of Recognition's fail-closed locked startup (OSF 5, 20;   *)
(* repo: recognition_locked_startup_browser_v1). The browser opens only if *)
(* identity, policy, the trust root, the evidence chain, and the signed    *)
(* SoftwareID all verify. Each check is modelled as a nondeterministic     *)
(* boolean; TLC explores all 2^5 combinations.                            *)
(*                                                                         *)
(* Safety property FailClosed: the window is NEVER open unless every check *)
(* passed. (Liveness "opens when all pass" holds by construction of        *)
(* Startup and is witnessed by the reachable state where all are TRUE.)    *)
(***************************************************************************)
VARIABLES identity, policy, trust, evidence, software, opened

vars == << identity, policy, trust, evidence, software, opened >>

AllPass == identity /\ policy /\ trust /\ evidence /\ software

Init ==
  /\ identity \in BOOLEAN
  /\ policy   \in BOOLEAN
  /\ trust    \in BOOLEAN
  /\ evidence \in BOOLEAN
  /\ software \in BOOLEAN
  /\ opened = FALSE

Startup ==
  /\ opened' = AllPass
  /\ UNCHANGED << identity, policy, trust, evidence, software >>

Next == Startup
Spec == Init /\ [][Next]_vars

(* security-critical direction: never open with a failed check *)
FailClosed == opened => AllPass

=============================================================================
