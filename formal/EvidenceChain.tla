---------------------------- MODULE EvidenceChain ----------------------------
(***************************************************************************)
(* Formal model of Recognition's append-only, hash-chained evidence log    *)
(* (OSF paper 4.3 / 5.1 / 5.2; repo: history, event-chain, chain-anchor).  *)
(*                                                                         *)
(* Hashes are modelled collision-free: the hash of a prefix IS the         *)
(* sequence of that prefix's values (an injective encoding). Each record   *)
(* stores prev = hash(prefix before it) and hash = hash(prefix incl. it).  *)
(*                                                                         *)
(* Checked properties:                                                     *)
(*   Sound          - an honestly-appended chain always verifies.          *)
(*   TamperEvidence - changing any record's value (without re-signing the  *)
(*                    hashes) is always detected (verification fails).     *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANT Values
VARIABLE chain

Rec(v, p, h) == [val |-> v, prev |-> p, hash |-> h]

(* values of the first k records, as a sequence == the abstract hash *)
Prefix(s, k) == [ j \in 1..k |-> s[j].val ]

WellFormed(s) ==
  \A i \in 1..Len(s) :
     /\ s[i].prev = Prefix(s, i - 1)
     /\ s[i].hash = Prefix(s, i)

Verify(s) == WellFormed(s)

Init == chain = << >>

AppendRec(v) ==
  chain' = Append(chain,
                  Rec(v, Prefix(chain, Len(chain)),
                         Append(Prefix(chain, Len(chain)), v)))

Next == \E v \in Values : AppendRec(v)

vars == << chain >>
Spec == Init /\ [][Next]_vars

MaxLen == 4
LenBound == Len(chain) =< MaxLen

(* --- invariants --- *)
Sound == Verify(chain)

TamperEvidence ==
  \A i \in 1..Len(chain) :
    \A v \in Values :
      v # chain[i].val => ~Verify([chain EXCEPT ![i].val = v])

=============================================================================
