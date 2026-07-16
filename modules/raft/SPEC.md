# raft — SPEC

Auditor/design reference for the `raft` module. Consumer usage lives in
[`README.md`](README.md); metadata (platform/role/deps) lives in `src/root.zig`'s
`pub const meta`.

## Purpose

Provide a Raft consensus implementation (leader election + log replication) that
is **model-checked in `netsim`** against Raft's five formal safety properties
under fuzzed crash / partition / message-reorder / clock-skew schedules. Modeled
after Ongaro & Ousterhout, *"In Search of an Understandable Consensus Algorithm"*
(extended version) — Figure 2 (state + RPCs), Figure 3 (safety properties),
§5.2–§5.4.

## The five safety properties checked (Figure 3)

| Property | Statement | How it is checked |
|---|---|---|
| **Election Safety** | At most one leader per term. | Live: `SafetyChecker.recordLeader` — a second distinct leader for a term trips `error.ElectionSafety`. |
| **Leader Append-Only** | A leader never overwrites or deletes entries in its own log; it only appends. | `appendOnlyHolds(before, after)` over per-leader log snapshots taken each `check`. |
| **Log Matching** | If two logs contain an entry with the same index and term, the logs are identical in all entries up through that index. | `logMatchingViolation(logs)` across all nodes' current logs. |
| **Leader Completeness** | An entry committed in a term is present in the logs of the leaders of all higher terms. | `leaderCompletenessHolds(leader_log, committed)` for every current leader against the committed set. |
| **State Machine Safety** | If a server has applied an entry at an index, no other server ever applies a different entry for that index. | Live: `SafetyChecker.recordApply` / `recordCommitted` — a divergent value at an index trips `error.StateMachineSafety`. |

Each checker has an independent **teeth test** (`checks.zig`) that feeds it a
hand-built violating state and asserts it is caught — so the harness is proven to
have teeth without depending on the (still-stubbed) consensus core.

## The Fable boundary — irreducible core vs mechanical scaffold

The **Fable-irreducible core** (`safety.zig`, all `@panic`-gated) is the pure
consensus-safety decision logic. Honest tiering — four genuinely-subtle functions
plus one near-mechanical helper that is implemented in the clear:

- **`logIsAtLeastAsUpToDate`** *(§5.4.1)* — the election restriction. The
  comparison order (term first, then index) is the whole game; getting it wrong
  elects a leader missing committed entries. **Genuinely Fable.**
- **`handleRequestVote`** *(§5.2, §5.4.1)* — grant iff, after term step-up,
  `term ≥ current` AND not-already-voted-this-term AND log up-to-date. Dropping
  any clause breaks Election Safety or Leader Completeness. **Genuinely Fable.**
- **`handleAppendEntries`** *(§5.3)* — the log-consistency check plus the
  **conflict-only truncation** rule (delete an existing entry only when it
  conflicts; skip already-matching entries) plus `min(leaderCommit, lastNew)`
  follower commit. The naive "truncate-after-prev then append" loses committed
  entries on a delayed/duplicate RPC. **Genuinely Fable.**
- **`leaderCommitIndex`** *(§5.4.2 — Figure 8)* — a leader may advance
  `commitIndex` only to an entry on a majority **AND from its current term**;
  older-term entries commit indirectly. This is the marquee subtlety the paper's
  formal proof exists for. **Genuinely Fable.**
- **`observeTerm`** *(§5.1)* — adopt any strictly-higher term and step down. A
  single comparison; **mechanical, implemented in the clear** (not stubbed) so
  the module does not inflate its Fable surface. It sits in `safety.zig` for
  cohesion (it is a term/role safety rule), not because it is hard.

The **mechanical scaffold** (written in Phase 1, all real today): the RPC/wire
codecs and persistent-state serialization (`types.zig`), the log container —
append / conflict-truncate primitive / random access / last-index-term summary
(`log.zig`), the election/heartbeat timers, the `netsim.Protocol` wiring
(send/recv/tick, candidate vote counting, `nextIndex`/`matchIndex` bookkeeping,
the state-machine apply loop) and the cluster scenario (`server.zig`), and the
five invariant checkers (`checks.zig`). The scaffold *executes* the verdicts the
core returns — it never makes a safety decision itself.

**Is there a genuine Fable kernel here? Yes.** Unlike some modules, Raft has a
real irreducible safety core — the four functions above are exactly what the
paper's formal proof (and its reputation for subtlety) is about. The scaffold is
substantial but honestly mechanical.

## Durability / persistent-state model

Raft's crash-durability contract (Figure 2): `currentTerm`, `votedFor`, and
`log[]` must survive a crash; `commitIndex`, `lastApplied`, `role`,
`nextIndex[]`, `matchIndex[]` are volatile and rebuilt on restart.
`types.PersistentState` is exactly that durable triple with a byte codec standing
in for the disk write; in the sim a node crash clears only volatile state and a
restart re-enters via the protocol's start hook, so "restart with term/vote/log
intact" is a real, tested property (the serialize/deserialize round-trip test).

## The positive control

`server.BrokenRaft` reimplements a naive election that declares leadership on its
election timeout **without collecting a majority** and never calls `safety.zig`.
With a fixed (un-spread) timeout every node self-promotes into the **same** term,
so two distinct leaders for one term are recorded — tripping the **Election
Safety** checker (`error.ElectionSafety`) on a clean run with no injected faults.
It reuses the exact `SafetyChecker` the real `RaftServer` is held to, and its
property/shrink/teeth tests (clean-replay, 100-seed sweep, ddmin minimization)
run today. The other four properties are proven to have teeth by the synthetic
predicate tests in `checks.zig`; the gated real-cluster tests exercise all five
end-to-end once the core lands.

## Membership changes (§6) — designed, stubbed

Phase 1 scaffolds membership without implementing its safety logic:

- Log entries carry an `EntryKind` (`noop` / `command` / `config`), so the log
  container is already membership-ready; `config` entries carry no payload yet.
- `safety.jointMajority` is the stubbed joint-consensus predicate: during a
  `C_old → C_old,new → C_new` transition an election/commit counts only if it
  wins majorities in **both** configurations. Left `@panic`-gated.

Full membership change (joint consensus, the config-entry-takes-effect-when-
appended-not-committed rule, the new-leader-commits-a-no-op-first precondition,
and fuzzing membership churn in the harness) is the natural next Fable increment,
scheduled after the core five properties hold. It is deliberately out of Phase-1
scope to keep the first safety kernel focused.

## Verification

Pure-logic + model-checking (CONVENTIONS.md §7): unit tests for codecs / log /
checkers, plus `netsim` property + shrink + seed-sweep teeth tests. `zig build
test-raft` is green in Debug and ReleaseFast today: 28 pass, 2 skip (the gated
real-`RaftServer` model-check tests, which unskip when
`gate.fable_core_implemented` flips to `true`).

## Backlog

1. Implement the four Fable-core decision functions; flip the gate; make the two
   real-cluster model-check tests green across the seed sweep.
2. Add a bounded-liveness property (a leader is eventually elected and progress
   is made on a network that is quiet long enough) — a post-run analyzer akin to
   df-elect's bounded-DF-window, distinct from the safety invariants.
3. Membership changes (§6) — joint consensus, config-entry semantics, fuzz churn.
4. Log compaction / snapshotting (§7) — out of current scope.
