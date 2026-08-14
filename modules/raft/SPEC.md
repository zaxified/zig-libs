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
have teeth independently of the consensus core.

## The Fable boundary — irreducible core vs mechanical scaffold

The **Fable-irreducible core** (`safety.zig`, implemented — the Fable pass
landed and `gate.fable_core_implemented` is `true`) is the pure
consensus-safety decision logic. Honest tiering — four genuinely-subtle functions
plus one near-mechanical helper:

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
  single comparison; **mechanical, implemented in the clear** so the module does
  not inflate its Fable surface. It sits in `safety.zig` for cohesion (it is a
  term/role safety rule), not because it is hard.

**Stepping down must clear `votedFor` AND re-arm the election timer** — two
protocol rules the decision kernel cannot enforce, because both the vote slot's
lifetime and the timer live in the plumbing. Both failures are liveness-only and
produce a node that answers every RPC correctly.

*Clearing the vote* is §5.1's "if `currentTerm` changes, `votedFor` resets" — one
ballot per term. `handleRequestVote` computes its own `effective_vote =
if (term_advanced) no_vote else voted_for`, but that covers **only the message
that itself carries the higher term**: the caller cannot pre-clear the slot,
because it learns of the step-down from the returned decision. A step-down
driven by some *other* message (an AppendEntries or RequestVote **response**)
leaves the next same-term RequestVote with `term_advanced == false`, the
compensation dormant, and a `votedFor` still naming last term's candidate —
so the node refuses a vote it must grant and the cluster burns another term.
The two mechanisms are complementary, not duplicated, and each is pinned by a
test the other does not fail: dropping `effective_vote` trips `safety.zig`'s
"§5.2 … a fresh (higher) term clears an old vote"; dropping `stepDown`'s clear
trips `server.zig`'s "a step-down CLEARS votedFor" and nothing else.

*Re-arming the timer.* A leader holds
no live election timer: the one it armed as a candidate fires and is *dropped*
by `onTimer` (`role == .leader` → return, deliberately not re-armed, so a
step-down starts a fresh full timeout rather than the remainder of a stale one).
So from one timeout after its election, a leader's only route back to an armed
timer is a step-down that re-arms — every path that sets `role = .follower`
therefore goes through `server.zig`'s `stepDown`. A step-down that skips the
re-arm produces a node that is **not wedged in any way a crash test can see**:
it answers every RPC correctly and is simply never electable again, so if the
rest of the cluster is gone the cluster is dead with a healthy-looking node in
it. That is why the regression test asserts an election actually *starts*;
asserting `role == .follower` after the step-down passes either way.

Two additional safety-relevant verdicts surfaced during the core pass and now
live in the core's contract rather than the plumbing:

- **`AppendOutcome.match_index`** — a success reply advertises the VERIFIED
  region (`prevLogIndex + entries.len`), never the follower's raw last index:
  the log may extend past the verified region with a stale tail an RPC neither
  checked nor truncated, and advertising it would let the leader count
  unverified (possibly divergent) entries toward a commit majority.
- **Vote tallying is a set, not a counter** (`server.zig`'s `votes_from`): the
  network duplicates messages, and counting one voter's duplicated grant twice
  manufactures a fake majority — two leaders in one term from a single
  `dup_once` fault.

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

### Leader Completeness scoping (harness fidelity)

Figure 3 states Leader Completeness for **the leaders of all higher-numbered
terms** than the term an entry was committed in. A deposed leader that still
holds `.leader` inside a minority partition legally misses entries committed in
LATER terms — checking every current leader against the full committed set
flags legal executions (observed live at seed 2 of the sweep). `RaftServer`
therefore tracks each index's **commit term** (the first `recordCommitted` for
an index is always by the committing leader itself: commitIndex advances on the
leader synchronously, before any follower can observe the new leaderCommit) and
scopes the per-leader check to entries with `commit_term <= leader.term`. The
`leaderCompletenessHolds` predicate is unchanged; only its input set is scoped.
A real committed-entry loss is still caught twice over: any future leader
missing the entry trips this check, and an overwritten committed entry trips
`recordCommitted`/`recordApply` (State Machine Safety).

## Durability / persistent-state model

Raft's crash-durability contract (Figure 2): `currentTerm`, `votedFor`, and
`log[]` must survive a crash; `commitIndex`, `lastApplied`, `role`,
`nextIndex[]`, `matchIndex[]` are volatile and rebuilt on restart.
`types.PersistentState` is exactly that durable triple with a byte codec standing
in for the disk write; in the sim a node crash clears only volatile state and a
restart re-enters via the protocol's start hook, so "restart with term/vote/log
intact" is a real, tested property (the serialize/deserialize round-trip test).

## Malformed messages

Every wire decoder in `types.zig` returns `DecodeError!T` (`Truncated` for a
length problem, `InvalidEncoding` for a well-sized but impossible field) and
validates against the buffer **before** indexing, looping, or allocating. This
is a change in failure semantics: decoding used to be infallible-by-assumption
and panicked on anything unexpected. Concretely it now rejects

- any payload shorter than the fixed fields (`decode(&[_]u8{0})` used to panic
  with `index out of bounds: index 9, len 1`);
- an undefined RPC tag byte or `EntryKind` byte — `@enumFromInt` on raw wire
  bytes panicked with `invalid enum value`. `tagOf` matters most: it runs
  *before* any decoder, so a fail-closed decoder behind a panicking tag read
  would never be reached;
- an `AppendEntriesReq` entry count above `max_entries_per_msg`, **and** one the
  remaining bytes cannot back — checked before the loop. This was previously a
  `std.debug.assert`, which is compiled out when safety is off: a 39-byte
  message declaring 65535 entries wrote past the caller's 8-element stack array
  (measured: SIGSEGV under `ReleaseFast`) — an out-of-bounds *write* from two
  attacker-chosen bytes;
- a `PersistentState` log count the image cannot back, **before** `alloc` — the
  same unbounded-count guard as `threshold_ecdsa.PublicKeys.fromBytesAlloc`. A
  16-byte image claiming 1,000,000 entries used to allocate 24 MB and then read
  far past the buffer; `0xFFFFFFFF` demanded ~103 GB.

**What the decoders deliberately do *not* range-limit: `term`.** `Term` is a `u64` and
`RequestVoteReq`/`AppendEntriesReq`/the two responses accept any value in it; `stepDown` then
assigns it verbatim (`server.zig:296-298`). Inside the harness that is exactly right — every byte
on the wire comes from our own `encode`, so a term only ever advances by one — but it is the one
remaining piece of wire-driven arithmetic that is not fail-closed the way the count fields above
now are: a peer that asserts `term = 2^64-1` leaves every node that observes it at
`current_term = maxInt(u64)`, and the next `startElection`'s `ns.current_term += 1`
(`server.zig:333-335`) then panics under Debug/ReleaseSafe or, under ReleaseFast, **wraps to 0** — a
term *regression*, which is precisely the failure `observeTerm` exists to make impossible. A
deployment reusing these codecs against untrusted peers must bound the adopted term (or use a
saturating increment) as well as the lengths and enum bytes.

**Policy on a malformed message: drop it and count it** (`RaftServer.
malformed_dropped`). Figure 2 defines no negative acknowledgement, so there is
nothing legal to reply, and inventing one would add both a protocol message and
an amplification vector. Dropping is what the network already does to a
corrupted packet, and Raft's liveness argument is built on tolerating loss — a
dropped RequestVote is retried by the next election timeout, a dropped
AppendEntries by the next heartbeat — so a drop costs no more liveness than the
packet loss the protocol already assumes.

The counter is the mechanism that keeps the drop from being *silent*. A peer
emitting only malformed messages is, to this node, indistinguishable from a dead
link; if enough peers do it the cluster loses quorum while every node looks
healthy. **That residual liveness concern is deliberately left to the operator,
not decided here** — the correct response (evict the peer, alarm, stop counting
it toward quorum) is policy above this layer. What this module guarantees is
that the condition is observable. In the harness every byte on the wire comes
from our own `encode`, so `malformed_dropped` must stay 0; the model-check
asserts exactly that across a seed sweep, which is what stops a fail-closed
decoder from quietly hiding a real codec bug.

## The positive control

`server.BrokenRaft` reimplements a naive election that declares leadership on its
election timeout **without collecting a majority** and never calls `safety.zig`.
With a fixed (un-spread) timeout every node self-promotes into the **same** term,
so two distinct leaders for one term are recorded — tripping the **Election
Safety** checker (`error.ElectionSafety`) on a clean run with no injected faults.
It reuses the exact `SafetyChecker` the real `RaftServer` is held to, and its
property/shrink/teeth tests (clean-replay, 100-seed sweep, ddmin minimization)
run today. The other four properties are proven to have teeth by the synthetic
predicate tests in `checks.zig`; the real-cluster model-check tests exercise all
five end-to-end.

## Membership changes (§6) — designed, predicate implemented, not yet wired

Phase 1 scaffolds membership without implementing its safety logic:

- Log entries carry an `EntryKind` (`noop` / `command` / `config`), so the log
  container is already membership-ready; `config` entries carry no payload yet.
- `safety.jointMajority` is the joint-consensus predicate: during a
  `C_old → C_old,new → C_new` transition an election/commit counts only if it
  wins majorities in **both** configurations. Implemented and unit-tested (the
  gate flip must leave no reachable `@panic`), but not yet wired into the
  protocol.

Full membership change (joint consensus, the config-entry-takes-effect-when-
appended-not-committed rule, the new-leader-commits-a-no-op-first precondition,
and fuzzing membership churn in the harness) is the natural next Fable increment,
scheduled after the core five properties hold. It is deliberately out of Phase-1
scope to keep the first safety kernel focused.

## Verification

Pure-logic + model-checking (CONVENTIONS.md §7): unit tests for codecs / log /
checkers / the safety kernel (one test per documented wrong-but-plausible
implementation, including the Figure-8 counterexample and the
duplicated-AppendEntries rollback trap), plus `netsim` property + shrink +
seed-sweep teeth tests. `zig build test-raft` is green in Debug and ReleaseFast:
58 pass, 0 skip — including the real-`RaftServer` model-check tests (a 300-seed
fuzzed fault sweep enforcing all five invariants live, a quiet-network
election-liveness run, and the two step-down regressions, which drive a real
leader to a demotion by response and then require it to campaign again and to
grant a vote in the term it just adopted).
During the core pass the suite was
additionally validated against an extended 1500-seed default sweep and a
500-seed heavy sweep (40 fault events, horizon 2500, until 3000) — both clean
(ad-hoc runs, not part of the committed suite).

Sim-vs-paper durability note: a netsim `crash_node` freezes a node (no
deliveries, no timer fires) and `restart_node` re-enters via `onStart`, so ALL
of `NodeState` survives a crash — a superset of Figure 2's durable triple. This
is safe (never loses required durable state); `onStart` re-derives the volatile
role as follower. The `PersistentState` codec keeps the exact durable-triple
contract tested independently.

## Backlog

1. ~~Implement the four Fable-core decision functions; flip the gate; make the
   two real-cluster model-check tests green across the seed sweep.~~ **Done.**
2. Add a bounded-liveness property (a leader is eventually elected and progress
   is made on a network that is quiet long enough) — a post-run analyzer akin to
   df-elect's bounded-DF-window, distinct from the safety invariants. **This is
   the gap both step-down defects fell through**: `netsim` runs `checkFn` after
   every event, but a `checkFn` can only reject a *state*, and neither "this node
   has stopped being electable" nor "this node refuses a vote it should grant"
   is a bad state — each is a good event that never arrives. Note what that
   costs: the vote-clear defect was sitting *behind* the timer defect, invisible
   until the first was fixed and probed, and the module's whole 300-seed sweep
   never saw either. **Every liveness property this module relies on needs its
   own event-shaped test** — drive the cluster into the situation, advance time
   or deliver the next message, and assert the good thing HAPPENS. Two exist
   (`re-arms its election timer`, `CLEARS votedFor`); the general property that
   would subsume them does not.
3. Membership changes (§6) — wire `jointMajority` in: joint consensus,
   config-entry semantics, fuzz churn. Note for whoever does it: a config change
   that removes this node from the voter set is another `role = .follower` site,
   and must go through `stepDown` (or deliberately stop the timer) — see the
   re-arm rule above.
4. ~~Client command proposals in the harness (today only leader no-ops populate
   the log).~~ **Done** — `RaftConfig.propose_client_commands` (default on) makes
   the leader propose one distinct `(term, index)` command per heartbeat, which
   is what gives `recordApply` a key that varies.
5. Log compaction / snapshotting (§7) — out of current scope.

## Anchoring

**Anchor grade:** class C · oracle n/a

- **Class C** — internal algorithm or data structure — no outside exists, so correctness is defined by invariants or a brute-force reference. Not anchor debt.
- **Oracle n/a** — class C/D carries no anchor debt, so there is no oracle grade to give.

**What the tests actually contain.** netsim model-checking vs Raft safety properties, no wire byte format
