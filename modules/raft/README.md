# raft

The **Raft consensus algorithm** — leader election + log replication — modeled
after Ongaro & Ousterhout, *"In Search of an Understandable Consensus Algorithm"*
(extended version), and **model-checked in [`netsim`](../netsim)** against Raft's
five formal safety properties under fuzzed crash / partition / message-reorder /
clock-skew fault schedules.

Raft runs as a `netsim.Protocol` consumer: election/heartbeat timers drive
RequestVote and AppendEntries RPC exchange over the simulated network, a live
invariant checker asserts the safety properties after every event, and the
deterministic seeded fuzzer + delta-debug shrinker (from `netsim`) search for and
minimize any counterexample.

> **Status — consensus-safety core IMPLEMENTED (Fable pass landed); the gate is
> flipped and the full model-check suite runs.** The irreducible safety kernel
> in `safety.zig` — the up-to-date election restriction, the RequestVote grant,
> the AppendEntries conflict-only truncation rule, and the Figure-8
> leader-commit rule — is real and unit-tested, and the `RaftServer` holds all
> five safety properties across the fuzzed crash/partition/reorder/clock-skew
> seed sweep. Membership changes (§6) remain design-only (the `jointMajority`
> predicate is implemented but not yet wired). See [`SPEC.md`](SPEC.md).

## Use

```zig
const raft = @import("raft");
const netsim = @import("netsim");

// Drive a 5-node cluster through the fault fuzzer, checking all five safety
// invariants continuously:
var srv = try raft.RaftServer.init(gpa, raft.CLUSTER_N, .{});
defer srv.deinit(gpa);
const case = netsim.Case{ .seed = 0, .scenario = raft.scenario, .protocol = srv.protocol(), .until = 2000 };
const failing = try netsim.findFailing(gpa, case, .{}, 1, 300); // null == all seeds safe
```

The safety-decision core is exposed directly for unit testing / reuse:
`handleRequestVote`, `handleAppendEntries`, `leaderCommitIndex`,
`logIsAtLeastAsUpToDate`, `observeTerm`. The invariant checkers —
`SafetyChecker` (Election Safety, State Machine Safety) plus the pure predicates
`logMatchingViolation` / `appendOnlyHolds` / `leaderCompletenessHolds` — are
reusable against any Raft-shaped state.

## Verify

```
zig build test-raft                      # Debug        — 58 pass
zig build test-raft -Doptimize=ReleaseFast   # ReleaseFast — 58 pass
```

The model-check tests drive the real `RaftServer` through a 300-seed fuzzed
fault sweep (all five invariants live), a quiet-network election-liveness run,
and two step-down regressions that demote a real leader with a higher-term
RESPONSE and then require it to stand for election again AND to grant a vote in
the term it just adopted (see SPEC.md — stepping down must clear `votedFor` and
re-arm the election timer). The `BrokenRaft` positive-control
tests MUST trip the Election-Safety checker — proving the harness has teeth
independent of the core.

Provenance: clean-room from the Raft paper (a public spec — no third-party source
ported or studied). VOPR-style model-checking methodology via `netsim`. No
`NOTICE` entry required.
