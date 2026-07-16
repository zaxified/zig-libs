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

> **Status — Phase 1 scaffold. The consensus-safety core is a gated Fable stub.**
> Real and passing today: the wire codecs + persistent-state serialization, the
> log container, all five safety checkers (with synthetic teeth tests), the
> protocol plumbing, and the `BrokenRaft` positive control. Behind the gate
> (`fable_core_implemented = false`): the irreducible safety kernel in
> `safety.zig` — the up-to-date election restriction, the RequestVote grant, the
> AppendEntries conflict rule, and the Figure-8 leader-commit rule — each a
> `@panic("TODO(fable/core): …")` stub. See [`SPEC.md`](SPEC.md).

## Use

```zig
const raft = @import("raft");
const netsim = @import("netsim");

// Drive a 5-node cluster through the fault fuzzer, checking all five safety
// invariants continuously (works once the Fable core is implemented):
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
zig build test-raft                      # Debug   — 28 pass, 2 skip (gated core)
zig build test-raft -Doptimize=ReleaseFast
```

The two skipped tests drive the real `RaftServer` and unskip the moment
`gate.fable_core_implemented` flips to `true`. The `BrokenRaft` positive-control
tests run today and MUST trip the Election-Safety checker — proving the harness
has teeth independent of the core.

Provenance: clean-room from the Raft paper (a public spec — no third-party source
ported or studied). VOPR-style model-checking methodology via `netsim`. No
`NOTICE` entry required.
