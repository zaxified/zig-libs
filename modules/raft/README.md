# raft

The **Raft consensus algorithm** — leader election + log replication — modeled
after Ongaro & Ousterhout, *"In Search of an Understandable Consensus Algorithm"*
(extended version), and **model-checked in [`netsim`](../netsim)** against Raft's
five formal safety properties under fuzzed crash / partition / message-reorder /
clock-skew fault schedules.

Two ways in:

- **`raft.Node`** — one runnable Raft server as a pure state machine. You own the
  transport, the disk, the clock and the state machine; the node owns every
  consensus decision. Any cluster size, entries carry your bytes, restart from
  what you persisted.
- **`raft.RaftServer`** — N of those `Node`s inside `netsim`, with a disk per
  server, driven through crash / partition / reorder / duplication / clock-skew
  fault schedules while a live checker asserts all five Figure 3 safety
  properties after every event. This is how the `Node` you run is verified.

> **Status — mvp.** Election, replication, the Figure-8 commit rule, restart
> from persisted state. Not yet: snapshots / log compaction (the whole log is in
> memory), membership changes (`jointMajority` exists, not wired), pre-vote and
> leadership transfer, linearizable reads. See [`SPEC.md`](SPEC.md).

## Use

```zig
const raft = @import("raft");

var node = try raft.Node.init(gpa, .{
    .id = my_id,
    .cluster_size = 3,
    .election_ticks = 10, // × your tick period
    .heartbeat_ticks = 2,
    .seed = random_u64, // different on every server
}, .{ .hard_state = persisted_hs, .entries = persisted_entries });
defer node.deinit();

// Feed it: node.tick() every tick period, node.stepBytes(from, frame) for every
// frame from a peer, node.propose(bytes) for a client write on the leader.
// After any of them:
while (node.hasReady()) {
    const rd = try node.ready();
    // 1. persist rd.hard_state, then delete stored entries > rd.truncate_after,
    //    then write rd.entries — durably;
    // 2. send each of rd.messages (m.encode / m.encodeAlloc) to m.to;
    // 3. apply rd.committed to your state machine, in order;
    try node.advance();
}
```

[`example/main.zig`](example/main.zig) is a complete three-node cluster in one
process (crash and restart included); [`example-apps/raft-kv`](../../example-apps/raft-kv)
is a replicated key-value store over TCP built on `Node`.

The model-check:

```zig
var srv = try raft.RaftServer.init(gpa, raft.CLUSTER_N, .{});
defer srv.deinit(gpa);
const case = netsim.Case{ .seed = 0, .scenario = raft.scenario, .protocol = srv.protocol(), .until = 2000 };
const failing = try netsim.findFailing(gpa, case, .{}, 1, 300); // null == all seeds safe
```

The safety-decision kernel is exposed on its own too (`handleRequestVote`,
`handleAppendEntries`, `leaderCommitIndex`, `logIsAtLeastAsUpToDate`,
`observeTerm`), and so are the invariant checkers (`SafetyChecker`,
`logMatchingViolation`, `appendOnlyHolds`, `leaderCompletenessHolds`).

## Verify

```
scripts/modtest raft                         # LLVM Debug
scripts/modtest raft -Doptimize=ReleaseSafe
```

The model-check drives N real `Node`s through two fuzzed fault sweeps (300
seeds, and 150 with Readys batched per tick so several inputs meet before one
`ready`), all five invariants live, with a restart that rebuilds a
server from its persisted state alone; plus a quiet-network liveness run, a
directed crash/restart run, and the step-down regressions. The positive
controls MUST trip the checkers: `BrokenRaft` (Election Safety) and the
index-only §5.4.1 rule injected into the real `Node` (Leader Completeness, on a
directed schedule).

Provenance: clean-room from the Raft paper (a public spec — no third-party source
ported or studied). VOPR-style model-checking methodology via `netsim`. No
`NOTICE` entry required.
