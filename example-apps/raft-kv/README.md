# raft-kv

A replicated key-value store that survives losing its leader. Three processes
form a [Raft] cluster: kill the leader mid-write and the survivors elect a new
one and keep serving; restart the corpse and it catches up from its own disk;
take away the majority and writes **refuse** instead of lying.

[Raft]: https://raft.github.io/raft.pdf

## Get it

Take this directory and nothing else — it is a self-contained project, and the
rest of the collection arrives as a pinned dependency, not as a checkout:

```sh
curl -L https://github.com/zaxified/zig-libs/archive/refs/tags/2026-08-24.tar.gz \
  | tar -xz --strip-components=2 'zig-libs-2026-08-24/example-apps/raft-kv'
cd raft-kv
```

With git instead, if you would rather have history:

```sh
git clone --depth 1 --filter=blob:none --sparse -b 2026-08-24 \
  https://github.com/zaxified/zig-libs.git
cd zig-libs && git sparse-checkout set example-apps/raft-kv
cd example-apps/raft-kv
```

## Build and run

```sh
./init.sh
```

Then a cluster on loopback — same binary, three data directories:

```sh
P=127.0.0.1:7801,127.0.0.1:7802,127.0.0.1:7803
./zig-out/bin/raft-kv node --id 0 --peers $P --data n0    # terminal 1
./zig-out/bin/raft-kv node --id 1 --peers $P --data n1    # terminal 2
./zig-out/bin/raft-kv node --id 2 --peers $P --data n2    # terminal 3
```

and from a fourth:

```sh
./zig-out/bin/raft-kv put --cluster $P city Brno   # follows redirects to the leader
./zig-out/bin/raft-kv get --cluster $P city        # Brno
./zig-out/bin/raft-kv dump --node 127.0.0.1:7802   # one node's applied state + role
./zig-out/bin/raft-kv status --cluster $P          # the whole cluster, one line per node
```

`status` is the view to keep open while you break things:

```
node 0  127.0.0.1:7801  follower  term=2  keys=3
node 1  127.0.0.1:7802  DOWN (ConnectionRefused)
node 2  127.0.0.1:7803  leader  term=2  keys=3
```

(A follower can trail the leader's key count for a heartbeat — commit index
travels with the next AppendEntries, and `status` shows you exactly that.)

Now `kill -9` the process that logged `LEADER` and run the `put` again: it
retries through the election and lands on the new leader. Restart the killed
node with the same command line and watch `dump` on it converge.

`init.sh` needs Zig 0.16.0 on `PATH` and installs nothing for you.

## What is worth reading it for

**The consensus kernel is the `raft` module's, verbatim — this app is its
first deployment outside the simulator.** The module's safety core
(`handleRequestVote`, `handleAppendEntries`, `leaderCommitIndex`,
`observeTerm`) is model-checked in `netsim` against Raft's five formal safety
properties under fuzzed crash/partition/reorder schedules. What the simulator
abstracts away, `src/node.zig` supplies for real: TCP between nodes, election
timers with per-node jitter, and a disk. Every consensus *decision* in this
app is a call into the kernel; the app code only carries verdicts to sockets
and storage, in the order Figure 2 requires — **persist, then answer**. The
peer messages are the module's own wire codec, the same bytes the model-check
exchanges.

**Durability is the `kv` module's fsync contract.** `currentTerm`, `votedFor`
and every log entry are written through `kv` (Bitcask-style, fsync on every
put, CRC on every read) *before* the RPC answer that promises them leaves the
node. A node that crashes and forgets a vote it granted can elect two
leaders; this one cannot, and the smoke test SIGKILLs a leader to check.

**Arbitrary values over a fixed-width kernel, honestly.** The module's
`Command` is a `u64` — the model-checked kernel agrees on
`(term, index, command)` and nothing else. KV operations ride alongside each
AppendEntries as length-prefixed blobs, and each entry's `command` is the
truncated SHA-256 of its blob. Before applying, a node re-hashes the blob and
**refuses** one that does not match the committed command — what the state
machines execute is bound to what consensus agreed on, up to a hash
collision.

**"No majority" is an answer, not a hang.** A leader that cannot replicate to
a majority answers `commit timed out (no majority?)` after 2 s, the client
retries elsewhere and eventually reports failure — the smoke test kills two
nodes and asserts the write FAILS. When the majority returns, so does
service.

## What it deliberately does not do

- **Reads are leader-local.** `get` is answered by the leader from its
  applied state — no read-index protocol, no leases. A deposed leader alone
  in a partition can serve a stale read until it observes the new term.
  `dump` is more honest still: any node, its own state, labeled as such.
- **Static membership.** The `--peers` list is fixed at start; §6 membership
  changes are design-only in the module and not wired here.
- **No snapshots/compaction.** The log replays from index 1 on restart.
- **No RPC deadlines.** One-shot request/response on loopback. A peer that
  accepts a connection and then never answers blocks the thread that made the
  call — and because replication threads are *joined* at shutdown, such a peer
  present at SIGTERM time would keep the whole process from exiting, not just
  stall one thread. On loopback with cooperating peers this never arises; a
  production build would put a deadline on every socket op.
- **One coarse lock, held across the fsync.** All node state is guarded by a
  single spinlock, and `kv`'s durable `put` (an fsync) runs *under* it, so
  writes are fully serialized and a slow disk can delay heartbeats. That is the
  simplest thing that is correct, not the fastest thing that works: a real
  system would persist off the critical path and replicate concurrently. Fine
  for a three-node loopback demo; not a template for production throughput.

## Modules used

| Module | What the app takes from it |
|---|---|
| `raft` | the model-checked consensus kernel + the RPC wire codec |
| `kv` | crash-consistent storage for term/vote/log (fsync per write) |
| `framing` | length-prefixed frames over TCP |
| `lockfree` | the `SpinLock` guarding all Raft state (see the note above) |
