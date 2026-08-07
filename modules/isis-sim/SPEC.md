# isis-sim — design & invariants

Auditor/design reference. The consumer-facing purpose, API and proof summary live
in `README.md`; this file records the node-state model, the netsim wiring, the
convergence/quiescence invariants, the reconvergence + partition handling, the
determinism argument, and the deferred list. Meta tags live in `src/root.zig`.

## 1. What this module is

An **integration harness**, not a new protocol. It stands up a small point-to-point
IS-IS fabric and drives the already-verified sibling stack — `isis` (codec),
`isis-lsdb` (database + SRM/SSN flags), `isis-flood` (transmit scheduler),
`isis-spf` (decision process) — on **every** node over the `netsim` discrete-event
engine, then asserts the fabric converges, reconverges after a link failure, and
detects a partition. It owns no wire format and no algorithm: every byte on the
medium is produced by `isis`, every flag transition by `isis-lsdb`, every send
decision by `isis-flood`, every route by `isis-spf`. What is new here is the
**composition** and the end-to-end assertions.

## 2. Node-state model

The `Fabric` (the netsim `Protocol` context) holds an array of `NodeState`, one
per netsim `NodeId`:

- `system_id` — `00:00:00:00:HH:LL` of `node + 1` (deterministic, dense, never
  the all-zero id).
- `neighbours` — one entry per circuit `{ neighbour NodeId, metric }`; the array
  index **is** the IS-IS `iface` used by the whole stack. Built once from the
  topology's undirected edge list.
- `link_failed` — a per-circuit boolean, mutated during a run by the
  failure-reaction timer, reset to all-false at the start of every drive.
- `lsdb` — an `isis-lsdb.Lsdb` with `interface_count = degree`, capacity
  `node_count + 8` (P2P: no broadcast interfaces).
- `sched` — an `isis-flood.Scheduler`.
- `seq` — the node's own LSP sequence number, bumped on each (re-)origination.

**Node ↔ adjacency:** a netsim bidirectional link is an up adjacency; there is no
handshake. The adjacency FSM (`isis-adj`) is the one layer this capstone omits by
design (§7).

## 3. netsim wiring

netsim owns the topology and the event schedule and calls the `Protocol` vtable;
the harness owns all per-node isis state in `ctx`.

- **Scenario seam.** netsim's `Scenario` is a bare `fn (*Sim)` with **no
  context**, the one place the topology must be parameterised. The active
  `Fabric` is passed through a `threadlocal` pointer set by `runToConvergence`
  around the single-threaded `replay` and cleared afterwards. This is
  deterministic: the sim runs on one thread and the pointer is stable for the
  duration of the replay. The scenario adds `node_count` nodes and one
  `addBiLink` per undirected edge (added once, for `a < b`).
- **onStart** originates the node's LSP (§4), arms the first flooding poll
  (`timer_poll = 0`, delay 1), and pre-arms a failure timer
  (`fail_timer_base + k`, delay = the failure's scheduled time) for each scheduled
  failure it terminates.
- **onMessage** decodes the PDU and applies it to the LSDB (insert / reconcile),
  then arms a flooding poll so the freshly-set SRM/SSN drain on the next `poll`.
- **onTimer** either polls-and-sends (`timer_poll`) or, for a failure timer,
  marks the circuit down + re-originates (§5) and then polls-and-sends.
- **checkFn** enforces `lsdb.count() ≤ node_count` on every node after every
  event (a runaway/corruption tripwire).
- **resetFn** deinits+re-inits every LSDB/scheduler and clears seq/link_failed to
  the t=0 baseline (allocation-free: `deinit` frees, the re-`init`s allocate
  nothing), so the same ctx can be replayed repeatedly.

### Why link-state changes are a *timer*, not an observation

netsim delivers **no fault notification** to the protocol: its `neighbors` view
ignores `link.up`, `severed` is private, and there is no adjacency FSM to time out
a hello. A link-state protocol therefore cannot *observe* a topology change
through the netsim seam. A topology change is modelled instead as a **scheduled
re-origination**: `runToConvergence` injects a netsim `link_down` fault (both
directions — severing transport at time *T*) **and** the two endpoints hold a
pre-armed timer at time *T* that re-originates their LSPs with the lost neighbour
removed. The pair together models "the adjacency went down and was detected, so
the LSP was re-originated" without an `isis-adj` FSM. This is the single most
significant shape difference from a naive "inject a fault and let the protocol
notice" design, and it is deliberate.

## 4. LSP origination

`originate(node)` bumps `seq`, builds an `isis` LSP (`LspBuilder`) carrying one
Extended IS Reachability (#22) TLV per **currently-up** neighbour (metric = the
edge metric; `isis-spf` clamps to ≥ 1), and `lsdb.insert`s it self-originated
(`arrival_iface = null`), which sets SRM on every circuit. The **checksum is
computed** (`LspBuilder.finishStamped`, ISO 10589 §7.3.11: "the source IS shall
compute the LSP Checksum when the LSP is generated"). This is load-bearing in
two directions. It must be *right*, because the very next hop `insert`s the same
bytes with `arrival_iface` set — a receive, and so subject to §7.3.14.2 e)'s
discard of a checksum failure; the harness previously stamped 0 ("checksumming
not in use"), which that rule rejects as "not computed" (RFC 3719 §7), so nothing
would flood at all. And it must be *deterministic*, because every copy of an
originator's LSP at a given sequence number must compare `.same` under
`isis-lsdb`'s §7.3.16.1 rule (a differing checksum against an active copy reads
as *newer* and re-floods forever) — which holds, because every node holds the
identical bytes the originator emitted. Remaining
Lifetime is stamped high and the harness never `tick`s the LSDBs, so nothing ages
during a run (aging races are deferred, §7).

## 5. Convergence, quiescence, and reconvergence

- **Flooding.** SRM-flagged LSPs are flooded by `isis-flood.poll`, sent to the
  neighbour on each effect's circuit; the receiver's `insert` sets SRM (flood
  onward) and SSN (ack); the ack (PSNP) reconciles into the sender's LSDB and
  clears SRM. The medium is **lossless** (no netsim loss/dup configured), so every
  flooded LSP is acknowledged and SRM clears without retransmission —
  `min_lsp_transmission_interval` is set beyond the run horizon so retransmit is
  inert and flooding is purely event-driven. Exactly one (initial) CSNP fires per
  circuit (the CSNP cadence is set beyond the horizon), exercising the
  `reconcileCsnp` path without periodic churn.
- **Self-terminating re-arm.** `pollAndSend` re-arms the poll only when the poll
  actually emitted an effect (a zero-effect poll ⇒ nothing pending ⇒ stop) and
  never past the run horizon. So the event chain is bounded and the fabric
  quiesces on its own.
- **Quiescence invariant.** A node is quiescent when it has no SRM (flood) or SSN
  (ack) flag set on an **up** circuit. SRM/SSN left set on a *failed* circuit is
  ignored on purpose: a down link never acks, so the re-origination that set SRM
  on it can never clear it, and that circuit is never polled. `runToConvergence`
  returns `.converged` iff every node is quiescent (and the run neither tripped
  the safety invariant nor hit the event cap).
- **Convergence invariant (`lsdbsAgree`).** Every node holds the identical
  `(originator → sequence-number)` map. Asserted by the tests for connected
  topologies; a partition does **not** satisfy it (the two sides hold different
  sets) and is validated by SPF reachability instead.
- **Reconvergence.** On the square, failing `A-B` at *T* makes A and B
  re-originate at sequence 2 without each other; the new LSPs flood out the
  surviving circuits; the fabric re-converges (databases agree again) and
  `isis-spf` reroutes A→B the long way (via D). The re-origination bumping the
  sequence number is what distinguishes a genuine reconvergence from a fresh
  start, and is asserted (`selfSequence == 2`).
- **Partition.** Failing a leaf's only link severs transport (the leaf's new LSP
  never propagates) and makes the surviving side re-originate without the leaf.
  `isis-spf`'s ISO §7.2.5 **two-way** reachability check then drops the leaf: the
  survivors' fresh LSPs no longer name it, so even the leaf's stale LSP (still
  naming its old neighbour) fails the two-way test and the leaf is unreachable —
  detected, not hung, bounded by the step cap.

## 6. Determinism

netsim is a pure function of `(seed, topology, fault trace)` with a totally
ordered `(time, seq)` event queue; the harness adds nothing non-deterministic
(the threadlocal is set/cleared around a single-threaded replay; LSDB/scheduler
iteration feeds deterministic map order that the sibling modules already prove
stable). So the same fabric + fault schedule yields the identical final LSDBs —
asserted by running two independent `Fabric`s with the same inputs and comparing
every node's stored-sequence map and self-sequence.

## 7. Positive control

A permanent RED sentinel: `broken_no_drain` makes `onMessage` insert the received
LSP but **skip arming the drain poll**, so SRM/SSN are never flooded onward.
Because retransmission is disabled (§5), the onMessage-armed poll is the *sole*
onward-flood path, and breaking it leaves nodes two-or-more hops from an
originator permanently ignorant of it — the convergence assertion (`lsdbsAgree`,
and "D lacks A's LSP") goes RED. If the flood-propagation wiring regressed into
always working regardless, this test would stop failing.

## 8. Deferred (explicit non-scope)

- **Adjacency FSM (`isis-adj`).** A netsim link is the adjacency; no hello /
  three-way handshake / hold-timer. This is the one stack layer the capstone omits.
- **Node crash / restart.** netsim supports it (`crash_node` / `restart_node`),
  but LSP purge/refresh-on-restart races are out of scope.
- **LSP purge & aging races.** The harness never `tick`s the LSDBs, so
  MaxAge/ZeroAgeLifetime purge and self-refresh do not interleave with flooding
  here.
- **LAN / pseudonodes.** P2P circuits only; no DIS, no pseudonode LSPs.
- **SPB data-plane.** Control-plane convergence only; no `l2forward`/PBB
  forwarding.
- **Scale / performance.** Fabrics are ≤ 6 nodes with a fixed set of golden
  topologies; no benchmark, no large fabric.
- **Topology fuzzing.** A fixed set of golden topologies + one golden fault
  schedule; property-based topology/fault fuzzing (which `netsim`'s own
  `run`/`shrink` could drive) is not wired here.

## 9. Verification

`zig build test-isis-sim`, green in Debug + ReleaseFast, `zig fmt` clean. The
tests are the golden-topology convergence + SPF-consistency + reconvergence +
partition + quiescence + determinism proofs plus the positive control, all under
`std.testing.allocator` (leak-checked). See `README.md` for the per-test summary.
Provenance: composes sibling modules over `netsim`; clean-room from ISO/IEC 10589,
no third-party source ported — no `/NOTICE` entry.
