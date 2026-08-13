# netsim

A **deterministic, seeded, discrete-event network simulator** — the harness that
model-checks distributed algorithms. A topology of nodes and directed links
(per-link latency / jitter / loss / duplication / reorder / bandwidth, per-node
clock skew) is driven by a seeded PRNG through a single time-ordered event queue
with deterministic tie-breaking, so **every run is a pure function of its seed
and replays byte-for-byte**.

On top of the engine sits the adversary: a seeded failure-schedule fuzzer (link
up/down, arbitrary-cut partitions and heals, message drop / duplicate / delay
spike, node crash and restart, clock jumps), caller-registered invariant
predicates checked after *every* event, byte-exact replay of a concrete trace,
and a delta-debugging (ddmin) counterexample minimizer.

This is the VOPR methodology already proven in [`kv`](../kv), generalized from a
single store to a network. netsim itself bakes in **no** protocol specifics: an
algorithm plugs in as a `Protocol` consumer — see [`raft`](../raft),
[`loopfree-reconv`](../loopfree-reconv), [`df-elect`](../df-elect) and
[`liveness-hyst`](../liveness-hyst).

- **Status:** complete. **Platform:** any — pure simulation, no OS or network
  I/O, no wall-clock read.
- **Deps:** none (std only).
- **Model after:** TigerBeetle's VOPR / deterministic discrete-event network
  simulation.

## Use

```zig
const netsim = @import("netsim");

// 1. Topology.
fn scenario(sim: *netsim.Sim) anyerror!void {
    for (0..5) |_| _ = try sim.addNode(.{});
    try sim.addBiLink(0, 1, .{ .latency = 10, .loss = 0.01 });
}

// 2. Algorithm as a Protocol (onStart / onMessage / onTimer / check), then
//    fuzz a fault schedule across a seed range; null == every seed held.
const case = netsim.Case{ .seed = 0, .scenario = scenario, .protocol = p, .until = 2000 };
const failing = try netsim.findFailing(gpa, case, .{}, 1, 300);

// 3. Minimize whatever it found, and replay it deterministically.
if (failing) |f| {
    var min = try netsim.shrink(gpa, &f);   // .before / .after event counts
    defer min.deinit();
    _ = try netsim.replay(gpa, case, min.trace.events, null);
}
```

`run` fuzzes one seed and returns `.ok` or `.violated` with the exact
`FaultTrace` reproducer; `replay` re-runs a concrete trace as a deterministic
oracle; `findFailing` + `shrink` search a seed range and minimize.

## Verify

```
zig build test-netsim                          # Debug       — 15 pass
zig build test-netsim -Doptimize=ReleaseFast   # ReleaseFast — 15 pass
```

The determinism property is the load-bearing one and is tested directly: the
same seed produces an identical event log, and a replayed trace reproduces the
violation it was minimized from. Consumers add their own invariants — a
harness with no teeth is the failure mode this module exists to avoid, so each
consumer ships a deliberately-broken positive control that MUST trip its
checker (see `raft`'s `BrokenRaft`).

Provenance: original work of the zig-libs authors (MIT) — the deterministic
seeded discrete-event simulator, the failure-schedule fuzzer, the byte-exact
replay oracle and the ddmin counterexample minimizer. The METHODOLOGY — a
simulator that is a pure function of its seed, driving a real implementation
under a fuzzed fault schedule with invariants checked after every event —
follows TigerBeetle's VOPR (**Apache-2.0**), a **design reference only**: no
TigerBeetle source was consulted or copied, and this module's engine, event
queue and API are unrelated to it. The splitmix64 mixer is Sebastiano Vigna's
public-domain algorithm. The methodology is borrowed from this repo's own `kv`
VOPR, not its code.
