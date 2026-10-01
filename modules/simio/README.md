# simio

A **deterministic `std.Io`** for simulation testing. Code written against
`std.Io` — servers, clients, anything that takes an `io: std.Io` — runs
unchanged on simulated hosts: every task is a fiber on one OS thread, time is
virtual, and every choice the simulator makes is drawn from one seed. A run is
a pure function of its seed, so a failure found on seed 1234 is reproduced by
running seed 1234 again.

- **Status:** M3 of five (see [SPEC.md](SPEC.md) § Milestones): the scheduler
  (tasks, groups, cancelation, futex, clocks, sleep, timeouts, seeded
  randomness), the network (streams, datagrams, ICMP echo over routed, faulty
  links), host crash/restart and fault search with shrinking. The file system
  with storage faults and the in-repo pilots are next.
- **Platform:** Linux on x86_64, aarch64 or riscv64 (`std.Io.fiber`).
- **Deps:** `netsim` (its seeded PRNG; its fault vocabulary from M3).
- **Model after:** tokio-rs/turmoil, madsim, FoundationDB's simulation testing.

## Use

```zig
const simio = @import("simio");

fn server(io: std.Io, state: *State) !void {
    // ordinary std.Io code: io.async, Io.Mutex, io.sleep, Io.Group, ...
}

test "my protocol under 200 schedules" {
    for (0..200) |seed| {
        var sim: simio.Sim = undefined;
        sim.init(std.testing.allocator, .{ .seed = seed });
        defer sim.deinit();

        const host = try sim.addHost(.{ .clock_skew_ns = 0 });
        var state: State = .{};
        try host.spawn(server, .{ host.io(), &state });

        const r = sim.run(); // .quiescent, .deadlock or .step_limit
        try std.testing.expectEqual(simio.Outcome.quiescent, r.outcome);
        try std.testing.expectEqual(@as(usize, 0), host.failures);
        try state.checkInvariants();
    }
}
```

- `Sim.run` returns when nothing can make progress: `.quiescent` (every task
  finished), `.deadlock` (tasks blocked that nothing can wake — `blocked` says
  how many) or `.step_limit`.
- `Host.spawn` starts a root task; an error it returns lands in
  `host.failure`/`host.failures` instead of vanishing.
- `Sim.fingerprint()` digests every scheduling decision. Run a seed twice and
  compare: a difference means the code under test is nondeterministic (a
  wall-clock read, a thread, an address-keyed map outside `std.Io`).
- `Options.schedule = .fifo` with no preemption is the "obvious" order;
  `.random` (default) plus `preempt_permille` explores interleavings.

### The network

```zig
const a = try sim.addHost(.{});            // 10.0.0.1
const b = try sim.addHost(.{});            // 10.0.0.2
try sim.link(a, b, .{ .latency_ns = 5 * std.time.ns_per_ms, .loss_permille = 20 });
try b.spawn(server, .{ b.io() });          // listen/accept as usual
try a.spawn(client, .{ a.io() });          // connect to 10.0.0.2
_ = sim.runFor(10 * std.time.ns_per_s);    // servers never finish: run a while
try sim.setLinkUp(a, b, false);            // partition, then run on
```

- Streams behave like TCP as an application sees it: refused, reset, timeouts,
  a flow-control window, end of stream on the peer's close — and reads that
  are sometimes short, on purpose.
- Datagrams can be lost, duplicated, reordered or have a bit flipped, per
  link. `bind` with `protocol = .icmp` gives a ping socket the target answers.
- Hosts with several links route over the shortest path that is up.

### Crashes, faults and search

```zig
fn setup(sim: *simio.Sim, ctx: ?*anyopaque) anyerror!void {
    const state: *State = @ptrCast(@alignCast(ctx.?));
    const a = try sim.addHost(.{});
    const b = try sim.addHost(.{});
    try sim.link(a, b, .{ .latency_ns = 20 * std.time.ns_per_ms });
    try b.spawnBoot(server, .{ b.io(), state });   // restarted after a crash
    try a.spawn(client, .{ a.io(), state });
}

fn invariant(sim: *simio.Sim, ctx: ?*anyopaque) anyerror!void {
    const state: *State = @ptrCast(@alignCast(ctx.?));
    if (state.applied > 1) return error.AppliedTwice;   // checked after every step
}

const case: simio.Case = .{ .setup = setup, .invariant = invariant, .reset = resetState, .ctx = &state };
if (try simio.findFailing(gpa, case, .{}, 0, 500)) |*failing| {
    defer failing.deinit();
    var small = try simio.shrink(gpa, failing);   // fewest faults, same error
    defer small.deinit();
    _ = try simio.replay(gpa, failing.case, small.trace.events, failing.tick_ns);
}
```

- `findFailing` draws a fault schedule per seed (netsim's generator: link and
  one-way failures, partitions, crashes and restarts, clock jumps, one-shot
  drops/duplicates/delays) and returns the first violation; `shrink` keeps the
  faults that matter; `replay` re-runs any concrete schedule.
- `Sim.crash(host)` is a power cut: tasks stop without running `defer`,
  sockets vanish, memory from `host.allocator()` is released. `restart`
  re-runs the `spawnBoot` tasks.
- `checkDeterminism` runs a seed twice and fails if the runs differ.

Operations simio does not simulate yet behave as in `std.Io.failing` (an
error, never a fake success).

## Verify

```
scripts/modtest simio
```

The suite checks the `std.Io` contract (cancelation delivered once, protection,
`recancel`, groups, timeouts against skewed clocks) and the property the module
exists for: one seed replays one schedule, different seeds find a planted lost
update that a mutex then prevents.

Provenance: original work of the zig-libs authors (MIT), except the fiber entry
trampoline and initial stack layout, taken from Zig's `std/Io/Uring.zig` (MIT) —
see [NOTICE](NOTICE). turmoil, madsim, marionette, FoundationDB and TigerBeetle
are design references only.
