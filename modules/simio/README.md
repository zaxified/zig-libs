# simio

A **deterministic `std.Io`** for simulation testing. Code written against
`std.Io` — servers, clients, anything that takes an `io: std.Io` — runs
unchanged on simulated hosts: every task is a fiber on one OS thread, time is
virtual, and every choice the simulator makes is drawn from one seed. A run is
a pure function of its seed, so a failure found on seed 1234 is reproduced by
running seed 1234 again.

- **Status:** M1 of five (see [SPEC.md](SPEC.md) § Milestones): the scheduler —
  tasks, groups, cancelation, futex (`Io.Mutex`, `Io.Condition`), clocks,
  sleep, timeouts, seeded randomness. The simulated network, file system and
  fault search (on [`netsim`](../netsim)) are next.
- **Platform:** Linux on x86_64, aarch64 or riscv64 (`std.Io.fiber`).
- **Deps:** `netsim` (its seeded PRNG today; its network model from M2).
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
