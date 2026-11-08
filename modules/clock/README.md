# clock

Monotonic and wall-clock reads for code without an `std.Io`, and the injectable clock values that
time-dependent modules take so their tests can move time by hand.

```zig
const clock = @import("clock");

const t0 = clock.monotonicNs();          // CLOCK_MONOTONIC (vDSO) / QPC, u64 ns
// …
const took = clock.elapsedNs(t0, clock.monotonicNs()); // saturates at 0

const unix_s = clock.realtimeS();        // also realtimeNs / realtimeMs (floored)
const cheap = clock.monotonicCoarseNs(); // tick resolution, for hot paths

// A module that needs time takes a Clock with a production default…
const Limiter = struct {
    clock: clock.Clock = .monotonic,
    fn tick(self: *Limiter) u64 { return self.clock.now(); }
};

// …and its test drives it:
var manual = clock.ManualClock.init(0);
var l: Limiter = .{ .clock = manual.clock() };
manual.advance(5 * std.time.ns_per_s);
```

Every function is total — no error, no panic, no allocation; a failed OS read returns 0.
`WallClock` / `ManualWallClock` are the wall-clock (Unix `i64` ns) counterparts.
Design, the comparison with Rust/Go/quanta and what is refused: `SPEC.md`.

`zig build test-clock` — invariants, cross-checks against `std.Io.Clock`, conversion edges, manual
clocks (including a 4-thread advance race).

Provenance: original work of the zig-libs authors, written against the Linux `clock_gettime(2)` man page
and the Windows QueryPerformanceCounter / RtlGetSystemTimePrecise documentation. No third-party source was
consulted or copied, so no `NOTICE` entry is required. The comparative benchmark under `tools/`
(`bench.zig` and its `rust_bench/` reference side, 2026-11-08) is our own tooling; it drives Rust std only
through its public API. DATA: none — `tools/rust_bench/main.rs` is source code of that benchmark, generated
by our own tooling; no captured or third-party data is committed.
