// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: `Reassembler.init` validates its config with
// `std.debug.assert`, which is a NO-OP in ReleaseFast and ReleaseSmall. The doc
// comments say "Must be at least 1" without saying that the enforcement
// disappears in the modes production actually ships. Audit F7 measured what
// survives: `max_inflight = 0` and an over-ceiling `max_frame_len` both gave a
// clean panic in Debug and **SIGSEGV** in ReleaseFast. And
// `max_fragments_per_datagram` was not validated at all, in any mode.
//
// ⚠ THIS PROBE IS FIVE FILES IN ONE, AND THAT MATTERS. The audit left
// `config.zig` (K1+K4), `k2.zig`, `k3.zig`, `churn.zig` and `churn2.zig` in the
// cache as separate programs. `k2` and `k3` differ ONLY in a print label and a
// comptime-constant toggle edited in place (`if (2 == 2)` vs `if (3 == 2)`);
// `churn` and `churn2` differ ONLY in which allocator backs the tracker. They
// were one instrument, forked by editing, five times over -- the same pattern
// as `ripemd160`'s `perf_cap`/`perf_cap2`/`perf_quad` and `xml`'s mislabelled
// `attrs_256k`. Here the choice is an ARGUMENT, so measuring a different case
// does not fork the source again.
//
//   config_probe                # K1 + K4 (safe in any mode)
//   config_probe --unchecked    # K2 + K3: only meaningful in ReleaseFast/Small
//   config_probe --churn [smp]  # K5: duplicate-drop churn, Debug or smp allocator
//
// ⚠ `--unchecked` is EXPECTED TO CRASH in ReleaseFast. That is the finding, not
// a malfunction: run it knowing the process may die, and read how far it got.
//
// Build (⚠ against the LIVE module, never a copy; run in BOTH modes):
//   zig build-exe -OReleaseFast --dep ethfrag \
//       -Mmain=config_probe.zig -Methfrag=../src/root.zig \
//       --cache-dir <scratch>/zc-cfg -femit-bin=<scratch>/config_probe

const std = @import("std");
const builtin = @import("builtin");
const ef = @import("ethfrag");
const Track = @import("track.zig").Track;

var wire: [70016]u8 = undefined;

fn mk(id: u16, off: u16, len: u16, more: bool) []u8 {
    std.mem.writeInt(u16, wire[0..2], id, .big);
    std.mem.writeInt(u16, wire[2..4], off, .big);
    std.mem.writeInt(u16, wire[4..6], len, .big);
    wire[6] = if (more) 1 else 0;
    wire[7] = 0;
    return wire[0 .. 8 + @as(usize, len)];
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next();
    var want_unchecked = false;
    var want_churn = false;
    var churn_smp = false;
    var want_invalid = false;
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--unchecked")) want_unchecked = true;
        if (std.mem.eql(u8, a, "--churn")) want_churn = true;
        if (std.mem.eql(u8, a, "smp")) churn_smp = true;
        if (std.mem.eql(u8, a, "--invalid-config")) want_invalid = true;
    }

    std.debug.print("\n### builtin.mode = {s} ###\n", .{@tagName(builtin.mode)});
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const base = da.allocator();

    if (want_churn) {
        // ── K5 (F8): duplicate-drop churn. The attacker sends a fragment and
        // then the SAME fragment: overlap -> the whole entry is dropped -> the
        // next pair allocates again. Wire bytes bought vs bytes turned over.
        // ⚠ The ABSOLUTE ns depends on the allocator (the audit measured
        // 1.4 us with smp and 7.4 us with DebugAllocator); the RATIO does not.
        var t: Track = .{ .child = if (churn_smp) std.heap.smp_allocator else base };
        const gpa = t.allocator();
        var r = ef.Reassembler.init(gpa, .{ .max_inflight = 64, .timeout_ns = 2 * std.time.ns_per_s });
        defer r.deinit();
        var wire_in: usize = 0;
        var i: usize = 0;
        while (i < 50_000) : (i += 1) {
            const w = mk(1, 0, 1, true);
            wire_in += w.len;
            _ = r.insert(w, 0) catch {};
        }
        std.debug.print("K5 duplicate-drop churn ({s}): wire_in={d}B -> total_alloc={d}B ({d}x), allocs={d}, peak={d}B\n", .{
            if (churn_smp) "smp_allocator" else "DebugAllocator",
            wire_in,
            t.total_alloc,
            if (wire_in > 0) t.total_alloc / wire_in else 0,
            t.n_alloc,
            t.peak,
        });
        return;
    }

    // ── K1: max_fragments_per_datagram = 0 ──────────────────────────────────
    // ⚠ OPT-IN, BECAUSE IT NOW KILLS THE PROCESS. When the audit ran, this
    // config was accepted silently in every mode (F7: "nevaliduje se ani tam").
    // Today `root.zig:402` answers with `@panic(...)`, which -- unlike the
    // `std.debug.assert` F7 complained about -- SURVIVES ReleaseFast. Measured
    // here: `panic: ReassemblerConfig.max_fragments_per_datagram must be at
    // least 1`, in a ReleaseFast build. That is F7's own proposed fix, landed.
    //
    // A `@panic` cannot be caught in-process, so leaving K1 in the default path
    // meant K4 below never ran at all -- a probe whose first scenario aborts
    // hides every measurement after it.
    if (want_invalid) {
        std.debug.print("K1: invalid config requested -- the process is EXPECTED to panic here\n", .{});
        var t: Track = .{ .child = base };
        var r = ef.Reassembler.init(t.allocator(), .{
            .max_inflight = 4,
            .max_frame_len = 65535,
            .max_fragments_per_datagram = 0,
            .timeout_ns = 1000,
        });
        defer r.deinit();
        var i: usize = 0;
        var last: []const u8 = "?";
        while (i < 1000) : (i += 1) {
            _ = r.insert(mk(1, 0, 1, true), 0) catch |e| {
                last = @errorName(e);
                continue;
            };
            last = "accepted";
        }
        std.debug.print("K1 max_fragments_per_datagram=0: 1000 inserts -> {s}; allocs={d}, total_alloc={d}B, peak={d}B, inflight={d}\n", .{
            last, t.n_alloc, t.total_alloc, t.peak, r.inflightCount(),
        });
    } else {
        std.debug.print("K1 skipped (pass --invalid-config): max_fragments_per_datagram=0 now PANICS even in ReleaseFast -- audit F7 is closed\n", .{});
    }

    // ── K2 / K3: only where the assert is compiled out, and only on request ──
    if (want_unchecked) {
        if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
            std.debug.print("K2/K3 skipped: asserts are LIVE in {s}; build -OReleaseFast to see what survives\n", .{@tagName(builtin.mode)});
        } else {
            std.debug.print("K2/K3: asserts compiled out -- the process may die here, which IS the finding\n", .{});
            {
                var r = ef.Reassembler.init(base, .{ .max_inflight = 0, .timeout_ns = 1000 });
                defer r.deinit();
                const res = r.insert(mk(1, 0, 1, true), 0);
                std.debug.print("K2 max_inflight=0: insert -> {s}\n", .{
                    if (res) |_| "accepted" else |e| @errorName(e),
                });
            }
            {
                var t: Track = .{ .child = base };
                var r = ef.Reassembler.init(t.allocator(), .{
                    .max_inflight = 1,
                    .max_frame_len = 1 << 24, // 16 MiB — above the documented 65535
                    .timeout_ns = 1000,
                });
                defer r.deinit();
                const res = r.insert(mk(1, 0, 1, true), 0);
                std.debug.print("K3 max_frame_len=16MiB: insert -> {s}; peak={d}B from a 9-byte fragment\n", .{
                    if (res) |_| "accepted" else |e| @errorName(e), t.peak,
                });
            }
        }
    }

    // ── K4: allocations per datagram on the happy path ──────────────────────
    for ([_]u16{ 1, 4, 64, 1024 }) |n| {
        var t: Track = .{ .child = base };
        const gpa = t.allocator();
        var r = ef.Reassembler.init(gpa, .{
            .max_inflight = 4,
            .max_frame_len = 65535,
            .max_fragments_per_datagram = 4096,
            .timeout_ns = std.math.maxInt(u64),
        });
        const frame_len: u16 = 60000;
        const chunk: u16 = frame_len / n;
        var i: u16 = 0;
        while (i < n) : (i += 1) {
            const off: u16 = i * chunk;
            const last = (i + 1 == n);
            const len: u16 = if (last) frame_len - off else chunk;
            switch (try r.insert(mk(1, off, len, !last), 0)) {
                .complete => |b| gpa.free(b),
                .incomplete => {},
            }
        }
        r.deinit();
        std.debug.print("K4 60000B frame, n={d:>4}: allocs={d:>3} resize={d:>3} remap={d:>3} total_alloc={d:>7}B peak={d:>7}B  ({d} wire bytes)\n", .{
            n, t.n_alloc, t.n_resize, t.n_remap, t.total_alloc, t.peak, @as(usize, n) * 8 + frame_len,
        });
    }
}
