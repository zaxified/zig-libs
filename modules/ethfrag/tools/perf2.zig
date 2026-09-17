// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: `perf.zig`'s three measurements, refined where the first
// answers were not conclusive.
//
//   E2b -> F4  the documented memory bound against a HARDENED config. This is
//              the sharper half of F4: the smaller `max_frame_len` a careful
//              consumer picks, the LARGER the share of real memory the formula
//              fails to describe (the audit measured 17.49x at a real
//              1500-byte Ethernet MTU, against 1.37x at the 65535 default).
//              A bound that gets worse the more you harden is the finding.
//   E3b -> F9  the overlap scan ALONE: no memcpy, no per-datagram buffer
//              churn, arena-backed so the allocator is not the thing under the
//              stopwatch. `ns/(n*n/2)` settling to a constant is the proof of
//              quadratic behaviour that E3's mixed measurement cannot give.
//   E3c -> F9  the same on a REAL split, to show E3b is not an artefact of
//              degenerate fragments.
//
// ⚠ BUILD WITH -OReleaseFast BEFORE THE -M ARGUMENTS -- see perf.zig's note.
// The mode is printed; read it before quoting any number.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -OReleaseFast --dep ethfrag \
//       -Mmain=perf2.zig -Methfrag=../src/root.zig \
//       --cache-dir <scratch>/zc-perf2 -femit-bin=<scratch>/perf2

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

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

pub fn main() !void {
    std.debug.print("\n### builtin.mode = {s} ###\n", .{@tagName(builtin.mode)});
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const base = da.allocator();

    // ── E2b (F4): hardened config — max_frame_len sized to a real MTU ───────
    std.debug.print("\n=== E2b (F4): documented bound vs reality across max_frame_len ===\n", .{});
    for ([_]usize{ 65535, 9216, 1500 }) |mfl| {
        const max_inflight: usize = 8;
        const max_frags: usize = 4096;
        var t: Track = .{ .child = base };
        const gpa = t.allocator();
        var r = ef.Reassembler.init(gpa, .{
            .max_inflight = max_inflight,
            .max_frame_len = mfl,
            .max_fragments_per_datagram = max_frags,
            .timeout_ns = std.math.maxInt(u64),
        });
        var wire_in: usize = 0;
        var id: u16 = 0;
        var first_err: []const u8 = "none";
        while (id < max_inflight) : (id += 1) {
            var k: usize = 0;
            // ⚠ 1-byte fragments at fresh offsets: since audit F1 a `more=true`
            // zero-length fragment is refused outright, so the audit's
            // pure-interval-growth shape no longer exists. Same attacker
            // freedom (n intervals, no completion), one byte of payload each.
            while (k < max_frags - 1) : (k += 1) {
                const w = mk(id, @intCast(k), 1, true);
                wire_in += w.len;
                _ = r.insert(w, 0) catch |e| {
                    if (std.mem.eql(u8, first_err, "none")) first_err = @errorName(e);
                    break;
                };
            }
        }
        const documented = max_inflight * mfl;
        std.debug.print("  max_frame_len={d:>5}: wire_in={d}B PEAK={d}B  documented={d}B  peak/documented={d}.{d:0>2}x  first_err={s}\n", .{
            mfl, wire_in, t.peak, documented, t.peak / documented, (t.peak * 100 / documented) % 100, first_err,
        });
        // ⚠ Float, not integer division -- same trap as perf.zig: this ratio is
        // legitimately below one now that F8 grows the buffer lazily, and `{d}`
        // on a usize quotient prints that as `0x`.
        if (wire_in > 0) std.debug.print("                    wire->held = {d:.2}x   inflight={d}\n", .{
            @as(f64, @floatFromInt(t.peak)) / @as(f64, @floatFromInt(wire_in)),
            r.inflightCount(),
        });
        r.deinit();
    }

    // ── E3b (F9): the overlap scan alone, arena-backed ──────────────────────
    std.debug.print("\n=== E3b (F9): n 1-byte fragments into ONE datagram (overlap scan), arena allocator ===\n", .{});
    std.debug.print("  {s:>6} {s:>12} {s:>12} {s:>14} {s:>12}\n", .{ "n", "wire_B", "best_ns", "ns/fragment", "ns/(n*n/2)" });
    for ([_]usize{ 64, 128, 256, 512, 1024, 2048, 4096 }) |n| {
        var best: u64 = std.math.maxInt(u64);
        var rep: usize = 0;
        while (rep < 7) : (rep += 1) {
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const gpa = arena.allocator();
            var r = ef.Reassembler.init(gpa, .{
                .max_inflight = 2,
                .max_frame_len = 65535,
                .max_fragments_per_datagram = 8192,
                .timeout_ns = std.math.maxInt(u64),
            });
            const t0 = nowNs();
            var i: usize = 0;
            while (i < n) : (i += 1) {
                _ = r.insert(mk(1, @intCast(i), 1, true), 0) catch break;
            }
            const dt = nowNs() - t0;
            if (dt < best) best = dt;
            r.deinit();
        }
        const pairs = n * n / 2;
        std.debug.print("  {d:>6} {d:>12} {d:>12} {d:>14} {d:>12.3}\n", .{
            n, n * 9, best, best / n, @as(f64, @floatFromInt(best)) / @as(f64, @floatFromInt(pairs)),
        });
    }

    // ── E3c (F9): the same on a REAL split ──────────────────────────────────
    std.debug.print("\n=== E3c (F9): 60000B frame split n ways, arena allocator ===\n", .{});
    std.debug.print("  {s:>6} {s:>12} {s:>14}\n", .{ "n", "best_ns", "ns/fragment" });
    const frame_len: u16 = 60000;
    for ([_]u16{ 64, 256, 1024, 2048, 4096 }) |n| {
        const chunk: u16 = frame_len / n;
        var best: u64 = std.math.maxInt(u64);
        var rep: usize = 0;
        while (rep < 7) : (rep += 1) {
            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const gpa = arena.allocator();
            var r = ef.Reassembler.init(gpa, .{
                .max_inflight = 2,
                .max_frame_len = 65535,
                .max_fragments_per_datagram = 8192,
                .timeout_ns = std.math.maxInt(u64),
            });
            const t0 = nowNs();
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
            const dt = nowNs() - t0;
            if (dt < best) best = dt;
            r.deinit();
        }
        std.debug.print("  {d:>6} {d:>12} {d:>14}\n", .{ n, best, best / n });
    }
}
