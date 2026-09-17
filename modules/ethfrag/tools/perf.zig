// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: three measurements behind three audit findings, none of
// which any test makes, because none is a pass/fail property.
//
//   E1 -> F5  wire bytes bought vs bytes HELD, on the config README suggests
//   E2 -> F4  the SPEC's "an attacker cannot grow it past
//             max_inflight * max_frame_len" claim, tested rather than read
//   E3 -> F9  is insertion accidentally quadratic in the fragment count?
//
// ⚠ PEAK LIVE BYTES, NOT A CUMULATIVE TOTAL (see `track.zig`). F4 and F5 are
// claims about what is held at once; a cumulative counter answers a different
// question and would make both look far worse than they are.
//
// ⚠ E3 IS A RATIO, NOT A TIME. Absolute ns/fragment belongs to this machine and
// this load; `ns/frag/n` settling to a constant is what says "quadratic", and
// that survives a busy machine. The audit was explicit that its absolute
// numbers were taken under three concurrent agents.
//
// ⚠ BUILD WITH -OReleaseFast BEFORE THE -M ARGUMENTS. The audit lost a
// measurement to exactly this: `zig build-exe -OReleaseFast` placed AFTER the
// `-M` flags is silently ignored, the binary is Debug, and Debug/ReleaseFast
// then agree to within a per-mille -- which looks like a result and is an
// artefact. Print `builtin.mode` and read it before quoting anything.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -OReleaseFast --dep ethfrag \
//       -Mmain=perf.zig -Methfrag=../src/root.zig \
//       --cache-dir <scratch>/zc-perf -femit-bin=<scratch>/perf

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

    // ── E1 (F5): wire bytes -> held bytes, README's own suggested config ────
    // README/example: .{ .max_inflight = 64, .timeout_ns = 2 * ns_per_s },
    // i.e. max_frame_len defaults to 65535.
    // ⚠ Since audit F8 the buffer grows lazily from what the FIRST fragment
    // needs instead of being allocated at max_frame_len up front, so the ratio
    // here is expected to be far below the audit's 8227x. Read the number.
    std.debug.print("\n=== E1 (F5): peak LIVE bytes, max_inflight=64, max_frame_len=default(65535) ===\n", .{});
    inline for (.{ @as(u16, 0), @as(u16, 1) }) |flen| {
        var t: Track = .{ .child = base };
        const gpa = t.allocator();
        var r = ef.Reassembler.init(gpa, .{ .max_inflight = 64, .timeout_ns = 2_000_000_000 });
        var wire_in: usize = 0;
        var id: u16 = 0;
        var refused: usize = 0;
        while (id < 64) : (id += 1) {
            const w = mk(id, 0, flen, true);
            wire_in += w.len;
            _ = r.insert(w, 0) catch {
                refused += 1;
            };
        }
        std.debug.print("  first-frag payload={d}B: {d} datagrams, refused={d}, wire_in={d}B, LIVE={d}B, PEAK={d}B, ratio={d}x, allocs={d}\n", .{
            flen,                                     r.inflightCount(), refused, wire_in, t.live, t.peak,
            if (wire_in > 0) t.peak / wire_in else 0, t.n_alloc,
        });
        r.deinit();
        std.debug.print("    after deinit: live={d}B (leak check)\n", .{t.live});
    }

    // ── E2 (F4): does the documented bound actually bound? ──────────────────
    std.debug.print("\n=== E2 (F4): SPEC claim \"an attacker cannot grow it past max_inflight * max_frame_len\" ===\n", .{});
    {
        const max_inflight: usize = 8;
        const mfl: usize = 65535;
        const max_frags: usize = 4096;
        var t: Track = .{ .child = base };
        const gpa = t.allocator();
        var r = ef.Reassembler.init(gpa, .{
            .max_inflight = max_inflight,
            .max_frame_len = mfl,
            .max_fragments_per_datagram = max_frags,
            .timeout_ns = std.math.maxInt(u64),
        });
        defer r.deinit();
        var wire_in: usize = 0;
        var id: u16 = 0;
        var first_err: []const u8 = "none";
        while (id < max_inflight) : (id += 1) {
            var k: usize = 0;
            // Interval-list growth with no payload: the term the documented
            // formula leaves out. ⚠ Since audit F1 a `more=true` zero-length
            // fragment is refused outright (EmptyNonFinalFragment), so this
            // now uses a 1-byte payload at a fresh offset each time -- same
            // shape, still attacker-chosen, still no completion.
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
        std.debug.print("  wire_in={d}B  LIVE={d}B  PEAK={d}B  first_err={s}\n", .{ wire_in, t.live, t.peak, first_err });
        std.debug.print("  documented bound (max_inflight*max_frame_len) = {d}B\n", .{documented});
        std.debug.print("  peak / documented = {d}.{d:0>2}x   overshoot = {d}B\n", .{
            t.peak / documented,                                 (t.peak * 100 / documented) % 100,
            if (t.peak > documented) t.peak - documented else 0,
        });
        // ⚠ Float, not integer division: this ratio can legitimately be BELOW
        // one (it is, now that F8 grows the buffer lazily), and `{d}` on a
        // usize quotient prints that as a flat `0x` -- a number that reads
        // like "no memory held" when it means "less held than sent".
        if (wire_in > 0) std.debug.print("  wire->held ratio = {d:.2}x\n", .{
            @as(f64, @floatFromInt(t.peak)) / @as(f64, @floatFromInt(wire_in)),
        });
    }

    // ── E3 (F9): accidentally quadratic? fixed 60000-byte frame, varying n ──
    std.debug.print("\n=== E3 (F9): reassembly of a 60000B frame vs fragment count (per-insert overlap scan) ===\n", .{});
    std.debug.print("  {s:>6} {s:>10} {s:>12} {s:>12} {s:>10}\n", .{ "n", "payload", "total_ns", "ns/frag", "ns/frag/n" });
    const frame_len: u16 = 60000;
    for ([_]u16{ 32, 64, 128, 256, 512, 1024, 2048, 4096 }) |n| {
        const chunk: u16 = frame_len / n;
        var best: u64 = std.math.maxInt(u64);
        var rep: usize = 0;
        while (rep < 5) : (rep += 1) {
            var r = ef.Reassembler.init(base, .{
                .max_inflight = 4,
                .max_frame_len = 65535,
                .max_fragments_per_datagram = 4096,
                .timeout_ns = std.math.maxInt(u64),
            });
            defer r.deinit();
            const t0 = nowNs();
            var i: u16 = 0;
            while (i < n) : (i += 1) {
                const off: u16 = i * chunk;
                const last = (i + 1 == n);
                const len: u16 = if (last) frame_len - off else chunk;
                const res = try r.insert(mk(1, off, len, !last), 0);
                switch (res) {
                    .complete => |b| base.free(b),
                    .incomplete => {},
                }
            }
            const dt = nowNs() - t0;
            if (dt < best) best = dt;
        }
        std.debug.print("  {d:>6} {d:>10} {d:>12} {d:>12} {d:>10}\n", .{
            n, chunk, best, best / n, best / n / n,
        });
    }
}
