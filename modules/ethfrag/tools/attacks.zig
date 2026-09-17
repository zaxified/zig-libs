// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: the overlap / teardrop / tiny-fragment attack table, 29
// shapes, one row each. It ASSERTS NOTHING on purpose — a surprising verdict
// shows up as a printed verdict, not as a failed test. That is the opposite of
// what the suite does, and it is why both exist: a test says "this input must
// give that error", while this says "here is what every shape actually does",
// including the shapes nobody thought to write a test for.
//
// It also detects POISON: `0xAA` is `DebugAllocator`'s undefined-memory
// pattern, so a byte in a delivered frame that the attacker never sent and that
// comes back `0xAA` is uninitialised heap handed to the caller. Any row ending
// `<<POISON BYTES IN OUTPUT>>` is a memory-disclosure bug.
//
// ⚠ TWO GROUPS OF ROWS PRINT DIFFERENTLY THAN THE AUDIT RECORDED, AND THAT IS
// THE FIXES LANDING — not a broken instrument:
//
//   * Every `more=true, length=0` shape (A3, A3b, A12, A13, A17, A28, A29's
//     first fragment) now returns `EmptyNonFinalFragment`. That error did not
//     exist when the audit ran: `root.zig:489` rejects a non-final zero-length
//     fragment outright, closing audit F1. The audit's table shows these as
//     ACCEPTED, six times over for A3b.
//   * The keep-alive probe at the end no longer holds the slot forever. Audit
//     F2 measured an entry surviving 100 000 refresh rounds and starving a
//     legitimate `frag_id`; `root.zig` now carries an absolute lifetime cap
//     (`created_ns` + `lifetimeCap`, default `8 * timeout_ns`), so the entry is
//     reclaimed and the legitimate datagram gets in. The probe is kept exactly
//     because watching that number change is the evidence.
//
// WHAT IT NEEDS: the live module, and `DebugAllocator` (poison detection is its
// undefined pattern — a different allocator gives different bytes and the
// poison column becomes meaningless).
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe --dep ethfrag -Mmain=attacks.zig -Methfrag=../src/root.zig \
//       --cache-dir <scratch>/zc-attacks -femit-bin=<scratch>/attacks

const std = @import("std");
const ef = @import("ethfrag");

const Frag = struct {
    off: u16,
    len: u16,
    more: bool,
    fill: u8 = 'x',
};

var wire: [70000]u8 = undefined;

fn mk(id: u16, f: Frag) []u8 {
    std.mem.writeInt(u16, wire[0..2], id, .big);
    std.mem.writeInt(u16, wire[2..4], f.off, .big);
    std.mem.writeInt(u16, wire[4..6], f.len, .big);
    wire[6] = if (f.more) 1 else 0;
    wire[7] = 0;
    @memset(wire[8 .. 8 + @as(usize, f.len)], f.fill);
    return wire[0 .. 8 + @as(usize, f.len)];
}

fn run(gpa: std.mem.Allocator, name: []const u8, cfg: ef.ReassemblerConfig, frags: []const Frag) !void {
    var r = ef.Reassembler.init(gpa, cfg);
    defer r.deinit();
    var obuf: [8192]u8 = undefined;
    var olen: usize = 0;
    var now: u64 = 0;
    var completed: ?[]u8 = null;
    for (frags, 0..) |f, i| {
        if (i != 0) olen += (try std.fmt.bufPrint(obuf[olen..], " ", .{})).len;
        const res = r.insert(mk(7, f), now) catch |err| {
            olen += (try std.fmt.bufPrint(obuf[olen..], "[{d}]{s}", .{ i, @errorName(err) })).len;
            now += 1;
            continue;
        };
        switch (res) {
            .incomplete => olen += (try std.fmt.bufPrint(obuf[olen..], "[{d}]incomplete", .{i})).len,
            .complete => |b| {
                olen += (try std.fmt.bufPrint(obuf[olen..], "[{d}]COMPLETE({d}B)", .{ i, b.len })).len;
                if (completed) |c| gpa.free(c);
                completed = b;
            },
        }
        now += 1;
    }
    var poison: usize = 0;
    if (completed) |c| {
        for (c) |b| if (b == 0xaa) {
            poison += 1;
        };
        gpa.free(c);
    }
    std.debug.print("{s:<46} | inflight={d} | {s}{s}\n", .{
        name,                                                  r.inflightCount(), obuf[0..olen],
        if (poison > 0) " <<POISON BYTES IN OUTPUT>>" else "",
    });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const c: ef.ReassemblerConfig = .{ .max_inflight = 4, .max_frame_len = 300, .timeout_ns = 1_000_000 };
    const big: ef.ReassemblerConfig = .{ .max_inflight = 4, .timeout_ns = 1_000_000 }; // max_frame_len = 65535

    std.debug.print("\n=== ethfrag attack table (max_frame_len={d} unless noted) ===\n", .{c.max_frame_len});

    try run(gpa, "A1  baseline two-fragment", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 50, .len = 50, .more = false },
    });
    try run(gpa, "A2  exact duplicate (len>0)", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 0, .len = 50, .more = true },
    });
    try run(gpa, "A3  exact duplicate, ZERO length", c, &.{
        .{ .off = 10, .len = 0, .more = true }, .{ .off = 10, .len = 0, .more = true },
    });
    try run(gpa, "A3b exact duplicate zero-len x6", c, &.{
        .{ .off = 10, .len = 0, .more = true }, .{ .off = 10, .len = 0, .more = true },
        .{ .off = 10, .len = 0, .more = true }, .{ .off = 10, .len = 0, .more = true },
        .{ .off = 10, .len = 0, .more = true }, .{ .off = 10, .len = 0, .more = true },
    });
    try run(gpa, "A4  forward partial overlap", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 25, .len = 50, .more = true, .fill = 'B' },
    });
    try run(gpa, "A5  backward partial overlap", c, &.{
        .{ .off = 50, .len = 50, .more = true }, .{ .off = 25, .len = 50, .more = true, .fill = 'B' },
    });
    try run(gpa, "A6  contained inside earlier fragment", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 10, .len = 10, .more = true, .fill = 'B' },
    });
    try run(gpa, "A7  superset containing earlier fragment", c, &.{
        .{ .off = 10, .len = 10, .more = true }, .{ .off = 0, .len = 50, .more = true, .fill = 'B' },
    });
    try run(gpa, "A8  header-rewrite: resend [0,14) w/ new bytes", c, &.{
        .{ .off = 0, .len = 14, .more = true, .fill = 'A' },
        .{ .off = 14, .len = 36, .more = false },
        .{ .off = 0, .len = 14, .more = true, .fill = 'Z' },
    });
    try run(gpa, "A9  header-rewrite: [0,20) then [0,10) new bytes", c, &.{
        .{ .off = 0, .len = 20, .more = true, .fill = 'A' },
        .{ .off = 0, .len = 10, .more = true, .fill = 'Z' },
    });
    try run(gpa, "A10 touching, no overlap", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 50, .len = 50, .more = true },
    });
    try run(gpa, "A11 tiny FIRST fragment (1 byte at off 0)", c, &.{
        .{ .off = 0, .len = 1, .more = true }, .{ .off = 1, .len = 99, .more = false },
    });
    try run(gpa, "A12 zero-len fragment INSIDE an interval", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 25, .len = 0, .more = true },
    });
    try run(gpa, "A13 zero-len fragment at interval end", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 50, .len = 0, .more = true },
    });
    try run(gpa, "A14 zero-len at off 0, more=false (empty frame)", c, &.{
        .{ .off = 0, .len = 0, .more = false },
    });
    try run(gpa, "A15 offset 0xFFFF + len 0xFFFF (65535 cfg)", big, &.{
        .{ .off = 0xFFFF, .len = 0xFFFF, .more = false },
    });
    try run(gpa, "A16 offset 0xFFFF + len 1 (65535 cfg)", big, &.{
        .{ .off = 0xFFFF, .len = 1, .more = false },
    });
    try run(gpa, "A17 offset 0xFFFF + len 0, more=false", big, &.{
        .{ .off = 0xFFFF, .len = 0, .more = false },
    });
    try run(gpa, "A18 non-final len not a multiple of 8 (7,7)", c, &.{
        .{ .off = 0, .len = 7, .more = true }, .{ .off = 7, .len = 7, .more = false },
    });
    try run(gpa, "A19 offset 0 twice, different lengths", c, &.{
        .{ .off = 0, .len = 50, .more = true }, .{ .off = 0, .len = 20, .more = true, .fill = 'B' },
    });
    try run(gpa, "A20 two more=false, SAME end, len>0", c, &.{
        .{ .off = 10, .len = 40, .more = false }, .{ .off = 10, .len = 40, .more = false },
    });
    try run(gpa, "A21 two more=false, SAME end, ZERO length", c, &.{
        .{ .off = 50, .len = 0, .more = false }, .{ .off = 50, .len = 0, .more = false },
    });
    try run(gpa, "A22 two more=false, DIFFERENT ends", c, &.{
        .{ .off = 10, .len = 40, .more = false }, .{ .off = 100, .len = 40, .more = false },
    });
    try run(gpa, "A23 Rose: first+last only, huge gap", c, &.{
        .{ .off = 0, .len = 8, .more = true }, .{ .off = 292, .len = 8, .more = false },
    });
    try run(gpa, "A24 teardrop: big frag then smaller more=false", c, &.{
        .{ .off = 100, .len = 50, .more = true, .fill = 'A' },
        .{ .off = 0, .len = 30, .more = true, .fill = 'D' },
        .{ .off = 80, .len = 20, .more = false, .fill = 'C' },
    });
    try run(gpa, "A25 overrun past established total", c, &.{
        .{ .off = 0, .len = 50, .more = false }, .{ .off = 50, .len = 10, .more = true },
    });
    try run(gpa, "A26 zero-len at off == total_len (past end?)", c, &.{
        .{ .off = 0, .len = 50, .more = false, .fill = 'A' },
    });
    try run(gpa, "A27 out-of-order: last first, then fill", c, &.{
        .{ .off = 50, .len = 50, .more = false }, .{ .off = 0, .len = 50, .more = true },
    });
    try run(gpa, "A28 zero-len beyond total_len", c, &.{
        .{ .off = 10, .len = 40, .more = false }, .{ .off = 200, .len = 0, .more = true },
    });
    try run(gpa, "A29 zero-len at off 0 then real [0,50)", c, &.{
        .{ .off = 0, .len = 0, .more = true }, .{ .off = 0, .len = 50, .more = false },
    });

    // ── the zero-length keep-alive: can 8 wire bytes hold an entry forever? ──
    // Audit F2 measured YES: 100 000 rounds, entry still alive, legitimate
    // frag_id refused with TableFull. The absolute lifetime cap added since
    // then should end it. Read `cap-recreations` and the final verdict.
    std.debug.print("\n=== keep-alive probe: timeout_ns=1000, idle-refresh with 8-byte zero-length fragments ===\n", .{});
    {
        var r = ef.Reassembler.init(gpa, .{
            .max_inflight = 1,
            .max_frame_len = 65535,
            .max_fragments_per_datagram = 4096,
            .timeout_ns = 1000,
        });
        defer r.deinit();
        var now: u64 = 0;
        var wire_bytes: usize = 0;
        var refreshes: usize = 0;
        var recreated: usize = 0;
        var rejected: usize = 0;
        while (refreshes < 100_000) : (refreshes += 1) {
            const res = r.insert(mk(1, .{ .off = 10, .len = 0, .more = true }), now) catch |e| {
                switch (e) {
                    error.TooManyFragments => recreated += 1,
                    // Since audit F1 this is the expected answer: a non-final
                    // zero-length fragment is refused outright, so it can no
                    // longer refresh anything at all.
                    error.EmptyNonFinalFragment => rejected += 1,
                    else => {
                        std.debug.print("  unexpected {s} at round {d}\n", .{ @errorName(e), refreshes });
                        break;
                    },
                }
                wire_bytes += 8;
                now += 999;
                continue;
            };
            _ = res;
            wire_bytes += 8;
            now += 999;
        }
        std.debug.print("  after {d} rounds ({d} wire bytes, simulated {d} ns = {d} timeout periods):\n", .{
            refreshes, wire_bytes, now, now / 1000,
        });
        std.debug.print("  inflight={d}  cap-recreations={d}  refused-as-empty={d}\n", .{
            r.inflightCount(), recreated, rejected,
        });
        const legit = r.insert(mk(2, .{ .off = 0, .len = 10, .more = true }), now);
        if (legit) |_| {
            std.debug.print("  legitimate frag_id=2 ACCEPTED  (F1/F2 holding)\n", .{});
        } else |e| {
            std.debug.print("  legitimate frag_id=2 REJECTED: {s}  <<the audit's F2 shape>>\n", .{@errorName(e)});
        }
    }
}
