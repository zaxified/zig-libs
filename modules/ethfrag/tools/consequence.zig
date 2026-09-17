// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: a mutation table says "the suite noticed" or "it did not".
// This says what the attacker GETS when it did not — which is the difference
// between a missing test and a memory-disclosure bug, and it is the reason
// audit F3 was rated HIGH rather than "some guards lack tests".
//
// Five scenarios, each targeting one mutation that survived the audit's suite:
//
//   C1 -> M1   a ONE-byte overlap slipping through
//   C2 -> M8   overlap compared only against the LAST accepted interval
//   C3 -> M6   retroactive bounds check weakened by one
//   C4 -> M2b  max_frame_len ceiling moved by one
//   C5 -> M12  trailing wire bytes beyond the header's declared length
//
// ⚠ ALL FIVE ARE NOW PINNED BY NAMED TESTS (`F3/M1-shape`, `F3/M8-shape`,
// `F3/M6-shape`, `F3/M2b-shape`, `F14`), so run against the live module every
// scenario should be refused. That is not a reason to delete this: the tests
// assert the mutation is CAUGHT, and this shows what a future regression would
// hand a caller. Run it against a mutant copy (see `mutate.py`) and the rows
// turn into 50 bytes of `0xAA`, a rewritten frame prefix, or a panic.
//
// POISON DETECTION: the reassembly buffer is never zeroed, so a byte the
// attacker never sent that comes back as `0xAA` (`DebugAllocator`'s undefined
// pattern) is uninitialised heap delivered to the caller. `rewritten` catches
// the other half: a later fragment silently overwriting bytes an earlier one
// already claimed — fragment-overlap IDS evasion.
//
// ⚠ Needs `DebugAllocator` specifically. Another allocator fills with different
// bytes and the poison column silently means nothing.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe --dep ethfrag -Mmain=consequence.zig -Methfrag=../src/root.zig \
//       --cache-dir <scratch>/zc-consequence -femit-bin=<scratch>/consequence

const std = @import("std");
const ef = @import("ethfrag");

var wire: [70016]u8 = undefined;

fn mk(id: u16, off: u16, len: u16, more: bool, fill: u8) []u8 {
    std.mem.writeInt(u16, wire[0..2], id, .big);
    std.mem.writeInt(u16, wire[2..4], off, .big);
    std.mem.writeInt(u16, wire[4..6], len, .big);
    wire[6] = if (more) 1 else 0;
    wire[7] = 0;
    @memset(wire[8 .. 8 + @as(usize, len)], fill);
    return wire[0 .. 8 + @as(usize, len)];
}

const F = struct { off: u16, len: u16, more: bool, fill: u8 };

fn scenario(gpa: std.mem.Allocator, name: []const u8, mfl: usize, frags: []const F) !void {
    var r = ef.Reassembler.init(gpa, .{
        .max_inflight = 4,
        .max_frame_len = mfl,
        .max_fragments_per_datagram = 4096,
        .timeout_ns = std.math.maxInt(u64),
    });
    defer r.deinit();
    var verdict: []const u8 = "incomplete";
    var poison: usize = 0;
    var rewritten: bool = false;
    var out_len: usize = 0;
    for (frags) |f| {
        const res = r.insert(mk(9, f.off, f.len, f.more, f.fill), 0) catch |e| {
            verdict = @errorName(e);
            break;
        };
        switch (res) {
            .incomplete => {},
            .complete => |b| {
                defer gpa.free(b);
                verdict = "COMPLETE";
                out_len = b.len;
                for (b) |x| if (x == 0xAA) {
                    poison += 1;
                };
                // Byte 0 rewritten by a later fragment than the one that first
                // claimed it? (scenarios use 'A' first, 'Z' as the rewrite.)
                if (b.len > 0 and b[0] == 'Z') rewritten = true;
            },
        }
    }
    std.debug.print("  {s:<52} -> {s:<26} len={d:<5} poison={d:<4} rewritten={}\n", .{
        name, verdict, out_len, poison, rewritten,
    });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    std.debug.print("\n--- consequence probes (against the LIVE module: every row should be refused) ---\n", .{});

    // C1 (M1: a ONE-byte overlap). Y=[0,51) overlaps X=[50,100) by exactly one
    // byte, and a final fragment at [101,102) makes covered == total_len while
    // byte 100 was never sent.
    try scenario(gpa, "C1 one-byte overlap + matching one-byte gap", 300, &.{
        .{ .off = 50, .len = 50, .more = true, .fill = 'A' },
        .{ .off = 0, .len = 51, .more = true, .fill = 'Z' },
        .{ .off = 101, .len = 1, .more = false, .fill = 'F' },
    });

    // C2 (M8: overlap compared only against the LAST interval). Z rewrites
    // [0,50) but only [100,150) is checked; the sums still add up while
    // [50,100) is a 50-byte hole.
    try scenario(gpa, "C2 non-adjacent overlap (rewrite [0,50) + 50B hole)", 300, &.{
        .{ .off = 0, .len = 50, .more = true, .fill = 'A' },
        .{ .off = 100, .len = 50, .more = true, .fill = 'B' },
        .{ .off = 0, .len = 50, .more = true, .fill = 'Z' },
        .{ .off = 150, .len = 50, .more = false, .fill = 'C' },
    });

    // C3 (M6: retroactive bounds check weakened by one). E ends one byte past
    // the later-established total_len; its length still counts toward covered,
    // so covered reaches total_len over a one-byte hole.
    try scenario(gpa, "C3 retro-bound off-by-one (1 byte outside the frame)", 300, &.{
        .{ .off = 100, .len = 1, .more = true, .fill = 'E' },
        .{ .off = 0, .len = 29, .more = true, .fill = 'D' },
        .{ .off = 30, .len = 70, .more = false, .fill = 'C' },
    });

    // C4 (M2b: max_frame_len ceiling moved by one) — one byte past the end of
    // the per-datagram buffer.
    try scenario(gpa, "C4 frag_end == max_frame_len + 1", 100, &.{
        .{ .off = 90, .len = 11, .more = false, .fill = 'X' },
    });

    // C5 (M12: trailing wire bytes) — a header claiming 4 payload bytes with 12
    // actually present.
    {
        var r = ef.Reassembler.init(gpa, .{ .max_inflight = 4, .max_frame_len = 300, .timeout_ns = std.math.maxInt(u64) });
        defer r.deinit();
        _ = mk(9, 0, 4, false, 'Q');
        @memset(wire[12..20], 'T'); // 8 unexplained trailing bytes
        const res = r.insert(wire[0..20], 0) catch |e| {
            std.debug.print("  {s:<52} -> {s}\n", .{ "C5 header claims 4B, 12B on the wire", @errorName(e) });
            return;
        };
        switch (res) {
            .incomplete => std.debug.print("  {s:<52} -> incomplete\n", .{"C5 header claims 4B, 12B on the wire"}),
            .complete => |b| {
                defer gpa.free(b);
                std.debug.print("  {s:<52} -> COMPLETE len={d} bytes={s}\n", .{ "C5 header claims 4B, 12B on the wire", b.len, b });
            },
        }
    }
}
