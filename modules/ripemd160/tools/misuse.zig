// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: two questions, neither pinned by any test in `src/`.
//
//  1. The EXHAUSTIVE streaming split differential — every length 0..600 at
//     every single split point, every length 0..260 at every ordered PAIR of
//     split points (empty chunks included), and a fixed chunk size 1..200 over
//     4 KiB. That is ~3.18 million comparisons. The module's fuzz target walks
//     splits the input picks; this walks ALL of them.
//
//  2. What the module DOES when the caller gets it wrong. Audit finding F5
//     (`final` is destructive; a second `final`, an `update` after `final`, or
//     reuse without `init` returns a silently WRONG digest) was closed as
//     DOCUMENTATION, not code — deliberately, to keep the `std.crypto.hash`
//     shape. So nothing executable records that behaviour. This does.
//
// ⚠ Nothing here is a supported use of the module. The point is to record the
// behaviour, not to bless it.
//
// ⚠ Section 7 uses a CONSTRUCTED state, not a fed one: `total_len` is written
// directly, because no machine can feed 2^61 bytes. Read it as "what the field
// does", never as "what was measured end to end".
//
// WHAT IT NEEDS: the live module. Build it in ReleaseSafe too — section 7 asks
// whether anything traps.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep ripemd160 \
//       -Mmain=misuse.zig -Mripemd160=../src/root.zig \
//       --cache-dir <scratch>/zc-misuse -femit-bin=<scratch>/misuse

const std = @import("std");
const rmd = @import("ripemd160");
const out = @import("out.zig");
const R160 = rmd.Ripemd160;

fn hex(d: [20]u8) [40]u8 {
    return std.fmt.bytesToHex(d, .lower);
}

pub fn main() !void {
    var msg: [4096]u8 = undefined;
    for (&msg, 0..) |*b, i| b.* = @intCast((i * 7 + 13) % 256);

    // ── 1. exhaustive streaming split differential ───────────────────────
    var bad2: usize = 0;
    var cmp2: usize = 0;
    for (0..601) |n| {
        var one: [20]u8 = undefined;
        R160.hash(msg[0..n], &one, .{});
        for (0..n + 1) |s| {
            var d = R160.init(.{});
            d.update(msg[0..s]);
            d.update(msg[s..n]);
            var got: [20]u8 = undefined;
            d.final(&got);
            cmp2 += 1;
            if (!std.mem.eql(u8, &one, &got)) bad2 += 1;
        }
    }
    out.print("2-way splits: {d} comparisons, {d} mismatches\n", .{ cmp2, bad2 });

    var bad3: usize = 0;
    var cmp3: usize = 0;
    for (0..261) |n| {
        var one: [20]u8 = undefined;
        R160.hash(msg[0..n], &one, .{});
        for (0..n + 1) |s| for (s..n + 1) |t| {
            var d = R160.init(.{});
            d.update(msg[0..s]);
            d.update(msg[s..t]);
            d.update(msg[t..n]);
            var got: [20]u8 = undefined;
            d.final(&got);
            cmp3 += 1;
            if (!std.mem.eql(u8, &one, &got)) bad3 += 1;
        };
    }
    out.print("3-way splits: {d} comparisons, {d} mismatches\n", .{ cmp3, bad3 });

    var badk: usize = 0;
    var one_big: [20]u8 = undefined;
    R160.hash(&msg, &one_big, .{});
    for (1..201) |k| {
        var d = R160.init(.{});
        var off: usize = 0;
        while (off < msg.len) {
            const n = @min(k, msg.len - off);
            d.update(msg[off..][0..n]);
            off += n;
        }
        var got: [20]u8 = undefined;
        d.final(&got);
        if (!std.mem.eql(u8, &one_big, &got)) badk += 1;
    }
    out.print("fixed chunk 1..200 over 4096B: 200 comparisons, {d} mismatches\n", .{badk});

    // ── 2. final() called twice (audit F5) ───────────────────────────────
    {
        var d = R160.init(.{});
        d.update("abc");
        var a: [20]u8 = undefined;
        var b: [20]u8 = undefined;
        d.final(&a);
        d.final(&b);
        out.print("final() 1st          : {s}\n", .{hex(a)});
        out.print("final() 2nd          : {s}  same={}\n", .{ hex(b), std.mem.eql(u8, &a, &b) });
    }

    // ── 3. update() after final() ────────────────────────────────────────
    {
        var d = R160.init(.{});
        d.update("abc");
        var a: [20]u8 = undefined;
        d.final(&a);
        d.update("def");
        var b: [20]u8 = undefined;
        d.final(&b);
        var want: [20]u8 = undefined;
        R160.hash("abcdef", &want, .{});
        out.print("update-after-final   : {s}\n", .{hex(b)});
        out.print("hash(\"abcdef\")       : {s}  same={}\n", .{ hex(want), std.mem.eql(u8, &b, &want) });
    }

    // ── 4. reusing a hasher for a second message without re-init ─────────
    {
        var d = R160.init(.{});
        d.update("abc");
        var a: [20]u8 = undefined;
        d.final(&a);
        d.update("abc"); // caller forgets `d = R160.init(.{})`
        var b: [20]u8 = undefined;
        d.final(&b);
        out.print("reuse without init   : {s}  equals-fresh={}\n", .{ hex(b), std.mem.eql(u8, &a, &b) });
    }

    // ── 5. out buffer aliasing the input slice ───────────────────────────
    {
        var buf: [64]u8 = undefined;
        for (&buf, 0..) |*b, i| b.* = @intCast(i);
        var ref: [20]u8 = undefined;
        R160.hash(&buf, &ref, .{});
        var buf2: [64]u8 = undefined;
        for (&buf2, 0..) |*b, i| b.* = @intCast(i);
        R160.hash(&buf2, buf2[10..30], .{}); // out aliases the input
        out.print("aliased out (one-shot): same={}\n", .{std.mem.eql(u8, &ref, buf2[10..30])});

        var buf3: [64]u8 = undefined;
        for (&buf3, 0..) |*b, i| b.* = @intCast(i);
        var d = R160.init(.{});
        d.update(&buf3);
        d.final(buf3[0..20]);
        out.print("aliased out (stream)  : same={}\n", .{std.mem.eql(u8, &ref, buf3[0..20])});
    }

    // ── 6. zero-length update in every position ──────────────────────────
    {
        var d = R160.init(.{});
        for (0..1000) |_| d.update("");
        d.update("abc");
        for (0..1000) |_| d.update("");
        var a: [20]u8 = undefined;
        d.final(&a);
        out.print("2000 empty updates    : {s}\n", .{hex(a)});
    }

    // ── 7. bit-length counter: CONSTRUCTED state, not a fed one ──────────
    {
        var a: [20]u8 = undefined;
        var b: [20]u8 = undefined;
        var c: [20]u8 = undefined;

        var d1 = R160.init(.{});
        d1.update("abc");
        d1.total_len = 3;
        d1.final(&a);

        var d2 = R160.init(.{});
        d2.update("abc");
        d2.total_len = 3 + (1 << 61); // +2^64 bits => wraps to the same field
        d2.final(&b);

        var d3 = R160.init(.{});
        d3.update("abc");
        d3.total_len = (1 << 61); // bit length wraps to exactly 0
        d3.final(&c);

        out.print("len-field  3 bytes    : {s}\n", .{hex(a)});
        out.print("len-field  3+2^61     : {s}  same-as-3={}\n", .{ hex(b), std.mem.eql(u8, &a, &b) });
        out.print("len-field  2^61 (->0) : {s}\n", .{hex(c)});

        var d4 = R160.init(.{});
        d4.update("abc");
        d4.total_len = std.math.maxInt(u64);
        var e: [20]u8 = undefined;
        d4.final(&e);
        out.print("len-field  u64 max    : {s} (no trap)\n", .{hex(e)});
    }

    out.flush();
}
