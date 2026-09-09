// SPDX-License-Identifier: MIT
//! Demonstrates `std.testing.Smith`'s ranged-draw semantics against plain
//! ASCII bytes vs. bytes crafted as in-range little-endian `u64` words —
//! the fact `SPEC.md`'s "What the fuzz harnesses actually ran, before and
//! after" section cites (a `Smith` ranged draw returns the range's MINIMUM
//! unless the input already lands inside the range; `Smith.bytes` alone
//! copies faithfully). Not diskfree-specific — it imports only `std`, and
//! exists to make that property visible without re-deriving it by hand.
//! `zig run` needs no module dependency: `zig run modules/diskfree/tools/smith-semantics.zig`.
//!
//! Per `CONVENTIONS.md` §9, moved here 2026-09-10 (A1 fixer campaign,
//! `diskfree`) from `20260901-zig-libs-audit/evidence/diskfree-oracle/`,
//! where the 2026-09-03 audit that used it had left it. Since this
//! demonstrates a `testkit`/`std.testing.Smith` property rather than
//! anything `diskfree`-specific, a future session may find it belongs
//! better in `modules/testkit/tools/` or `scripts/` (CONVENTIONS.md §9's
//! "instrument that serves several modules" case) — left here for now
//! because that is where the audit that built it filed it, and this move
//! only relocates it out of the audit directory, it does not re-triage it.

const std = @import("std");
pub fn main() !void {
    // 1. ASCII corpus bytes, exactly what `.corpus = &.{@embedFile(...)}` supplies.
    const ascii = "/dev/sda1 /mnt/x ext4 rw 0 0\n/dev/sdb1 /mnt/y ext4 rw 0 0\n";
    var s1: std.testing.Smith = .{ .in = ascii };
    std.debug.print("ASCII corpus:  pick(0..1)={d} branch(0..4)={d} len(0..2048)={d} value(u8)={d} index(165)={d}\n", .{
        s1.valueRangeAtMost(u8, 0, 1),     s1.valueRangeAtMost(u8, 0, 4),
        s1.valueRangeAtMost(u16, 0, 2048), s1.value(u8),
        s1.index(165),
    });
    // 2. Bytes crafted as little-endian u64 words that DO land in range.
    var crafted: [40]u8 = @splat(0);
    std.mem.writeInt(u64, crafted[0..8], 1, .little);
    std.mem.writeInt(u64, crafted[8..16], 3, .little);
    std.mem.writeInt(u64, crafted[16..24], 900, .little);
    std.mem.writeInt(u64, crafted[24..32], 200, .little);
    std.mem.writeInt(u64, crafted[32..40], 77, .little);
    var s2: std.testing.Smith = .{ .in = &crafted };
    std.debug.print("crafted u64s:  pick(0..1)={d} branch(0..4)={d} len(0..2048)={d} value(u8)={d} index(165)={d}\n", .{
        s2.valueRangeAtMost(u8, 0, 1),     s2.valueRangeAtMost(u8, 0, 4),
        s2.valueRangeAtMost(u16, 0, 2048), s2.value(u8),
        s2.index(165),
    });
    // 3. Smith.bytes, by contrast, copies the input faithfully.
    var s3: std.testing.Smith = .{ .in = ascii };
    var out: [16]u8 = undefined;
    s3.bytes(&out);
    std.debug.print("bytes() copy:  [{s}]\n", .{out});
}
