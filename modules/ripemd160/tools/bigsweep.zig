// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: the module's largest KAT is the million-'a' vector. This
// takes the hash into the tens of megabytes and, at every size, compares the
// ONE-SHOT path against the STREAMING path fed in pseudo-random chunks — a
// differential the suite performs only at small sizes.
//
// WHAT IT NEEDS: the live module, and ~16 MiB of writable space next to the
// binary for the blobs it emits (so `openssl`/`hashlib` can read them back).
// ⚠ Put the scratch under `.zig-cache/`, never `/tmp` — 16 MiB blobs in tmpfs
// are RAM.
//
// WHAT IT PRODUCES: one line per size:
//     <one-shot-hex> <streamed-hex> <hash160-hex> <len> <file>
// Column 1 vs 2 is the internal differential; columns 1 and 3 go to the
// external oracles.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep ripemd160 \
//       -Mmain=bigsweep.zig -Mripemd160=../src/root.zig \
//       --cache-dir <scratch>/zc-bigsweep -femit-bin=<scratch>/bigsweep

const std = @import("std");
const rmd = @import("ripemd160");
const out = @import("out.zig");
const linux = std.os.linux;

var data: [16 << 20]u8 = undefined;

var lcg: u64 = 0x2545F4914F6CDD1D;
fn nextByte() u8 {
    lcg = lcg *% 6364136223846793005 +% 1442695040888963407;
    return @truncate(lcg >> 33);
}
fn nextU64() u64 {
    lcg = lcg *% 6364136223846793005 +% 1442695040888963407;
    return lcg >> 11;
}

// Sizes: mixed multi-MB, plus exact block multiples and their neighbours,
// plus the 55/56/57-style padding-spill offsets scaled up.
const sizes = [_]usize{
    1 << 20,        (1 << 20) - 1,  (1 << 20) + 1,
    (1 << 20) + 55, (1 << 20) + 56, (1 << 20) + 57,
    3_000_000,      5_242_880,      7_654_321,
    9_999_999,      12_345_678,     16 << 20,
};

pub fn main() !void {
    for (sizes, 0..) |len, i| {
        for (data[0..len]) |*b| b.* = nextByte();
        const msg = data[0..len];

        var name: [32]u8 = undefined;
        const path = std.fmt.bufPrintZ(&name, "blob_{d:0>2}.bin", .{i}) catch unreachable;
        const fd: i32 = @intCast(linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644));
        var w: usize = 0;
        while (w < len) w += linux.write(fd, msg[w..].ptr, len - w);
        _ = linux.close(fd);

        var a: [20]u8 = undefined;
        rmd.Ripemd160.hash(msg, &a, .{});

        var d = rmd.Ripemd160.init(.{});
        var off: usize = 0;
        while (off < msg.len) {
            const n = @min(1 + (nextU64() % 200_000), msg.len - off);
            d.update(msg[off..][0..n]);
            off += n;
        }
        var b: [20]u8 = undefined;
        d.final(&b);

        var c: [20]u8 = undefined;
        rmd.hash160(msg, &c);

        out.print("{x} {x} {x} {d} {s}\n", .{ &a, &b, &c, len, path });
    }
    out.flush();
}
