// SPDX-License-Identifier: MIT
//
// WHY THIS EXISTS: `sweep` and `bigsweep` hash data they generate themselves.
// This hashes data somebody ELSE chose — any file on disk — so the module can
// be held against `openssl dgst -rmd160 <file>` on real bytes rather than on a
// family its own instrument invented.
//
// ⚠ It was found only in `.zig-cache/audit-ripemd160`, not in the audit's
// repro stash. Had the migration trusted the stash alone, it would have been
// deleted with the cache.
//
// WHAT IT NEEDS: the live module. Files up to 24 MiB each (fixed buffer).
//
// WHAT IT PRODUCES: one line per argv file:
//     <one-shot-hex> <streamed-hex> <hash160-hex> <len> <path>
// A difference between columns 1 and 2 is an internal streaming defect.
//
// Build (⚠ against the LIVE module, never a copy):
//   zig build-exe -O ReleaseFast --dep ripemd160 \
//       -Mmain=filehash.zig -Mripemd160=../src/root.zig \
//       --cache-dir <scratch>/zc-filehash -femit-bin=<scratch>/filehash

const std = @import("std");
const rmd = @import("ripemd160");
const out = @import("out.zig");
const linux = std.os.linux;

var data: [24 << 20]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    var prng = std.Random.DefaultPrng.init(0xA1A1A1);
    const rnd = prng.random();

    // ⚠ 0.16 removed `std.os.argv`. `iterate` (not `iterateAllocator`) walks the
    // vector without an allocator, which is the whole point here: this harness
    // must allocate nothing, or it cannot be paired with the module's own
    // no-allocation claim.
    var it = init.minimal.args.iterate();
    _ = it.next(); // exe name

    while (it.next()) |path| {
        const fd: i32 = @intCast(linux.open(path, .{ .ACCMODE = .RDONLY }, 0));
        if (fd < 0) {
            out.print("OPEN FAILED {s}\n", .{path});
            continue;
        }
        var len: usize = 0;
        while (true) {
            const r = linux.read(fd, data[len..].ptr, data.len - len);
            if (r == 0) break;
            len += r;
        }
        _ = linux.close(fd);
        const msg = data[0..len];

        var a: [20]u8 = undefined;
        rmd.Ripemd160.hash(msg, &a, .{});

        var d = rmd.Ripemd160.init(.{});
        var off: usize = 0;
        while (off < msg.len) {
            const n = @min(rnd.intRangeAtMost(usize, 1, 200_000), msg.len - off);
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
