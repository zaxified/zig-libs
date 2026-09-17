// SPDX-License-Identifier: MIT
//! Differential-oracle producer for `testkit.hex`: exhaustively runs every
//! length-0..3 string over a hostile alphabet (hex digits, ASCII neighbours,
//! NUL, whitespace, high bytes, `+`/`-`/`x`) through the module's PUBLIC API
//! — `testkit.hex.into` and `testkit.hex.alloc`, nothing internal — and
//! prints one TSV line per input for `oracle.py` to grade against a
//! from-scratch strict RFC 4648 decoder and Python's own `bytes.fromhex`.
//!
//! Needs: Zig 0.16.0 (same toolchain as the rest of this repo).
//! Produces: `<input-as-hex>\t<into()-result>\t<alloc()-result>\n` per line,
//! where a result is `OK:<hexbytes>` or `E:<error name>`. ⚠ Written via
//! `std.debug.print`, which is **stderr**, not stdout — redirect `2>`, not `>`.
//!
//! Build and run (see `tools/README.md` for the full recipe and the measured
//! result of the last run):
//!   zig build-exe -OReleaseFast -femit-bin=<scratch>/hexprobe \
//!     --dep testkit -Mroot=modules/testkit/tools/hexprobe.zig \
//!     -Mtestkit=modules/testkit/src/root.zig --cache-dir <scratch>
//!   <scratch>/hexprobe > /dev/null 2> <scratch>/hex-zig.tsv

const std = @import("std");
const hex = @import("testkit").hex;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;

    // Alphabet: the hex digits plus every ASCII neighbour that matters, plus
    // NUL, whitespace, high bytes, and 'x' for the 0x-prefix question.
    const alpha = [_]u8{
        '0', '9', 'a', 'f',  'A',  'F',  'g',  'G',  '`',  '{', '/', ':', '@', 'Z',
        'x', 'X', ' ', '\t', '\n', 0x00, 0x7f, 0x80, 0xff, '+', '-',
    };

    var s: [4]u8 = undefined;
    var len: usize = 0;
    while (len <= 3) : (len += 1) {
        var count: usize = 1;
        var k: usize = 0;
        while (k < len) : (k += 1) count *= alpha.len;
        var idx: usize = 0;
        while (idx < count) : (idx += 1) {
            var rem = idx;
            var j: usize = 0;
            while (j < len) : (j += 1) {
                s[j] = alpha[rem % alpha.len];
                rem /= alpha.len;
            }
            const in = s[0..len];
            try w.print("{x}\t", .{in});

            // into() with a generously-sized buffer
            var buf: [16]u8 = undefined;
            if (hex.into(&buf, in)) |got| {
                try w.print("OK:{x}\t", .{got});
            } else |e| {
                try w.print("E:{t}\t", .{e});
            }
            // alloc()
            if (hex.alloc(gpa, in)) |got| {
                defer gpa.free(got);
                try w.print("OK:{x}\n", .{got});
            } else |e| {
                try w.print("E:{t}\n", .{e});
            }
        }
    }
    var rest: []const u8 = aw.written();
    while (rest.len > 0) {
        const n = @min(rest.len, 4096);
        std.debug.print("{s}", .{rest[0..n]});
        rest = rest[n..];
    }
}
