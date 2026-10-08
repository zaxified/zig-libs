// SPDX-License-Identifier: MIT

//! count — instruction-count cases for `scripts/count-insns`. Off by
//! default: the test returns `SkipZigTest` unless `ZIGLIBS_COUNT` names a case
//! and a round count, `<case>=<rounds>`. The script runs the filtered test
//! binary under cachegrind and holds the cost per round to
//! `tools/count.tsv`.
//!
//! One case per AEAD path: 64 B goes to std (`Path.std_delegated`), 1 KiB and
//! 16 KiB to the wide engine. A case does the same work every round, from an
//! input that is not a compile-time constant.

const std = @import("std");
const root = @import("root.zig");

test "count (opt-in via ZIGLIBS_COUNT)" {
    const spec = std.testing.environ.getPosix("ZIGLIBS_COUNT") orelse return error.SkipZigTest;
    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.BadCountSpec;
    const case = spec[0..eq];
    const rounds = try std.fmt.parseInt(u32, spec[eq + 1 ..], 10);

    const size: usize = if (std.mem.eql(u8, case, "aead-seal-64B"))
        64
    else if (std.mem.eql(u8, case, "aead-seal-1KiB"))
        1024
    else if (std.mem.eql(u8, case, "aead-seal-16KiB"))
        16384
    else
        return error.UnknownCountCase;

    var m: [16384]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    var c: [16384]u8 = undefined;
    var tag: [root.ChaCha20Poly1305.tag_length]u8 = undefined;
    var key: [root.ChaCha20Poly1305.key_length]u8 = @splat(0x42);
    var nonce: [root.ChaCha20Poly1305.nonce_length]u8 = @splat(0x24);
    std.mem.doNotOptimizeAway(&key);
    std.mem.doNotOptimizeAway(&nonce);
    for (0..rounds) |_| {
        std.mem.doNotOptimizeAway(&m);
        root.ChaCha20Poly1305.encrypt(c[0..size], &tag, m[0..size], "ad", nonce, key);
        std.mem.doNotOptimizeAway(&c);
        std.mem.doNotOptimizeAway(&tag);
    }
}
