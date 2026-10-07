// SPDX-License-Identifier: MIT

//! count — instruction-count cases for `scripts/count-insns` (pilot). Off by
//! default: the test returns `SkipZigTest` unless `ZIGLIBS_COUNT` names a case
//! and a round count, `<case>=<rounds>`. The script runs the filtered test
//! binary under cachegrind and holds the cost per round to
//! `tools/count.tsv`.
//!
//! A case does the same work every round, from an input that is not a
//! compile-time constant, so the count per round is the code's own.

const std = @import("std");
const root = @import("root.zig");

test "count (opt-in via ZIGLIBS_COUNT)" {
    const spec = std.testing.environ.getPosix("ZIGLIBS_COUNT") orelse return error.SkipZigTest;
    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.BadCountSpec;
    const case = spec[0..eq];
    const rounds = try std.fmt.parseInt(u32, spec[eq + 1 ..], 10);

    var input: [1024]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    if (std.mem.eql(u8, case, "sha256-1KiB")) {
        for (0..rounds) |_| {
            std.mem.doNotOptimizeAway(&input);
            var out: [root.Sha256.digest_length]u8 = undefined;
            root.Sha256.hash(&input, &out, .{});
            std.mem.doNotOptimizeAway(&out);
        }
    } else if (std.mem.eql(u8, case, "sha512-1KiB")) {
        for (0..rounds) |_| {
            std.mem.doNotOptimizeAway(&input);
            var out: [root.Sha512.digest_length]u8 = undefined;
            root.Sha512.hash(&input, &out, .{});
            std.mem.doNotOptimizeAway(&out);
        }
    } else return error.UnknownCountCase;
}
