// SPDX-License-Identifier: MIT

//! count — instruction-count cases for `scripts/count-insns` (pilot). Off by
//! default: the test returns `SkipZigTest` unless `ZIGLIBS_COUNT` names a case
//! and a round count, `<case>=<rounds>`. The script runs the filtered test
//! binary under cachegrind and holds the cost per round to
//! `tools/count.tsv`.

const std = @import("std");
const root = @import("root.zig");

test "count (opt-in via ZIGLIBS_COUNT)" {
    const spec = std.testing.environ.getPosix("ZIGLIBS_COUNT") orelse return error.SkipZigTest;
    const eq = std.mem.indexOfScalar(u8, spec, '=') orelse return error.BadCountSpec;
    const case = spec[0..eq];
    const rounds = try std.fmt.parseInt(u32, spec[eq + 1 ..], 10);

    var input: [4096]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    if (std.mem.eql(u8, case, "crc32c-4KiB")) {
        for (0..rounds) |_| {
            std.mem.doNotOptimizeAway(&input);
            std.mem.doNotOptimizeAway(root.hash(&input));
        }
    } else return error.UnknownCountCase;
}
