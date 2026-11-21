// SPDX-License-Identifier: MIT
//! Size probe for the `small` lane (CONVENTIONS §4.2): compiles and runs a
//! pattern from the command line in both grammars, the shape of a consumer
//! that takes user patterns. Built at ReleaseSmall under `-Dprofile=default`
//! and `-Dprofile=small` by `scripts/checks/small-sizes.sh`; the difference is
//! the Unicode property tables (`-Dregex-unicode`), held to its floor in
//! `scripts/checks/small-size-expected.tsv`.
const std = @import("std");
const regex = @import("regex");

pub fn main(init: std.process.Init) !void {
    var args = init.minimal.args.iterate();
    _ = args.next();
    const pattern = args.next() orelse return error.Usage;
    const text = args.next() orelse return error.Usage;
    inline for (.{ regex.Syntax.perl, regex.Syntax.rust }) |syntax| {
        var re = try regex.Regex.compileOptions(init.gpa, pattern, .{ .syntax = syntax });
        defer re.deinit(init.gpa);
        std.mem.doNotOptimizeAway(re.isMatch(text));
    }
}
