// SPDX-License-Identifier: MIT

//! OFFLINE anchor: libpsl's answers (the Public Suffix List C library, MIT,
//! via `tools/psl_oracle.py`) over our own made-up list `psl_mini.dat` --
//! every rule kind, an IDN rule, a wildcard with an exception -- replayed
//! against `psl.zig`. Only libpsl's observable answers were recorded; no
//! libpsl source was read. The full system list is compared live by
//! `zig build interop-cookies`.

const std = @import("std");
const testing = std.testing;
const psl = @import("psl.zig");
const vectors = @import("psl_vectors.zig");

test "libpsl oracle: public suffix and registrable domain over the mini list" {
    var list = try psl.PublicSuffixList.parse(testing.allocator, vectors.list);
    defer list.deinit();
    var bad: usize = 0;
    for (vectors.cases) |c| {
        const ps = list.publicSuffix(c.host);
        const reg = list.registrableDomain(c.host);
        const reg_ok = if (c.registrable) |want| (reg != null and std.mem.eql(u8, reg.?, want)) else reg == null;
        if (std.mem.eql(u8, ps, c.public_suffix) and reg_ok) continue;
        bad += 1;
        std.debug.print("{s}: libpsl {s} / {?s}, ours {s} / {?s}\n", .{ c.host, c.public_suffix, c.registrable, ps, reg });
    }
    try testing.expectEqual(@as(usize, 0), bad);
}
