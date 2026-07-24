//! geoindex — static spatial index for bbox / nearest-neighbour queries over
//! a large, fixed set of geo-points (lat/lon).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "packed Hilbert R-tree (STR); geohash grid",
    .deps = .{},
};

test "smoke" {
    try std.testing.expect(true);
}
