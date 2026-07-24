//! readthrough — a backend-agnostic read-through cache coordinator:
//! serve-from-cache, or on a miss coalesce concurrent fetches (single-flight),
//! store with TTL, and invalidate explicitly. The read-path counterpart to
//! `writebehind`.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .threadsafe,
    .model_after = "prest read-through cache; Go singleflight; Caffeine loading cache",
    .deps = .{"ramcache"},
};

test "smoke" {
    try std.testing.expect(true);
}
