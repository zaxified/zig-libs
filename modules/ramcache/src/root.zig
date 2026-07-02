//! ramcache — bounded in-memory cache with two independent freshness axes:
//! TTL (wall-time) + generation (logical invalidation, lazy drop, no sweep).
//!
//! STUB. Real implementation to be extracted from poc-wf-analytic `src/cache.zig`
//! (byte-cap + entry-cap, expired-then-LRU eviction, ~ns hits; caller supplies
//! clock + generation counter → zero global/time dependency, headless-testable).

const std = @import("std");

pub const meta = .{
    .status = .extract, // seeded in poc-wf-analytic/src/cache.zig (done, pure-std, tested)
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner, // one thread/loop owns it, lock-free (like the poc Bus)
    .model_after = "groupcache / ristretto semantics; generation-tie is the novel bit",
    .deps = .{}, // std only
};

// ── public API (stub) ─────────────────────────────────────────────────────────

/// Returns true if an entry stamped at `stored_ns` is still fresh at `now_ns`
/// under a `ttl_ns` window. Placeholder for the real Cache type.
pub fn isFresh(now_ns: i128, stored_ns: i128, ttl_ns: i128) bool {
    return now_ns - stored_ns < ttl_ns;
}

test "isFresh window" {
    try std.testing.expect(isFresh(1_000, 500, 1_000));
    try std.testing.expect(!isFresh(2_000, 500, 1_000));
}
