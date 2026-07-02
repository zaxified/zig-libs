//! <capability> — one-line description of what this module provides.
//!
//! Copy this folder to modules/<name>/ and register it in build.zig.
//! See ../../CONVENTIONS.md for the `meta` tag vocabulary.

const std = @import("std");

pub const meta = .{
    .status = .gap, // .extract | .gap | .adopt
    .platform = .any, // .any | .posix | .linux
    .role = .util, // .client | .server | .codec | .both | .util
    .concurrency = .reentrant, // .reentrant | .threadsafe | .single_owner | .blocking
    .model_after = "<reference impl in another language>",
    .deps = .{}, // sibling modules / std this builds on
};

// ── public API ──────────────────────────────────────────────────────────────

// TODO: implement.

test "smoke" {
    try std.testing.expect(true);
}
