// SPDX-License-Identifier: MIT

//! <capability> — one-line description of what this module provides.
//!
//! Copy this folder to modules/<name>/ and register it in build.zig.
//! See ../../CONVENTIONS.md for the `meta` tag vocabulary, and ../README.md
//! for the full checklist a new module has to satisfy.
//!
//! BEFORE YOU DRAW ANY RANDOMNESS, read `CONVENTIONS.md` §2.2. It is a rule
//! about which call you write, so it is cheaper to read now than to be told at
//! audit time: a draw that BECOMES A SECRET (key, private scalar, nonce/IV,
//! salt, session id) uses `try io.randomSecure(buf)`, or `entropy.fill(io, buf)`
//! where the signature has no error channel — `std.Io.random` is documented to
//! degrade silently to a weaker seed, and no test downstream can see it happen.
//! Everything else (jitter, backoff, tiebreaks, hash seeds, fixtures) uses
//! `io.random` and must not pay for more. §2.2 closes with: "A new module that
//! draws a secret and does neither of the above is a finding."

const std = @import("std");

pub const meta = .{
    .platform = .any, // .any | .posix | .linux
    .role = .util, // .client | .server | .codec | .both | .util
    .concurrency = .reentrant, // .reentrant | .threadsafe | .single_owner | .blocking
    .model_after = "<reference impl in another language>",
    // Sibling modules / std this builds on. If any draw here becomes a secret,
    // `entropy` belongs in this list (CONVENTIONS.md §2.2).
    .deps = .{},
};

// ── public API ──────────────────────────────────────────────────────────────

// TODO: implement.

// ── tests ───────────────────────────────────────────────────────────────────
//
// WHAT A TEST HERE HAS TO DO, because a green suite is not the goal:
//
//   * Assert the VALUE, not the mechanism that produced it. A test written in
//     terms of the constant it is checking (`try expect(x == the_limit)`) stays
//     green when the constant is wrong, and pins the defect instead of catching
//     it.
//   * Feed something that separates this module from its NEIGHBOURS. An input
//     any sibling would also accept anchors nothing.
//   * Prove the test can go red, by breaking the thing it covers on purpose and
//     watching THAT test — not merely some test — fail. If it stays green, the
//     coverage is not there yet.
//   * A bare `return;` from a Zig test PASSES; it does not skip. If a
//     precondition is genuinely absent, say so with `error.SkipZigTest`, never
//     by returning early.
//   * Multi-file modules: every submodule needs a `test { _ = <file>; }` line in
//     this file, or its tests are never compiled and never run — silently, with
//     the suite total agreeing with itself (CONVENTIONS.md §6 step 3;
//     `zig build check-dark-tests`).

test "TODO: replace this placeholder with the module's first real test" {
    // Deliberately RED, and deliberately not a skip.
    //
    // This used to be `test "smoke" { try std.testing.expect(true); }` — a test
    // that cannot fail, seeded into every module started from this folder. It
    // did get copied and kept: on 2026-08-13 three modules still carried it
    // verbatim (`opcua`, `liveness-hyst`, `pping` — the last two dressed up as
    // "this file is reachable from the build", which their own root.zig already
    // guaranteed), and a fourth, `rsa`, carries the same body written through an
    // aliased `testing`. A module could therefore be registered, report a green
    // suite, and carry that green through review having asserted nothing at all.
    // `error.SkipZigTest` would be no better here: a skip is not a finding
    // anyone chases, and this repo's history is a list of tests that were green
    // for the wrong reason.
    //
    // So the first `zig build test-<name>` is red until a real test replaces
    // this one. Delete it — do not weaken it.
    return error.TemplateTestNotReplaced;
}
