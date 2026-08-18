// SPDX-License-Identifier: MIT

//! drand — a drand randomness-beacon **client core**: parse a chain-info
//! (`/info`) document, decode a beacon round (`/public/<round>`), and
//! BLS-verify a round's threshold signature against the chain public key.
//! The cryptography is entirely `bls12_381`'s (pairing + RFC-9380
//! hash-to-curve) and the quicknet message-hashing is REUSED verbatim
//! from `tlock.ciphersuite` (`beaconId`/`h1`), so `drand` and `tlock` can
//! never drift on the scheme.
//!
//! **Transport-agnostic — by design.** This module never opens a socket
//! or speaks TLS: the caller fetches the `/info` and `/public/<round>`
//! response bytes with their own HTTPS client and hands them here to be
//! parsed + verified — exactly the way `tlock` consumes a round signature
//! without fetching it (`CONVENTIONS.md` §2's "bring-your-own transport"
//! posture). `round.roundPath`/`round.latestPath` build the request path
//! as a convenience; performing the request is the caller's job.
//!
//! **Scheme coverage.** Verification targets the League-of-Entropy
//! **quicknet** scheme `bls-unchained-g1-rfc9380` (signatures in `G1`,
//! master key in `G2`, message `H1(SHA-256(round_be))`) — the scheme
//! `tlock` also targets. The legacy chained scheme and the deprecated
//! `bls-unchained-on-g1` are RECOGNIZED and parsed but not verified
//! (`error.UnsupportedScheme`); see `SPEC.md`'s deferred list.
//!
//! ## Layout
//!
//! - `chaininfo.zig` — `parseInfo` → `ChainInfo` (typed, plain value;
//!   decodes + `KeyValidate`s the `G2` chain key for quicknet).
//! - `round.zig` — `parseRound` → `Round` (typed; decodes the `G1`
//!   signature; retains `randomness`/`previous_signature`), plus the
//!   `roundPath`/`latestPath` request-path helpers.
//! - `verify.zig` — `verifyRound(info, round)`: the drand
//!   `VerifyBeacon` pairing equation on `bls12_381.pairing`, plus the
//!   `randomness == SHA-256(signature)` check.

const std = @import("std");

pub const chaininfo = @import("chaininfo.zig");
pub const round = @import("round.zig");
pub const verify = @import("verify.zig");

// ── flattened public API ───────────────────────────────────────────────

pub const ChainInfo = chaininfo.ChainInfo;
pub const Scheme = chaininfo.Scheme;
pub const ParseError = chaininfo.ParseError;
pub const parseInfo = chaininfo.parseInfo;

pub const Round = round.Round;
pub const RoundParseError = round.RoundParseError;
pub const parseRound = round.parseRound;
pub const roundPath = round.roundPath;
pub const latestPath = round.latestPath;

pub const VerifyError = verify.VerifyError;
pub const verifyRound = verify.verifyRound;
pub const verifyRoundPoints = verify.verifyRoundPoints;
pub const expectedRound = verify.expectedRound;

/// Re-exported: the sibling crypto module every point/pairing comes from.
pub const bls12_381 = @import("bls12_381");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure parse + verify; no I/O, no syscalls
    .role = .client, // a beacon-client core (verification + codec half); transport is the caller's
    .concurrency = .reentrant, // every type is a plain value; no shared state, no globals
    .model_after = "drand/drand HTTP beacon client + crypto.Scheme.VerifyBeacon (Go) — quicknet's SigsOnG1ID/\"bls-unchained-g1-rfc9380\" scheme; bls12_381 (this repo) supplies the pairing + RFC-9380 hash-to-curve, and tlock.ciphersuite supplies the byte-identical quicknet beaconId/h1 message hashing",
    .deps = .{ "bls12_381", "tlock" },
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary — every submodule must be named here too.
test {
    _ = chaininfo;
    _ = round;
    _ = verify;
}

test "meta.deps is exactly {bls12_381, tlock}" {
    try std.testing.expectEqual(@as(usize, 2), meta.deps.len);
    try std.testing.expectEqualStrings("bls12_381", meta.deps[0]);
    try std.testing.expectEqualStrings("tlock", meta.deps[1]);
}

test "end-to-end: parse genuine quicknet /info + /public/1000 and verify" {
    const info_json =
        \\{
        \\  "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
        \\  "period": 3,
        \\  "genesis_time": 1692803367,
        \\  "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
        \\  "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
        \\  "schemeID": "bls-unchained-g1-rfc9380",
        \\  "metadata": { "beaconID": "quicknet" }
        \\}
    ;
    const round_json =
        \\{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const info = try parseInfo(std.testing.allocator, info_json);
    const rnd = try parseRound(std.testing.allocator, round_json);
    try verifyRound(&info, &rnd);
}
