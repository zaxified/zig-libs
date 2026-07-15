// SPDX-License-Identifier: MIT
//! mls — Messaging Layer Security (RFC 9420), the scalable group-messaging
//! complement to this repo's 1:1 `signal` module. A multi-part arc; this
//! is **Part 1: foundation** — the mandatory cipher suite, the labeled-
//! crypto primitives every later derivation composes, the ratchet tree's
//! pure integer math, and the TLS-presentation-language wire codec RFC
//! 9420 is written in. TreeKEM, KeyPackage/LeafNode/Proposal/Commit
//! framing, the key schedule, and the secret tree are LATER parts — see
//! `SPEC.md`'s "Arc breakdown" for the full decomposition and tier
//! tagging (the genuinely Fable-hard piece, TreeKEM path/parent-hash/
//! resolution validation, is deliberately NOT built here).
//!
//! | File | What it provides |
//! |---|---|
//! | `codec.zig` | The RFC 9420 §2.1 TLS-presentation-language (de)serializer: fixed-width big-endian ints, `optional<T>`, enums, and RFC 9420's ONE deviation from plain RFC 8446 — QUIC-style variable-length-integer VECTOR length prefixes (§2.1.2) — every later part's wire formats are built on `Writer`/`Reader` |
//! | `suite.zig` | `CipherSuite(...)`, a comptime bundle of (KEM, KDF, AEAD, Hash, Signature); `Mls128X25519Aes128GcmSha256Ed25519` (suite `0x0001`, RFC 9420's mandatory-to-implement suite) is the only one instantiated |
//! | `crypto.zig` | The seven labeled-crypto primitives RFC 9420 §5/§8/§9.1 define: `RefHash`/`make_keypackage_ref`/`make_proposal_ref`, `ExpandWithLabel`/`DeriveSecret`, `DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel`, `EncryptWithLabel`/`DecryptWithLabel` (the last pair delegates to the sibling `hpke` module's `sealBase`/`openBase`) |
//! | `treemath.zig` | RFC 9420 Appendix C's array-based binary tree math — `left`/`right`/`parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`, `node_width`, `level` — a direct port of the RFC's own published Python |
//! | `kat_test.zig` | The official RFC 9420 interop vectors (`mlswg/mls-implementations`'s `tree-math.json`/`crypto-basics.json`), embedded and driven end-to-end — see `NOTICE` for provenance |
//!
//! **Status: Part 1 COMPLETE and entirely Sonnet-tier** — mechanical
//! composition + exact conformance to published RFC vectors, no novel
//! cryptography. `treemath.zig` is a pure port of the RFC's own reference
//! code; `crypto.zig` composes `codec.zig` + the sibling `hpke`/std.crypto
//! primitives exactly as RFC 9420 §5/§8/§9.1 specify, byte-exact against
//! `kat_test.zig`'s embedded vectors (including a stronger-than-required
//! check for `sign_with_label`: Ed25519 is deterministic, RFC 8032, so
//! this module's own signing reproduces the vector's signature bytes
//! exactly, not merely a verify-round-trip).
//!
//! Consumer: a group-messaging application wanting RFC 9420 interop
//! (Matrix, MLS-based E2EE messaging, or any protocol layering on MLS's
//! group key agreement) — THIS part alone is not yet a usable MLS client;
//! it's the foundation later parts (TreeKEM, framing, key schedule) build
//! group operations on. See `README.md` for the current/planned surface.
//!
//! Provenance: clean-room from RFC 9420 (a public IETF specification, not
//! copyrightable expression — see `CONVENTIONS.md` §5's merger-doctrine
//! note) plus `treemath.zig`'s direct port of RFC 9420 Appendix C's own
//! published reference algorithm (the RFC's stated intent — it publishes
//! runnable code, not just prose, specifically so implementations match
//! it exactly). `kat_test.zig` embeds official `mlswg/mls-implementations`
//! interop vectors — public conformance DATA, not copyrightable
//! expression, same posture as this repo's `bn254`/`bls12_381` KAT
//! sources; see `NOTICE` for the exact commit/fetch-date citation anyway,
//! out of the same caution those modules apply.

const std = @import("std");

pub const codec = @import("codec.zig");
pub const suite = @import("suite.zig");
pub const crypto = @import("crypto.zig");
pub const treemath = @import("treemath.zig");

// Flat re-exports of the surface most callers want.
pub const CipherSuite = suite.CipherSuite;
pub const CipherSuiteId = suite.CipherSuiteId;
pub const default_suite = suite.default;

pub const RefHash = crypto.RefHash;
pub const make_keypackage_ref = crypto.make_keypackage_ref;
pub const make_proposal_ref = crypto.make_proposal_ref;
pub const ExpandWithLabel = crypto.ExpandWithLabel;
pub const DeriveSecret = crypto.DeriveSecret;
pub const DeriveTreeSecret = crypto.DeriveTreeSecret;
pub const SignWithLabel = crypto.SignWithLabel;
pub const VerifyWithLabel = crypto.VerifyWithLabel;
pub const EncryptWithLabel = crypto.EncryptWithLabel;
pub const DecryptWithLabel = crypto.DecryptWithLabel;

pub const meta = .{
    .platform = .any,
    // Pure computation over caller-supplied bytes/keys, like the sibling
    // `hpke`/`signal` modules — no owned socket/transport of its own (a
    // later framing part may introduce wire I/O, but Part 1 is
    // computation-only).
    .role = .util,
    // No shared/global state — every type here is a plain caller-owned
    // value (`codec.Writer`/`Reader` wrap a caller-supplied buffer;
    // `suite.CipherSuite(...)` is a comptime type, not an instance).
    .concurrency = .reentrant,
    .model_after = "RFC 9420 (Messaging Layer Security); treemath.zig ports Appendix C's own published Python reference verbatim",
    .deps = .{"hpke"},
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too (the dtls/noise/tlsresume/hpke/ssh precedent this module
// follows).
test {
    _ = codec;
    _ = suite;
    _ = crypto;
    _ = treemath;
    _ = @import("kat_test.zig");
}

test "meta.deps is exactly {\"hpke\"}" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("hpke", meta.deps[0]);
}

test "meta.role is .util (no owned transport/socket in Part 1)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "default_suite is RFC 9420's mandatory-to-implement suite, 0x0001" {
    try std.testing.expectEqual(CipherSuiteId.mls_128_dhkemx25519_aes128gcm_sha256_ed25519, default_suite.id);
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(default_suite.id));
}
