// SPDX-License-Identifier: MIT
//! mls — Messaging Layer Security (RFC 9420), the scalable group-messaging
//! complement to this repo's 1:1 `signal` module. A multi-part arc.
//! **Part 1: foundation** — the mandatory cipher suite, the labeled-crypto
//! primitives every later derivation composes, the ratchet tree's pure
//! integer math, and the TLS-presentation-language wire codec RFC 9420 is
//! written in — COMPLETE. **Part 2: TreeKEM — COMPLETE.** The ratchet
//! tree's data structures/wire codec/tree-hash/tree-editing plus the five
//! algorithmically-hard cores (`resolution`/`parentHash`/
//! `validateParentHashes`/`processUpdatePath`/`applyUpdatePath`,
//! `treekem.zig`) are all implemented and pinned byte-exact against the
//! official mlswg `tree-validation`/`tree-operations`/`treekem` interop
//! vectors (the `gate.treekem_core_implemented` switch is now `true`) — see
//! `SPEC.md`'s "Part 2 — TreeKEM" section for the full breakdown.
//! KeyPackage/LeafNode-validation/Credential (Part 3), the key
//! schedule (Part 4), and Proposal/Commit/framing (Part 5) are LATER
//! parts — see `SPEC.md`'s "Arc breakdown" for the full decomposition.
//!
//! | File | What it provides |
//! |---|---|
//! | `codec.zig` | The RFC 9420 §2.1 TLS-presentation-language (de)serializer: fixed-width big-endian ints, `optional<T>`, enums, and RFC 9420's ONE deviation from plain RFC 8446 — QUIC-style variable-length-integer VECTOR length prefixes (§2.1.2) — every later part's wire formats are built on `Writer`/`Reader` |
//! | `suite.zig` | `CipherSuite(...)`, a comptime bundle of (KEM, KDF, AEAD, Hash, Signature); `Mls128X25519Aes128GcmSha256Ed25519` (suite `0x0001`, RFC 9420's mandatory-to-implement suite) is the only one instantiated |
//! | `crypto.zig` | The seven labeled-crypto primitives RFC 9420 §5/§8/§9.1 define: `RefHash`/`make_keypackage_ref`/`make_proposal_ref`, `ExpandWithLabel`/`DeriveSecret`, `DeriveTreeSecret`, `SignWithLabel`/`VerifyWithLabel`, `EncryptWithLabel`/`DecryptWithLabel` (the last pair delegates to the sibling `hpke` module's `sealBase`/`openBase`) |
//! | `treemath.zig` | RFC 9420 Appendix C's array-based binary tree math — `left`/`right`/`parent`/`sibling`, `root`, `direct_path`, `copath`, `is_leaf`, `node_width`, `level` — a direct port of the RFC's own published Python |
//! | `kat_test.zig` | Part 1's official RFC 9420 interop vectors (`tree-math.json`/`crypto-basics.json`), embedded and driven end-to-end — see `NOTICE` for provenance |
//! | `wire_lists.zig` | Part 2's shared variable-length-vector encode/decode helpers (`Writer`/`Reader`-based, no allocator needed for `encode`/`encodedLen`) |
//! | `tree.zig` | Part 2's `LeafNode`/`ParentNode`/`Node`/`RatchetTree` (§7.1/§7.2/§12.4.3.3), wire codec, leaf-signature verification, and the mechanical (non-Fable) tree-shape edits `addLeaf`/`updateLeaf`/`removeLeaf` (§7.7/§12.1.1-3) |
//! | `treehash.zig` | Part 2's RFC 9420 §7.8 tree hash — real, recursive, KAT'd byte-exact |
//! | `treekem.zig` | Part 2's `HPKECiphertext`/`UpdatePathNode`/`UpdatePath` (§7.6) plus the five Fable cores (`resolution`/`parentHash`/`validateParentHashes`/`processUpdatePath`/`applyUpdatePath`), implemented and KAT-pinned |
//! | `gate.zig` | Part 2's `treekem_core_implemented` switch — now `true` (the five cores are implemented; the gated TreeKEM KATs run) |
//! | `kat_treekem_test.zig` | Part 2's KAT harness: `tree-validation.json`/`tree-operations.json`/`treekem.json` driven byte-exact against the five cores (the `gate.treekem_core_implemented`-gated tests now run — resolution, parent-hash accept/tamper, UpdatePath process + merge) |
//!
//! **Status: Part 1 COMPLETE (Sonnet-tier). Part 2 COMPLETE (Sonnet
//! data/codec/tree-hash/tree-editing + Fable tree-algorithm cores, all
//! KAT-pinned byte-exact).** `treemath.zig` is a pure port of the RFC's own
//! reference code; `crypto.zig` composes `codec.zig` + the sibling
//! `hpke`/std.crypto primitives exactly as RFC 9420 §5/§8/§9.1 specify,
//! byte-exact against `kat_test.zig`'s embedded vectors (including a
//! stronger-than-required check for `sign_with_label`: Ed25519 is
//! deterministic, RFC 8032, so this module's own signing reproduces the
//! vector's signature bytes exactly, not merely a verify-round-trip).
//! Part 2's `tree.zig`/`treehash.zig` are similarly byte-exact against
//! `tree-validation.json`/`tree-operations.json` — see `SPEC.md` for the
//! full KAT breakdown and the real bug (`removeLeaf`'s truncation
//! boundary arithmetic) this harness caught during scaffolding.
//!
//! Consumer: a group-messaging application wanting RFC 9420 interop
//! (Matrix, MLS-based E2EE messaging, or any protocol layering on MLS's
//! group key agreement) — Parts 1+2 alone are not yet a usable MLS client
//! (no KeyPackage/Proposal/Commit framing, no key schedule); it's the
//! foundation later parts build group operations on. See `README.md` for
//! the current/planned surface.
//!
//! Provenance: clean-room from RFC 9420 (a public IETF specification, not
//! copyrightable expression — see `CONVENTIONS.md` §5's merger-doctrine
//! note) plus `treemath.zig`'s direct port of RFC 9420 Appendix C's own
//! published reference algorithm (the RFC's stated intent — it publishes
//! runnable code, not just prose, specifically so implementations match
//! it exactly). `kat_test.zig`/`kat_treekem_test.zig` embed official
//! `mlswg/mls-implementations` interop vectors — public conformance DATA,
//! not copyrightable expression, same posture as this repo's `bn254`/
//! `bls12_381` KAT sources; see `NOTICE` for the exact commit/fetch-date
//! citation anyway, out of the same caution those modules apply.

const std = @import("std");

pub const codec = @import("codec.zig");
pub const suite = @import("suite.zig");
pub const crypto = @import("crypto.zig");
pub const treemath = @import("treemath.zig");
pub const tree = @import("tree.zig");
pub const treehash = @import("treehash.zig");
pub const treekem = @import("treekem.zig");
pub const gate = @import("gate.zig");

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

pub const LeafNode = tree.LeafNode;
pub const ParentNode = tree.ParentNode;
pub const Node = tree.Node;
pub const RatchetTree = tree.RatchetTree;
pub const treeHash = treehash.treeHash;
pub const rootHash = treehash.rootHash;
pub const UpdatePath = treekem.UpdatePath;
pub const UpdatePathNode = treekem.UpdatePathNode;
pub const HPKECiphertext = treekem.HPKECiphertext;

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
    _ = @import("wire_lists.zig");
    _ = tree;
    _ = treehash;
    _ = treekem;
    _ = gate;
    _ = @import("kat_treekem_test.zig");
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
