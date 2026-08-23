// SPDX-License-Identifier: MIT

//! ibe — standalone **Boneh-Franklin Identity-Based Encryption**
//! ("FullIdent", Boneh & Franklin, CRYPTO 2001 §4.2) over
//! `bls12_381`: any string can be a public key (an email address, a
//! device serial, a policy tag); a trusted Private Key Generator (PKG)
//! — run by the CALLER of this module, via `Setup`/`Extract` — derives
//! the matching private key on demand. Encrypt to an identity before
//! its holder has ever contacted the PKG; the PKG (or the identity
//! holder, once it has extracted its key) can decrypt at any later
//! time.
//!
//! **Status: REAL — fully implemented, no stubs.** `Setup`, `Extract`,
//! `encrypt`, and `decrypt` are all real, built directly on
//! `bls12_381`'s already-proven field/group/pairing/hash-to-curve
//! primitives and on the exact BF-IBE assembly this repo's sibling
//! `tlock` module proved (interop-verified against drand's Go
//! implementation) — see `ibe.zig`'s module doc comment for the full
//! construction and `ibe.zig`'s "No drand-style cube" section for the
//! one deliberate divergence from `tlock`'s Gt-representation handling.
//!
//! ## Relationship to `tlock`
//!
//! `tlock` (this repo) is the SAME Boneh-Franklin "FullIdent"
//! primitive, specialized so that the PKG IS a drand randomness beacon
//! and the "identity" is a future round number — nobody can `Extract`
//! (i.e. nobody has the round's threshold-BLS signature) until that
//! round is reached, which is what makes `tlock` a TIMELOCK. This
//! module (`ibe`) is the GENERAL case: YOU run the PKG (`Setup`
//! generates `(msk, mpk)`; `Extract(msk, id)` derives a private key for
//! any identity string you choose, at any time you choose), with no
//! notion of "future round" or external beacon at all. Every
//! group/pairing/hash-to-curve primitive both modules use comes from
//! the same proven `bls12_381` foundation; `ibe`'s own hash/DST layer
//! (`ciphersuite.zig`) is its own (not drand's), since there is no
//! external implementation to interop with — see that file's module
//! doc comment.
//!
//! ## Layout
//!
//! - `ciphersuite.zig` — `h1` (identity -> `G1`, RFC 9380
//!   hash-to-curve via `bls12_381.hash_to_curve`), `h2`/`h3`/`h4` (this
//!   module's own domain-separated SHA-256/SHA-512 constructions),
//!   `randomSigma` (entropy source for `encrypt`'s explicit `sigma`
//!   parameter).
//! - `ibe.zig` — `KeyPair`, `setup`/`extract` (the PKG API),
//!   `Ciphertext` `(U ∈ G2, V, W)` struct + byte codec, `encrypt`/
//!   `decrypt` (the BF-IBE FullIdent core) + the private `fp12Pow` `Gt`
//!   exponentiation helper.
//! - `kat_test.zig` — round-trip, pairing-consistency and soundness
//!   (tamper/wrong-key rejection) KATs, plus the **drand-parameterised
//!   interop anchor**: `ibe.Scheme` instantiated with drand's
//!   ciphersuite must reproduce a genuine ciphertext produced by
//!   drand's own Go `tle` CLI, byte for byte, which is what pins this
//!   module's ASSEMBLY against a foreign artifact. This module's own
//!   DSTs/tags and its no-cube choice are pinned by the
//!   self-consistency tests and cannot be anchored externally (RFC 9380
//!   §3.1 requires each application to pick its own DST — there is no
//!   foreign value to match). See that file's module doc comment for
//!   the full split.
//!
//! ## Honest limitations (read before reaching for this module)
//!
//! - **NOT post-quantum.** Pairing-based (BLS12-381) — Shor's-
//!   algorithm-vulnerable, exactly like `tlock`/`bbs`/threshold-BLS/KZG
//!   and every other `bls12_381`-built module in this repo. For
//!   long-term confidentiality against a future quantum adversary who
//!   has recorded today's ciphertexts, HYBRIDIZE: encrypt the same
//!   symmetric key under both this module's IBE layer and a genuinely
//!   post-quantum KEM (e.g. this repo's `hqc`), requiring EITHER to be
//!   broken — the same composition `tlock`'s own "Honest limitations"
//!   section documents, a consumer-side decision out of scope here.
//! - **Key escrow is inherent, not a bug.** The PKG (whoever holds
//!   `msk`) can `Extract` a private key for ANY identity — this is
//!   Boneh-Franklin IBE's well-known property, not specific to this
//!   implementation. Deploy only where a single trusted PKG (or a
//!   threshold of them, via a separate DKG this module does not
//!   provide) is an acceptable trust model.
//! - **Consumer**: encrypt-to-a-name systems where key distribution is
//!   the pain point a PKI would otherwise solve (message encryption to
//!   a recipient's email/device-ID before they have published any
//!   public key of their own; access control keyed by policy strings
//!   an authority extracts on demand).

const std = @import("std");

pub const ciphersuite = @import("ciphersuite.zig");

const ibe_mod = @import("ibe.zig");
pub const KeyPair = ibe_mod.KeyPair;
pub const Ciphertext = ibe_mod.Ciphertext;
pub const DecryptError = ibe_mod.DecryptError;
pub const block_bytes = ibe_mod.block_bytes;

pub const setup = ibe_mod.setup;
pub const extract = ibe_mod.extract;
pub const encrypt = ibe_mod.encrypt;
pub const decrypt = ibe_mod.decrypt;

/// Re-exported: the sibling module this module builds on.
pub const bls12_381 = @import("bls12_381");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Standalone Boneh-Franklin Identity-Based Encryption over `bls12_381` — a self-run PKG extracts per-identity keys. Not post-quantum; key escrow is inherent.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure computation; the one entropy source (setup's Fr.random / ciphersuite.randomSigma) takes a portable std.Io, no raw getrandom(2)
    .role = .util, // no I/O, no wire framing beyond the fixed Ciphertext codec
    .concurrency = .reentrant, // every type is a plain value; no globals
    .model_after = "Boneh, D. and Franklin, M., \"Identity-Based Encryption from the Weil Pairing\" (CRYPTO 2001, \"FullIdent\", section 4.2); the encrypt/decrypt assembly mirrors this repo's own tlock module (interop-verified against drand/kyber's Go implementation), adapted to a caller-run PKG instead of a drand beacon; bls12_381 (this repo) supplies the field/group/pairing/hash-to-curve primitives",
    .deps = .{ "bls12_381", "entropy" }, // entropy: fail-closed `sigma` / master-key draws
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.

const kat_test = @import("kat_test.zig");

test {
    _ = ciphersuite;
    _ = ibe_mod;
    _ = kat_test;
}

test "meta.model_after names Boneh-Franklin CRYPTO 2001" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "Boneh") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "CRYPTO 2001") != null);
}

test "meta.deps is exactly {bls12_381, entropy}" {
    try std.testing.expectEqual(@as(usize, 2), meta.deps.len);
    try std.testing.expectEqualStrings("bls12_381", meta.deps[0]);
    try std.testing.expectEqualStrings("entropy", meta.deps[1]);
}

test "Ciphertext.encoded_bytes is 160 (96-byte G2 U + 32-byte V + 32-byte W)" {
    try std.testing.expectEqual(@as(usize, 160), Ciphertext.encoded_bytes);
}

test "block_bytes is 32 (this module's own choice — see ciphersuite.zig)" {
    try std.testing.expectEqual(@as(usize, 32), block_bytes);
}
