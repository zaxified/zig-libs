// SPDX-License-Identifier: MIT

//! tlock — drand-style **timelock encryption**: Identity-Based
//! Encryption (Boneh-Franklin, over `bls12_381`) where the "identity"
//! encrypted TO is a future ROUND NUMBER of a drand randomness beacon.
//! Nobody can decrypt until that round is reached and the beacon
//! publishes its threshold-BLS signature for it — which turns out to
//! BE the BF-IBE private key for that round's identity, by
//! construction (see `tlock.zig`'s module doc comment for the full
//! equation). This is the scheme Gailly/Melissaris/Romailler's
//! `drand/tlock` (Go) ships, targeting the League of Entropy's
//! **quicknet** beacon (`SigsOnG1ID` / `"bls-unchained-g1-rfc9380"`
//! scheme — see `ciphersuite.zig`'s module doc comment for why THIS
//! variant, confirmed live against quicknet's own chain info).
//!
//! **Status: REAL — interop-verified.** `ciphersuite.zig` (`beaconId`/
//! `h1`/`h2`/`h3`/`h4`/`randomSigma`), `tlock.zig`'s `Ciphertext`
//! struct + byte codec, AND the two cryptographic cores `encrypt`/
//! `decrypt` (the BF-IBE FullIdent assembly + Fiat-Shamir-Okamoto CCA
//! consistency check + a module-local constant-time `fp12Pow`) are all
//! implemented (`gate.core_implemented = true`) — transcribed from
//! drand's actual production Go source (`drand/drand`'s
//! `crypto/schemes.go`, `drand/kyber`'s `encrypt/ibe/ibe.go`,
//! `drand/tlock`'s `tlock.go` — see `NOTICE`) and byte-exact-verified
//! IN BOTH DIRECTIONS against a genuine ciphertext produced by drand's
//! own Go `tle` CLI (`kat_test.zig`'s interop vector — which caught a
//! real Gt-representation divergence a self-consistent round trip
//! never could: drand/kilic hashes the canonical pairing value's CUBE;
//! see `tlock.zig`'s `gtToDrandRepr` and `SPEC.md`).
//!
//! ## Layout
//!
//! - `ciphersuite.zig` — REAL. `beaconId` (drand's unchained beacon
//!   digest, also the IBE identity string), `h1` (identity -> `G1`,
//!   RFC 9380 hash-to-curve via `bls12_381.hash_to_curve`), `h2`/`h3`/
//!   `h4` (drand/kyber's domain-separated SHA-256 constructions),
//!   `randomSigma` (entropy source for `encrypt`'s explicit `sigma`
//!   parameter).
//! - `tlock.zig` — `Ciphertext` `(U ∈ G2, V, W)` struct + byte codec
//!   (128 bytes, byte-for-byte drand's own wire format); the two
//!   **FABLE CORE** functions `encrypt`/`decrypt` (REAL) + the private
//!   `fp12Pow`/`gtToDrandRepr` Gt helpers.
//! - `gate.zig` — the single switch (`core_implemented`, now `true`)
//!   gating `encrypt`/`decrypt`'s KAT tests in `kat_test.zig`.
//! - `kat_test.zig` — the KAT harness: REAL ungated tests (byte-exact
//!   `beaconId` digests, `h1` on-curve/subgroup checks, byte-exact
//!   pairing sanity checks against GENUINE, live-fetched drand round
//!   signatures), gate-guarded `encrypt`/`decrypt` round-trip/
//!   tamper-rejection tests, and the byte-exact drand interop vector
//!   (a real Go-`tle`-produced ciphertext, both decrypted and
//!   re-encrypted byte-exactly).
//!
//! ## Honest limitations (read before reaching for this module)
//!
//! - **NOT post-quantum.** This is pairing-based (BLS12-381) —
//!   Shor's-algorithm-vulnerable, exactly like every other module in
//!   this repo built on `bls12_381`/`bn254` (`bbs`, threshold-BLS,
//!   KZG). Timelock encryption's security model is fundamentally about
//!   gating on TIME (nobody has the round signature yet — a temporal
//!   secret, not a computational hardness assumption alone), which
//!   makes it a natural fit to HYBRIDIZE with a genuinely post-quantum
//!   KEM (e.g. this repo's own `hqc`) for anyone who also wants
//!   long-term confidentiality against a future quantum adversary who
//!   has recorded today's ciphertexts: encrypt the SAME payload's
//!   actual symmetric key under both an `hqc` KEM ciphertext and this
//!   module's IBE layer, requiring EITHER to be broken (not
//!   requiring both to survive — that composition choice is a
//!   consumer-side decision, out of scope for this module itself).
//! - **The beacon is a trusted, external input.** This module never
//!   runs a drand beacon or a DKG — every `p_pub: g2.Affine` (encrypt)
//!   and `round_signature: g1.Affine` (decrypt) is CALLER-SUPPLIED.
//!   Verifying that a `round_signature` genuinely came from the
//!   claimed beacon (rather than trusting it blindly) is the SAME
//!   pairing check `kat_test.zig`'s ungated "pairing sanity" test
//!   performs — callers crossing a trust boundary should perform it
//!   too, exactly like `bls12_381.bls_sig`'s verify family expects of
//!   ITS callers.
//! - **Consumer**: a dead-man-switch / scheduled-disclosure primitive
//!   (encrypt a secret NOW, guarantee it becomes readable at/after a
//!   known future WALL-CLOCK time without any single party holding the
//!   key early) — this repo's "encrypted disclosure"
//!   surface, and the generic use case `drand/tlock`'s own README
//!   documents (sealed bids, embargoed documents, voting).

const std = @import("std");

pub const ciphersuite = @import("ciphersuite.zig");
pub const gate = @import("gate.zig");

const tlock_mod = @import("tlock.zig");
pub const Ciphertext = tlock_mod.Ciphertext;
pub const DecryptError = tlock_mod.DecryptError;
pub const block_bytes = tlock_mod.block_bytes;

/// FABLE CORE — see `tlock.zig`.
pub const encrypt = tlock_mod.encrypt;
/// FABLE CORE — see `tlock.zig`.
pub const decrypt = tlock_mod.decrypt;

/// Re-exported: the sibling module this module builds on.
pub const bls12_381 = @import("bls12_381");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any, // pure computation; the one entropy source (ciphersuite.randomSigma) takes a portable std.Io, no raw getrandom(2)
    .role = .util, // no I/O, no wire framing beyond the fixed 128-byte Ciphertext codec
    .concurrency = .reentrant, // every type is a plain value; no globals
    .model_after = "drand/tlock (Go, Gailly/Melissaris/Romailler) + drand/kyber's encrypt/ibe package (Boneh-Franklin \"FullIdent\" IBE, CRYPTO 2001 §4.2) — quicknet's SigsOnG1ID/\"bls-unchained-g1-rfc9380\" scheme; bls12_381 (this repo) supplies the field/group/pairing/hash-to-curve primitives",
    .deps = .{ "bls12_381", "entropy" }, // entropy: the fail-closed `sigma` draw
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull x's
// tests into the test binary on its own — every submodule must be named
// here too.

const kat_test = @import("kat_test.zig");

test {
    _ = ciphersuite;
    _ = gate;
    _ = tlock_mod;
    _ = kat_test;
}

test "meta.model_after names drand/tlock and drand/kyber" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "drand/tlock") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "drand/kyber") != null);
}

test "meta.deps is exactly {bls12_381, entropy}" {
    try std.testing.expectEqual(@as(usize, 2), meta.deps.len);
    try std.testing.expectEqualStrings("bls12_381", meta.deps[0]);
    try std.testing.expectEqualStrings("entropy", meta.deps[1]);
}

test "gate IS flipped (encrypt/decrypt are real and interop-verified)" {
    try std.testing.expect(gate.core_implemented);
}

test "Ciphertext.encoded_bytes is 128 (96-byte G2 U + 16-byte V + 16-byte W)" {
    try std.testing.expectEqual(@as(usize, 128), Ciphertext.encoded_bytes);
}

test "block_bytes is 16 (drand's own DEK width)" {
    try std.testing.expectEqual(@as(usize, 16), block_bytes);
}
