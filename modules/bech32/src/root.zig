// SPDX-License-Identifier: MIT
//! bech32 — Bitcoin address encodings: bech32 (BIP173) + bech32m (BIP350)
//! segwit addresses, and base58/base58check (the pre-segwit P2PKH/P2SH/WIF
//! encoding). Parses untrusted address strings, so every public decode
//! function is fail-closed: mixed case, out-of-charset characters, a bad
//! checksum, wrong bech32-vs-bech32m variant, and every BIP173/BIP350
//! length/range limit are all rejected with a specific typed error, never a
//! best-effort partial parse.
//!
//! Three independent layers, composed but each usable standalone:
//!   • `bech32.zig` — the generic BIP173/BIP350 codec (BCH checksum, HRP
//!     expansion, charset, `encode`/`decode` over 5-bit-grouped data). No
//!     notion of witness versions.
//!   • `segwit.zig` — layers BIP141/BIP173/BIP350's segwit-address
//!     consensus rules on top (witver 0..16, program 2-40 bytes, v0 must be
//!     exactly 20/32 bytes, v0=bech32/v1+=bech32m variant matching).
//!   • `base58.zig` — the unrelated, older Base58Check encoding (bignum
//!     multiply-add over a 58-symbol alphabet + a 4-byte double-SHA256
//!     checksum), plus P2PKH/P2WPKH convenience built on `ripemd160`'s
//!     `hash160`.
//!
//! No allocation anywhere: every decode/encode function works through
//! fixed-size stack buffers sized to the specs' own length ceilings
//! (bech32/bech32m: 90-character total; base58(check): a generous
//! 128-byte-payload bound covering every real Bitcoin base58 payload with
//! headroom) and returns owned value types or writes into a caller buffer.
//!
//! Provenance: original work of the zig-libs authors (MIT); the algorithms
//! are the public BIP173/BIP350 specifications and the well-known
//! Bitcoin-Core-style Base58(Check) bignum algorithm (public technique, no
//! source ported — see `NOTICE` if that changes). The BIP173/BIP350 test
//! vectors in `kat_vectors.zig` are a public specification artifact, fetched
//! directly from the `bitcoin/bips` repository and machine-transcribed (not
//! copied from any other implementation's test suite).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Bitcoin address encodings — bech32 (BIP173) / bech32m (BIP350) codec, segwit address encode/decode, base58check, P2PKH/P2WPKH.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant, // pure functions over caller-owned buffers; no shared state
    .model_after = "BIP173 (bech32) + BIP350 (bech32m) + Bitcoin Core's base58.cpp Base58Check algorithm",
    .deps = .{"ripemd160"}, // hash160 for the P2PKH/P2WPKH address helpers; std.crypto.hash.sha2.Sha256 for base58check
};

const bech32_impl = @import("bech32.zig");
const segwit_impl = @import("segwit.zig");

// ── bech32 / bech32m (BIP173 / BIP350) — generic 5-bit-grouped codec ───────

pub const Encoding = bech32_impl.Encoding;
pub const charset = bech32_impl.charset;
pub const max_hrp_len = bech32_impl.max_hrp_len;
pub const max_len = bech32_impl.max_len;
pub const checksum_len = bech32_impl.checksum_len;
pub const max_data_len = bech32_impl.max_data_len;

pub const DecodeError = bech32_impl.DecodeError;
pub const Decoded = bech32_impl.Decoded;
/// Decodes and checksum-verifies a bech32/bech32m string.
pub const decode = bech32_impl.decode;

pub const EncodeError = bech32_impl.EncodeError;
pub const Bech32String = bech32_impl.Bech32String;
/// Encodes `hrp` + 5-bit `data` with a fresh checksum for `encoding`.
pub const encode = bech32_impl.encode;

// ── Segwit addresses (BIP141 consensus rules over bech32/bech32m) ──────────

pub const min_program_len = segwit_impl.min_program_len;
pub const max_program_len = segwit_impl.max_program_len;
pub const max_witver = segwit_impl.max_witver;

pub const SegwitError = segwit_impl.SegwitError;
pub const SegwitData = segwit_impl.SegwitData;
/// Decodes + fully validates a segwit address against `expected_hrp`.
pub const decodeSegwit = segwit_impl.decodeSegwit;
/// Encodes a segwit address (v0 -> bech32, v1+ -> bech32m per BIP350).
pub const encodeSegwit = segwit_impl.encodeSegwit;

// ── base58 / base58check (pre-segwit P2PKH/P2SH/WIF encoding) ──────────────

/// Namespaced (not flattened) because `encode`/`decode` would otherwise
/// collide with the bech32 names above: `bech32.base58.encode`,
/// `bech32.base58.checkEncode`, `bech32.base58.encodeP2PKH`,
/// `bech32.base58.p2wpkhWitnessProgram`, etc.
pub const base58 = @import("base58.zig");

// Dark-tests aggregator: a bare `pub const`/`@import` re-export does NOT
// pull a submodule's tests into the test binary — this reference does.
test {
    _ = bech32_impl;
    _ = segwit_impl;
    _ = base58;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
