// SPDX-License-Identifier: MIT

//! bip32 — BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic
//! (HD) keys over secp256k1.
//!
//! Two layers, composed but each usable standalone:
//!   • `mnemonic` (`bip39.zig`) — BIP-39: entropy ↔ mnemonic word phrase
//!     (the embedded 2048-word official English wordlist), and
//!     `mnemonicToSeed` (PBKDF2-HMAC-SHA512) → the 64-byte BIP-32 seed.
//!   • The top-level API (`bip32.zig`) — BIP-32: `masterFromSeed`,
//!     `ckdPriv`/`ckdPub` (hardened + normal child derivation),
//!     `serializePriv`/`serializePub`/`parseExtended` (xprv/xpub
//!     Base58Check), and `parsePath`/`derivePath`
//!     (`m/44'/0'/0'/0/0`-style paths).
//!
//! Handles SECRET key material (mnemonic entropy, seeds, extended private
//! keys): every stack buffer this module owns that can hold private-key-
//! derived bytes is zeroized before the owning function returns (HMAC
//! outputs, the hardened-derivation HMAC input, passphrase salt buffers,
//! decode scratch space). `ExtendedPrivKey.deinit` lets the caller zero the
//! long-lived struct once done with it.
//!
//! Provenance: original work of the zig-libs authors (MIT); BIP-39 and
//! BIP-32 are public `bitcoin/bips` specifications (merger doctrine — no
//! NOTICE entry required for the algorithm). The embedded English wordlist
//! and the official test vectors are machine-transcribed spec/reference
//! artifacts, not ported from any implementation's source — see SPEC.md.

const std = @import("std");

pub const mnemonic = @import("bip39.zig");

const bip32_impl = @import("bip32.zig");

pub const version_mainnet_priv = bip32_impl.version_mainnet_priv;
pub const version_mainnet_pub = bip32_impl.version_mainnet_pub;
pub const hardened_offset = bip32_impl.hardened_offset;
pub const serialized_payload_len = bip32_impl.serialized_payload_len;
pub const max_serialized_len = bip32_impl.max_serialized_len;
pub const max_path_depth = bip32_impl.max_path_depth;

pub const ExtendedPrivKey = bip32_impl.ExtendedPrivKey;
pub const ExtendedPubKey = bip32_impl.ExtendedPubKey;
pub const ParsedKey = bip32_impl.ParsedKey;

pub const MasterError = bip32_impl.MasterError;
pub const CkdError = bip32_impl.CkdError;
pub const ParseError = bip32_impl.ParseError;
pub const PathError = bip32_impl.PathError;

pub const masterFromSeed = bip32_impl.masterFromSeed;
pub const ckdPriv = bip32_impl.ckdPriv;
pub const ckdPub = bip32_impl.ckdPub;
pub const neuter = bip32_impl.neuter;
pub const fingerprint = bip32_impl.fingerprint;
pub const serializePriv = bip32_impl.serializePriv;
pub const serializePub = bip32_impl.serializePub;
pub const parseExtended = bip32_impl.parseExtended;
pub const parsePath = bip32_impl.parsePath;
pub const derivePath = bip32_impl.derivePath;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic keys over secp256k1 — the wallet key-derivation foundation.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant, // pure functions over caller-owned buffers; no shared state
    .model_after = "BIP-39 (Mnemonic code for generating deterministic keys) + BIP-32 (Hierarchical Deterministic Wallets), bitcoin/bips",
    .deps = .{ "k256", "ripemd160", "bech32" },
};

// Dark-tests aggregator: a bare `pub const`/`@import` re-export does NOT
// pull a submodule's tests into the test binary — this reference does
// (CONVENTIONS.md §6).
test {
    _ = mnemonic;
    _ = bip32_impl;
    _ = @import("bip32_vectors.zig");
    _ = @import("bip39_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names BIP-39 and BIP-32" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BIP-39") != null);
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BIP-32") != null);
}
