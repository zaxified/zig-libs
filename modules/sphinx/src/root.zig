// SPDX-License-Identifier: MIT
//! sphinx — Lightning BOLT#4 Sphinx onion routing: the mix-net packet
//! construction that gives Lightning HTLC payments per-hop unlinkability
//! (each forwarding hop learns only its immediate predecessor and
//! successor, never the full route or its own position in it).
//!
//! **Status: complete.** The wire format, key derivation, per-hop TLV
//! framing, AND the three crypto cores (`core.deriveHopSecrets`,
//! `core.construct`, `core.process`) are all implemented and KAT-verified
//! against the official BOLT#4 test vector — including `construct`
//! reproducing the published 1366-byte onion packet byte-exact and a full
//! 5-hop construct → process round-trip. See `SPEC.md` for the design and
//! threat model.
//!
//! What's real:
//!   - `packet.OnionPacket` — the fixed 1366-byte wire packet (`version(1)
//!     ‖ public_key(33) ‖ hop_payloads(1300) ‖ hmac(32)`), parse/serialize,
//!     with the packet-level checks BOLT#4 "Onion Decryption" assigns
//!     before any crypto runs (version == 0, `public_key` a valid on-curve
//!     compressed secp256k1 point).
//!   - `keyderive.generateKey`/`.generateCipherStream` — BOLT#4 "Key
//!     Generation" (`HMAC-SHA256(key_type_label, shared_secret)` for
//!     `rho`/`mu`/`um`/`pad`) and "Pseudo Random Byte Stream"
//!     (`ChaCha20(key, nonce=0^96)` as a keystream generator).
//!   - `bigsize` — BOLT#1's canonical variable-length integer codec, used
//!     for each hop's `hop_payload` length prefix.
//!   - `hopframe` — the per-hop `bigsize(length) ‖ payload ‖ hmac(32)`
//!     frame shape inside `hop_payloads`, the `shiftSize` arithmetic BOLT#4
//!     "Packet Construction" defines, and the right-/left-shift buffer
//!     primitives `construct`/`process` drive.
//!
//! The crypto cores (`core.zig`): `deriveHopSecrets` (BOLT#4 "Shared
//! Secret" + "Blinding Ephemeral Onion Keys" — the forward chain of per-hop
//! ECDH + blinding that only the SENDER runs), `construct` (BOLT#4 "Packet
//! Construction" — assembling the full packet, reverse-route order,
//! including filler generation), and `process` (BOLT#4 "Onion Decryption"
//! — a single hop's unwrap: verify HMAC in constant time, deobfuscate,
//! extract this hop's payload, derive the next hop's blinded pubkey).
//!
//! KAT: the official BOLT#4 test vector (`bolt04/onion-test.json` +
//! `04-onion-routing.md`'s "Test Vector" section, `lightning/bolts` —
//! see `kat_vectors.zig`'s doc comment for exact provenance and `SPEC.md`
//! for the independent-re-derivation log). `kat_test.zig` verifies all 5
//! published shared secrets, the published onion packet byte-exact from
//! `construct`, hop-0 `process` of the published packet, the full 5-hop
//! round-trip, and the fail-closed HMAC tamper path.
//!
//! Provenance: clean-room from BOLT#4 (`lightning/bolts`, a public Lightning
//! Network specification — merger doctrine, no NOTICE entry required for
//! the citation alone; see `NOTICE`). Zig std GAP: yes — `std.crypto.ecc.
//! Secp256k1` (ECDH), `std.crypto.stream.chacha.ChaCha20IETF` (keystream),
//! `std.crypto.auth.hmac.sha2.HmacSha256`/`std.crypto.hash.sha2.Sha256`
//! supply every primitive, but ship no Sphinx-specific layer (key
//! derivation labels, the blinding chain, the packet/hop-frame shapes) —
//! that is entirely this module's own.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Lightning BOLT#4 Sphinx onion routing — forward ECDH blinding chain, layered packet construction, constant-time layer peeling.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // pure wire framing + crypto core, no I/O of its own
    .concurrency = .reentrant, // no shared/global state; every type here is a plain value type
    .model_after = "BOLT#4 (lightning/bolts) - Sphinx onion routing for Lightning HTLCs; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1); std.crypto.stream.chacha/auth.hmac supply the rest",
    .deps = .{"k256"}, // k256 curve group (byte-exact to std); std for chacha/hmac
};

pub const bigsize = @import("bigsize.zig");
pub const keyderive = @import("keyderive.zig");
pub const packet = @import("packet.zig");
pub const hopframe = @import("hopframe.zig");
pub const core = @import("core.zig");

// ── convenience re-exports (the common call-site surface) ──────────────────

pub const OnionPacket = packet.OnionPacket;
pub const ParseError = packet.ParseError;
pub const version_byte = packet.version_byte;
pub const pubkey_len = packet.pubkey_len;
pub const hop_payloads_len = packet.hop_payloads_len;
pub const hmac_len = packet.hmac_len;
pub const packet_len = packet.packet_len;

pub const KeyType = keyderive.KeyType;
pub const generateKey = keyderive.generateKey;
pub const generateCipherStream = keyderive.generateCipherStream;

pub const HopSecret = core.HopSecret;
pub const SharedSecretError = core.SharedSecretError;
pub const deriveHopSecrets = core.deriveHopSecrets;

pub const ConstructError = core.ConstructError;
pub const construct = core.construct;
pub const max_hops = core.max_hops;

pub const ProcessError = core.ProcessError;
pub const ProcessResult = core.ProcessResult;
pub const process = core.process;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too.
test {
    _ = bigsize;
    _ = keyderive;
    _ = packet;
    _ = hopframe;
    _ = core;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}

test "meta.model_after names BOLT#4" {
    try std.testing.expect(std.mem.indexOf(u8, meta.model_after, "BOLT#4") != null);
}

test "meta.deps is {\"k256\"} (curve group; byte-exact to std)" {
    try std.testing.expectEqual(@as(usize, 1), meta.deps.len);
    try std.testing.expectEqualStrings("k256", meta.deps[0]);
}

test "packet_len re-export matches the BOLT#4 fixed size (1366 bytes)" {
    try std.testing.expectEqual(@as(usize, 1366), packet_len);
}
