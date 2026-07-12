// SPDX-License-Identifier: MIT
//! hpke — Hybrid Public Key Encryption (RFC 9180): DHKEM + HKDF + AEAD
//! composed into a single-shot "seal to a public key" / "open with a
//! private key" API, plus a multi-message `Context` for streaming use
//! (§5.2) and secret export for higher-level protocols to derive their own
//! keys from an HPKE exchange (§5.3, e.g. MLS/draft-irtf-cfrg-hpke's own
//! consumers).
//!
//! **Status: crypto-implementation pass DONE — every core is real and
//! KAT-validated** against RFC 9180 Appendix A.1 (X25519 + AES-128-GCM
//! base mode, the full vector: DHKEM Encap/Decap/DeriveKeyPair, key
//! schedule, all 6 encryption tuples, all 3 exported values, and the
//! single-shot `sealBase`/`openBase`), A.2 (ChaCha20Poly1305), and A.3
//! (P-256), byte-exact:
//!
//! | File | What it provides |
//! |---|---|
//! | `suite.zig` | Suite/KEM id constants, `Mode`, `I2OSP`/`OS2IP`, `suite_id`/`kem_suite_id` construction, `LabeledExtract`/`LabeledExpand` (§4) |
//! | `dhkem.zig` | `X25519Kem`/`P256Kem`: `Encap`/`Decap`/`AuthEncap`/`AuthDecap`/`DeriveKeyPair`/`generateKeyPair` (§4.1/§7.1.1-§7.1.3) |
//! | `schedule.zig` | `KeySchedule` (§5.1), `Context.seal`/`.open`/`.exportSecret` (§5.2/§5.3), `computeNonce`/`incrementSeq`, `sealBase`/`openBase` (§6.1) |
//! | `kat_rfc9180.zig` | RFC 9180 Appendix A.1 (full) + A.2/A.3 (headers) known-answer vectors, driven end-to-end |
//!
//! `auth`/`auth_psk`-mode KEM folds (`AuthEncap`/`AuthDecap`) are
//! implemented and self-consistency-tested (RFC 9180 Appendix A publishes
//! no auth-mode vector this module embeds — see SPEC.md's done-record
//! item 8). See `SPEC.md` for the full threat model.
//!
//! Provenance: clean-room from RFC 9180 (a public IETF specification, not
//! copyrightable expression — see CONVENTIONS.md §5's merger-doctrine
//! note, so no NOTICE entry is strictly required for the RFC citation
//! alone; this module names no third-party implementation as a design
//! reference, so `NOTICE` carries only the RFC 9180 citation). Built
//! entirely on `std.crypto` (`std.crypto.dh.X25519`, `std.crypto.ecc.P256`,
//! `std.crypto.kdf.hkdf.HkdfSha256`, `std.crypto.aead.aes_gcm.{Aes128Gcm,
//! Aes256Gcm}`, `std.crypto.aead.chacha_poly.ChaCha20Poly1305`) — no
//! sibling-module dependency, `deps = .{}`.

const std = @import("std");

pub const suite = @import("suite.zig");
pub const dhkem = @import("dhkem.zig");
pub const schedule = @import("schedule.zig");

pub const KemId = suite.KemId;
pub const KdfId = suite.KdfId;
pub const AeadId = suite.AeadId;
pub const Mode = suite.Mode;

pub const X25519Kem = dhkem.X25519Kem;
pub const P256Kem = dhkem.P256Kem;

pub const Context = schedule.Context;
pub const keySchedule = schedule.keySchedule;
pub const sealBase = schedule.sealBase;
pub const openBase = schedule.openBase;

pub const meta = .{
    .platform = .any,
    // Pure computation over caller-supplied bytes/keys — no owned socket,
    // no wire framing of its own (an application picks how `enc` +
    // ciphertext travel), matching `noise`'s scoping rather than a
    // transport module's `.client`/`.server`/`.both`.
    .role = .util,
    // No shared/global state: `Context` is a plain caller-owned value
    // (like `noise.state.CipherState`), and every free function
    // (`suite.labeledExtract`/`.labeledExpand`, `dhkem.*Kem.*`) touches
    // only its parameters.
    .concurrency = .reentrant,
    .model_after = "RFC 9180 (Hybrid Public Key Encryption)",
    .deps = .{},
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too (the dtls/noise/tlsresume/ssh precedent this module follows).
test {
    _ = suite;
    _ = dhkem;
    _ = schedule;
    _ = @import("kat_rfc9180.zig");
}

test "meta.deps is empty (std only, no sibling-module dependencies)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}

test "meta.role is .util (no owned transport/socket, unlike a .client/.server module)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "KemId/KdfId/AeadId ordinals match RFC 9180 Tables 2/3/5" {
    try std.testing.expectEqual(@as(u16, 0x0020), @intFromEnum(KemId.dhkem_x25519_hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0010), @intFromEnum(KemId.dhkem_p256_hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(KdfId.hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(AeadId.aes128gcm));
    try std.testing.expectEqual(@as(u16, 0x0002), @intFromEnum(AeadId.aes256gcm));
    try std.testing.expectEqual(@as(u16, 0x0003), @intFromEnum(AeadId.chacha20poly1305));
    try std.testing.expectEqual(@as(u16, 0xffff), @intFromEnum(AeadId.export_only));
}
