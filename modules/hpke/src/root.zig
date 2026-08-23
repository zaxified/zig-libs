// SPDX-License-Identifier: MIT
//! hpke — Hybrid Public Key Encryption (RFC 9180): DHKEM + HKDF + AEAD
//! composed into §5.1's `setupBaseS`/`setupBaseR` (+ psk/auth/auth_psk
//! variants) — encapsulate/decapsulate to a public key and hand back the
//! multi-message `Context` itself — plus §6.1's single-shot "seal to a
//! public key" / "open with a private key" wrappers built as thin
//! compositions over that same `setup*`/`Context` pair. `Context.seal`/
//! `.open` (§5.2) serve repeated messages; `Context.exportSecret` (§5.3)
//! lets higher-level protocols derive their own keys from an HPKE exchange
//! without ever sealing a message through it (e.g. MLS/RFC 9420's
//! external-init and external-commit, §8.3/§12.4).
//!
//! Three DHKEMs: `X25519Kem`, `P256Kem` (curve group from the local
//! asm-accelerated `p256` module) and `P384Kem` (curve group from
//! `std.crypto.ecc.P384` directly — no local perf-specialized sibling
//! exists for P-384, see `dhkem.zig`'s module doc comment). RFC 9180
//! Appendix A publishes no worked test-vector section for DHKEM(P-384,
//! HKDF-SHA384) — `P384Kem` is anchored by type widths, self-consistency
//! round trips and malformed-input rejection instead; see `dhkem.zig` and
//! SPEC.md.
//!
//! **Status: crypto-implementation pass DONE — every core is real and
//! KAT-validated** against RFC 9180 Appendix A, byte-exact, in ALL FOUR
//! modes:
//!
//! | Mode | Vectors driven end-to-end |
//! |---|---|
//! | `base` (0x00) | A.1.1 (full: DeriveKeyPair, Encap/Decap, key schedule, all 6 encryption tuples, all 3 exports, single-shot `sealBase`/`openBase`) + A.2/A.3 headers |
//! | `psk` (0x01) | A.1.2 (full) + A.3.2 (P-256) |
//! | `auth` (0x02) | A.1.3 (full) + A.3.3 (P-256) |
//! | `auth_psk` (0x03) | A.1.4 (full) + A.3.4 (P-256) |
//!
//! | File | What it provides |
//! |---|---|
//! | `suite.zig` | Suite/KEM id constants, `Mode`, `I2OSP`/`OS2IP`, `suite_id`/`kem_suite_id` construction, `LabeledExtract`/`LabeledExpand` (§4) |
//! | `dhkem.zig` | `X25519Kem`/`P256Kem`: `Encap`/`Decap`/`AuthEncap`/`AuthDecap`/`DeriveKeyPair`/`generateKeyPair` (§4.1/§7.1.1-§7.1.3) |
//! | `schedule.zig` | `KeySchedule` (§5.1), `Context.seal`/`.open`/`.exportSecret` (§5.2/§5.3), `computeNonce`/`incrementSeq`, §5.1's `setupBaseS`/`setupPskS`/`setupAuthS`/`setupAuthPskS` + their `setup*R` mirrors (return the `Context` itself), and §6.1's single-shot `sealBase`/`sealPsk`/`sealAuth`/`sealAuthPsk` + their `open*` mirrors (thin compositions over `setup*` + one `Context.seal`/`.open`) |
//! | `kat_rfc9180.zig` | RFC 9180 Appendix A known-answer vectors (A.1 all four modes, A.2/A.3 headers, A.3 all three non-base modes), driven end-to-end |
//!
//! The `auth`/`auth_psk` KEM folds (`AuthEncap`/`AuthDecap`) are anchored
//! to the RFC's own published `enc`/`shared_secret` for BOTH KEMs — not
//! merely round-trip-tested, which cannot detect a misreading the sender
//! and recipient share. See `SPEC.md` for the full threat model, including
//! the one place this module is deliberately stricter than RFC 9180 (§5.1.2's
//! PSK-length floor, enforced as `error.PskTooShort`).
//!
//! Provenance: clean-room from RFC 9180 (a public IETF specification, not
//! copyrightable expression — see CONVENTIONS.md §5's merger-doctrine
//! note, so no NOTICE entry is strictly required for the RFC citation
//! alone; this module names no third-party implementation as a design
//! reference, so `NOTICE` carries only the RFC 9180 citation). Built
//! entirely on `std.crypto` (`std.crypto.dh.X25519`, `std.crypto.ecc.P256`,
//! `std.crypto.ecc.P384` (`P384Kem`'s group — no local perf module for
//! P-384, see `dhkem.zig`), `std.crypto.kdf.hkdf.HkdfSha256`/`.HkdfSha512`/`.Hkdf` — the key-schedule
//! KDF is `Nh`-dispatched across all three RFC 9180 widths, `schedule.
//! KdfOf` — `std.crypto.aead.aes_gcm.{Aes128Gcm, Aes256Gcm}`,
//! `std.crypto.aead.chacha_poly.ChaCha20Poly1305`).

const std = @import("std");
const chachapoly = @import("chachapoly");

pub const suite = @import("suite.zig");
pub const dhkem = @import("dhkem.zig");
pub const schedule = @import("schedule.zig");

pub const KemId = suite.KemId;
pub const KdfId = suite.KdfId;
pub const AeadId = suite.AeadId;
pub const Mode = suite.Mode;

pub const X25519Kem = dhkem.X25519Kem;
pub const P256Kem = dhkem.P256Kem;
pub const P384Kem = dhkem.P384Kem;

pub const Context = schedule.Context;
pub const keySchedule = schedule.keySchedule;

/// RFC 9180 Table 5 `aead_id = 0x0003` (ChaCha20Poly1305) — the SIMD
/// `chachapoly` sibling, byte-exact to `std.crypto.aead.chacha_poly.
/// ChaCha20Poly1305`. Re-exported as this module's RECOMMENDED binding for
/// the ChaCha suite; nothing here hard-wires an AEAD (every entry point takes
/// it as a comptime parameter), so std's type stays equally bindable and both
/// map to the same registered `aead_id` — the choice cannot reach the wire.
/// The RFC 9180 A.2 vectors are run under both (`kat_rfc9180.zig`).
///
/// The AES-GCM suites have no sibling implementation and come from std;
/// reach them as `std.crypto.aead.aes_gcm.Aes128Gcm` / `.Aes256Gcm`.
pub const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

// RFC 9180 §5.1's `Setup*S`/`Setup*R` pairs, one per mode — the
// multi-message counterpart to §6.1's single-shot `Seal*`/`Open*` pairs
// below: returns the `Context` itself (plus `enc`, for the sender) instead
// of consuming it for one `Seal`/`Open`. This is what a protocol layered
// over HPKE that wants ONLY `Context.exportSecret` (e.g. MLS's
// external-init/external-commit, RFC 9420 §8.3/§12.4 — derive an
// `init_secret`, never seal/open a message through the HPKE context
// itself) needs instead of the single-shot wrappers. The `*Deterministic`
// variants stay behind `schedule.` for the same reason `sealBaseDeterministic`
// etc. do below.
pub const Setup = schedule.Setup;
pub const setupBaseS = schedule.setupBaseS;
pub const setupBaseR = schedule.setupBaseR;
pub const setupPskS = schedule.setupPskS;
pub const setupPskR = schedule.setupPskR;
pub const setupAuthS = schedule.setupAuthS;
pub const setupAuthR = schedule.setupAuthR;
pub const setupAuthPskS = schedule.setupAuthPskS;
pub const setupAuthPskR = schedule.setupAuthPskR;

// RFC 9180 §6.1's single-shot `Seal*`/`Open*` pairs, one per mode. The
// `*Deterministic` variants (ephemeral keypair injected instead of drawn
// from `io`) stay behind `schedule.` — they exist for the Appendix A KATs,
// and reusing an ephemeral key across calls voids HPKE's security argument,
// so they are deliberately not re-exported at the top level.
pub const sealBase = schedule.sealBase;
pub const openBase = schedule.openBase;
pub const sealPsk = schedule.sealPsk;
pub const openPsk = schedule.openPsk;
pub const sealAuth = schedule.sealAuth;
pub const openAuth = schedule.openAuth;
pub const sealAuthPsk = schedule.sealAuthPsk;
pub const openAuthPsk = schedule.openAuthPsk;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "HPKE — Hybrid Public Key Encryption (RFC 9180): DHKEM(X25519/P-256) encap/decap, all four key-schedule modes, AEAD seal/open + export.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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
    // p256: the DHKEM(P-256) group from the asm-accelerated p256 (byte-exact
    // to std.crypto.ecc.P256); the X25519 KEM path stays on std.
    // chachapoly: the RFC 9180 Table 5 `aead_id = 0x0003` AEAD (byte-exact to
    // std). Both are implementation choices behind comptime parameters — no
    // wire byte depends on either.
    // entropy: the `random(Nsk)` in each KEM's `generateKeyPair`, i.e. the
    // ephemeral key behind every `sealBase`/`sealPsk`/`sealAuth`/`encap`.
    .deps = .{ "p256", "chachapoly", "entropy" },
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

test "meta.deps is exactly {p256, chachapoly, entropy} (the P-256 group + the ChaCha AEAD + the fail-closed key draw; else std only)" {
    try std.testing.expectEqual(@as(usize, 3), meta.deps.len);
    try std.testing.expectEqualStrings("p256", meta.deps[0]);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[1]);
    // `entropy` is the `random(Nsk)` in RFC 9180 §4's `GenerateKeyPair() =
    // DeriveKeyPair(random(Nsk))`, i.e. the sender's ephemeral key in every
    // mode. Unlike the two above it is NOT an inert swap: dropping it puts
    // that key back on `io.random`'s silent-degrade path.
    try std.testing.expectEqualStrings("entropy", meta.deps[2]);
}

test "the ChaCha AEAD swap is inert: chachapoly and std agree on every RFC 9180 Nk/Nn/Nt" {
    const Std = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    try std.testing.expectEqual(Std.key_length, ChaCha20Poly1305.key_length); // Nk = 32
    try std.testing.expectEqual(Std.nonce_length, ChaCha20Poly1305.nonce_length); // Nn = 12
    try std.testing.expectEqual(Std.tag_length, ChaCha20Poly1305.tag_length); // Nt = 16
}

test "meta.role is .util (no owned transport/socket, unlike a .client/.server module)" {
    try std.testing.expectEqual(.util, meta.role);
}

test "KemId/KdfId/AeadId ordinals match RFC 9180 Tables 2/3/5" {
    try std.testing.expectEqual(@as(u16, 0x0020), @intFromEnum(KemId.dhkem_x25519_hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0010), @intFromEnum(KemId.dhkem_p256_hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0011), @intFromEnum(KemId.dhkem_p384_hkdf_sha384));
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(KdfId.hkdf_sha256));
    try std.testing.expectEqual(@as(u16, 0x0001), @intFromEnum(AeadId.aes128gcm));
    try std.testing.expectEqual(@as(u16, 0x0002), @intFromEnum(AeadId.aes256gcm));
    try std.testing.expectEqual(@as(u16, 0x0003), @intFromEnum(AeadId.chacha20poly1305));
    try std.testing.expectEqual(@as(u16, 0xffff), @intFromEnum(AeadId.export_only));
}
