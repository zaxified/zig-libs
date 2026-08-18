// SPDX-License-Identifier: MIT

//! tlsresume — server-side TLS 1.3 session-ticket resumption (RFC 8446
//! §4.2.11 / §4.6.1 / §7.1 / §8): the piece this collection's `dtls` module
//! (and the vendored `ianic/tls.zig` client-only implementation this
//! module studies as a design reference) both lack on the SERVER side. This
//! module is **engine-agnostic**: it never owns a TLS state machine, never
//! parses a ClientHello/ServerHello, and never touches a socket — the TLS
//! engine passes in already-computed transcript-hash bytes and secrets, and
//! this module returns derived keys / accept-reject decisions / wire bytes.
//! That split mirrors `dtls.keyschedule`/`dtls.aead` (pure crypto/codec over
//! caller-supplied bytes, no I/O) rather than `dtls.Connection` (which DOES
//! own connection state).
//!
//! **Status: fully implemented — codec, bookkeeping, and crypto all REAL,
//! KAT-validated against RFC 8448.** The module landed in two passes
//! following this repo's `dtls`/`noise` precedent (framing/bookkeeping
//! scaffold first, then a dedicated crypto-implementation pass):
//!
//! | File | What it provides |
//! |---|---|
//! | `ticket.zig` | `NewSessionTicket` encode/decode (RFC 8446 §4.6.1) — pure wire codec, KAT-validated byte-for-byte against RFC 8448 §3's real NewSessionTicket message |
//! | `stek.zig` | STEK ring (`rotate`/`findKey`/`activeKey` bookkeeping, no key generation) + `seal`/`open` (AES-256-GCM ticket-blob AEAD, key id bound as AAD) |
//! | `psk.zig` | `derivePsk`/`earlySecret`/`binderKey`/`computeBinder`/`verifyBinder` (RFC 8446 §7.1/§4.2.11.2 HKDF/HMAC chain, byte-exact vs RFC 8448 §4) |
//! | `earlydata.zig` | 0-RTT early-data key schedule (RFC 8446 §7.1 early branch + §7.3): `clientEarlyTrafficSecret`/`earlyExporterMasterSecret`/`earlyTrafficKeyIv` + `EarlyDataContext` convenience — byte-exact vs RFC 8448 §4's 0-RTT trace, incl. opening its real encrypted early-data record |
//! | `replay.zig` | `obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow` (RFC 8446 §4.2.11.1) + `StrikeRegister` (RFC 8446 §8/§8.1 bounded single-use anti-replay) |
//! | `select.zig` | `SessionState(rms_len)` (de)serialization (this module's own STEK-plaintext layout) + `selectPsk` (the server-side §4.2.11 selection loop composing all of the above) |
//!
//! `psk.zig` remains the highest-severity file: a wrong or skipped PSK
//! binder check is a full resumption-PSK-splicing vulnerability (RFC 8446
//! §4.2.11.2). See SPEC.md's threat model.
//!
//! **Recon: `std.crypto.tls.hkdfExpandLabel` is directly reusable here.**
//! Unlike `dtls` (DTLS 1.3, which needs the `"dtls13"` label prefix RFC
//! 9147 §5.9 mandates instead of TLS's `"tls13 "`), `tlsresume` targets
//! plain TLS 1.3, for which std's hardcoded `"tls13 "` prefix is exactly
//! correct (RFC 8446 §7.1) — NOT a std gap, see `psk.zig`'s module doc for
//! the detail. Zig 0.16 ships no AES key-wrap/session-cache/ticket-codec
//! primitives, so `stek.zig`/`ticket.zig` are this module's own.
//!
//! Provenance: clean-room from RFC 8446 §4.2.11/§4.2.11.1/§4.2.11.2/§4.6.1/
//! §7.1/§8 (all public IETF specification text — not copyrightable
//! expression per CONVENTIONS.md §5's merger-doctrine note, so no NOTICE
//! entry is strictly required for the RFC citations alone). Design
//! reference (studied for the exact client-side label/wire shapes a
//! compliant server must match, no source copied): `ianic/tls.zig`'s
//! `transcript.zig` (`setPreSharedSecret`, `resumptionSecret`, `pskBinder`,
//! `pskBinder_`) and `handshake_client.zig` (`Options.SessionResumption.
//! Ticket.obfuscatedAge`, `makeClientHello`'s `preSharedKey`/
//! `preSharedKeyBinder` wire construction) — see `NOTICE` and README.md.

const std = @import("std");

pub const stek = @import("stek.zig");
pub const ticket = @import("ticket.zig");
pub const psk = @import("psk.zig");
pub const earlydata = @import("earlydata.zig");
pub const replay = @import("replay.zig");
pub const select = @import("select.zig");

pub const StekRing = stek.StekRing;
pub const NewSessionTicket = ticket.NewSessionTicket;
pub const StrikeRegister = replay.StrikeRegister;
pub const EarlyDataContext = earlydata.EarlyDataContext;

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    // Server-side only, by design (RFC 8446 §4.2.11/§4.6.1 resumption is
    // symmetric in principle, but the client half already exists —
    // `ianic/tls.zig`'s `transcript.zig`/`handshake_client.zig` — and this
    // module exists specifically to fill the SERVER gap `dtls`'s SPEC.md
    // and this collection's client-only vendored TLS both declare).
    .role = .server,
    // Every exported type (StekRing, StrikeRegister) is a plain caller-owned
    // value with no internal locking, like `dtls.Connection` and `ssh.
    // Transport; the free functions (psk.zig, replay.zig, ticket.zig) touch
    // no shared/global state at all.
    .concurrency = .single_owner,
    .model_after = "RFC 8446 §4.2.11/§4.2.11.1/§4.2.11.2/§4.6.1/§7.1/§8 (TLS 1.3 session resumption + PSK binder + anti-replay); design ref ianic/tls.zig transcript.zig/handshake_client.zig (client-side label/wire shapes studied, no source copied)",
    .deps = .{}, // std only
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s
// tests into the test binary on its own — every submodule must be named
// here too (the dtls/noise/ssh precedent this module follows).
test {
    _ = stek;
    _ = ticket;
    _ = psk;
    _ = earlydata;
    _ = replay;
    _ = select;
}

test "meta.deps is empty (std only, no sibling-module dependencies)" {
    try std.testing.expectEqual(@as(usize, 0), meta.deps.len);
}

test "meta.role is .server (client-side resumption already exists elsewhere)" {
    try std.testing.expectEqual(.server, meta.role);
}
