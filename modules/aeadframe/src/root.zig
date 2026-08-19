// SPDX-License-Identifier: MIT

//! aeadframe — a per-key AEAD record/frame layer: seal/open messages under one
//! key with a monotonic counter nonce (never reused), epoch-based rekey, a
//! sliding-window anti-replay filter, and AAD binding (context/tenant). Generic
//! over the AEAD — ChaCha20-Poly1305 (via the `chachapoly` sibling) and
//! AES-256-GCM (via std). Distilled from the IPsec ESP / DTLS 1.3 record layer:
//! the KEY ESTABLISHMENT (Noise/HPKE/X25519 handshake) is OUT OF SCOPE — the
//! 32-byte key is an input, supplied by a caller/future module.
//!
//! The motivating consumer is per-tenant L2VPN confidentiality: one `Channel` per
//! I-SID (the I-SID → channel map is the orchestrator's glue), giving
//! cryptographic tenant isolation over the shared encrypted backbone. The `aad`
//! argument is the tenant/context binding — a record opens only against the
//! identical `aad`.
//!
//! ## Usage
//!
//! ```zig
//! const af = @import("aeadframe");
//! var s = af.ChaChaChannel.Sealer.init(key, 0); // epoch 0
//! var o = af.ChaChaChannel.Opener.init(key, 0);
//! var rec: [af.ChaChaChannel.Sealer.sealedLen(msg.len)]u8 = undefined;
//! const n = try s.seal(&rec, msg, "tenant-A"); // aad = tenant binding
//! var pt: [msg.len]u8 = undefined;
//! const m = try o.open(&pt, rec[0..n], "tenant-A");
//! ```
//!
//! `AesGcmChannel` is the drop-in FIPS/compliance instantiation with the same
//! API. Both are zero-allocation (caller supplies the output buffers).

const std = @import("std");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // pure computation over caller buffers, no I/O
    .concurrency = .single_owner, // one owner per Sealer/Opener; lock-free
    .model_after = "IPsec ESP / DTLS 1.3 record layer (seq nonce + replay window + epoch rekey)",
    .deps = .{"chachapoly"},
};

// ── public API ────────────────────────────────────────────────────────────────

const channel = @import("channel.zig");
pub const record = @import("record.zig");
pub const replay = @import("replay.zig");

/// Build a record channel over any std/`chachapoly`-shaped AEAD
/// (32-byte key, 12-byte nonce, 16-byte tag).
pub const Channel = channel.Channel;

/// ChaCha20-Poly1305 record channel (via the `chachapoly` sibling).
pub const ChaChaChannel = channel.ChaChaChannel;
/// AES-256-GCM record channel (via std) — FIPS/compliance instantiation.
pub const AesGcmChannel = channel.AesGcmChannel;

pub const ChaChaSealer = channel.ChaChaSealer;
pub const ChaChaOpener = channel.ChaChaOpener;
pub const AesGcmSealer = channel.AesGcmSealer;
pub const AesGcmOpener = channel.AesGcmOpener;

pub const SealError = channel.SealError;
pub const EpochError = channel.EpochError;
pub const OpenError = channel.OpenError;

pub const ReplayWindow = replay.ReplayWindow;
pub const version = record.version;
pub const overhead = record.overhead;

// Pull every submodule's tests into the module test binary (the dark-tests
// rule — a bare re-export does not).
test {
    _ = channel;
    _ = record;
    _ = replay;
}
