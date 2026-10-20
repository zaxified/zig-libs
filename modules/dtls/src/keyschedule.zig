// SPDX-License-Identifier: MIT

//! dtls.keyschedule — the RFC 9147 §5.8 / RFC 8446 §7.1 key schedule for DTLS
//! 1.3, under the names this module has always exported. Since 2026-10-20 the
//! schedule itself lives in the `tls13` module (`tls13.keyschedule`, one
//! `Schedule(prefix)` instance per protocol); this file binds the `dtls13`
//! instance (the `"dtls13"` HKDF-Expand-Label prefix, RFC 9147 §5.9) to the
//! old names, so `Connection.zig` and every consumer of `dtls.keyschedule`
//! are unchanged. The KATs (RFC 8448 with `tls13 `, an independent oracle with
//! `dtls13`) moved with the code. Only `deriveSequenceNumberKey` — DTLS's
//! record-number masking key, with no TLS 1.3 counterpart — is defined here.

const std = @import("std");
const ks = @import("tls13").keyschedule;
const S = ks.dtls13;

/// RFC 8446 §7.1 HKDF-Expand-Label prefix (TLS 1.3).
pub const tls13_prefix = ks.tls13_prefix;
/// RFC 9147 §5.9 HKDF-Expand-Label prefix (DTLS 1.3) — no trailing space.
pub const dtls13_prefix = ks.dtls13_prefix;

pub const expandLabel = ks.expandLabel;
pub const hkdfExpandLabel = S.hkdfExpandLabel;
pub const deriveSecret = S.deriveSecret;
pub const earlySecret = S.earlySecret;
pub const binderKey = S.binderKey;
pub const pskBinder = S.pskBinder;
pub const deriveHandshakeSecret = S.deriveHandshakeSecret;
pub const deriveHandshakeTrafficSecrets = S.deriveHandshakeTrafficSecrets;
pub const deriveMasterSecret = S.deriveMasterSecret;
pub const deriveApplicationTrafficSecrets = S.deriveApplicationTrafficSecrets;
pub const deriveFinishedKey = S.deriveFinishedKey;
pub const computeFinishedVerifyData = S.computeFinishedVerifyData;
pub const deriveTrafficKeyIv = S.deriveTrafficKeyIv;

/// RFC 9147 §4.2.3: `sn_key = HKDF-Expand-Label(Secret, "sn", "",
/// key_length)` — the key for the sequence-number-masking keystream
/// (`aead.encryptSequenceNumber*`). DTLS-specific; no TLS 1.3 equivalent.
pub fn deriveSequenceNumberKey(
    comptime Hkdf: type,
    comptime key_len: usize,
    out: *[key_len]u8,
    traffic_secret: *const [Hkdf.prk_length]u8,
) void {
    S.hkdfExpandLabel(Hkdf, key_len, out, traffic_secret, "sn", "");
}

test "deriveSequenceNumberKey: the RFC 9147 sn key of the independent-oracle schedule" {
    // Same vector as tls13's "DTLS13 prefix: full psk_ke schedule" test (PSK
    // 0x01..0x20, psk_ke, server handshake traffic secret).
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    var hs_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hs_secret, "6e663c1527a961cf462bd3d1e674f00acd5f7679d6566c68823e3a27fc071d60");
    var snk: [16]u8 = undefined;
    deriveSequenceNumberKey(HkdfSha256, 16, &snk, &hs_secret);
    var want: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "a5c0ea3a852584f23e5fab16dab5d753");
    try std.testing.expectEqualSlices(u8, &want, &snk);
}
