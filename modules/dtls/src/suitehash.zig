// SPDX-License-Identifier: MIT

//! dtls.suitehash — the negotiated suite's hash (RFC 8446 §7.1), chosen at
//! RUNTIME. Every secret, transcript hash and Finished MAC of a DTLS 1.3
//! handshake is `Hash.length` bytes for the suite's hash: 32 for the
//! `_sha256` suites, 48 for `aes_256_gcm_sha384`. They are stored in
//! `max_hash_len` buffers (`Secret`) and handed to the comptime-typed key
//! schedule (`keyschedule.zig`, i.e. `tls13.keyschedule`) through the
//! runtime-dispatching wrappers here, one `inline else` switch each, sliced
//! to `HashAlg.len()`.
//!
//! The transcript is the one place the hash cannot be known up front: a
//! client offering suites of both hashes learns which one applies only from
//! the ServerHello (or a HelloRetryRequest), so `Transcript` runs SHA-256
//! and SHA-384 side by side until `select` drops the other one.

const std = @import("std");
const keyschedule = @import("keyschedule.zig");
const tls13_transcript = @import("tls13").transcript;

/// The hash of a TLS 1.3 / DTLS 1.3 cipher suite.
pub const HashAlg = enum {
    sha256,
    sha384,

    /// `Hash.length` (RFC 8446 §7.1).
    pub fn len(self: HashAlg) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
        };
    }
};

/// The longest `Hash.length` of any wired suite.
pub const max_hash_len = 48;
/// A secret / hash / MAC of the suite's hash, in a `max_hash_len` buffer:
/// only the first `HashAlg.len()` bytes are live.
pub const Secret = [max_hash_len]u8;

const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);

/// The comptime primitives of `alg`.
pub fn Types(comptime alg: HashAlg) type {
    return switch (alg) {
        .sha256 => struct {
            pub const Hash = Sha256;
            pub const Hkdf = HkdfSha256;
            pub const Hmac = HmacSha256;
            pub const n = 32;
        },
        .sha384 => struct {
            pub const Hash = Sha384;
            pub const Hkdf = HkdfSha384;
            pub const Hmac = HmacSha384;
            pub const n = 48;
        },
    };
}

/// `Hash("")`, RFC 8446 §7.1's empty transcript hash.
pub fn emptyHash(alg: HashAlg) []const u8 {
    return switch (alg) {
        inline else => |a| @import("tls13").keyschedule.emptyTranscriptHash(Types(a).Hash),
    };
}

/// `Hash.length` zero bytes: RFC 8446 §7.1's PSK input when there is no PSK.
pub fn zeros(alg: HashAlg) []const u8 {
    const z = comptime @as(Secret, @splat(0));
    return z[0..alg.len()];
}

pub fn earlySecret(alg: HashAlg, out: *Secret, psk: []const u8) void {
    switch (alg) {
        inline else => |a| keyschedule.earlySecret(Types(a).Hkdf, out[0..Types(a).n], psk),
    }
}

pub fn binderKey(alg: HashAlg, out: *Secret, early_secret: *const Secret) void {
    switch (alg) {
        inline else => |a| keyschedule.binderKey(Types(a).Hkdf, out[0..Types(a).n], early_secret[0..Types(a).n], emptyHash(a)),
    }
}

/// RFC 8446 §4.2.11.2 binder over `truncated_hash`; returns `out`'s live part.
pub fn pskBinder(alg: HashAlg, out: *Secret, binder_key: *const Secret, truncated_hash: []const u8) []const u8 {
    switch (alg) {
        inline else => |a| {
            const T = Types(a);
            keyschedule.pskBinder(T.Hkdf, T.Hmac, out[0..T.n], binder_key[0..T.n], truncated_hash);
            return out[0..T.n];
        },
    }
}

pub fn deriveHandshakeSecret(alg: HashAlg, out: *Secret, early_secret: *const Secret, dhe: ?[]const u8) void {
    switch (alg) {
        inline else => |a| keyschedule.deriveHandshakeSecret(Types(a).Hkdf, out[0..Types(a).n], early_secret[0..Types(a).n], emptyHash(a), dhe),
    }
}

pub fn deriveHandshakeTrafficSecrets(alg: HashAlg, client: *Secret, server: *Secret, handshake_secret: *const Secret, th: []const u8) void {
    switch (alg) {
        inline else => |a| keyschedule.deriveHandshakeTrafficSecrets(Types(a).Hkdf, client[0..Types(a).n], server[0..Types(a).n], handshake_secret[0..Types(a).n], th),
    }
}

pub fn deriveMasterSecret(alg: HashAlg, out: *Secret, handshake_secret: *const Secret) void {
    switch (alg) {
        inline else => |a| keyschedule.deriveMasterSecret(Types(a).Hkdf, out[0..Types(a).n], handshake_secret[0..Types(a).n], emptyHash(a)),
    }
}

pub fn deriveApplicationSecrets(alg: HashAlg, client: *Secret, server: *Secret, exporter: *Secret, master_secret: *const Secret, th: []const u8) void {
    switch (alg) {
        inline else => |a| keyschedule.deriveApplicationSecrets(Types(a).Hkdf, client[0..Types(a).n], server[0..Types(a).n], exporter[0..Types(a).n], master_secret[0..Types(a).n], th),
    }
}

/// RFC 8446 §4.4.4: `HMAC(finished_key(traffic_secret), th)` into `out`;
/// returns its live part. The finished key is wiped.
pub fn finishedVerifyData(alg: HashAlg, out: *Secret, traffic_secret: *const Secret, th: []const u8) []const u8 {
    switch (alg) {
        inline else => |a| {
            const T = Types(a);
            var fk: [T.n]u8 = undefined;
            defer std.crypto.secureZero(u8, &fk);
            keyschedule.deriveFinishedKey(T.Hkdf, T.n, &fk, traffic_secret[0..T.n]);
            keyschedule.computeFinishedVerifyData(T.Hmac, out[0..T.n], &fk, th);
            return out[0..T.n];
        },
    }
}

/// RFC 8446 §7.2: `secret` becomes `application_traffic_secret_N+1`.
pub fn nextApplicationTrafficSecret(alg: HashAlg, secret: *Secret) void {
    switch (alg) {
        inline else => |a| keyschedule.nextApplicationTrafficSecret(Types(a).Hkdf, secret[0..Types(a).n], secret[0..Types(a).n]),
    }
}

/// RFC 8446 §7.3 key + iv and RFC 9147 §4.2.3 sn key at the suite's widths
/// (`key_len`/`sn_len` 16 or 32 — the callers' `SuiteParams` hold nothing
/// else).
pub fn deriveTrafficKeys(
    alg: HashAlg,
    key_len: u8,
    sn_len: u8,
    key: *[32]u8,
    iv: *[12]u8,
    sn_key: *[32]u8,
    traffic_secret: *const Secret,
) void {
    switch (alg) {
        inline else => |a| {
            const T = Types(a);
            const s = traffic_secret[0..T.n];
            // HKDF-Expand-Label's length is part of its input, so a 16-byte
            // key is NOT a prefix of a 32-byte one: expand at the exact width.
            switch (key_len) {
                16 => keyschedule.deriveTrafficKeyIv(T.Hkdf, 16, 12, key[0..16], iv, s),
                else => keyschedule.deriveTrafficKeyIv(T.Hkdf, 32, 12, key[0..32], iv, s),
            }
            switch (sn_len) {
                16 => keyschedule.deriveSequenceNumberKey(T.Hkdf, 16, sn_key[0..16], s),
                else => keyschedule.deriveSequenceNumberKey(T.Hkdf, 32, sn_key[0..32], s),
            }
        },
    }
}

/// The longest exporter output under `alg` (255 HKDF blocks).
pub fn maxExporterLen(alg: HashAlg) usize {
    return switch (alg) {
        inline else => |a| keyschedule.maxExporterLen(Types(a).Hkdf),
    };
}

/// Constant-time equality of the `alg`-length MAC `expected` and the
/// received `got` (false on a length mismatch — the length is public).
pub fn macEql(alg: HashAlg, expected: []const u8, got: []const u8) bool {
    if (got.len != alg.len() or expected.len != alg.len()) return false;
    return switch (alg) {
        inline else => |a| std.crypto.timing_safe.eql([Types(a).n]u8, expected[0..Types(a).n].*, got[0..Types(a).n].*),
    };
}

/// RFC 8446 §4.4.1's running transcript under both suite hashes until
/// `select` names one (the ServerHello's suite, or the HelloRetryRequest's).
/// The hashes are over public handshake bytes, not secrets.
pub const Transcript = struct {
    t256: tls13_transcript.Transcript(Sha256) = .{},
    t384: tls13_transcript.Transcript(Sha384) = .{},
    /// `null` while both run.
    alg: ?HashAlg = null,

    /// Commits one handshake message (see `tls13.transcript.Transcript`).
    pub fn append(self: *Transcript, msg_type: u8, body: []const u8) void {
        if (self.alg != .sha384) self.t256.append(msg_type, body);
        if (self.alg != .sha256) self.t384.append(msg_type, body);
    }

    /// From now on only `alg` runs.
    pub fn select(self: *Transcript, alg: HashAlg) void {
        self.alg = alg;
    }

    /// The `alg` transcript hash so far, into `out`; returns its live part.
    pub fn currentHash(self: *const Transcript, alg: HashAlg, out: *Secret) []const u8 {
        switch (alg) {
            .sha256 => out[0..32].* = self.t256.currentHash(),
            .sha384 => out[0..48].* = self.t384.currentHash(),
        }
        return out[0..alg.len()];
    }

    /// RFC 8446 §4.2.11.2's binder hash (see `tls13`'s `wouldBeHash`).
    pub fn wouldBeHash(self: *const Transcript, alg: HashAlg, msg_type: u8, full_len: usize, partial_body: []const u8, out: *Secret) []const u8 {
        switch (alg) {
            .sha256 => out[0..32].* = self.t256.wouldBeHash(msg_type, full_len, partial_body),
            .sha384 => out[0..48].* = self.t384.wouldBeHash(msg_type, full_len, partial_body),
        }
        return out[0..alg.len()];
    }

    /// RFC 8446 §4.4.1's `message_hash` rewrite under `alg` (the
    /// HelloRetryRequest's suite hash), which also selects `alg`.
    /// `client_hello1_hash.len` must be `alg.len()`.
    pub fn resetToMessageHash(self: *Transcript, alg: HashAlg, client_hello1_hash: []const u8) void {
        self.select(alg);
        switch (alg) {
            .sha256 => self.t256.resetToMessageHash(client_hello1_hash[0..32].*),
            .sha384 => self.t384.resetToMessageHash(client_hello1_hash[0..48].*),
        }
    }
};

const testing = std.testing;

test "suitehash: Transcript runs both hashes until select, then only the selected one" {
    var t = Transcript{};
    t.append(1, "client hello");
    var a = tls13_transcript.Transcript(Sha256){};
    var b = tls13_transcript.Transcript(Sha384){};
    a.append(1, "client hello");
    b.append(1, "client hello");
    var buf: Secret = undefined;
    try testing.expectEqualSlices(u8, &a.currentHash(), t.currentHash(.sha256, &buf));
    try testing.expectEqualSlices(u8, &b.currentHash(), t.currentHash(.sha384, &buf));
    t.select(.sha384);
    t.append(2, "server hello");
    b.append(2, "server hello");
    try testing.expectEqualSlices(u8, &b.currentHash(), t.currentHash(.sha384, &buf));
    // The dropped hash no longer advances.
    try testing.expectEqualSlices(u8, &a.currentHash(), t.currentHash(.sha256, &buf));
}

test "suitehash: resetToMessageHash under SHA-384 is tls13's SHA-384 rewrite" {
    var ch1: [48]u8 = undefined;
    Sha384.hash("ch1", &ch1, .{});
    var t = Transcript{};
    t.append(1, "ch1");
    t.resetToMessageHash(.sha384, &ch1);
    var ref = tls13_transcript.Transcript(Sha384){};
    ref.resetToMessageHash(ch1);
    var buf: Secret = undefined;
    try testing.expectEqualSlices(u8, &ref.currentHash(), t.currentHash(.sha384, &buf));
    try testing.expectEqual(@as(?HashAlg, .sha384), t.alg);
}

test "suitehash: emptyHash and zeros have the suite's length" {
    var h: [48]u8 = undefined;
    Sha384.hash("", &h, .{});
    try testing.expectEqualSlices(u8, &h, emptyHash(.sha384));
    try testing.expectEqual(@as(usize, 32), emptyHash(.sha256).len);
    try testing.expectEqual(@as(usize, 48), zeros(.sha384).len);
}

test "suitehash: macEql refuses a wrong length instead of slicing past it" {
    const x = @as(Secret, @splat(7));
    try testing.expect(macEql(.sha384, x[0..48], x[0..48]));
    try testing.expect(!macEql(.sha384, x[0..48], x[0..32]));
    try testing.expect(!macEql(.sha256, x[0..32], x[0..48]));
}

test "suitehash: the SHA-384 schedule wrappers equal the comptime schedule" {
    const T = Types(.sha384);
    const psk = "external psk bytes";
    var es: Secret = undefined;
    earlySecret(.sha384, &es, psk);
    var es_ref: [48]u8 = undefined;
    keyschedule.earlySecret(T.Hkdf, &es_ref, psk);
    try testing.expectEqualSlices(u8, &es_ref, es[0..48]);
    var hs: Secret = undefined;
    deriveHandshakeSecret(.sha384, &hs, &es, null);
    var hs_ref: [48]u8 = undefined;
    keyschedule.deriveHandshakeSecret(T.Hkdf, &hs_ref, &es_ref, emptyHash(.sha384), null);
    try testing.expectEqualSlices(u8, &hs_ref, hs[0..48]);
    var s = hs;
    nextApplicationTrafficSecret(.sha384, &s);
    var s_ref: [48]u8 = undefined;
    keyschedule.nextApplicationTrafficSecret(T.Hkdf, &s_ref, &hs_ref);
    try testing.expectEqualSlices(u8, &s_ref, s[0..48]);
}
