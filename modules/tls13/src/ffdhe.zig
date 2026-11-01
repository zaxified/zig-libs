// SPDX-License-Identifier: MIT

//! tls13.ffdhe -- the finite-field DH named groups ffdhe2048 .. ffdhe8192
//! (RFC 7919 Appendix A; TLS 1.3 code points 0x0100..0x0104, RFC 8446 §4.2.7),
//! the arithmetic behind the `kex` entry points for those groups.
//!
//! * Group: the RFC 7919 safe prime p (`ffdhe_params.zig`), g = 2, q = (p-1)/2.
//! * Private exponent: `xbits` random bits, uniform in [1, 2^xbits - 1], with the
//!   lengths OpenSSL uses for these named groups (225 / 275 / 325 / 375 / 400 bits;
//!   `crypto/ffc/ffc_dh.c`, `FFDHE(sz, keylength)`; RFC 7919 §5.2 asks for at
//!   least 225 / 275 / 325 / 375 / 400).
//! * Public value Y = g^x mod p, big-endian, LEFT-padded to len(p) (RFC 8446
//!   §4.2.8.1).
//! * Peer check (RFC 8446 §4.2.8.1, RFC 7919 §5.1; OpenSSL `DH_check_pub_key` for
//!   a safe-prime group): length exactly len(p), 1 < Y < p-1, Y^q = 1 (mod p).
//! * Shared secret Z = Y^x mod p, left-padded to len(p), leading zeros KEPT
//!   (RFC 8446 §7.4.1).
//!
//! The arithmetic is `montint.DynModint`: `pow` (constant-time in base and
//! exponent) for every operation on the private exponent, `powPublic`
//! (variable-time in a PUBLIC exponent) only for Y^q. Nothing here branches on
//! x or Z.

const std = @import("std");
const montint = @import("montint");
const params = @import("ffdhe_params.zig");

/// One modulus type for all five groups: the slots 32 / 48 / 64 / 96 / 128
/// limbs are exact for 2048 / 3072 / 4096 / 6144 / 8192 bits.
pub const Dyn = montint.DynModint(8192);

pub const Error = error{
    /// The peer value failed the check, or the exponent is unusable (zero), or
    /// the RNG produced 64 zero exponents in a row.
    KeyExchangeFailed,
    /// The peer value is not len(p) bytes long.
    MissingKeyShare,
};

pub const Info = struct {
    /// RFC 8446 §4.2.7 NamedGroup code point.
    code: u16,
    /// The prime, big-endian, len(p) = bits / 8 bytes.
    p: []const u8,
    /// q = (p - 1) / 2, big-endian, same length.
    q: []const u8,
    /// Private-exponent length in bits.
    xbits: u16,

    /// Bytes of a public value / shared secret (RFC 8446 §4.2.8.1).
    pub fn plen(self: *const Info) usize {
        return self.p.len;
    }

    /// Bytes `KeyPair.secret` holds for the exponent (`xbits` rounded up).
    pub fn xlen(self: *const Info) usize {
        return (@as(usize, self.xbits) + 7) / 8;
    }
};

/// The longest public value / shared secret: ffdhe8192's.
pub const max_plen = 1024;

fn nibbles(comptime hex: []const u8) usize {
    @setEvalBranchQuota(2_000_000);
    var n: usize = 0;
    for (hex) |c| {
        if (c != ' ') n += 1;
    }
    return n;
}

fn decode(comptime hex: []const u8) [nibbles(hex) / 2]u8 {
    @setEvalBranchQuota(2_000_000);
    var out: [nibbles(hex) / 2]u8 = undefined;
    var i: usize = 0;
    var hi: ?u8 = null;
    for (hex) |c| {
        if (c == ' ') continue;
        const d = std.fmt.charToDigit(c, 16) catch @compileError("ffdhe: bad hex digit");
        if (hi) |h| {
            out[i] = h << 4 | d;
            i += 1;
            hi = null;
        } else hi = d;
    }
    return out;
}

fn halfMinusOne(comptime p: []const u8) [p.len]u8 {
    @setEvalBranchQuota(2_000_000);
    var out: [p.len]u8 = p[0..p.len].*;
    out[p.len - 1] -= 1; // p is odd (checked in `make`)
    var carry: u8 = 0;
    for (&out) |*b| {
        const next = (b.* >> 1) | carry;
        carry = (b.* & 1) << 7;
        b.* = next;
    }
    return out;
}

fn make(comptime code: u16, comptime bits: usize, comptime hex: []const u8, comptime xbits: u16) Info {
    const H = struct {
        const pb = decode(hex);
        const qb = halfMinusOne(&pb);
    };
    comptime {
        // RFC 7919 construction: p = 2^N - 2^(N-64) + ... - 1, so the top 64 and
        // the bottom 64 bits are all ones; a safe prime is 3 mod 4.
        std.debug.assert(H.pb.len * 8 == bits);
        for (H.pb[0..8]) |b| std.debug.assert(b == 0xff);
        for (H.pb[H.pb.len - 8 ..]) |b| std.debug.assert(b == 0xff);
        std.debug.assert(H.pb[H.pb.len - 1] & 3 == 3);
        // The exponent is shorter than q (so < q and the group order is not wrapped).
        std.debug.assert(xbits < bits - 1 and xbits >= 225);
        std.debug.assert(H.qb[0] == 0x7f);
    }
    return .{ .code = code, .p = &H.pb, .q = &H.qb, .xbits = xbits };
}

/// The five groups, RFC 8446 §4.2.7 code points. Exponent lengths: OpenSSL
/// `crypto/ffc/ffc_dh.c` (`FFDHE(2048, 225)` .. `FFDHE(8192, 400)`).
pub const infos = [_]Info{
    make(0x0100, 2048, params.p2048, 225),
    make(0x0101, 3072, params.p3072, 275),
    make(0x0102, 4096, params.p4096, 325),
    make(0x0103, 6144, params.p6144, 375),
    make(0x0104, 8192, params.p8192, 400),
};

pub fn find(code: u16) ?*const Info {
    for (&infos) |*i| {
        if (i.code == code) return i;
    }
    return null;
}

/// Draws the private exponent into `secret` (`info.xlen()` bytes) and writes
/// Y = 2^x mod p, left-padded, into `public` (`info.plen()` bytes).
pub fn generate(info: *const Info, random: std.Random, secret: []u8, public: []u8) Error!void {
    std.debug.assert(secret.len == info.xlen() and public.len == info.plen());
    const excess: u3 = @intCast(secret.len * 8 - info.xbits);
    var tries: usize = 0;
    while (true) : (tries += 1) {
        if (tries == 64) return error.KeyExchangeFailed;
        random.bytes(secret);
        secret[0] &= @as(u8, 0xff) >> excess;
        // x = 0 is excluded (a 2^-xbits event, so a broken RNG in practice).
        if (!std.mem.allEqual(u8, secret, 0)) break;
    }
    var x = Dyn.loadBE(secret) catch return error.KeyExchangeFailed;
    defer std.crypto.secureZero(u64, &x);
    const m = Dyn.fromBytesBEPublic(info.p) catch return error.KeyExchangeFailed;
    var g = Dyn.zero;
    g[0] = 2;
    const y = m.pow(&g, &x);
    m.toBytesBE(&y, public);
}

/// The peer check of RFC 8446 §4.2.8.1 / RFC 7919 §5.1 and Z = Y^x mod p into
/// `out` (`info.plen()` bytes, leading zeros kept).
pub fn shared(info: *const Info, secret: []const u8, peer: []const u8, out: []u8) Error!void {
    std.debug.assert(out.len == info.plen());
    if (secret.len < info.xlen()) return error.KeyExchangeFailed;
    if (peer.len != info.plen()) return error.MissingKeyShare;
    const m = Dyn.fromBytesBEPublic(info.p) catch return error.KeyExchangeFailed;
    const y = m.elemFromBytesBE(peer) catch return error.KeyExchangeFailed; // Y < p
    const one = Dyn.one();
    const p_minus_1 = m.neg(&one);
    // 1 < Y < p - 1 ...
    if (Dyn.isZero(&y) or Dyn.isOne(&y) or Dyn.eql(&y, &p_minus_1)) return error.KeyExchangeFailed;
    // ... and Y in the order-q subgroup: Y^q = 1 (q is public, so powPublic).
    const t = m.powPublic(&y, info.q);
    if (!Dyn.isOne(&t)) return error.KeyExchangeFailed;

    var x = Dyn.loadBE(secret[0..info.xlen()]) catch return error.KeyExchangeFailed;
    defer std.crypto.secureZero(u64, &x);
    // A wiped / never-generated key: refuse rather than hand out Z = 1.
    if (Dyn.isZero(&x)) return error.KeyExchangeFailed;
    var z = m.pow(&y, &x);
    defer std.crypto.secureZero(u64, &z);
    m.toBytesBE(&z, out);
}
