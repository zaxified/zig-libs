// SPDX-License-Identifier: MIT
//! LM-OTS (RFC 8554 §4), the LMS node hashes (§5.3) and every verification
//! path (Algorithms 4a/4b, 6, 6a, HSS §6.3), plus the public-key wire formats.
//!
//! Everything here is allocation-free. The secret-touching primitives
//! (`otsPublicKeyHash`, `otsSign`, `deriveX`, `deriveRandomizer`) live here
//! too because they share the exact hash layout with verification; they wipe
//! their own buffers, but stack left behind by `Sha256` is the caller's
//! (`sign.zig` burns it).

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const params = @import("params.zig");

pub const n = params.n;
pub const id_len = params.id_len;
pub const OtsParamSet = params.OtsParamSet;
pub const ParamSet = params.ParamSet;
pub const max_levels = params.max_levels;

/// §7.1 domain separators. `D_PBLC` closes an LM-OTS public key, `D_MESG`
/// starts the message hash, `D_LEAF` / `D_INTR` hash tree nodes.
pub const d_pblc: u16 = 0x8080;
pub const d_mesg: u16 = 0x8181;
pub const d_leaf: u16 = 0x8282;
pub const d_intr: u16 = 0x8383;

/// `H(I || u32str(q) || u16str(i) || u8str(j) || x)`: one Winternitz chain
/// step (§4.3), and with `j = 0xff` the Appendix A private-value derivation
/// (`x` is then the SEED).
pub fn chainHash(id: *const [id_len]u8, q: u32, i: u16, j: u8, x: *const [n]u8) [n]u8 {
    var buf: [id_len + 4 + 2 + 1 + n]u8 = undefined;
    @memcpy(buf[0..id_len], id);
    std.mem.writeInt(u32, buf[16..20], q, .big);
    std.mem.writeInt(u16, buf[20..22], i, .big);
    buf[22] = j;
    @memcpy(buf[23..55], x);
    var out: [n]u8 = undefined;
    Sha256.hash(&buf, &out, .{});
    std.crypto.secureZero(u8, &buf);
    return out;
}

/// `H(I || u32str(r) || u16str(D_LEAF) || K)` (§5.3, leaf node `r >= 2^h`).
pub fn leafHash(id: *const [id_len]u8, r: u32, k: *const [n]u8) [n]u8 {
    var h = Sha256.init(.{});
    h.update(id);
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, r)));
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_leaf)));
    h.update(k);
    return h.finalResult();
}

/// `H(I || u32str(r) || u16str(D_INTR) || left || right)` (§5.3, interior node).
pub fn intrHash(id: *const [id_len]u8, r: u32, left: *const [n]u8, right: *const [n]u8) [n]u8 {
    var h = Sha256.init(.{});
    h.update(id);
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, r)));
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_intr)));
    h.update(left);
    h.update(right);
    return h.finalResult();
}

/// `coef(S, i, w)` of §3.1.3. `i` must address a w-bit element inside `S`
/// (callers pass `i < p`, and `S` is `Q || Cksm(Q)`, 34 bytes).
pub fn coef(s: []const u8, i: usize, w: u4) u8 {
    const wide: usize = w;
    const mask: u8 = @intCast((@as(u16, 1) << w) - 1);
    const byte = s[i * wide / 8];
    const shift: u3 = @intCast(8 - (wide * (i % (8 / wide)) + wide));
    return (byte >> shift) & mask;
}

/// `Q || Cksm(Q)` (Algorithm 2, §4.4): the message hash followed by its
/// 16-bit checksum, already shifted left by `ls`.
pub fn withChecksum(ots: OtsParamSet, q_hash: *const [n]u8) [n + 2]u8 {
    const w = ots.w();
    const max: u32 = (@as(u32, 1) << w) - 1;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < n * 8 / @as(usize, w)) : (i += 1) sum += max - coef(q_hash, i, w);
    // Largest case (w = 1): 256 << 7 = 32768; w = 2: 384 << 6; w = 4: 960 << 4;
    // w = 8: 8160 << 0. All fit the 16-bit `sum` the RFC specifies.
    const ck: u16 = @intCast(sum << ots.ls());
    var out: [n + 2]u8 = undefined;
    @memcpy(out[0..n], q_hash);
    std.mem.writeInt(u16, out[n..][0..2], ck, .big);
    return out;
}

/// `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)` (Algorithm 3/4b).
pub fn messageHash(id: *const [id_len]u8, q: u32, c: *const [n]u8, msg: []const u8) [n]u8 {
    var h = Sha256.init(.{});
    h.update(id);
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
    h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_mesg)));
    h.update(c);
    h.update(msg);
    return h.finalResult();
}

/// Algorithm 4b, step 3: the public-key candidate `Kc` from `y[0..p]`
/// (`y.len == p * n`, checked by the caller), the randomizer and the message.
pub fn otsCandidate(
    ots: OtsParamSet,
    id: *const [id_len]u8,
    q: u32,
    c: *const [n]u8,
    y: []const u8,
    msg: []const u8,
) [n]u8 {
    std.debug.assert(y.len == @as(usize, ots.p()) * n);
    const w = ots.w();
    const top: u16 = (@as(u16, 1) << w) - 1;
    const qq = messageHash(id, q, c, msg);
    const s = withChecksum(ots, &qq);
    var outer = Sha256.init(.{});
    outer.update(id);
    outer.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
    outer.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_pblc)));
    var i: u16 = 0;
    while (i < ots.p()) : (i += 1) {
        const a: u16 = coef(&s, i, w);
        var tmp: [n]u8 = y[@as(usize, i) * n ..][0..n].*;
        var j: u16 = a;
        while (j < top) : (j += 1) tmp = chainHash(id, q, i, @intCast(j), &tmp);
        outer.update(&tmp);
    }
    return outer.finalResult();
}

/// Appendix A: `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.
/// The result is a secret, so it goes to `out` (never returned by value).
pub fn deriveX(out: *[n]u8, id: *const [id_len]u8, q: u32, i: u16, seed: *const [n]u8) void {
    out.* = chainHash(id, q, i, 0xff, seed);
}

/// The LM-OTS randomizer `C`. RFC 8554 requires it to be uniformly random or
/// "another unpredictable process" (§7.1); this module has no RNG, so it is
/// derived from the secret: `H(I || u32str(q) || u16str(0xffff) || u8str(0xff)
/// || SEED)`. `i = 0xffff` is unreachable by a chain index (`i <= 264`), so
/// this hash input is distinct from every other use of `H` in the scheme.
/// It depends on `q` and the secret only, which is safe because each `q`
/// signs one message; re-signing the same message at the same leaf gives the
/// identical signature.
pub fn deriveRandomizer(id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
    return chainHash(id, q, 0xffff, 0xff, seed);
}

/// Algorithm 1: the LM-OTS public key hash `K` of leaf `q`, from the seed.
pub fn otsPublicKeyHash(ots: OtsParamSet, id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
    const top: u16 = (@as(u16, 1) << ots.w()) - 1;
    var outer = Sha256.init(.{});
    outer.update(id);
    outer.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
    outer.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_pblc)));
    var i: u16 = 0;
    while (i < ots.p()) : (i += 1) {
        var tmp: [n]u8 = undefined;
        deriveX(&tmp, id, q, i, seed);
        var j: u16 = 0;
        while (j < top) : (j += 1) tmp = chainHash(id, q, i, @intCast(j), &tmp);
        outer.update(&tmp);
        std.crypto.secureZero(u8, &tmp);
    }
    return outer.finalResult();
}

/// Algorithm 3: the LM-OTS signature `u32str(type) || C || y[0] || ... ||
/// y[p-1]` of `msg` under leaf `q`, written to `out` (`out.len == ots.sigLen()`).
/// `c` is the randomizer (see `deriveRandomizer`).
pub fn otsSign(
    ots: OtsParamSet,
    id: *const [id_len]u8,
    q: u32,
    seed: *const [n]u8,
    c: *const [n]u8,
    msg: []const u8,
    out: []u8,
) void {
    std.debug.assert(out.len == ots.sigLen());
    const w = ots.w();
    std.mem.writeInt(u32, out[0..4], ots.typecode(), .big);
    @memcpy(out[4..][0..n], c);
    const qq = messageHash(id, q, c, msg);
    const s = withChecksum(ots, &qq);
    var i: u16 = 0;
    while (i < ots.p()) : (i += 1) {
        const a = coef(&s, i, w);
        var tmp: [n]u8 = undefined;
        deriveX(&tmp, id, q, i, seed);
        var j: u16 = 0;
        while (j < a) : (j += 1) tmp = chainHash(id, q, i, @intCast(j), &tmp);
        @memcpy(out[4 + n + @as(usize, i) * n ..][0..n], &tmp);
        std.crypto.secureZero(u8, &tmp);
    }
}

// ─── wire formats ────────────────────────────────────────────────────────────

/// `LMS signature` length for the given sets: `12 + n * (p + 1) + m * h` (§5.4).
pub fn lmsSignatureLength(lms: ParamSet, ots: OtsParamSet) usize {
    return 4 + ots.sigLen() + 4 + n * @as(usize, lms.height());
}

/// The largest LMS signature any supported set can produce (H25 with W1).
pub const max_lms_signature_length = lmsSignatureLength(.sha256_m32_h25, .sha256_n32_w1);

pub const ParseError = error{
    /// The byte string is not exactly the length its typecodes imply.
    InvalidLength,
    /// The LMS typecode is not one of the five SHA-256/32 sets.
    UnsupportedLmsType,
    /// The LM-OTS typecode is not one of the four SHA-256/32 sets.
    UnsupportedOtsType,
    /// HSS public key: `L` is outside 1..8.
    InvalidLevels,
};

/// LMS public key (§5.3): `u32str(type) || u32str(otstype) || I || T[1]`.
pub const LmsPublicKey = struct {
    lms: ParamSet,
    ots: OtsParamSet,
    id: [id_len]u8,
    root: [n]u8,

    pub const encoded_len = 4 + 4 + id_len + n;

    /// Algorithm 6 steps 1–2: exact length and typecode checks.
    pub fn parse(bytes: []const u8) ParseError!LmsPublicKey {
        if (bytes.len < 8) return error.InvalidLength;
        const lms = ParamSet.fromTypecode(std.mem.readInt(u32, bytes[0..4], .big)) orelse
            return error.UnsupportedLmsType;
        const ots = OtsParamSet.fromTypecode(std.mem.readInt(u32, bytes[4..8], .big)) orelse
            return error.UnsupportedOtsType;
        if (bytes.len != encoded_len) return error.InvalidLength;
        return .{ .lms = lms, .ots = ots, .id = bytes[8..24].*, .root = bytes[24..56].* };
    }

    pub fn toBytes(self: LmsPublicKey) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.lms.typecode(), .big);
        std.mem.writeInt(u32, out[4..8], self.ots.typecode(), .big);
        @memcpy(out[8..24], &self.id);
        @memcpy(out[24..56], &self.root);
        return out;
    }

    /// Algorithm 6 (LMS verification). `false` for every malformed input.
    pub fn verify(self: LmsPublicKey, msg: []const u8, sig: []const u8) bool {
        const tc = lmsCandidate(self, msg, sig) orelse return false;
        return std.mem.eql(u8, &tc, &self.root);
    }
};

/// HSS public key (§6.1): `u32str(L) || pub[0]`.
pub const HssPublicKey = struct {
    levels: u8,
    top: LmsPublicKey,

    pub const encoded_len = 4 + LmsPublicKey.encoded_len;

    pub fn parse(bytes: []const u8) ParseError!HssPublicKey {
        if (bytes.len < 4) return error.InvalidLength;
        const levels = std.mem.readInt(u32, bytes[0..4], .big);
        if (levels < 1 or levels > max_levels) return error.InvalidLevels;
        const top = try LmsPublicKey.parse(bytes[4..]);
        return .{ .levels = @intCast(levels), .top = top };
    }

    pub fn toBytes(self: HssPublicKey) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.levels, .big);
        @memcpy(out[4..], &self.top.toBytes());
        return out;
    }

    /// §6.3 (HSS signature verification). `false` for every malformed input.
    pub fn verify(self: HssPublicKey, msg: []const u8, sig: []const u8) bool {
        if (self.levels < 1 or self.levels > max_levels) return false;
        if (sig.len < 4) return false;
        const nspk = std.mem.readInt(u32, sig[0..4], .big);
        if (nspk != @as(u32, self.levels) - 1) return false;
        var key = self.top;
        var off: usize = 4;
        var i: u32 = 0;
        while (i < nspk) : (i += 1) {
            // The length of sig[i] follows from the *key's* parameter sets;
            // a signature that claims other sets fails inside `lmsCandidate`.
            const sl = lmsSignatureLength(key.lms, key.ots);
            if (sig.len - off < sl + LmsPublicKey.encoded_len) return false;
            const s = sig[off..][0..sl];
            const next_bytes = sig[off + sl ..][0..LmsPublicKey.encoded_len];
            if (!key.verify(next_bytes, s)) return false;
            key = LmsPublicKey.parse(next_bytes) catch return false;
            off += sl + LmsPublicKey.encoded_len;
        }
        return key.verify(msg, sig[off..]);
    }
};

/// Verify an LMS signature against a serialized LMS public key.
pub fn lmsVerify(pub_bytes: []const u8, msg: []const u8, sig: []const u8) bool {
    const pk = LmsPublicKey.parse(pub_bytes) catch return false;
    return pk.verify(msg, sig);
}

/// Verify an HSS signature against a serialized HSS public key.
pub fn hssVerify(pub_bytes: []const u8, msg: []const u8, sig: []const u8) bool {
    const pk = HssPublicKey.parse(pub_bytes) catch return false;
    return pk.verify(msg, sig);
}

/// Algorithm 6a: the LMS public-key candidate `Tc`, or null when the
/// signature is malformed for this public key. Every length and typecode is
/// checked before any field is used to index.
pub fn lmsCandidate(pk: LmsPublicKey, msg: []const u8, sig: []const u8) ?[n]u8 {
    const h: usize = pk.lms.height();
    const ots_len = pk.ots.sigLen();
    if (sig.len != lmsSignatureLength(pk.lms, pk.ots)) return null;
    const q = std.mem.readInt(u32, sig[0..4], .big);
    if (std.mem.readInt(u32, sig[4..8], .big) != pk.ots.typecode()) return null;
    if (std.mem.readInt(u32, sig[4 + ots_len ..][0..4], .big) != pk.lms.typecode()) return null;
    if (q >= pk.lms.leaves()) return null;

    const c = sig[8..][0..n];
    const y = sig[8 + n .. 4 + ots_len];
    const kc = otsCandidate(pk.ots, &pk.id, q, c, y, msg);

    const path = sig[8 + ots_len ..];
    std.debug.assert(path.len == h * n);
    var node_num: u32 = pk.lms.leaves() + q;
    var tmp = leafHash(&pk.id, node_num, &kc);
    var i: usize = 0;
    while (node_num > 1) : (i += 1) {
        const sib = path[i * n ..][0..n];
        const parent = node_num >> 1;
        tmp = if (node_num & 1 == 1)
            intrHash(&pk.id, parent, sib, &tmp)
        else
            intrHash(&pk.id, parent, &tmp, sib);
        node_num = parent;
    }
    return tmp;
}
