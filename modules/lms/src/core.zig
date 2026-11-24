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
const Shake256 = std.crypto.hash.sha3.Shake256;
const params = @import("params.zig");
const burn = @import("burn.zig");

pub const n = params.n;
pub const id_len = params.id_len;
pub const OtsParamSet = params.OtsParamSet;
pub const ParamSet = params.ParamSet;
pub const HashFn = params.HashFn;
pub const max_levels = params.max_levels;

/// §7.1 domain separators. `D_PBLC` closes an LM-OTS public key, `D_MESG`
/// starts the message hash, `D_LEAF` / `D_INTR` hash tree nodes.
pub const d_pblc: u16 = 0x8080;
pub const d_mesg: u16 = 0x8181;
pub const d_leaf: u16 = 0x8282;
pub const d_intr: u16 = 0x8383;

/// An incremental `H` for one hash, fixed at compile time so a SHA-256 path
/// never carries SHAKE256's Keccak state on its stack (the verify-only bound,
/// SPEC § Verification-only use): SHA-256 (truncated to 24 bytes for the
/// SHA-256/192 sets, RFC 9858 §2.1) or SHAKE256 (its first `len` bytes,
/// §2.2/§2.3). Values are `[n]u8` with the bytes past `len` zero.
pub fn HasherFor(comptime hash: params.Hash) type {
    return struct {
        len: u8,
        st: switch (hash) {
            .sha256 => Sha256,
            .shake256 => Shake256,
        },

        const Self = @This();

        pub fn init(len: u8) Self {
            return .{ .len = len, .st = .init(.{}) };
        }

        pub fn update(self: *Self, bytes: []const u8) void {
            self.st.update(bytes);
        }

        pub fn final(self: *Self) [n]u8 {
            var out: [n]u8 = @splat(0);
            switch (hash) {
                .sha256 => {
                    var full: [Sha256.digest_length]u8 = undefined;
                    self.st.final(&full);
                    @memcpy(out[0..self.len], full[0..self.len]);
                    std.crypto.secureZero(u8, &full);
                },
                .shake256 => self.st.squeeze(out[0..self.len]),
            }
            std.crypto.secureZero(u8, std.mem.asBytes(&self.st));
            return out;
        }
    };
}

/// `HasherFor` chosen at run time, for callers outside the hot paths (tests,
/// one-off hashes). The scheme's own paths dispatch once per call instead.
pub const Hasher = struct {
    inner: union(enum) { sha: HasherFor(.sha256), shake: HasherFor(.shake256) },

    pub fn init(hf: HashFn) Hasher {
        return .{ .inner = switch (hf.hash) {
            .sha256 => .{ .sha = .init(hf.len) },
            .shake256 => .{ .shake = .init(hf.len) },
        } };
    }

    pub fn update(self: *Hasher, bytes: []const u8) void {
        switch (self.inner) {
            inline else => |*h| h.update(bytes),
        }
    }

    pub fn final(self: *Hasher) [n]u8 {
        return switch (self.inner) {
            inline else => |*h| h.final(),
        };
    }
};

/// The per-hash implementations: `hash` is comptime, the length is not.
fn Impl(comptime hash: params.Hash) type {
    return struct {
        const H = HasherFor(hash);

        fn chainHashT(len: u8, id: *const [id_len]u8, q: u32, i: u16, j: u8, x: *const [n]u8) [n]u8 {
            var buf: [id_len + 4 + 2 + 1]u8 = undefined;
            @memcpy(buf[0..id_len], id);
            std.mem.writeInt(u32, buf[16..20], q, .big);
            std.mem.writeInt(u16, buf[20..22], i, .big);
            buf[22] = j;
            var h = H.init(len);
            h.update(&buf);
            h.update(x[0..len]);
            return h.final();
        }

        fn leafHashT(len: u8, id: *const [id_len]u8, r: u32, k: *const [n]u8) [n]u8 {
            var h = H.init(len);
            h.update(id);
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, r)));
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_leaf)));
            h.update(k[0..len]);
            return h.final();
        }

        fn intrHashT(len: u8, id: *const [id_len]u8, r: u32, left: *const [n]u8, right: *const [n]u8) [n]u8 {
            var h = H.init(len);
            h.update(id);
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, r)));
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_intr)));
            h.update(left[0..len]);
            h.update(right[0..len]);
            return h.final();
        }

        fn messageHashT(len: u8, id: *const [id_len]u8, q: u32, c: *const [n]u8, msg: []const u8) [n]u8 {
            var h = H.init(len);
            h.update(id);
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
            h.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_mesg)));
            h.update(c[0..len]);
            h.update(msg);
            return h.final();
        }

        fn otsCandidate(ots: OtsParamSet, id: *const [id_len]u8, q: u32, c: *const [n]u8, y: []const u8, msg: []const u8) [n]u8 {
            const len = ots.nLen();
            const w = ots.w();
            const top: u16 = (@as(u16, 1) << w) - 1;
            const qq = messageHashT(len, id, q, c, msg);
            const s = withChecksum(ots, &qq);
            var outer = H.init(len);
            outer.update(id);
            outer.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
            outer.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_pblc)));
            var i: u16 = 0;
            while (i < ots.p()) : (i += 1) {
                const a: u16 = coef(&s, i, w);
                var tmp: [n]u8 = @splat(0);
                @memcpy(tmp[0..len], y[@as(usize, i) * len ..][0..len]);
                var j: u16 = a;
                while (j < top) : (j += 1) tmp = chainHashT(len, id, q, i, @intCast(j), &tmp);
                outer.update(tmp[0..len]);
            }
            return outer.final();
        }

        fn rootCandidate(lms: ParamSet, id: *const [id_len]u8, q: u32, kc: *const [n]u8, path: []const u8) [n]u8 {
            const m = lms.mLen();
            var node_num: u32 = lms.leaves() + q;
            var tmp = leafHashT(m, id, node_num, kc);
            var i: usize = 0;
            while (node_num > 1) : (i += 1) {
                var sib: [n]u8 = @splat(0);
                @memcpy(sib[0..m], path[i * m ..][0..m]);
                const parent = node_num >> 1;
                tmp = if (node_num & 1 == 1)
                    intrHashT(m, id, parent, &sib, &tmp)
                else
                    intrHashT(m, id, parent, &tmp, &sib);
                node_num = parent;
            }
            return tmp;
        }

        fn otsPublicKeyHash(ots: OtsParamSet, id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
            const hf = ots.hashFn();
            const top: u16 = (@as(u16, 1) << ots.w()) - 1;
            var outer = H.init(hf.len);
            outer.update(id);
            outer.update(&std.mem.toBytes(std.mem.nativeToBig(u32, q)));
            outer.update(&std.mem.toBytes(std.mem.nativeToBig(u16, d_pblc)));
            var i: u16 = 0;
            while (i < ots.p()) : (i += 1) {
                var tmp: [n]u8 = undefined;
                deriveX(hf, &tmp, id, q, i, seed);
                var j: u16 = 0;
                while (j < top) : (j += 1) tmp = chainHashT(hf.len, id, q, i, @intCast(j), &tmp);
                outer.update(tmp[0..hf.len]);
                std.crypto.secureZero(u8, &tmp);
            }
            return outer.final();
        }

        fn otsSign(ots: OtsParamSet, id: *const [id_len]u8, q: u32, seed: *const [n]u8, c: *const [n]u8, msg: []const u8, out: []u8) void {
            const hf = ots.hashFn();
            const len: usize = hf.len;
            const w = ots.w();
            std.mem.writeInt(u32, out[0..4], ots.typecode(), .big);
            @memcpy(out[4..][0..len], c[0..len]);
            const qq = messageHashT(hf.len, id, q, c, msg);
            const s = withChecksum(ots, &qq);
            var i: u16 = 0;
            while (i < ots.p()) : (i += 1) {
                const a = coef(&s, i, w);
                var tmp: [n]u8 = undefined;
                deriveX(hf, &tmp, id, q, i, seed);
                var j: u16 = 0;
                while (j < a) : (j += 1) tmp = chainHashT(hf.len, id, q, i, @intCast(j), &tmp);
                @memcpy(out[4 + len + @as(usize, i) * len ..][0..len], tmp[0..len]);
                std.crypto.secureZero(u8, &tmp);
            }
        }
    };
}

/// `H(I || u32str(q) || u16str(i) || u8str(j) || x)`: one Winternitz chain
/// step (§4.3), and with `j = 0xff` the Appendix A private-value derivation
/// (`x` is then the SEED).
pub fn chainHash(hf: HashFn, id: *const [id_len]u8, q: u32, i: u16, j: u8, x: *const [n]u8) [n]u8 {
    return switch (hf.hash) {
        inline else => |h| Impl(h).chainHashT(hf.len, id, q, i, j, x),
    };
}

/// `H(I || u32str(r) || u16str(D_LEAF) || K)` (§5.3, leaf node `r >= 2^h`).
// secret-api-ok: `k` is an LM-OTS public key hash (a Merkle leaf, published in signatures), not key material
pub fn leafHash(hf: HashFn, id: *const [id_len]u8, r: u32, k: *const [n]u8) [n]u8 {
    return switch (hf.hash) {
        inline else => |h| Impl(h).leafHashT(hf.len, id, r, k),
    };
}

/// `H(I || u32str(r) || u16str(D_INTR) || left || right)` (§5.3, interior node).
pub fn intrHash(hf: HashFn, id: *const [id_len]u8, r: u32, left: *const [n]u8, right: *const [n]u8) [n]u8 {
    return switch (hf.hash) {
        inline else => |h| Impl(h).intrHashT(hf.len, id, r, left, right),
    };
}

/// `coef(S, i, w)` of §3.1.3. `i` must address a w-bit element inside `S`
/// (callers pass `i < p`, and `S` is `Q || Cksm(Q)`, `n + 2` bytes).
pub fn coef(s: []const u8, i: usize, w: u4) u8 {
    const wide: usize = w;
    const mask: u8 = @intCast((@as(u16, 1) << w) - 1);
    const byte = s[i * wide / 8];
    const shift: u3 = @intCast(8 - (wide * (i % (8 / wide)) + wide));
    return (byte >> shift) & mask;
}

/// `Q || Cksm(Q)` (Algorithm 2, §4.4): the message hash (`ots.nLen()` bytes)
/// followed by its 16-bit checksum, already shifted left by `ls`.
pub fn withChecksum(ots: OtsParamSet, q_hash: *const [n]u8) [n + 2]u8 {
    const w = ots.w();
    const len: usize = ots.nLen();
    const max: u32 = (@as(u32, 1) << w) - 1;
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < len * 8 / @as(usize, w)) : (i += 1) sum += max - coef(q_hash, i, w);
    // Largest cases: n = 32, w = 1: 256 << 7 = 32768; n = 24, w = 1: 192 << 8
    // = 49152; w = 2: 384 << 6; w = 4: 960 << 4; w = 8: 8160 << 0. All fit the
    // 16-bit `sum` the RFC specifies.
    const ck: u16 = @intCast(sum << ots.ls());
    var out: [n + 2]u8 = @splat(0);
    @memcpy(out[0..len], q_hash[0..len]);
    std.mem.writeInt(u16, out[len..][0..2], ck, .big);
    return out;
}

/// `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)` (Algorithm 3/4b).
pub fn messageHash(hf: HashFn, id: *const [id_len]u8, q: u32, c: *const [n]u8, msg: []const u8) [n]u8 {
    return switch (hf.hash) {
        inline else => |h| Impl(h).messageHashT(hf.len, id, q, c, msg),
    };
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
    std.debug.assert(y.len == @as(usize, ots.p()) * ots.nLen());
    return switch (ots.hashFn().hash) {
        inline else => |h| Impl(h).otsCandidate(ots, id, q, c, y, msg),
    };
}

/// Appendix A: `x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED)`.
/// The result is a secret, so it goes to `out` (never returned by value).
///
/// Burned (`burn.derive_burn`) on its own because it is a public building
/// block; inside `Tree` it also runs under the entry point's burn (one
/// extra 2 KiB zeroing per chain start, noise next to the chain's hashes).
pub fn deriveX(hf: HashFn, out: *[n]u8, id: *const [id_len]u8, q: u32, i: u16, seed: *const [n]u8) void {
    burn.run(burn.derive_burn, void, deriveXBody, .{ hf, out, id, q, i, seed });
}

fn deriveXBody(hf: HashFn, out: *[n]u8, id: *const [id_len]u8, q: u32, i: u16, seed: *const [n]u8) void {
    out.* = chainHash(hf, id, q, i, 0xff, seed);
}

/// The LM-OTS randomizer `C`. RFC 8554 requires it to be uniformly random or
/// "another unpredictable process" (§7.1); this module has no RNG, so it is
/// derived from the secret: `H(I || u32str(q) || u16str(0xffff) || u8str(0xff)
/// || SEED)`. `i = 0xffff` is unreachable by a chain index (`i <= 264`), so
/// this hash input is distinct from every other use of `H` in the scheme.
/// It depends on `q` and the secret only, which is safe because each `q`
/// signs one message; re-signing the same message at the same leaf gives the
/// identical signature.
///
/// Burned (`burn.derive_burn`), like `deriveX`.
pub fn deriveRandomizer(hf: HashFn, id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
    return burn.run(burn.derive_burn, [n]u8, deriveRandomizerBody, .{ hf, id, q, seed });
}

fn deriveRandomizerBody(hf: HashFn, id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
    return chainHash(hf, id, q, 0xffff, 0xff, seed);
}

/// Algorithm 1: the LM-OTS public key hash `K` of leaf `q`, from the seed.
// secret-api-ok: a building block: the chain values come from deriveX (burned) and the frames below are the caller's to burn (Tree's init_burn / sign_burn, module doc)
pub fn otsPublicKeyHash(ots: OtsParamSet, id: *const [id_len]u8, q: u32, seed: *const [n]u8) [n]u8 {
    return switch (ots.hashFn().hash) {
        inline else => |h| Impl(h).otsPublicKeyHash(ots, id, q, seed),
    };
}

/// Algorithm 3: the LM-OTS signature `u32str(type) || C || y[0] || ... ||
/// y[p-1]` of `msg` under leaf `q`, written to `out` (`out.len == ots.sigLen()`).
/// `c` is the randomizer (see `deriveRandomizer`).
// secret-api-ok: a building block: the chain values come from deriveX (burned) and the frames below are the caller's to burn (Tree's init_burn / sign_burn, module doc)
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
    switch (ots.hashFn().hash) {
        inline else => |h| Impl(h).otsSign(ots, id, q, seed, c, msg, out),
    }
}

// ─── wire formats ────────────────────────────────────────────────────────────

/// `LMS signature` length for the given sets: `12 + n * (p + 1) + m * h` (§5.4).
pub fn lmsSignatureLength(lms: ParamSet, ots: OtsParamSet) usize {
    return 4 + ots.sigLen() + 4 + @as(usize, lms.mLen()) * @as(usize, lms.height());
}

/// The largest LMS signature any supported set can produce (H25 with W1, n = 32).
pub const max_lms_signature_length = lmsSignatureLength(.sha256_m32_h25, .sha256_n32_w1);

pub const ParseError = error{
    /// The byte string is not exactly the length its typecodes imply.
    InvalidLength,
    /// The LMS typecode is not one of RFC 8554's or RFC 9858's.
    UnsupportedLmsType,
    /// The LM-OTS typecode is not one of RFC 8554's or RFC 9858's, or it uses
    /// another hash or length than the LMS typecode (one `H` per key).
    UnsupportedOtsType,
    /// HSS public key: `L` is outside 1..8.
    InvalidLevels,
};

/// LMS public key (§5.3): `u32str(type) || u32str(otstype) || I || T[1]`.
/// `root` holds `m` bytes (24 or 32); the rest is zero.
pub const LmsPublicKey = struct {
    lms: ParamSet,
    ots: OtsParamSet,
    id: [id_len]u8,
    root: [n]u8,

    /// The encoding's length for the largest `m` (32): the size of the buffer
    /// `encode` takes.
    pub const max_encoded_len = 4 + 4 + id_len + n;

    /// The encoding's length for `lms`'s `m`.
    pub fn encodedLenFor(lms: ParamSet) usize {
        return 4 + 4 + id_len + @as(usize, lms.mLen());
    }

    pub fn encodedLen(self: LmsPublicKey) usize {
        return encodedLenFor(self.lms);
    }

    /// The length of the LMS public key at the start of `bytes`, from its LMS
    /// typecode, or null when the typecode is unknown or `bytes` too short.
    pub fn peekLen(bytes: []const u8) ?usize {
        if (bytes.len < 4) return null;
        const lms = ParamSet.fromTypecode(std.mem.readInt(u32, bytes[0..4], .big)) orelse return null;
        return encodedLenFor(lms);
    }

    /// Algorithm 6 steps 1–2: exact length and typecode checks.
    pub fn parse(bytes: []const u8) ParseError!LmsPublicKey {
        if (bytes.len < 8) return error.InvalidLength;
        const lms = ParamSet.fromTypecode(std.mem.readInt(u32, bytes[0..4], .big)) orelse
            return error.UnsupportedLmsType;
        const ots = OtsParamSet.fromTypecode(std.mem.readInt(u32, bytes[4..8], .big)) orelse
            return error.UnsupportedOtsType;
        if (!lms.matches(ots)) return error.UnsupportedOtsType;
        if (bytes.len != encodedLenFor(lms)) return error.InvalidLength;
        var pk: LmsPublicKey = .{ .lms = lms, .ots = ots, .id = bytes[8..24].*, .root = @splat(0) };
        @memcpy(pk.root[0..lms.mLen()], bytes[24..]);
        return pk;
    }

    /// The encoding into `out`; returns `out[0..encodedLen()]`.
    pub fn encode(self: LmsPublicKey, out: *[max_encoded_len]u8) []u8 {
        const m: usize = self.lms.mLen();
        std.mem.writeInt(u32, out[0..4], self.lms.typecode(), .big);
        std.mem.writeInt(u32, out[4..8], self.ots.typecode(), .big);
        @memcpy(out[8..24], &self.id);
        @memcpy(out[24..][0..m], self.root[0..m]);
        return out[0 .. 24 + m];
    }

    /// Algorithm 6 (LMS verification). `false` for every malformed input.
    pub fn verify(self: LmsPublicKey, msg: []const u8, sig: []const u8) bool {
        if (!self.lms.matches(self.ots)) return false;
        const tc = lmsCandidate(self, msg, sig) orelse return false;
        return std.mem.eql(u8, &tc, &self.root);
    }
};

/// HSS public key (§6.1): `u32str(L) || pub[0]`.
pub const HssPublicKey = struct {
    levels: u8,
    top: LmsPublicKey,

    pub const max_encoded_len = 4 + LmsPublicKey.max_encoded_len;

    pub fn encodedLen(self: HssPublicKey) usize {
        return 4 + self.top.encodedLen();
    }

    pub fn parse(bytes: []const u8) ParseError!HssPublicKey {
        if (bytes.len < 4) return error.InvalidLength;
        const levels = std.mem.readInt(u32, bytes[0..4], .big);
        if (levels < 1 or levels > max_levels) return error.InvalidLevels;
        const top = try LmsPublicKey.parse(bytes[4..]);
        return .{ .levels = @intCast(levels), .top = top };
    }

    /// The encoding into `out`; returns `out[0..encodedLen()]`.
    pub fn encode(self: HssPublicKey, out: *[max_encoded_len]u8) []u8 {
        std.mem.writeInt(u32, out[0..4], self.levels, .big);
        const t = self.top.encode(out[4..]);
        return out[0 .. 4 + t.len];
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
            if (sig.len - off < sl) return false;
            const s = sig[off..][0..sl];
            // The next key's length follows from its own LMS typecode.
            const pl = LmsPublicKey.peekLen(sig[off + sl ..]) orelse return false;
            if (sig.len - off - sl < pl) return false;
            const next_bytes = sig[off + sl ..][0..pl];
            if (!key.verify(next_bytes, s)) return false;
            key = LmsPublicKey.parse(next_bytes) catch return false;
            off += sl + pl;
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
    const nb: usize = pk.ots.nLen();
    const m: usize = pk.lms.mLen();
    const hf = pk.lms.hashFn();
    if (sig.len != lmsSignatureLength(pk.lms, pk.ots)) return null;
    const q = std.mem.readInt(u32, sig[0..4], .big);
    if (std.mem.readInt(u32, sig[4..8], .big) != pk.ots.typecode()) return null;
    if (std.mem.readInt(u32, sig[4 + ots_len ..][0..4], .big) != pk.lms.typecode()) return null;
    if (q >= pk.lms.leaves()) return null;

    var c: [n]u8 = @splat(0);
    @memcpy(c[0..nb], sig[8..][0..nb]);
    const y = sig[8 + nb .. 4 + ots_len];
    const kc = otsCandidate(pk.ots, &pk.id, q, &c, y, msg);

    const path = sig[8 + ots_len ..];
    std.debug.assert(path.len == h * m);
    return switch (hf.hash) {
        inline else => |hh| Impl(hh).rootCandidate(pk.lms, &pk.id, q, &kc, path),
    };
}
