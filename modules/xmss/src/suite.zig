// SPDX-License-Identifier: MIT
//! The XMSS hash suites (RFC 8391 §5.1, NIST SP 800-208 §5): the keyed hash
//! functions F, H, H_msg, PRF and PRF_keygen, WOTS+ and the L-tree, generic over
//! the hash and `n`. Every suite uses w = 16; `len_1 = 2n`, `len_2 = 3`.
//!
//! | suite | H | n | padding | RFC 8391 / SP 800-208 OIDs |
//! |---|---|---|---|---|
//! | `sha2_256` | SHA-256 | 32 | 32 | 0x01..0x03 |
//! | `sha2_512` | SHA-512 | 64 | 64 | 0x04..0x06 |
//! | `shake128_256` | SHAKE128 | 32 | 32 | 0x07..0x09 |
//! | `shake256_512` | SHAKE256 | 64 | 64 | 0x0a..0x0c |
//! | `sha2_192` | SHA-256 truncated | 24 | 4 | 0x0d..0x0f |
//! | `shake256_256` | SHAKE256 | 32 | 32 | 0x10..0x12 |
//! | `shake256_192` | SHAKE256 | 24 | 4 | 0x13..0x15 |
//!
//! The domain-separation prefix is `toByte(i, padding_len)`: `n` bytes, except
//! 4 for the 192-bit sets (SP 800-208 §5.1 / §5.3, as xmss-reference does).

const std = @import("std");
const burn = @import("burn.zig");

/// The hash function of a suite.
pub const Hash = enum { sha256, sha512, shake128, shake256 };

pub const Config = struct {
    hash: Hash,
    n: usize,
};

pub const sha2_256: Config = .{ .hash = .sha256, .n = 32 };
pub const sha2_512: Config = .{ .hash = .sha512, .n = 64 };
pub const shake128_256: Config = .{ .hash = .shake128, .n = 32 };
pub const shake256_512: Config = .{ .hash = .shake256, .n = 64 };
pub const sha2_192: Config = .{ .hash = .sha256, .n = 24 };
pub const shake256_256: Config = .{ .hash = .shake256, .n = 32 };
pub const shake256_192: Config = .{ .hash = .shake256, .n = 24 };

/// toByte(x, 32) (§2.4): 32-byte big-endian encoding of an integer.
pub fn toByte32(x: u64) [32]u8 {
    var out = @as([32]u8, @splat(0));
    std.mem.writeInt(u64, out[24..32], x, .big);
    return out;
}

/// §2.5 hash function address: eight big-endian 32-bit words.
/// Word layout: [0] layer, [1..2] tree (64-bit), [3] type, [4] OTS/L-tree
/// address (or padding for hash-tree), [5] chain address / tree height,
/// [6] hash address / tree index, [7] keyAndMask.
pub const Adrs = struct {
    words: [8]u32 = @splat(0),

    pub const type_ots: u32 = 0;
    pub const type_ltree: u32 = 1;
    pub const type_hashtree: u32 = 2;

    pub fn fromWords(words: [8]u32) Adrs {
        return .{ .words = words };
    }

    pub fn setLayerAddress(a: *Adrs, v: u32) void {
        a.words[0] = v;
    }

    pub fn setTreeAddress(a: *Adrs, v: u64) void {
        a.words[1] = @truncate(v >> 32);
        a.words[2] = @truncate(v);
    }

    /// §2.5: whenever the type word changes, all following words reset to 0.
    pub fn setType(a: *Adrs, t: u32) void {
        a.words[3] = t;
        @memset(a.words[4..8], 0);
    }

    pub fn setOtsAddress(a: *Adrs, v: u32) void {
        a.words[4] = v;
    }

    pub fn setLtreeAddress(a: *Adrs, v: u32) void {
        a.words[4] = v;
    }

    pub fn setChainAddress(a: *Adrs, v: u32) void {
        a.words[5] = v;
    }

    pub fn setTreeHeight(a: *Adrs, v: u32) void {
        a.words[5] = v;
    }

    pub fn setHashAddress(a: *Adrs, v: u32) void {
        a.words[6] = v;
    }

    pub fn setTreeIndex(a: *Adrs, v: u32) void {
        a.words[6] = v;
    }

    pub fn getTreeIndex(a: Adrs) u32 {
        return a.words[6];
    }

    pub fn setKeyAndMask(a: *Adrs, v: u32) void {
        a.words[7] = v;
    }

    /// Serialize as the 32-byte ADRS hash input (big-endian words).
    pub fn toBytes(a: Adrs) [32]u8 {
        var out: [32]u8 = undefined;
        for (a.words, 0..) |word, i| {
            std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .big);
        }
        return out;
    }
};

pub fn Suite(comptime cfg: Config) type {
    switch (cfg.hash) {
        .sha256 => std.debug.assert(cfg.n == 32 or cfg.n == 24),
        .sha512 => std.debug.assert(cfg.n == 64),
        .shake128 => std.debug.assert(cfg.n == 32),
        .shake256 => std.debug.assert(cfg.n == 24 or cfg.n == 32 or cfg.n == 64),
    }
    return struct {
        pub const config = cfg;
        /// Security parameter n: bytes per hash/node/seed.
        pub const n = cfg.n;
        /// Bytes of the domain-separation prefix `toByte(i, padding_len)`.
        pub const padding_len: usize = if (n == 24) 4 else n;
        /// Winternitz parameter (every RFC 8391 / SP 800-208 set uses w = 16).
        pub const w = 16;
        /// len_1 = ceil(8n / lg(w)) (§3.1.1).
        pub const wots_len1 = 2 * n;
        /// len_2 = floor(lg(len_1 * (w - 1)) / lg(w)) + 1 (§3.1.1): 3 for
        /// n = 24, 32 and 64.
        pub const wots_len2 = 3;
        /// len = len_1 + len_2: n-byte strings per WOTS+ key/signature (§3.1.1).
        pub const wots_len = wots_len1 + wots_len2;

        fn padPrefix(comptime i: u8) [padding_len]u8 {
            var p = @as([padding_len]u8, @splat(0));
            p[padding_len - 1] = i;
            return p;
        }
        const pad_f = padPrefix(0);
        const pad_h = padPrefix(1);
        const pad_hmsg = padPrefix(2);
        const pad_prf = padPrefix(3);
        const pad_prf_keygen = padPrefix(4);

        /// The suite's hash, output truncated / squeezed to n bytes.
        const Hasher = struct {
            st: switch (cfg.hash) {
                .sha256 => std.crypto.hash.sha2.Sha256,
                .sha512 => std.crypto.hash.sha2.Sha512,
                .shake128 => std.crypto.hash.sha3.Shake128,
                .shake256 => std.crypto.hash.sha3.Shake256,
            },

            fn init() Hasher {
                return .{ .st = .init(.{}) };
            }

            fn update(self: *Hasher, b: []const u8) void {
                self.st.update(b);
            }

            fn final(self: *Hasher) [n]u8 {
                var out: [n]u8 = undefined;
                switch (cfg.hash) {
                    .sha256, .sha512 => {
                        const D = @TypeOf(self.st);
                        var full: [D.digest_length]u8 = undefined;
                        self.st.final(&full);
                        out = full[0..n].*;
                        std.crypto.secureZero(u8, &full);
                    },
                    .shake128, .shake256 => self.st.squeeze(&out),
                }
                std.crypto.secureZero(u8, std.mem.asBytes(&self.st));
                return out;
            }
        };

        fn keyedHash(comptime pad: *const [padding_len]u8, key: *const [n]u8, m: []const u8) [n]u8 {
            var st = Hasher.init();
            st.update(pad);
            st.update(key);
            st.update(m);
            return st.final();
        }

        /// F (§5.1): H(toByte(0, padding_len) || KEY || M), M of n bytes.
        // secret-api-ok: KEY is derived from the public SEED (RFC 8391 §5.1; every caller passes PRF(SEED, ADRS) or SEED itself), never SK_SEED; the secret chain values travel in M and are the caller's
        pub fn hashF(key: *const [n]u8, m: *const [n]u8) [n]u8 {
            return keyedHash(&pad_f, key, m);
        }

        /// H (§5.1): H(toByte(1, padding_len) || KEY || M), M of 2n bytes.
        // secret-api-ok: KEY is derived from the public SEED (RFC 8391 §5.1; every caller passes PRF(SEED, ADRS) or SEED itself), never SK_SEED; the secret chain values travel in M and are the caller's
        pub fn hashH(key: *const [n]u8, m: *const [2 * n]u8) [n]u8 {
            return keyedHash(&pad_h, key, m);
        }

        /// PRF (§5.1): H(toByte(3, padding_len) || KEY || M), M a 32-byte index/ADRS.
        // secret-api-ok: KEY is derived from the public SEED (RFC 8391 §5.1; every caller passes PRF(SEED, ADRS) or SEED itself), never SK_SEED; the secret chain values travel in M and are the caller's
        pub fn prf(key: *const [n]u8, m: *const [32]u8) [n]u8 {
            return keyedHash(&pad_prf, key, m);
        }

        /// H_msg (§5.1, §4.1.9): H(toByte(2, padding_len) || r || root || toByte(idx, n)
        /// || M) — the randomized message digest. Streams M (arbitrary length).
        pub fn hashMsg(r: *const [n]u8, root: *const [n]u8, idx: u64, msg: []const u8) [n]u8 {
            var st = Hasher.init();
            st.update(&pad_hmsg);
            st.update(r);
            st.update(root);
            var idx_bytes: [n]u8 = @splat(0); // toByte(idx, n)
            std.mem.writeInt(u64, idx_bytes[n - 8 ..][0..8], idx, .big);
            st.update(&idx_bytes);
            st.update(msg);
            return st.final();
        }

        /// PRF_keygen (SP 800-208 / xmss-reference): H(toByte(4, padding_len) ||
        /// SK_SEED || SEED || ADRS) — derives one WOTS+ secret chain start. The
        /// result is secret, so it is written through `out`, never returned.
        pub fn prfKeygen(out: *[n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *const [32]u8) void {
            burn.run(burn.prf_burn, void, prfKeygenBody, .{ out, sk_seed, pub_seed, adrs });
        }

        fn prfKeygenBody(out: *[n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *const [32]u8) void {
            var st = Hasher.init();
            st.update(&pad_prf_keygen);
            st.update(sk_seed);
            st.update(pub_seed);
            st.update(adrs);
            out.* = st.final();
        }

        /// One F iteration of the §3.1.2 chain, in place: key = PRF(SEED, ADRS·k=0),
        /// bitmask = PRF(SEED, ADRS·k=1), x = F(key, x XOR bitmask). Caller must have
        /// set the chain and hash address words; this only touches keyAndMask. `x` is
        /// a chain value — secret below the chain's public end — so it is updated
        /// where it lies rather than copied in and out by value.
        pub fn chainStep(x: *[n]u8, pub_seed: *const [n]u8, adrs: *Adrs) void {
            adrs.setKeyAndMask(0);
            const key = prf(pub_seed, &adrs.toBytes());
            adrs.setKeyAndMask(1);
            const bm = prf(pub_seed, &adrs.toBytes());
            for (x, bm) |*xb, mb| xb.* ^= mb;
            x.* = hashF(&key, x);
        }

        /// chain (§3.1.2, Algorithm 2, iteratively), in place: F iterated `steps`
        /// times on `x`, at hash addresses start .. start+steps-1. Requires
        /// start + steps <= w-1. In place because every value below the chain's public
        /// end is secret (the whole-array by-value copies of the earlier
        /// `chain(x) [n]u8` left behind).
        ///
        /// The raw WOTS+ primitives do not burn the stack their callees used: a
        /// caller using them directly owns that stack. `keyGen`, `sign` and
        /// `buildAuth` do (see `burn.zig`).
        pub fn chain(x: *[n]u8, start: u32, steps: u32, pub_seed: *const [n]u8, adrs: *Adrs) void {
            std.debug.assert(start + steps <= w - 1);
            var i = start;
            while (i < start + steps) : (i += 1) {
                adrs.setHashAddress(i);
                chainStep(x, pub_seed, adrs);
            }
        }

        /// RAND_HASH (§4.1.4, Algorithm 7): the randomized tree-node hash.
        pub fn randHash(left: *const [n]u8, right: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [n]u8 {
            adrs.setKeyAndMask(0);
            const key = prf(pub_seed, &adrs.toBytes());
            adrs.setKeyAndMask(1);
            const bm0 = prf(pub_seed, &adrs.toBytes());
            adrs.setKeyAndMask(2);
            const bm1 = prf(pub_seed, &adrs.toBytes());
            var buf: [2 * n]u8 = undefined;
            for (buf[0..n], left, bm0) |*b, v, m| b.* = v ^ m;
            for (buf[n..], right, bm1) |*b, v, m| b.* = v ^ m;
            return hashH(&key, &buf);
        }

        /// Pseudorandom WOTS+ private key (§3.1.3 + SP 800-208 derivation): chain i
        /// start value = PRF_keygen(sk_seed, SEED || ADRS·chain=i,hash=0,k=0). The
        /// whole private key (≈ 2 KiB) is secret, so it is written through `sk`.
        pub fn wotsSkGen(sk: *[wots_len][n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) void {
            burn.run(burn.prf_burn, void, wotsSkGenBody, .{ sk, sk_seed, pub_seed, adrs });
        }

        fn wotsSkGenBody(sk: *[wots_len][n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) void {
            adrs.setHashAddress(0);
            adrs.setKeyAndMask(0);
            for (sk, 0..) |*chain_sk, i| {
                adrs.setChainAddress(@intCast(i));
                prfKeygen(chain_sk, sk_seed, pub_seed, &adrs.toBytes());
            }
        }

        /// WOTS_genPK (§3.1.4, Algorithm 4), with the private key derived from
        /// sk_seed. ADRS must be an OTS address; only its last three words change.
        /// The result is the PUBLIC key (the private key is chained in place into it);
        /// the secrets it passed through are in this call's frames, which the caller
        /// owns (see `chain`).
        pub fn wotsPkGen(sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
            return burn.run(burn.burn_size, [wots_len][n]u8, wotsPkGenBody, .{ sk_seed, pub_seed, adrs });
        }

        fn wotsPkGenBody(sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
            var pk: [wots_len][n]u8 = undefined;
            wotsSkGen(&pk, sk_seed, pub_seed, adrs);
            for (&pk, 0..) |*node, i| {
                adrs.setChainAddress(@intCast(i));
                chain(node, 0, w - 1, pub_seed, adrs);
            }
            return pk;
        }

        /// base_w (§2.6, Algorithm 1) of the message plus the §3.1.5 checksum: the
        /// len_1 message digits followed by len_2 checksum digits, all in 0..w-1.
        pub fn msgToBaseW(msg: *const [n]u8) [wots_len]u8 {
            var out: [wots_len]u8 = undefined;
            // Message: two base-16 digits per byte, big-endian nibble order.
            var csum: u32 = 0;
            for (msg, 0..) |b, i| {
                out[2 * i] = b >> 4;
                out[2 * i + 1] = b & 15;
                csum += (w - 1 - @as(u32, b >> 4)) + (w - 1 - @as(u32, b & 15));
            }
            // Checksum (§3.1.5): csum << (8 - ((len_2 * lg(w)) % 8)), then
            // base_w(toByte(csum, ceil(len_2 * lg(w) / 8)), w, len_2).
            csum <<= 8 - ((wots_len2 * 4) % 8);
            var csum_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &csum_bytes, @intCast(csum), .big);
            out[wots_len1] = csum_bytes[0] >> 4;
            out[wots_len1 + 1] = csum_bytes[0] & 15;
            out[wots_len1 + 2] = csum_bytes[1] >> 4;
            return out;
        }

        /// WOTS_sign (§3.1.5, Algorithm 5) on an n-byte message digest. The result
        /// is the PUBLIC signature (the private key is chained in place into it);
        /// the secrets it passed through are in this call's frames, which the caller
        /// owns (see `chain`).
        pub fn wotsSign(msg: *const [n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
            return burn.run(burn.burn_size, [wots_len][n]u8, wotsSignBody, .{ msg, sk_seed, pub_seed, adrs });
        }

        fn wotsSignBody(msg: *const [n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
            const digits = msgToBaseW(msg);
            var sig: [wots_len][n]u8 = undefined;
            wotsSkGen(&sig, sk_seed, pub_seed, adrs);
            for (&sig, digits, 0..) |*node, d, i| {
                adrs.setChainAddress(@intCast(i));
                chain(node, 0, d, pub_seed, adrs);
            }
            return sig;
        }

        /// WOTS_pkFromSig (§3.1.6, Algorithm 6): complete the chains from a
        /// signature; equals the WOTS+ public key iff the signature is valid.
        pub fn wotsPkFromSig(sig: *const [wots_len][n]u8, msg: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
            const digits = msgToBaseW(msg);
            var pk: [wots_len][n]u8 = undefined;
            for (&pk, sig, digits, 0..) |*node, sig_node, d, i| {
                adrs.setChainAddress(@intCast(i));
                node.* = sig_node;
                chain(node, d, w - 1 - d, pub_seed, adrs);
            }
            return pk;
        }

        /// ltree (§4.1.5, Algorithm 8): compress a WOTS+ public key to one n-byte
        /// leaf. Consumes pk in place. ADRS must be an L-tree address.
        pub fn ltree(pk: *[wots_len][n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [n]u8 {
            var l: usize = wots_len;
            adrs.setTreeHeight(0);
            var height: u32 = 0;
            while (l > 1) {
                for (0..l / 2) |i| {
                    adrs.setTreeIndex(@intCast(i));
                    pk[i] = randHash(&pk[2 * i], &pk[2 * i + 1], pub_seed, adrs);
                }
                if (l % 2 == 1) pk[l / 2] = pk[l - 1];
                l = (l + 1) / 2;
                height += 1;
                adrs.setTreeHeight(height);
            }
            return pk[0];
        }

        /// Compute the L-tree leaf for one WOTS+ key pair (§4.1.6 treeHash inner
        /// steps): fresh OTS + L-tree addresses at `leaf_idx`, single-tree layout
        /// (layer = 0, tree = 0).
        pub fn genLeaf(sk_seed: *const [n]u8, pub_seed: *const [n]u8, leaf_idx: u32) [n]u8 {
            return burn.run(burn.burn_size, [n]u8, genLeafBody, .{ sk_seed, pub_seed, leaf_idx });
        }

        fn genLeafBody(sk_seed: *const [n]u8, pub_seed: *const [n]u8, leaf_idx: u32) [n]u8 {
            var ots_adrs = Adrs{};
            ots_adrs.setType(Adrs.type_ots);
            ots_adrs.setOtsAddress(leaf_idx);
            var pk = wotsPkGen(sk_seed, pub_seed, &ots_adrs);

            var ltree_adrs = Adrs{};
            ltree_adrs.setType(Adrs.type_ltree);
            ltree_adrs.setLtreeAddress(leaf_idx);
            return ltree(&pk, pub_seed, &ltree_adrs);
        }
    };
}
