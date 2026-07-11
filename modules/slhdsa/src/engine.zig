// SPDX-License-Identifier: MIT
//! engine — the FIPS 205 SLH-DSA construction, generic over a parameter set.
//!
//! Implements every layer of the scheme: both §11 hash instantiations —
//! SHAKE256 (§11.1) and SHA-2 (§11.2, incl. the category-3/5 SHA-512 split
//! for H/T_l/H_msg/PRF_msg) — WOTS+ one-time signatures (§5), XMSS Merkle
//! trees (§6), the hypertree (§7), FORS few-time signatures (§8), and the
//! `slh_keygen_internal` / `slh_sign_internal` / `slh_verify_internal`
//! top level (§9/§10) plus the pure external interface with context strings
//! (§10.2, Algorithms 22/24). Pre-hash variants (HashSLH-DSA) are not
//! implemented. All twelve FIPS 205 parameter sets instantiate.

const std = @import("std");
const params = @import("params.zig");
const address = @import("address.zig");

const Address = address.Address;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const Shake256 = std.crypto.hash.sha3.Shake256;

/// Convert a byte string to base-2^b digits (FIPS 205 Algorithm 4).
/// `b` <= 16; `x` must hold at least ceil(out.len * b / 8) bytes.
fn base2b(x: []const u8, comptime b: usize, out: []u32) void {
    comptime std.debug.assert(b >= 1 and b <= 16);
    var in: usize = 0;
    var bits: u5 = 0;
    // Meaningful low bits of `total` = `bits` (< b + 8 <= 24); the shift
    // discards exhausted high bits, the mask below selects the digit.
    var total: u32 = 0;
    for (out) |*digit| {
        while (bits < b) {
            total = (total << 8) | x[in];
            in += 1;
            bits += 8;
        }
        bits -= @intCast(b);
        digit.* = (total >> bits) & comptime ((1 << b) - 1);
    }
}

test "base2b splits into nibbles and 6-bit digits" {
    var out4: [4]u32 = undefined;
    base2b(&.{ 0x12, 0xAF }, 4, &out4);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 0xA, 0xF }, &out4);
    var out6: [4]u32 = undefined;
    // Bitstream 111111|000000|111111|000000 -> digits 63, 0, 63, 0.
    base2b(&.{ 0b1111_1100, 0b0000_1111, 0b1100_0000 }, 6, &out6);
    try std.testing.expectEqualSlices(u32, &.{ 63, 0, 63, 0 }, &out6);
    var out5: [3]u32 = undefined;
    // Bitstream 10110|01101|10010 (0xB3, 0x64...) -> 22, 13, 18.
    base2b(&.{ 0b1011_0011, 0b0110_0100 }, 5, &out5);
    try std.testing.expectEqualSlices(u32, &.{ 22, 13, 18 }, &out5);
    // Digits wider than a byte (FORS a = 12/14 in the s parameter sets).
    var out12: [2]u32 = undefined;
    base2b(&.{ 0xAB, 0xCD, 0xEF }, 12, &out12);
    try std.testing.expectEqualSlices(u32, &.{ 0xABC, 0xDEF }, &out12);
    var out14: [2]u32 = undefined;
    // Bitstream 11111111111111|00000000000000 -> 16383, 0.
    base2b(&.{ 0xFF, 0xFC, 0x00, 0x00 }, 14, &out14);
    try std.testing.expectEqualSlices(u32, &.{ 16383, 0 }, &out14);
}

/// SLH-DSA over one FIPS 205 parameter set. Instantiate as e.g.
/// `SlhDsa(params.sha2_128f)`; all state is per-call, no global state.
pub fn SlhDsa(comptime P: params.Params) type {
    comptime P.validate();

    return struct {
        /// The parameter set this instantiation implements.
        pub const parameter_set = P;

        pub const n = P.n;
        pub const public_key_length = 2 * n;
        pub const secret_key_length = 4 * n;
        pub const signature_length = P.sigLen();

        const w: u32 = P.w();
        const len1 = P.len1();
        const len2 = P.len2();
        const wots_len = P.wotsLen();
        const hp = P.hp; // h' — height of one XMSS tree
        const d = P.d;
        const fors_a = P.a;
        const fors_k = P.k;
        const md_len = P.mdLen();
        const idx_tree_len = P.idxTreeLen();
        const idx_leaf_len = P.idxLeafLen();

        const wots_sig_len = wots_len * n;
        const xmss_sig_len = wots_sig_len + hp * n;
        const fors_sig_len = fors_k * (1 + fors_a) * n;
        const ht_sig_len = d * xmss_sig_len;

        const tree_bits = P.h - P.hp;
        const tree_mask: u64 = if (tree_bits == 64)
            ~@as(u64, 0)
        else
            (@as(u64, 1) << tree_bits) - 1;
        const leaf_mask: u32 = (1 << hp) - 1;

        comptime {
            std.debug.assert(signature_length ==
                n + fors_sig_len + ht_sig_len);
        }

        /// PK = (PK.seed, PK.root) — FIPS 205 §9.1.
        pub const PublicKey = struct {
            seed: [n]u8,
            root: [n]u8,

            pub fn fromBytes(bytes: [public_key_length]u8) PublicKey {
                return .{ .seed = bytes[0..n].*, .root = bytes[n..].* };
            }

            pub fn toBytes(pk: PublicKey) [public_key_length]u8 {
                return pk.seed ++ pk.root;
            }
        };

        /// SK = (SK.seed, SK.prf, PK.seed, PK.root) — FIPS 205 §9.1.
        pub const SecretKey = struct {
            seed: [n]u8,
            prf: [n]u8,
            pk: PublicKey,

            pub fn fromBytes(bytes: [secret_key_length]u8) SecretKey {
                return .{
                    .seed = bytes[0..n].*,
                    .prf = bytes[n .. 2 * n].*,
                    .pk = PublicKey.fromBytes(bytes[2 * n ..].*),
                };
            }

            pub fn toBytes(sk: SecretKey) [secret_key_length]u8 {
                return sk.seed ++ sk.prf ++ sk.pk.toBytes();
            }
        };

        pub const KeyPair = struct {
            sk: SecretKey,
            pk: PublicKey,
        };

        // ── §11 hash instantiations ───────────────────────────────────────

        /// "Big" hash for H/T_l/H_msg/PRF_msg in the SHA2 family: SHA-256 at
        /// security category 1 (§11.2.1), SHA-512 at categories 3/5
        /// (§11.2.2). F and PRF stay SHA-256 at every category.
        const Sha2Big = if (P.n == 16) Sha256 else Sha512;
        const HmacBig = if (P.n == 16) HmacSha256 else HmacSha512;

        /// Tweakable-hash context, comptime-selected by `P.hash`. Both
        /// variants absorb PK.seed once at init and copy the midstate per
        /// call. For SHA2, PK.seed || toByte(0, block-n) is exactly one
        /// compression block — the standard FIPS 205 speedup; SHAKE has no
        /// block alignment to exploit but the state copy still saves work.
        const Thash = switch (P.hash) {
            .sha2 => struct {
                base_f: Sha256,
                base_h: Sha2Big,

                fn init(pk_seed: [n]u8) @This() {
                    var st_f = Sha256.init(.{});
                    var block_f: [Sha256.block_length]u8 = @splat(0);
                    block_f[0..n].* = pk_seed;
                    st_f.update(&block_f);
                    var st_h = Sha2Big.init(.{});
                    var block_h: [Sha2Big.block_length]u8 = @splat(0);
                    block_h[0..n].* = pk_seed;
                    st_h.update(&block_h);
                    return .{ .base_f = st_f, .base_h = st_h };
                }

                /// F and PRF (§11.2): Trunc_n(SHA-256(PK.seed ||
                /// toByte(0, 64-n) || ADRS_c || M...)).
                fn f(t: @This(), adrs: Address, parts: []const []const u8) [n]u8 {
                    var st = t.base_f;
                    st.update(&adrs.compressed());
                    for (parts) |p| st.update(p);
                    var digest: [Sha256.digest_length]u8 = undefined;
                    st.final(&digest);
                    return digest[0..n].*;
                }

                /// H and T_l (§11.2): the same shape over the category hash
                /// (SHA-512 padded to its 128-byte block for categories 3/5).
                fn h(t: @This(), adrs: Address, parts: []const []const u8) [n]u8 {
                    var st = t.base_h;
                    st.update(&adrs.compressed());
                    for (parts) |p| st.update(p);
                    var digest: [Sha2Big.digest_length]u8 = undefined;
                    st.final(&digest);
                    return digest[0..n].*;
                }
            },
            .shake => struct {
                base: Shake256,

                fn init(pk_seed: [n]u8) @This() {
                    var st = Shake256.init(.{});
                    st.update(&pk_seed);
                    return .{ .base = st };
                }

                /// F/H/T_l/PRF (§11.1) are all one function:
                /// SHAKE256(PK.seed || ADRS || M..., 8n) — the full 32-byte
                /// ADRS, no compression in the SHAKE instantiation.
                fn f(t: @This(), adrs: Address, parts: []const []const u8) [n]u8 {
                    var st = t.base;
                    st.update(&adrs.bytes);
                    for (parts) |p| st.update(p);
                    var out: [n]u8 = undefined;
                    st.squeeze(&out);
                    return out;
                }

                fn h(t: @This(), adrs: Address, parts: []const []const u8) [n]u8 {
                    return t.f(adrs, parts);
                }
            },
        };

        /// H_msg: SHAKE256(R || PK.seed || PK.root || M, 8m) (§11.1), or
        /// MGF1-Hash(R || PK.seed || Hash(R || PK.seed || PK.root || M), m)
        /// with Hash = SHA-256 / SHA-512 by category (§11.2). The message is
        /// taken as parts so the §10.2 pure prefix needs no concat buffer.
        fn hMsg(r: [n]u8, pk: PublicKey, msg_parts: []const []const u8) [P.m]u8 {
            if (comptime P.hash == .shake) {
                var st = Shake256.init(.{});
                st.update(&r);
                st.update(&pk.seed);
                st.update(&pk.root);
                for (msg_parts) |p| st.update(p);
                var out: [P.m]u8 = undefined;
                st.squeeze(&out);
                return out;
            }
            var st = Sha2Big.init(.{});
            st.update(&r);
            st.update(&pk.seed);
            st.update(&pk.root);
            for (msg_parts) |p| st.update(p);
            var inner: [Sha2Big.digest_length]u8 = undefined;
            st.final(&inner);

            // MGF1: concat Hash(seed || counter_be32) blocks.
            var seed: [2 * n + Sha2Big.digest_length + 4]u8 = undefined;
            seed[0..n].* = r;
            seed[n .. 2 * n].* = pk.seed;
            seed[2 * n ..][0..Sha2Big.digest_length].* = inner;
            var out: [P.m]u8 = undefined;
            var counter: u32 = 0;
            var off: usize = 0;
            while (off < P.m) : (counter += 1) {
                std.mem.writeInt(u32, seed[2 * n + Sha2Big.digest_length ..][0..4], counter, .big);
                var block: [Sha2Big.digest_length]u8 = undefined;
                Sha2Big.hash(&seed, &block, .{});
                const take = @min(Sha2Big.digest_length, P.m - off);
                @memcpy(out[off..][0..take], block[0..take]);
                off += take;
            }
            return out;
        }

        /// PRF_msg: SHAKE256(SK.prf || opt_rand || M, 8n) (§11.1), or
        /// Trunc_n(HMAC-Hash(SK.prf, opt_rand || M)) by category (§11.2).
        fn prfMsg(sk_prf: [n]u8, opt_rand: [n]u8, msg_parts: []const []const u8) [n]u8 {
            if (comptime P.hash == .shake) {
                var st = Shake256.init(.{});
                st.update(&sk_prf);
                st.update(&opt_rand);
                for (msg_parts) |p| st.update(p);
                var out: [n]u8 = undefined;
                st.squeeze(&out);
                return out;
            }
            var mac = HmacBig.init(&sk_prf);
            mac.update(&opt_rand);
            for (msg_parts) |p| mac.update(p);
            var out: [HmacBig.mac_length]u8 = undefined;
            mac.final(&out);
            return out[0..n].*;
        }

        // ── §5 WOTS+ ──────────────────────────────────────────────────────

        /// Algorithm 5: apply F `s` times starting from chain index `i`.
        fn chainF(th: Thash, x: [n]u8, i: u32, s: u32, adrs: *Address) [n]u8 {
            var tmp = x;
            var j = i;
            while (j < i + s) : (j += 1) {
                adrs.setHash(j);
                tmp = th.f(adrs.*, &.{&tmp});
            }
            return tmp;
        }

        /// WOTS+ message digits incl. checksum (Algorithm 7 lines 1-7).
        fn wotsDigits(msg: [n]u8) [wots_len]u32 {
            var digits: [wots_len]u32 = undefined;
            base2b(&msg, P.lg_w, digits[0..len1]);
            var csum: u32 = 0;
            for (digits[0..len1]) |digit| csum += w - 1 - digit;
            csum <<= comptime ((8 - ((len2 * P.lg_w) % 8)) % 8);
            const csum_bytes_len = (len2 * P.lg_w + 7) / 8;
            var csum_bytes: [csum_bytes_len]u8 = undefined;
            var v = csum;
            var idx: usize = csum_bytes_len;
            while (idx > 0) {
                idx -= 1;
                csum_bytes[idx] = @truncate(v);
                v >>= 8;
            }
            base2b(&csum_bytes, P.lg_w, digits[len1..]);
            return digits;
        }

        /// Algorithm 6: WOTS+ public key (T_len over the chain tops).
        /// `adrs` must be WOTS_HASH-typed with the key-pair address set.
        fn wotsPkGen(th: Thash, sk_seed: [n]u8, adrs: Address) [n]u8 {
            var sk_adrs = adrs;
            sk_adrs.setTypeAndClear(.wots_prf);
            sk_adrs.setKeyPair(adrs.getKeyPair());
            var chain_adrs = adrs;
            var tmp: [wots_sig_len]u8 = undefined;
            for (0..wots_len) |i| {
                sk_adrs.setChain(@intCast(i));
                const sk = th.f(sk_adrs, &.{&sk_seed}); // PRF
                chain_adrs.setChain(@intCast(i));
                tmp[i * n ..][0..n].* = chainF(th, sk, 0, w - 1, &chain_adrs);
            }
            var pk_adrs = adrs;
            pk_adrs.setTypeAndClear(.wots_pk);
            pk_adrs.setKeyPair(adrs.getKeyPair());
            return th.h(pk_adrs, &.{&tmp}); // T_len
        }

        /// Algorithm 7: WOTS+ signature over an n-byte message.
        fn wotsSign(th: Thash, msg: [n]u8, sk_seed: [n]u8, adrs: Address, out: *[wots_sig_len]u8) void {
            const digits = wotsDigits(msg);
            var sk_adrs = adrs;
            sk_adrs.setTypeAndClear(.wots_prf);
            sk_adrs.setKeyPair(adrs.getKeyPair());
            var chain_adrs = adrs;
            for (0..wots_len) |i| {
                sk_adrs.setChain(@intCast(i));
                const sk = th.f(sk_adrs, &.{&sk_seed}); // PRF
                chain_adrs.setChain(@intCast(i));
                out[i * n ..][0..n].* = chainF(th, sk, 0, digits[i], &chain_adrs);
            }
        }

        /// Algorithm 8: recover the WOTS+ public key from a signature.
        fn wotsPkFromSig(th: Thash, sig: *const [wots_sig_len]u8, msg: [n]u8, adrs: Address) [n]u8 {
            const digits = wotsDigits(msg);
            var chain_adrs = adrs;
            var tmp: [wots_sig_len]u8 = undefined;
            for (0..wots_len) |i| {
                chain_adrs.setChain(@intCast(i));
                tmp[i * n ..][0..n].* = chainF(
                    th,
                    sig[i * n ..][0..n].*,
                    digits[i],
                    w - 1 - digits[i],
                    &chain_adrs,
                );
            }
            var pk_adrs = adrs;
            pk_adrs.setTypeAndClear(.wots_pk);
            pk_adrs.setKeyPair(adrs.getKeyPair());
            return th.h(pk_adrs, &.{&tmp}); // T_len
        }

        // ── §6 XMSS ───────────────────────────────────────────────────────

        /// Algorithm 9: Merkle node (i, z) of the XMSS tree addressed by
        /// `adrs` (layer + tree address). Recursion depth <= h'.
        fn xmssNode(th: Thash, sk_seed: [n]u8, i: u32, z: u32, adrs: Address) [n]u8 {
            var node_adrs = adrs;
            if (z == 0) {
                node_adrs.setTypeAndClear(.wots_hash);
                node_adrs.setKeyPair(i);
                return wotsPkGen(th, sk_seed, node_adrs);
            }
            const lnode = xmssNode(th, sk_seed, 2 * i, z - 1, adrs);
            const rnode = xmssNode(th, sk_seed, 2 * i + 1, z - 1, adrs);
            node_adrs.setTypeAndClear(.tree);
            node_adrs.setTreeHeight(z);
            node_adrs.setTreeIndex(i);
            return th.h(node_adrs, &.{ &lnode, &rnode }); // H
        }

        /// Algorithm 10: WOTS+ signature + authentication path for leaf idx.
        fn xmssSign(th: Thash, msg: [n]u8, sk_seed: [n]u8, idx: u32, adrs: Address, out: *[xmss_sig_len]u8) void {
            for (0..hp) |j| {
                const sibling = (idx >> @intCast(j)) ^ 1;
                out[wots_sig_len + j * n ..][0..n].* =
                    xmssNode(th, sk_seed, sibling, @intCast(j), adrs);
            }
            var wots_adrs = adrs;
            wots_adrs.setTypeAndClear(.wots_hash);
            wots_adrs.setKeyPair(idx);
            wotsSign(th, msg, sk_seed, wots_adrs, out[0..wots_sig_len]);
        }

        /// Algorithm 11: recompute the XMSS root from a signature.
        fn xmssPkFromSig(th: Thash, idx: u32, sig: *const [xmss_sig_len]u8, msg: [n]u8, adrs: Address) [n]u8 {
            var wots_adrs = adrs;
            wots_adrs.setTypeAndClear(.wots_hash);
            wots_adrs.setKeyPair(idx);
            var node = wotsPkFromSig(th, sig[0..wots_sig_len], msg, wots_adrs);

            var node_adrs = adrs;
            node_adrs.setTypeAndClear(.tree);
            node_adrs.setTreeIndex(idx);
            for (0..hp) |k| {
                node_adrs.setTreeHeight(@intCast(k + 1));
                const auth = sig[wots_sig_len + k * n ..][0..n];
                if ((idx >> @intCast(k)) & 1 == 0) {
                    node_adrs.setTreeIndex(node_adrs.getTreeIndex() / 2);
                    node = th.h(node_adrs, &.{ &node, auth }); // H
                } else {
                    node_adrs.setTreeIndex((node_adrs.getTreeIndex() - 1) / 2);
                    node = th.h(node_adrs, &.{ auth, &node }); // H
                }
            }
            return node;
        }

        // ── §7 hypertree ──────────────────────────────────────────────────

        /// Algorithm 12: chain of d XMSS signatures bottom layer -> top.
        fn htSign(th: Thash, msg: [n]u8, sk_seed: [n]u8, idx_tree_in: u64, idx_leaf_in: u32, out: *[ht_sig_len]u8) void {
            var idx_tree = idx_tree_in;
            var idx_leaf = idx_leaf_in;
            var root = msg;
            var adrs: Address = .{};
            for (0..d) |j| {
                adrs.setLayer(@intCast(j));
                adrs.setTree(idx_tree);
                const sig_part = out[j * xmss_sig_len ..][0..xmss_sig_len];
                xmssSign(th, root, sk_seed, idx_leaf, adrs, sig_part);
                if (j < d - 1) {
                    root = xmssPkFromSig(th, idx_leaf, sig_part, root, adrs);
                    idx_leaf = @intCast(idx_tree & leaf_mask);
                    idx_tree >>= hp;
                }
            }
        }

        /// Algorithm 13: verify a hypertree signature against PK.root.
        fn htVerify(th: Thash, msg: [n]u8, sig: *const [ht_sig_len]u8, idx_tree_in: u64, idx_leaf_in: u32, pk_root: [n]u8) bool {
            var idx_tree = idx_tree_in;
            var idx_leaf = idx_leaf_in;
            var node = msg;
            var adrs: Address = .{};
            for (0..d) |j| {
                adrs.setLayer(@intCast(j));
                adrs.setTree(idx_tree);
                node = xmssPkFromSig(th, idx_leaf, sig[j * xmss_sig_len ..][0..xmss_sig_len], node, adrs);
                idx_leaf = @intCast(idx_tree & leaf_mask);
                idx_tree >>= hp;
            }
            return std.mem.eql(u8, &node, &pk_root);
        }

        // ── §8 FORS ───────────────────────────────────────────────────────

        /// Algorithm 14: PRF-derived FORS secret value for leaf `idx`.
        /// `adrs` is the FORS_TREE address (key pair = hypertree leaf).
        fn forsSkGen(th: Thash, sk_seed: [n]u8, adrs: Address, idx: u32) [n]u8 {
            var sk_adrs = adrs;
            sk_adrs.setTypeAndClear(.fors_prf);
            sk_adrs.setKeyPair(adrs.getKeyPair());
            sk_adrs.setTreeIndex(idx);
            return th.f(sk_adrs, &.{&sk_seed}); // PRF
        }

        /// Algorithm 15: Merkle node (i, z) across the k FORS trees.
        fn forsNode(th: Thash, sk_seed: [n]u8, i: u32, z: u32, adrs: Address) [n]u8 {
            var node_adrs = adrs;
            if (z == 0) {
                const sk = forsSkGen(th, sk_seed, adrs, i);
                node_adrs.setTreeHeight(0);
                node_adrs.setTreeIndex(i);
                return th.f(node_adrs, &.{&sk}); // F
            }
            const lnode = forsNode(th, sk_seed, 2 * i, z - 1, adrs);
            const rnode = forsNode(th, sk_seed, 2 * i + 1, z - 1, adrs);
            node_adrs.setTreeHeight(z);
            node_adrs.setTreeIndex(i);
            return th.h(node_adrs, &.{ &lnode, &rnode }); // H
        }

        /// Algorithm 16: k secret values + authentication paths.
        fn forsSign(th: Thash, md: *const [md_len]u8, sk_seed: [n]u8, adrs: Address, out: *[fors_sig_len]u8) void {
            var indices: [fors_k]u32 = undefined;
            base2b(md, P.a, &indices);
            for (0..fors_k) |i| {
                const off = i * (1 + fors_a) * n;
                out[off..][0..n].* = forsSkGen(
                    th,
                    sk_seed,
                    adrs,
                    @intCast(i * (1 << fors_a) + indices[i]),
                );
                for (0..fors_a) |j| {
                    const sibling = (indices[i] >> @intCast(j)) ^ 1;
                    out[off + (1 + j) * n ..][0..n].* = forsNode(
                        th,
                        sk_seed,
                        @intCast(i * (@as(u32, 1) << @intCast(fors_a - j)) + sibling),
                        @intCast(j),
                        adrs,
                    );
                }
            }
        }

        /// Algorithm 17: recompute the FORS public key from a signature.
        fn forsPkFromSig(th: Thash, sig: *const [fors_sig_len]u8, md: *const [md_len]u8, adrs: Address) [n]u8 {
            var indices: [fors_k]u32 = undefined;
            base2b(md, P.a, &indices);
            var roots: [fors_k * n]u8 = undefined;
            var node_adrs = adrs;
            for (0..fors_k) |i| {
                const off = i * (1 + fors_a) * n;
                node_adrs.setTreeHeight(0);
                node_adrs.setTreeIndex(@intCast(i * (1 << fors_a) + indices[i]));
                var node = th.f(node_adrs, &.{sig[off..][0..n]}); // F
                for (0..fors_a) |j| {
                    const auth = sig[off + (1 + j) * n ..][0..n];
                    node_adrs.setTreeHeight(@intCast(j + 1));
                    if ((indices[i] >> @intCast(j)) & 1 == 0) {
                        node_adrs.setTreeIndex(node_adrs.getTreeIndex() / 2);
                        node = th.h(node_adrs, &.{ &node, auth }); // H
                    } else {
                        node_adrs.setTreeIndex((node_adrs.getTreeIndex() - 1) / 2);
                        node = th.h(node_adrs, &.{ auth, &node }); // H
                    }
                }
                roots[i * n ..][0..n].* = node;
            }
            var pk_adrs = adrs;
            pk_adrs.setTypeAndClear(.fors_roots);
            pk_adrs.setKeyPair(adrs.getKeyPair());
            return th.h(pk_adrs, &.{&roots}); // T_k
        }

        // ── §9/§10 SLH-DSA ────────────────────────────────────────────────

        /// slh_keygen_internal (Algorithm 18) from the three n-byte seeds.
        pub fn keyGenFromSeed(sk_seed: [n]u8, sk_prf: [n]u8, pk_seed: [n]u8) KeyPair {
            const th = Thash.init(pk_seed);
            var adrs: Address = .{};
            adrs.setLayer(d - 1);
            const root = xmssNode(th, sk_seed, 0, hp, adrs);
            const pk: PublicKey = .{ .seed = pk_seed, .root = root };
            return .{
                .sk = .{ .seed = sk_seed, .prf = sk_prf, .pk = pk },
                .pk = pk,
            };
        }

        /// Convenience wrapper: one 3n-byte seed blob laid out as
        /// SK.seed || SK.prf || PK.seed (the FIPS 205 §9.1 order). The
        /// caller supplies the randomness (e.g. from the OS CSPRNG).
        pub fn keyGen(seed: [3 * n]u8) KeyPair {
            return keyGenFromSeed(seed[0..n].*, seed[n .. 2 * n].*, seed[2 * n ..].*);
        }

        /// Fold a short big-endian byte string into a u64 (toInt, Alg 2).
        fn toInt64(bytes: []const u8) u64 {
            var v: u64 = 0;
            for (bytes) |b| v = (v << 8) | b;
            return v;
        }

        fn signInternalParts(out: *[signature_length]u8, msg_parts: []const []const u8, sk: SecretKey, addrnd: ?[n]u8) void {
            const th = Thash.init(sk.pk.seed);

            // Randomizer: opt_rand = addrnd, or PK.seed for the FIPS 205
            // deterministic variant (Algorithm 19 line 4).
            const opt_rand = addrnd orelse sk.pk.seed;
            const r = prfMsg(sk.prf, opt_rand, msg_parts);
            out[0..n].* = r;

            const digest = hMsg(r, sk.pk, msg_parts);
            const md = digest[0..md_len];
            const idx_tree = toInt64(digest[md_len..][0..idx_tree_len]) & tree_mask;
            const idx_leaf: u32 = @intCast(
                toInt64(digest[md_len + idx_tree_len ..][0..idx_leaf_len]) & leaf_mask,
            );

            var adrs: Address = .{};
            adrs.setTree(idx_tree);
            adrs.setTypeAndClear(.fors_tree);
            adrs.setKeyPair(idx_leaf);

            const sig_fors = out[n..][0..fors_sig_len];
            forsSign(th, md, sk.seed, adrs, sig_fors);
            const pk_fors = forsPkFromSig(th, sig_fors, md, adrs);
            htSign(th, pk_fors, sk.seed, idx_tree, idx_leaf, out[n + fors_sig_len ..][0..ht_sig_len]);
        }

        /// slh_sign_internal (Algorithm 19). `addrnd` is the additional
        /// randomness for hedged signing; pass `null` for the deterministic
        /// variant (opt_rand = PK.seed). This is the raw-message interface
        /// ACVP tests as "internal"; applications normally want `sign`.
        pub fn signInternal(out: *[signature_length]u8, msg: []const u8, sk: SecretKey, addrnd: ?[n]u8) void {
            signInternalParts(out, &.{msg}, sk, addrnd);
        }

        fn verifyInternalParts(sig: []const u8, msg_parts: []const []const u8, pk: PublicKey) bool {
            if (sig.len != signature_length) return false;
            const th = Thash.init(pk.seed);

            const r: [n]u8 = sig[0..n].*;
            const digest = hMsg(r, pk, msg_parts);
            const md = digest[0..md_len];
            const idx_tree = toInt64(digest[md_len..][0..idx_tree_len]) & tree_mask;
            const idx_leaf: u32 = @intCast(
                toInt64(digest[md_len + idx_tree_len ..][0..idx_leaf_len]) & leaf_mask,
            );

            var adrs: Address = .{};
            adrs.setTree(idx_tree);
            adrs.setTypeAndClear(.fors_tree);
            adrs.setKeyPair(idx_leaf);

            const pk_fors = forsPkFromSig(th, sig[n..][0..fors_sig_len], md, adrs);
            return htVerify(th, pk_fors, sig[n + fors_sig_len ..][0..ht_sig_len], idx_tree, idx_leaf, pk.root);
        }

        /// slh_verify_internal (Algorithm 20). Any malformed input —
        /// including a wrong-length signature — returns false, never panics.
        pub fn verifyInternal(sig: []const u8, msg: []const u8, pk: PublicKey) bool {
            return verifyInternalParts(sig, &.{msg}, pk);
        }

        pub const SignError = error{
            /// FIPS 205 limits the context string to 255 bytes.
            ContextTooLong,
        };

        /// slh_sign, pure variant (Algorithm 22): signs
        /// M' = 0x00 || len(ctx) || ctx || M. Pass `addrnd = null` for
        /// deterministic signing, or n fresh random bytes for hedged
        /// signing (recommended by FIPS 205 where randomness is available).
        pub fn sign(out: *[signature_length]u8, msg: []const u8, sk: SecretKey, ctx: []const u8, addrnd: ?[n]u8) SignError!void {
            if (ctx.len > 255) return error.ContextTooLong;
            const prefix: [2]u8 = .{ 0x00, @intCast(ctx.len) };
            signInternalParts(out, &.{ &prefix, ctx, msg }, sk, addrnd);
        }

        /// slh_verify, pure variant (Algorithm 24). Returns false (never
        /// panics) for wrong-length signatures or a context over 255 bytes.
        pub fn verify(sig: []const u8, msg: []const u8, pk: PublicKey, ctx: []const u8) bool {
            if (ctx.len > 255) return false;
            const prefix: [2]u8 = .{ 0x00, @intCast(ctx.len) };
            return verifyInternalParts(sig, &.{ &prefix, ctx, msg }, pk);
        }
    };
}

// ── component round-trip tests (full KATs live in kat_test.zig) ────────────

const TestScheme = SlhDsa(params.sha2_128f);

fn testSeed(comptime fill: u8) [16]u8 {
    return @splat(fill);
}

test "WOTS+ sign -> pkFromSig recovers pkGen's public key" {
    const th = TestScheme.Thash.init(testSeed(0xA5));
    var adrs: Address = .{};
    adrs.setTypeAndClear(.wots_hash);
    adrs.setKeyPair(3);
    const pk = TestScheme.wotsPkGen(th, testSeed(0x11), adrs);
    const msg = testSeed(0x7E);
    var sig: [TestScheme.wots_sig_len]u8 = undefined;
    TestScheme.wotsSign(th, msg, testSeed(0x11), adrs, &sig);
    const recovered = TestScheme.wotsPkFromSig(th, &sig, msg, adrs);
    try std.testing.expectEqualSlices(u8, &pk, &recovered);
    // A different message must not recover the same key.
    const other = TestScheme.wotsPkFromSig(th, &sig, testSeed(0x7F), adrs);
    try std.testing.expect(!std.mem.eql(u8, &pk, &other));
}

test "WOTS+ round-trip holds for the SHAKE and SHA2 category-3 hashes" {
    inline for (.{ SlhDsa(params.shake_128f), SlhDsa(params.sha2_192f) }) |S| {
        const seed: [S.n]u8 = @splat(0x27);
        const th = S.Thash.init(seed);
        var adrs: Address = .{};
        adrs.setTypeAndClear(.wots_hash);
        adrs.setKeyPair(1);
        const sk_seed: [S.n]u8 = @splat(0x4D);
        const pk = S.wotsPkGen(th, sk_seed, adrs);
        const msg: [S.n]u8 = @splat(0xB2);
        var sig: [S.wots_sig_len]u8 = undefined;
        S.wotsSign(th, msg, sk_seed, adrs, &sig);
        const recovered = S.wotsPkFromSig(th, &sig, msg, adrs);
        try std.testing.expectEqualSlices(u8, &pk, &recovered);
        var msg2 = msg;
        msg2[0] ^= 1;
        const other = S.wotsPkFromSig(th, &sig, msg2, adrs);
        try std.testing.expect(!std.mem.eql(u8, &pk, &other));
    }
}

test "XMSS sign -> pkFromSig recovers the tree root for every leaf" {
    const th = TestScheme.Thash.init(testSeed(0x42));
    var adrs: Address = .{};
    adrs.setLayer(1);
    adrs.setTree(0x123456);
    const root = TestScheme.xmssNode(th, testSeed(0x99), 0, TestScheme.hp, adrs);
    const msg = testSeed(0xC3);
    var idx: u32 = 0;
    while (idx < (1 << TestScheme.hp)) : (idx += 1) {
        var sig: [TestScheme.xmss_sig_len]u8 = undefined;
        TestScheme.xmssSign(th, msg, testSeed(0x99), idx, adrs, &sig);
        const recovered = TestScheme.xmssPkFromSig(th, idx, &sig, msg, adrs);
        try std.testing.expectEqualSlices(u8, &root, &recovered);
    }
}

test "FORS sign -> pkFromSig is self-consistent and message-bound" {
    const th = TestScheme.Thash.init(testSeed(0x33));
    var adrs: Address = .{};
    adrs.setTree(77);
    adrs.setTypeAndClear(.fors_tree);
    adrs.setKeyPair(5);
    var md: [TestScheme.md_len]u8 = undefined;
    for (&md, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var sig: [TestScheme.fors_sig_len]u8 = undefined;
    TestScheme.forsSign(th, &md, testSeed(0x55), adrs, &sig);
    const pk = TestScheme.forsPkFromSig(th, &sig, &md, adrs);
    TestScheme.forsSign(th, &md, testSeed(0x55), adrs, &sig);
    const pk_again = TestScheme.forsPkFromSig(th, &sig, &md, adrs);
    try std.testing.expectEqualSlices(u8, &pk, &pk_again);
    var md2 = md;
    md2[0] ^= 1;
    const pk_other = TestScheme.forsPkFromSig(th, &sig, &md2, adrs);
    try std.testing.expect(!std.mem.eql(u8, &pk, &pk_other));
}

test "key serialization round-trips" {
    const kp = TestScheme.keyGenFromSeed(testSeed(1), testSeed(2), testSeed(3));
    const pk2 = TestScheme.PublicKey.fromBytes(kp.pk.toBytes());
    const sk2 = TestScheme.SecretKey.fromBytes(kp.sk.toBytes());
    try std.testing.expectEqualSlices(u8, &kp.pk.toBytes(), &pk2.toBytes());
    try std.testing.expectEqualSlices(u8, &kp.sk.toBytes(), &sk2.toBytes());
    const kp2 = TestScheme.keyGen(testSeed(1) ++ testSeed(2) ++ testSeed(3));
    try std.testing.expectEqualSlices(u8, &kp.sk.toBytes(), &kp2.sk.toBytes());
}
