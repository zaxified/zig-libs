// SPDX-License-Identifier: MIT
//! xmss — XMSS, the eXtended Merkle Signature Scheme (RFC 8391): stateful
//! hash-based digital signatures, pure Zig over std.crypto's SHA-256.
//!
//! Status: complete for the single-tree SHA-256 ciphersuite (n = 32, w = 16,
//! len = 67). All three REQUIRED RFC 8391 parameter sets are exported —
//! XMSS-SHA2_10_256 / _16_256 / _20_256 (IANA OIDs 0x01/0x02/0x03) — and any
//! tree height can be instantiated via `XmssSha2(h, oid)`. Implements keygen,
//! sign and verify: the WOTS+ one-time signatures (§3.1: chain, pkGen, sign,
//! pkFromSig, base-w + checksum), the hash-address scheme (§2.5), the keyed
//! hash functions F/H/H_msg/PRF (§5.1: SHA-256(toByte(i, 32) || KEY || M)
//! with domain-separation prefixes i = 0..3), L-trees (§4.1.5), treeHash
//! (§4.1.6), randomized message hashing (§4.1.9) and the RFC wire formats
//! (public key OID || root || SEED; signature idx || r || sig_ots || auth).
//!
//! Validation (see src/kat_vectors.zig for provenance): byte-exact against
//! the official XMSS reference implementation (github.com/XMSS/xmss-reference,
//! the code linked from RFC 8391 §7) for (a) the F/H/H_msg/PRF primitives,
//! (b) full WOTS+ pkGen + sign + pkFromSig, (c) XMSS keygen + sign at a
//! reduced test height h = 4, and (d) `verify` of two reference-generated
//! XMSS-SHA2_10_256 signatures (leaf 0 and leaf 517) under the reference's
//! h = 10 public key — i.e. a real external (pk, msg, sig) interop triple.
//! Additionally, h = 10 keyGen reproduces the reference root byte-exactly
//! (verified out-of-band; excluded from the unit suite — ~40 s in Debug).
//! keygen/sign at h = 16/20 are the same code path, exercised only at h ≤ 10.
//!
//! ** STATEFUL-SIGNATURE HAZARD ** — XMSS is stateful: every WOTS+ one-time
//! key (leaf index) MUST sign at most one message. Reusing an index reveals
//! enough chain intermediates to forge signatures — it breaks the scheme,
//! not just one signature. `sign` advances `SecretKey.idx` before producing
//! output (RFC 8391 §4.1.9) and errors with `KeyExhausted` after 2^h uses,
//! but the CALLER owns durability: persist the updated private key before
//! releasing a signature, never restore an old key copy from backup, never
//! share one key across processes/machines without index partitioning
//! (§4.1.12). If you cannot guarantee that, use a stateless scheme (sibling
//! `slhdsa` module) instead.
//!
//! WOTS+ secret chains are derived from `sk_seed`, not stored: sk[i] =
//! PRF_keygen(sk_seed, SEED || ADRS) with prefix toByte(4, 32) — the
//! NIST SP 800-208 / xmss-reference derivation (RFC 8391 §3.1.7 explicitly
//! leaves this implementation-defined; it does not affect verify interop).
//! Key generation takes caller-supplied seeds — bring your own CSPRNG (std
//! 0.16 removed std.crypto.random); there is no internal randomness, so all
//! operations are deterministic and reproducible.
//!
//! Auth-path traversal: BDS (Buchmann–Dahmen–Schneider) log-space Merkle
//! traversal is maintained in `SecretKey.bds`, ported from the reference
//! `xmss_core_fast.c` with parameter k = 0. `sign` emits the current leaf's
//! precomputed auth path and advances the state to the next leaf in ~O(h)
//! hashing (≈ verify cost) rather than rebuilding it O(2^h). The BDS state
//! advances in lockstep with `idx`; a caller that jumps `idx` out of band
//! triggers an automatic O(2^h) resync so the emitted signature stays
//! byte-exact. keyGen is still O(2^h) (it now also seeds the BDS state).
//!
//! Out of scope: XMSS^MT (§4.2 multi-tree) and the SHA-512 and SHAKE
//! ciphersuites (§5 OPTIONAL sets).
//! Not constant-time hardened (hash-based; no secret-dependent branching
//! beyond the hash inputs themselves — verify is public-data only).
//!
//! Zig std GAP: yes — std.crypto has no stateful hash-based signature
//! (RFC 8391 XMSS / RFC 8554 LMS). Recon: std.crypto.hash.sha2.Sha256 for
//! all keyed hashes; std.mem.writeInt/readInt for toByte/index encodings;
//! plain comparison for verify (public data — no std.crypto.timing_safe
//! needed). Consumer: SCADA firmware signing (IEC 62443-style code-signing
//! chains standardize on SP 800-208 stateful HBS).

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const meta = .{
    .platform = .any,
    .role = .util, // pure computation — no I/O, no allocation
    .concurrency = .reentrant, // no globals; SecretKey mutation is caller-owned
    .model_after = "RFC 8391 (XMSS); XMSS/xmss-reference as KAT oracle",
    .deps = .{}, // std only (SHA-256)
};

/// Security parameter n (§5.1, SHA-256 suite): bytes per hash/node/seed.
pub const n = 32;
/// Winternitz parameter (§5.2: all RFC 8391 sets use w = 16).
pub const w = 16;
/// len_1 = ceil(8n / lg(w)) (§3.1.1).
pub const wots_len1 = 64;
/// len_2 = floor(lg(len_1 * (w - 1)) / lg(w)) + 1 (§3.1.1).
pub const wots_len2 = 3;
/// len = len_1 + len_2: n-byte strings per WOTS+ key/signature (§3.1.1).
pub const wots_len = wots_len1 + wots_len2;

// §5.1 domain-separation prefixes: toByte(i, 32) for i = 0..4. Index 4 is
// PRF_keygen from NIST SP 800-208 (see doc comment).
fn padPrefix(comptime i: u8) [n]u8 {
    var p = [_]u8{0} ** n;
    p[n - 1] = i;
    return p;
}
const pad_f = padPrefix(0);
const pad_h = padPrefix(1);
const pad_hmsg = padPrefix(2);
const pad_prf = padPrefix(3);
const pad_prf_keygen = padPrefix(4);

/// toByte(x, 32) (§2.4): 32-byte big-endian encoding of an integer.
pub fn toByte32(x: u64) [32]u8 {
    var out = [_]u8{0} ** 32;
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

fn keyedHash(comptime pad: *const [n]u8, key: *const [n]u8, m: []const u8) [n]u8 {
    var st = Sha256.init(.{});
    st.update(pad);
    st.update(key);
    st.update(m);
    var out: [n]u8 = undefined;
    st.final(&out);
    return out;
}

/// F (§5.1): SHA-256(toByte(0, 32) || KEY || M), M of n bytes.
pub fn hashF(key: *const [n]u8, m: *const [n]u8) [n]u8 {
    return keyedHash(&pad_f, key, m);
}

/// H (§5.1): SHA-256(toByte(1, 32) || KEY || M), M of 2n bytes.
pub fn hashH(key: *const [n]u8, m: *const [2 * n]u8) [n]u8 {
    return keyedHash(&pad_h, key, m);
}

/// PRF (§5.1): SHA-256(toByte(3, 32) || KEY || M), M a 32-byte index/ADRS.
pub fn prf(key: *const [n]u8, m: *const [32]u8) [n]u8 {
    return keyedHash(&pad_prf, key, m);
}

/// H_msg (§5.1, §4.1.9): SHA-256(toByte(2, 32) || r || root || toByte(idx, n)
/// || M) — the randomized message digest. Streams M (arbitrary length).
pub fn hashMsg(r: *const [n]u8, root: *const [n]u8, idx: u64, msg: []const u8) [n]u8 {
    var st = Sha256.init(.{});
    st.update(&pad_hmsg);
    st.update(r);
    st.update(root);
    st.update(&toByte32(idx));
    st.update(msg);
    var out: [n]u8 = undefined;
    st.final(&out);
    return out;
}

/// PRF_keygen (SP 800-208 / xmss-reference): SHA-256(toByte(4, 32) ||
/// SK_SEED || SEED || ADRS) — derives one WOTS+ secret chain start.
pub fn prfKeygen(sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *const [32]u8) [n]u8 {
    var st = Sha256.init(.{});
    st.update(&pad_prf_keygen);
    st.update(sk_seed);
    st.update(pub_seed);
    st.update(adrs);
    var out: [n]u8 = undefined;
    st.final(&out);
    return out;
}

/// One F iteration of the §3.1.2 chain: key = PRF(SEED, ADRS·k=0), bitmask =
/// PRF(SEED, ADRS·k=1), out = F(key, in XOR bitmask). Caller must have set
/// the chain and hash address words; this only touches keyAndMask.
pub fn chainStep(x: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [n]u8 {
    adrs.setKeyAndMask(0);
    const key = prf(pub_seed, &adrs.toBytes());
    adrs.setKeyAndMask(1);
    const bm = prf(pub_seed, &adrs.toBytes());
    var tmp: [n]u8 = undefined;
    for (&tmp, x, bm) |*t, xb, mb| t.* = xb ^ mb;
    return hashF(&key, &tmp);
}

/// chain (§3.1.2, Algorithm 2, iteratively): F iterated `steps` times on X,
/// at hash addresses start .. start+steps-1. Requires start + steps <= w-1.
pub fn chain(x: [n]u8, start: u32, steps: u32, pub_seed: *const [n]u8, adrs: *Adrs) [n]u8 {
    std.debug.assert(start + steps <= w - 1);
    var tmp = x;
    var i = start;
    while (i < start + steps) : (i += 1) {
        adrs.setHashAddress(i);
        tmp = chainStep(&tmp, pub_seed, adrs);
    }
    return tmp;
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
/// start value = PRF_keygen(sk_seed, SEED || ADRS·chain=i,hash=0,k=0).
pub fn wotsSkGen(sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
    var sk: [wots_len][n]u8 = undefined;
    adrs.setHashAddress(0);
    adrs.setKeyAndMask(0);
    for (&sk, 0..) |*chain_sk, i| {
        adrs.setChainAddress(@intCast(i));
        chain_sk.* = prfKeygen(sk_seed, pub_seed, &adrs.toBytes());
    }
    return sk;
}

/// WOTS_genPK (§3.1.4, Algorithm 4), with the private key derived from
/// sk_seed. ADRS must be an OTS address; only its last three words change.
pub fn wotsPkGen(sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
    var pk = wotsSkGen(sk_seed, pub_seed, adrs);
    for (&pk, 0..) |*node, i| {
        adrs.setChainAddress(@intCast(i));
        node.* = chain(node.*, 0, w - 1, pub_seed, adrs);
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

/// WOTS_sign (§3.1.5, Algorithm 5) on an n-byte message digest.
pub fn wotsSign(msg: *const [n]u8, sk_seed: *const [n]u8, pub_seed: *const [n]u8, adrs: *Adrs) [wots_len][n]u8 {
    const digits = msgToBaseW(msg);
    var sig = wotsSkGen(sk_seed, pub_seed, adrs);
    for (&sig, digits, 0..) |*node, d, i| {
        adrs.setChainAddress(@intCast(i));
        node.* = chain(node.*, 0, d, pub_seed, adrs);
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
        node.* = chain(sig_node, d, w - 1 - d, pub_seed, adrs);
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
    var ots_adrs = Adrs{};
    ots_adrs.setType(Adrs.type_ots);
    ots_adrs.setOtsAddress(leaf_idx);
    var pk = wotsPkGen(sk_seed, pub_seed, &ots_adrs);

    var ltree_adrs = Adrs{};
    ltree_adrs.setType(Adrs.type_ltree);
    ltree_adrs.setLtreeAddress(leaf_idx);
    return ltree(&pk, pub_seed, &ltree_adrs);
}

/// Single-tree XMSS over the SHA-256 suite (n = 32, w = 16) at a comptime
/// tree height. `oid` is the 4-byte IANA identifier written into the wire
/// public key (use the RFC-assigned value for standard heights; anything in
/// 0xDDDDDDDD..0xFFFFFFFF is free for private/test use).
pub fn XmssSha2(comptime tree_height: u5, comptime wire_oid: u32) type {
    std.debug.assert(tree_height >= 1 and tree_height <= 30);
    return struct {
        const Self = @This();

        pub const h = tree_height;
        pub const oid = wire_oid;
        /// 2^h: one-time keys available == max messages signable (§4.1.1).
        pub const max_signatures: u64 = 1 << h;
        /// §4.1.8 wire signature: idx(4) || r(n) || sig_ots(len*n) || auth(h*n).
        pub const signature_length: usize = 4 + n + wots_len * n + @as(usize, h) * n;
        /// §4.1.7 / B.3 wire public key: OID(4) || root(n) || SEED(n).
        pub const public_key_length: usize = 4 + 2 * n;

        /// §4.1.3 private key. `idx` is the STATE: the next unused leaf.
        /// `bds` is the BDS tree-traversal state that lets `sign` update the
        /// authentication path in ~O(h) instead of rebuilding it (O(2^h)).
        /// Both advance together on every `sign`. Persist the WHOLE struct
        /// after every sign; see module doc.
        pub const SecretKey = struct {
            /// Next unused WOTS+ leaf index — advanced by `sign`.
            idx: u32,
            /// Secret seed for WOTS+ chain derivation (never on the wire).
            sk_seed: [n]u8,
            /// Secret key for the §4.1.9 randomized message hash.
            sk_prf: [n]u8,
            /// Tree root (public; kept here as §4.1.3 requires it to sign).
            root: [n]u8,
            /// Public seed SEED for keys/bitmasks.
            pub_seed: [n]u8,
            /// BDS auth-path traversal state; kept in lockstep with `idx`.
            bds: BdsState,
        };

        pub const PublicKey = struct {
            root: [n]u8,
            seed: [n]u8,

            /// Wire encode (§B.3): OID || root || SEED.
            pub fn toBytes(pk: PublicKey) [public_key_length]u8 {
                var out: [public_key_length]u8 = undefined;
                std.mem.writeInt(u32, out[0..4], oid, .big);
                out[4 .. 4 + n].* = pk.root;
                out[4 + n ..].* = pk.seed;
                return out;
            }

            pub fn fromBytes(bytes: *const [public_key_length]u8) error{UnsupportedOid}!PublicKey {
                if (std.mem.readInt(u32, bytes[0..4], .big) != oid) return error.UnsupportedOid;
                return .{ .root = bytes[4 .. 4 + n].*, .seed = bytes[4 + n ..].* };
            }
        };

        pub const KeyPair = struct {
            sk: SecretKey,
            pk: PublicKey,
        };

        // ===== BDS tree-traversal state (§4.1 fast auth-path update) =====
        // Buchmann–Dahmen–Schneider log-space Merkle traversal (RFC 8391
        // App. C references it; "Post-Quantum Cryptography", Springer 2009).
        // Ported from the official reference `xmss_core_fast.c` with the BDS
        // parameter k = 0 (no `retain` array): k affects only internal state
        // and per-signature work, never the emitted signature, which is a
        // property of the tree and leaf index alone. Each `sign` emits the
        // current leaf's precomputed auth path and then advances the state to
        // the next leaf with ~(h/2) leaf generations instead of 2^h.

        /// Number of `keep` slots (§ reference `tree_height >> 1`).
        const keep_len = h >> 1;

        /// One treehash instance: computes a future auth node at height
        /// `target_h`, one leaf at a time, sharing `BdsState.stack`.
        const TreehashInst = struct {
            node: [n]u8 = @splat(0),
            /// Next leaf this instance will consume.
            next_idx: u32 = 0,
            /// Height of the auth node this instance produces.
            target_h: u5 = 0,
            /// How many slots this instance currently owns on the shared stack.
            stackusage: u32 = 0,
            completed: bool = true,
        };

        /// BDS traversal state. Small, fixed-size, no allocation. Held inside
        /// `SecretKey` and advanced atomically with `idx` on every `sign`.
        pub const BdsState = struct {
            /// Shared work stack for the treehash instances.
            stack: [h + 1][n]u8 = @splat(@splat(0)),
            stacklevels: [h + 1]u5 = @splat(0),
            stackoffset: u32 = 0,
            /// Authentication path for leaf `covered_idx`.
            auth: [h][n]u8 = @splat(@splat(0)),
            /// Left nodes retained for upcoming auth-path refreshes.
            keep: [keep_len][n]u8 = @splat(@splat(0)),
            treehash: [h]TreehashInst = @splat(.{}),
            /// Leaf index that `auth` currently authenticates. Kept equal to
            /// `SecretKey.idx`; a mismatch triggers a resync in `sign`.
            covered_idx: u32 = 0,
        };

        /// Initialize the BDS state for leaf 0 and return the tree root. This
        /// is the §4.1.6 treeHash pass instrumented to also capture leaf 0's
        /// authentication path and seed the treehash instances that will
        /// produce future auth nodes. O(2^h) hashing — same order as a plain
        /// root computation, so `keyGen` cost is unchanged in big-O (it now
        /// also records the initial traversal state).
        fn bdsInit(state: *BdsState, sk_seed: *const [n]u8, pub_seed: *const [n]u8) [n]u8 {
            for (&state.treehash, 0..) |*th, i| {
                th.* = .{ .target_h = @intCast(i), .completed = true, .stackusage = 0 };
            }
            var stack: [h + 1][n]u8 = undefined;
            var stacklevels: [h + 1]u5 = undefined;
            var sp: u32 = 0;
            var i: u32 = 0; // count of leaves consumed (reference `i`)
            var leaf: u32 = 0;
            while (leaf < max_signatures) : (leaf += 1) {
                stack[sp] = genLeaf(sk_seed, pub_seed, leaf);
                stacklevels[sp] = 0;
                sp += 1;
                while (sp > 1 and stacklevels[sp - 1] == stacklevels[sp - 2]) {
                    const nodeh = stacklevels[sp - 1];
                    const shifted = i >> nodeh;
                    if (shifted == 1) {
                        // Right sibling on leaf 0's path at this height.
                        state.auth[nodeh] = stack[sp - 1];
                    } else if (shifted == 3) {
                        // First future auth node at this height.
                        state.treehash[nodeh].node = stack[sp - 1];
                    }
                    var adrs = Adrs{};
                    adrs.setType(Adrs.type_hashtree);
                    adrs.setTreeHeight(nodeh);
                    adrs.setTreeIndex(leaf >> (nodeh + 1));
                    stack[sp - 2] = randHash(&stack[sp - 2], &stack[sp - 1], pub_seed, &adrs);
                    stacklevels[sp - 2] += 1;
                    sp -= 1;
                }
                i += 1;
            }
            state.stackoffset = 0;
            state.covered_idx = 0;
            return stack[0];
        }

        /// Lowest node height held on the shared stack by `th` (reference
        /// `treehash_minheight_on_stack`).
        fn treehashMinheight(state: *const BdsState, th: *const TreehashInst) u5 {
            var r: u5 = h;
            var k: u32 = 0;
            while (k < th.stackusage) : (k += 1) {
                const lvl = state.stacklevels[state.stackoffset - k - 1];
                if (lvl < r) r = lvl;
            }
            return r;
        }

        /// One step of a treehash instance: consume its next leaf and fold it
        /// into the shared stack (reference `treehash_update`).
        fn treehashUpdate(state: *BdsState, th: *TreehashInst, sk_seed: *const [n]u8, pub_seed: *const [n]u8) void {
            var node = genLeaf(sk_seed, pub_seed, th.next_idx);
            var nodeheight: u5 = 0;
            while (th.stackusage > 0 and state.stacklevels[state.stackoffset - 1] == nodeheight) {
                const left = state.stack[state.stackoffset - 1];
                var adrs = Adrs{};
                adrs.setType(Adrs.type_hashtree);
                adrs.setTreeHeight(nodeheight);
                adrs.setTreeIndex(th.next_idx >> (nodeheight + 1));
                node = randHash(&left, &node, pub_seed, &adrs);
                nodeheight += 1;
                th.stackusage -= 1;
                state.stackoffset -= 1;
            }
            if (nodeheight == th.target_h) {
                th.node = node;
                th.completed = true;
            } else {
                state.stack[state.stackoffset] = node;
                state.stacklevels[state.stackoffset] = nodeheight;
                state.stackoffset += 1;
                th.stackusage += 1;
                th.next_idx += 1;
            }
        }

        /// Perform up to `updates` treehash steps on the instance that needs
        /// it most (reference `bds_treehash_update`, k = 0).
        fn bdsTreehashUpdate(state: *BdsState, updates: u32, sk_seed: *const [n]u8, pub_seed: *const [n]u8) void {
            var j: u32 = 0;
            while (j < updates) : (j += 1) {
                var l_min: u5 = h;
                var level: u32 = h; // sentinel: nothing to do
                var idx: u32 = 0;
                while (idx < h) : (idx += 1) {
                    const th = &state.treehash[idx];
                    var low: u5 = undefined;
                    if (th.completed) {
                        low = h;
                    } else if (th.stackusage == 0) {
                        low = @intCast(idx);
                    } else {
                        low = treehashMinheight(state, th);
                    }
                    if (low < l_min) {
                        level = idx;
                        l_min = low;
                    }
                }
                if (level == h) break;
                treehashUpdate(state, &state.treehash[level], sk_seed, pub_seed);
            }
        }

        /// Emit the auth path for `leaf_idx` (already in `state.auth`) and
        /// compute the auth path for the NEXT leaf (reference `bds_round`,
        /// k = 0). Must only be called for `leaf_idx < max_signatures - 1`.
        fn bdsRound(state: *BdsState, leaf_idx: u32, sk_seed: *const [n]u8, pub_seed: *const [n]u8) void {
            var tau: u5 = h;
            {
                var i: u5 = 0;
                while (i < h) : (i += 1) {
                    if ((leaf_idx >> i) & 1 == 0) {
                        tau = i;
                        break;
                    }
                }
            }

            var buf_left: [n]u8 = undefined;
            var buf_right: [n]u8 = undefined;
            if (tau > 0) {
                buf_left = state.auth[tau - 1];
                buf_right = state.keep[(tau - 1) >> 1];
            }
            if (((leaf_idx >> (tau + 1)) & 1) == 0 and tau < h - 1) {
                state.keep[tau >> 1] = state.auth[tau];
            }
            if (tau == 0) {
                state.auth[0] = genLeaf(sk_seed, pub_seed, leaf_idx);
            } else {
                var adrs = Adrs{};
                adrs.setType(Adrs.type_hashtree);
                adrs.setTreeHeight(tau - 1);
                adrs.setTreeIndex(leaf_idx >> tau);
                state.auth[tau] = randHash(&buf_left, &buf_right, pub_seed, &adrs);
                var i: u5 = 0;
                while (i < tau) : (i += 1) {
                    state.auth[i] = state.treehash[i].node;
                }
                i = 0;
                while (i < tau) : (i += 1) {
                    const startidx = leaf_idx + 1 + 3 * (@as(u32, 1) << i);
                    if (@as(u64, startidx) < max_signatures) {
                        state.treehash[i].target_h = i;
                        state.treehash[i].next_idx = startidx;
                        state.treehash[i].completed = false;
                        state.treehash[i].stackusage = 0;
                    }
                }
            }
        }

        /// Reconstruct the BDS state so that `bds.auth` authenticates leaf
        /// `target`, by replaying the traversal from leaf 0. Used only when
        /// the caller advanced `idx` out of band (manual jump, restored/copied
        /// key). O(target * h) leaf generations. The replay is exactly the
        /// sequence `sign` would have produced, so the resulting auth path is
        /// identical to a from-scratch (`buildAuth`) computation.
        fn rebuildStateTo(sk: *SecretKey, target: u32) void {
            _ = bdsInit(&sk.bds, &sk.sk_seed, &sk.pub_seed);
            var leaf: u32 = 0;
            while (leaf < target) : (leaf += 1) {
                bdsRound(&sk.bds, leaf, &sk.sk_seed, &sk.pub_seed);
                bdsTreehashUpdate(&sk.bds, h >> 1, &sk.sk_seed, &sk.pub_seed);
            }
            sk.bds.covered_idx = target;
        }

        /// treeHash (§4.1.6, Algorithm 9): root of the height-`t` subtree
        /// whose leftmost leaf is `s` (s must be 2^t-aligned). O(2^t) WOTS+
        /// key generations; fixed stack, no allocation.
        pub fn treeHash(sk_seed: *const [n]u8, pub_seed: *const [n]u8, s: u32, t: u5) [n]u8 {
            std.debug.assert(t <= h);
            std.debug.assert(s % (@as(u32, 1) << t) == 0);
            var stack: [h + 1][n]u8 = undefined;
            var heights: [h + 1]u5 = undefined;
            var sp: usize = 0;

            var i: u32 = 0;
            while (i < (@as(u32, 1) << t)) : (i += 1) {
                var node = genLeaf(sk_seed, pub_seed, s + i);
                var node_height: u5 = 0;
                var tree_idx: u32 = s + i;
                var adrs = Adrs{};
                adrs.setType(Adrs.type_hashtree);
                while (sp > 0 and heights[sp - 1] == node_height) {
                    tree_idx = (tree_idx - 1) / 2;
                    adrs.setTreeHeight(node_height);
                    adrs.setTreeIndex(tree_idx);
                    node = randHash(&stack[sp - 1], &node, pub_seed, &adrs);
                    sp -= 1;
                    node_height += 1;
                }
                stack[sp] = node;
                heights[sp] = node_height;
                sp += 1;
            }
            return stack[0];
        }

        /// XMSS_keyGen (§4.1.7, Algorithm 10) from caller-supplied seeds
        /// (uniform random, n bytes each; sk_seed and sk_prf secret, SEED
        /// public). Deterministic; O(2^h) hashing.
        pub fn keyGen(sk_seed: [n]u8, sk_prf: [n]u8, pub_seed: [n]u8) KeyPair {
            var bds: BdsState = .{};
            const root = bdsInit(&bds, &sk_seed, &pub_seed);
            return .{
                .sk = .{ .idx = 0, .sk_seed = sk_seed, .sk_prf = sk_prf, .root = root, .pub_seed = pub_seed, .bds = bds },
                .pk = .{ .root = root, .seed = pub_seed },
            };
        }

        /// buildAuth (§4.1.9): auth[j] = root of the height-j subtree that
        /// is the sibling of the path from leaf `idx` — naive recompute
        /// (O(2^h) total), no state beyond the seeds. Retained as the
        /// from-scratch reference that the BDS traversal is differential-
        /// tested against (both must yield the identical auth path).
        pub fn buildAuth(sk_seed: *const [n]u8, pub_seed: *const [n]u8, idx: u32, auth: *[h][n]u8) void {
            for (auth, 0..) |*node, j| {
                const jj: u5 = @intCast(j);
                const k = (idx >> jj) ^ 1;
                node.* = treeHash(sk_seed, pub_seed, k << jj, jj);
            }
        }

        /// XMSS_sign (§4.1.9, Algorithm 12): sign `msg`, writing the wire
        /// signature to `out`. Advances sk.idx AND the BDS state together
        /// before producing output — persist sk before releasing the
        /// signature (see module doc). The auth path is taken from the BDS
        /// state (computed during the previous round / keyGen), then the
        /// state is advanced to the next leaf in ~O(h) hashing instead of
        /// recomputing it O(2^h). The emitted signature is byte-identical to
        /// a from-scratch auth-path build. Errors with KeyExhausted once all
        /// 2^h one-time keys are used.
        pub fn sign(sk: *SecretKey, out: *[signature_length]u8, msg: []const u8) error{KeyExhausted}!void {
            if (sk.idx >= max_signatures) return error.KeyExhausted;
            const idx = sk.idx;

            // Resync if the caller advanced idx out of band (manual jump, or a
            // restored/copied key): rebuild the traversal state for this leaf
            // so the emitted auth path stays byte-exact. Normal sequential
            // signing never triggers this (covered_idx tracks idx exactly).
            if (sk.bds.covered_idx != idx) {
                rebuildStateTo(sk, idx);
            }

            sk.idx = idx + 1;

            const r = prf(&sk.sk_prf, &toByte32(idx));
            const mhash = hashMsg(&r, &sk.root, idx, msg);

            std.mem.writeInt(u32, out[0..4], idx, .big);
            out[4 .. 4 + n].* = r;

            // treeSig (§4.1.9, Algorithm 11): WOTS+ signature + auth path.
            var ots_adrs = Adrs{};
            ots_adrs.setType(Adrs.type_ots);
            ots_adrs.setOtsAddress(idx);
            const sig_ots = wotsSign(&mhash, &sk.sk_seed, &sk.pub_seed, &ots_adrs);
            for (sig_ots, 0..) |node, i| {
                out[4 + n + i * n ..][0..n].* = node;
            }

            // Auth path for leaf `idx`, held in the BDS state.
            for (sk.bds.auth, 0..) |node, j| {
                out[4 + n + wots_len * n + j * n ..][0..n].* = node;
            }

            // Advance the traversal state to prepare leaf idx+1's auth path.
            if (idx < max_signatures - 1) {
                bdsRound(&sk.bds, idx, &sk.sk_seed, &sk.pub_seed);
                bdsTreehashUpdate(&sk.bds, h >> 1, &sk.sk_seed, &sk.pub_seed);
            }
            sk.bds.covered_idx = idx + 1;
        }

        /// XMSS_rootFromSig (§4.1.10, Algorithm 13): the root value implied
        /// by a signature; equals pk.root iff the signature is valid.
        pub fn rootFromSig(idx: u32, sig_ots: *const [wots_len][n]u8, auth: *const [h][n]u8, mhash: *const [n]u8, seed: *const [n]u8) [n]u8 {
            var ots_adrs = Adrs{};
            ots_adrs.setType(Adrs.type_ots);
            ots_adrs.setOtsAddress(idx);
            var pk_ots = wotsPkFromSig(sig_ots, mhash, seed, &ots_adrs);

            var ltree_adrs = Adrs{};
            ltree_adrs.setType(Adrs.type_ltree);
            ltree_adrs.setLtreeAddress(idx);
            var node = ltree(&pk_ots, seed, &ltree_adrs);

            var adrs = Adrs{};
            adrs.setType(Adrs.type_hashtree);
            var tree_idx = idx;
            for (auth, 0..) |*sibling, k| {
                adrs.setTreeHeight(@intCast(k));
                if (tree_idx % 2 == 0) {
                    tree_idx /= 2;
                    adrs.setTreeIndex(tree_idx);
                    node = randHash(&node, sibling, seed, &adrs);
                } else {
                    tree_idx = (tree_idx - 1) / 2;
                    adrs.setTreeIndex(tree_idx);
                    node = randHash(sibling, &node, seed, &adrs);
                }
            }
            return node;
        }

        /// XMSS_verify (§4.1.10, Algorithm 14). Rejects malformed lengths
        /// and out-of-range indexes. Public-data comparison (not secret).
        pub fn verify(pk: PublicKey, msg: []const u8, sig: []const u8) bool {
            if (sig.len != signature_length) return false;
            const idx = std.mem.readInt(u32, sig[0..4], .big);
            if (idx >= max_signatures) return false;
            const r: *const [n]u8 = sig[4 .. 4 + n];

            var sig_ots: [wots_len][n]u8 = undefined;
            for (&sig_ots, 0..) |*node, i| {
                node.* = sig[4 + n + i * n ..][0..n].*;
            }
            var auth: [h][n]u8 = undefined;
            for (&auth, 0..) |*node, j| {
                node.* = sig[4 + n + wots_len * n + j * n ..][0..n].*;
            }

            const mhash = hashMsg(r, &pk.root, idx, msg);
            const root = rootFromSig(idx, &sig_ots, &auth, &mhash, &pk.seed);
            return std.mem.eql(u8, &root, &pk.root);
        }
    };
}

/// XMSS-SHA2_10_256 (§5.3 REQUIRED; IANA OID 0x00000001): 2^10 signatures,
/// 2500-byte signature. The byte-exact KAT/interop target of this module.
pub const XmssSha2_10_256 = XmssSha2(10, 0x00000001);
/// XMSS-SHA2_16_256 (§5.3 REQUIRED; IANA OID 0x00000002): 2^16 signatures.
/// Same code path as h = 10; keygen ≈ 79e6 hashes — minutes, not seconds.
pub const XmssSha2_16_256 = XmssSha2(16, 0x00000002);
/// XMSS-SHA2_20_256 (§5.3 REQUIRED + RFC default; IANA OID 0x00000003):
/// 2^20 signatures. Keygen ≈ 1.3e9 hashes; naive auth paths make signing
/// O(2^20) hashing too — practical only with out-of-band caching.
pub const XmssSha2_20_256 = XmssSha2(20, 0x00000003);

test "API surface: RFC 8391 sizes" {
    // §4.1.8: |Sig| = 4 + n + (len + h)*n; Table 3 |Sig| column.
    try std.testing.expectEqual(@as(usize, 2500), XmssSha2_10_256.signature_length);
    try std.testing.expectEqual(@as(usize, 2692), XmssSha2_16_256.signature_length);
    try std.testing.expectEqual(@as(usize, 2820), XmssSha2_20_256.signature_length);
    try std.testing.expectEqual(@as(usize, 68), XmssSha2_10_256.public_key_length);
    try std.testing.expectEqual(@as(u64, 1024), XmssSha2_10_256.max_signatures);
}

test "public key wire round-trip and OID rejection" {
    const X = XmssSha2_10_256;
    var pk = X.PublicKey{ .root = undefined, .seed = undefined };
    for (&pk.root, 0..) |*b, i| b.* = @truncate(i);
    for (&pk.seed, 0..) |*b, i| b.* = @truncate(i * 3);
    const bytes = pk.toBytes();
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, bytes[0..4], .big));
    const back = try X.PublicKey.fromBytes(&bytes);
    try std.testing.expectEqualSlices(u8, &pk.root, &back.root);
    try std.testing.expectEqualSlices(u8, &pk.seed, &back.seed);
    try std.testing.expectError(error.UnsupportedOid, XmssSha2_16_256.PublicKey.fromBytes(&bytes));
}

test "base-w + checksum example (§2.6: 0x1234 -> 1,2,3,4)" {
    var msg = [_]u8{0} ** n;
    msg[0] = 0x12;
    msg[1] = 0x34;
    const digits = msgToBaseW(&msg);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, digits[0..4]);
    // Checksum: 64 digits, csum = 64*15 - (1+2+3+4) = 950; digits from
    // toByte(950 << 4, 2) = 0x3b60 -> 3, 11, 6.
    try std.testing.expectEqualSlices(u8, &.{ 3, 11, 6 }, digits[wots_len1..]);
}

test "stateful discipline: sign advances idx, never repeats, fails closed when exhausted" {
    // Reduced height h = 4 (16 one-time keys) — full lifecycle in ~ms.
    const X = XmssSha2(4, 0xDDDDDDDD);
    var sk_seed: [n]u8 = undefined;
    var sk_prf: [n]u8 = undefined;
    var pub_seed: [n]u8 = undefined;
    for (&sk_seed, 0..) |*b, i| b.* = @truncate(i + 1);
    for (&sk_prf, 0..) |*b, i| b.* = @truncate(i + 101);
    for (&pub_seed, 0..) |*b, i| b.* = @truncate(i + 201);
    var kp = X.keyGen(sk_seed, sk_prf, pub_seed);

    var sig: [X.signature_length]u8 = undefined;
    var seen = [_]bool{false} ** X.max_signatures;
    var k: u32 = 0;
    while (k < X.max_signatures) : (k += 1) {
        // `idx` is the NEXT unused leaf before signing.
        try std.testing.expectEqual(k, kp.sk.idx);
        try X.sign(&kp.sk, &sig, "message");
        // The wire index equals the leaf that was just consumed …
        const wire_idx = std.mem.readInt(u32, sig[0..4], .big);
        try std.testing.expectEqual(k, wire_idx);
        // … which must never have been used before (no silent reuse) …
        try std.testing.expect(!seen[wire_idx]);
        seen[wire_idx] = true;
        // … and the state advanced by exactly one.
        try std.testing.expectEqual(k + 1, kp.sk.idx);
        // Every emitted signature verifies under the public key.
        try std.testing.expect(X.verify(kp.pk, "message", &sig));
    }

    // All 2^h one-time keys consumed: further signing fails closed, and the
    // index neither wraps nor rolls back to a reusable leaf.
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "message"));
    try std.testing.expectEqual(@as(u32, X.max_signatures), kp.sk.idx);
    try std.testing.expectError(error.KeyExhausted, X.sign(&kp.sk, &sig, "message"));
    try std.testing.expectEqual(@as(u32, X.max_signatures), kp.sk.idx);
}

test "fuzz: PublicKey.fromBytes never panics on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzPublicKeyFromBytes, .{});
}

fn fuzzPublicKeyFromBytes(_: void, smith: *std.testing.Smith) !void {
    const X = XmssSha2_10_256;
    var bytes: [X.public_key_length]u8 = undefined;
    smith.bytes(&bytes);
    _ = X.PublicKey.fromBytes(&bytes) catch return;
}

test "fuzz: verify (the wire signature parser) never panics on arbitrary pk/msg/sig bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{});
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    // XmssSha2_10_256: the 2500-byte-signature, smallest/fastest variant —
    // same `verify` code path as every other height, cheapest for fuzzing.
    const X = XmssSha2_10_256;
    var pk_bytes: [X.public_key_length]u8 = undefined;
    smith.bytes(&pk_bytes);
    // Force a valid OID so `PublicKey.fromBytes` succeeds most of the time
    // and `verify`'s actual signature-parsing body (not just the early OID
    // guard) gets exercised.
    std.mem.writeInt(u32, pk_bytes[0..4], X.oid, .big);
    const pk = X.PublicKey.fromBytes(&pk_bytes) catch return;

    var msg: [64]u8 = undefined;
    smith.bytes(&msg);

    var sig_buf: [X.signature_length]u8 = undefined;
    smith.bytes(&sig_buf);
    const len: usize = smith.valueRangeAtMost(u16, 0, sig_buf.len);
    // `verify` parses `idx`/`r`/`sig_ots`/`auth` straight out of `sig` with
    // no bounds checks beyond the `sig.len != signature_length` guard — it
    // must never panic/OOB regardless of length or content.
    _ = X.verify(pk, &msg, sig_buf[0..len]);
}

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
