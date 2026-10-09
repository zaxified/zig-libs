// SPDX-License-Identifier: MIT
//! Key generation and signing: one LMS tree (`Tree`, `LmsSecretKey`) and the
//! HSS hierarchy over it (`SecretKey`, `SigningKey`).
//!
//! ## What is stored
//!
//! The private key of a tree is `(SEED, I)` plus the index of the next unused
//! leaf; every LM-OTS private value is re-derived on demand with RFC 8554
//! Appendix A (`x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) ||
//! SEED)`), so nothing but the 32-byte SEED is secret. The *public* interior
//! nodes are cached in memory so a signature needs no tree walk:
//!
//!   - every node at height `>= c` is kept, where `c = max(0, h - 15)`, i.e.
//!     at most `2^16 - 1` nodes (2 MiB) whatever `h` is;
//!   - the `c` lowest levels of the authentication path are recomputed for
//!     each signature from the `2^c - 1` sibling leaves (`c = 0` for H5, H10
//!     and H15, 5 for H20, 10 for H25).
//!
//! Key generation always computes all `2^h` LM-OTS public keys once. That is
//! the cost the RFC's Table 3 lists (minutes for H20 with hardware SHA-256 and
//! threads); this module is single-threaded, so H20 takes hours and H25 days
//! — use HSS with a small top tree (`H5`/`H10`/`H15`) instead, which is what
//! HSS exists for.
//!
//! ## HSS
//!
//! The private key is `(SEED, I_0, levels, position)`. Lower-level trees are
//! not stored in the key: the tree at level `i` for the signature position
//! `(q_0 .. q_{i-1})` is derived deterministically from SEED and that path
//! (`deriveChild`), regenerated on demand when the position leaves it, and
//! signed by the parent at leaf `q_{i-1}`. Because that derivation and every
//! signature are pure functions of the key, re-deriving a child tree after a
//! restart re-signs the *same* message at the *same* leaf, which produces the
//! identical bytes and reveals nothing new. Only the message signature at the
//! bottom leaf consumes state; that is what `position` counts.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const core = @import("core.zig");
const params = @import("params.zig");
const burn = @import("burn.zig");

const n = core.n;
const id_len = core.id_len;
const ParamSet = params.ParamSet;
const OtsParamSet = params.OtsParamSet;
const Level = params.Level;
const max_levels = params.max_levels;
const LmsPublicKey = core.LmsPublicKey;
const HssPublicKey = core.HssPublicKey;

/// Nodes at heights below `cacheHeight` are recomputed per signature; see the
/// module doc.
const max_cached_span = 15;

fn cacheHeight(lms: ParamSet) u5 {
    const h = lms.height();
    return if (h > max_cached_span) h - max_cached_span else 0;
}

pub const SignError = error{
    /// All `2^h` (or, for HSS, all `prod 2^h_i`) one-time keys are spent.
    KeyExhausted,
    /// `out` is shorter than the signature.
    OutputTooSmall,
};

/// One LMS tree with the secret seed and a cache of its public nodes. It has
/// **no** signing state: `sign` takes the leaf index and does not remember
/// it. Use `LmsSecretKey` or HSS `SecretKey` for the stateful discipline.
pub const Tree = struct {
    gpa: Allocator,
    lms: ParamSet,
    ots: OtsParamSet,
    id: [id_len]u8,
    /// Secret (RFC 8554 Appendix A `SEED`). Wiped by `deinit`.
    seed: [n]u8,
    /// `c`: nodes at heights below it are not cached.
    cache_h: u5,
    /// `nodes[r - 1]` is `T[r]` for every node number `r < 2^(h - c + 1)`.
    nodes: [][n]u8,

    /// Build the tree into `out`: `2^h` LM-OTS public keys are computed. O(2^h
    /// * p * 2^w) hashes; see the module doc for wall-clock at H15..H25. The
    /// seed goes in by pointer and the tree (which holds a copy) comes out
    /// by pointer, so no frame of ours or the caller's holds the SEED; the
    /// stack the body dirtied is zeroed. On error `out` holds no secret
    /// (`deinit` on it is a no-op).
    pub fn init(out: *Tree, gpa: Allocator, lms: ParamSet, ots: OtsParamSet, id: [id_len]u8, seed: *const [n]u8) Allocator.Error!void {
        return initCached(out, gpa, lms, ots, id, seed, cacheHeight(lms));
    }

    /// `init` with an explicit cache height `c <= h`: nodes at heights `>= c`
    /// are kept (`2^(h-c+1) - 1` of them), the `c` lowest path levels are
    /// recomputed per signature. Signatures are identical for every `c`.
    pub fn initCached(out: *Tree, gpa: Allocator, lms: ParamSet, ots: OtsParamSet, id: [id_len]u8, seed: *const [n]u8, c: u5) Allocator.Error!void {
        return burn.run(burn.init_burn, Allocator.Error!void, build, .{ out, gpa, lms, ots, id, seed, c });
    }

    fn build(out: *Tree, gpa: Allocator, lms: ParamSet, ots: OtsParamSet, id: [id_len]u8, seed: *const [n]u8, c: u5) Allocator.Error!void {
        const h = lms.height();
        std.debug.assert(c <= h);
        const count: usize = (@as(usize, 1) << (h - c + 1)) - 1;
        const nodes = gpa.alloc([n]u8, count) catch |e| {
            out.* = .{ .gpa = gpa, .lms = lms, .ots = ots, .id = id, .seed = @splat(0), .cache_h = c, .nodes = &.{} };
            return e;
        };
        out.* = .{ .gpa = gpa, .lms = lms, .ots = ots, .id = id, .seed = seed.*, .cache_h = c, .nodes = nodes };
        // Level c: each node is the root of a 2^c-leaf subtree.
        const first: usize = @as(usize, 1) << (h - c);
        var j: u32 = 0;
        while (j < first) : (j += 1) {
            nodes[first + j - 1] = out.subtreeRoot(c, j << c);
        }
        // Above it, plain hashing.
        var r: usize = first - 1;
        while (r >= 1) : (r -= 1) {
            nodes[r - 1] = core.intrHash(&out.id, @intCast(r), &nodes[2 * r - 1], &nodes[2 * r]);
        }
    }

    /// Frees the node cache and wipes the seed. The cache holds only public
    /// nodes (hashes of the OTS public keys), so it needs no wipe.
    pub fn deinit(self: *Tree) void {
        self.gpa.free(self.nodes);
        std.crypto.secureZero(u8, &self.seed);
        self.nodes = &.{};
    }

    pub fn root(self: *const Tree) [n]u8 {
        return self.nodes[0];
    }

    pub fn publicKey(self: *const Tree) LmsPublicKey {
        return .{ .lms = self.lms, .ots = self.ots, .id = self.id, .root = self.root() };
    }

    fn leafNode(self: *const Tree, idx: u32) [n]u8 {
        const k = core.otsPublicKeyHash(self.ots, &self.id, idx, &self.seed);
        return core.leafHash(&self.id, self.lms.leaves() + idx, &k);
    }

    /// Root of the subtree of height `k` whose leftmost leaf is `start`
    /// (Appendix C, with a fixed-size stack of at most 26 nodes).
    fn subtreeRoot(self: *const Tree, k: u5, start: u32) [n]u8 {
        var stack: [26][n]u8 = undefined;
        var levels: [26]u8 = undefined;
        var sp: usize = 0;
        const count: u32 = @as(u32, 1) << k;
        var i: u32 = 0;
        while (i < count) : (i += 1) {
            const idx = start + i;
            var node = self.leafNode(idx);
            var lvl: u8 = 0;
            var num: u32 = self.lms.leaves() + idx;
            while (sp > 0 and levels[sp - 1] == lvl) {
                sp -= 1;
                num >>= 1;
                node = core.intrHash(&self.id, num, &stack[sp], &node);
                lvl += 1;
            }
            stack[sp] = node;
            levels[sp] = lvl;
            sp += 1;
        }
        std.debug.assert(sp == 1);
        return stack[0];
    }

    /// Write the LMS signature (§5.4) of `msg` under leaf `q` to `out`
    /// (`out.len == lmsSignatureLength`). Does not touch any state: signing
    /// one leaf twice with different messages breaks the scheme.
    pub fn sign(self: *const Tree, q: u32, msg: []const u8, out: []u8) void {
        burn.run(burn.sign_burn, void, signDerived, .{ self, q, msg, out });
    }

    fn signDerived(self: *const Tree, q: u32, msg: []const u8, out: []u8) void {
        const rnd = core.deriveRandomizer(&self.id, q, &self.seed);
        self.signBody(q, msg, &rnd, out);
    }

    /// `sign` with a caller-chosen LM-OTS randomizer `C` — for known-answer
    /// tests, where the RFC's `C` is fixed. `C` must be unpredictable to an
    /// attacker (§7.1); prefer `sign`.
    pub fn signWithRandomizer(self: *const Tree, q: u32, msg: []const u8, rnd: *const [n]u8, out: []u8) void {
        burn.run(burn.sign_burn, void, signBody, .{ self, q, msg, rnd, out });
    }

    fn signBody(self: *const Tree, q: u32, msg: []const u8, rnd: *const [n]u8, out: []u8) void {
        std.debug.assert(q < self.lms.leaves());
        std.debug.assert(out.len == core.lmsSignatureLength(self.lms, self.ots));
        const h: u5 = self.lms.height();
        const c = self.cache_h;
        const ots_len = self.ots.sigLen();
        std.mem.writeInt(u32, out[0..4], q, .big);
        core.otsSign(self.ots, &self.id, q, &self.seed, rnd, msg, out[4..][0..ots_len]);
        std.mem.writeInt(u32, out[4 + ots_len ..][0..4], self.lms.typecode(), .big);
        const path = out[8 + ots_len ..];
        const r: u32 = self.lms.leaves() + q;
        var i: u5 = 0;
        while (i < h) : (i += 1) {
            const sib: u32 = (r >> i) ^ 1; // node number of path[i]
            const dst = path[@as(usize, i) * n ..][0..n];
            if (i >= c) {
                dst.* = self.nodes[sib - 1];
            } else {
                const first_leaf = (sib - (self.lms.leaves() >> i)) << i;
                dst.* = self.subtreeRoot(i, first_leaf);
            }
        }
    }
};

/// One stateful LMS key: a `Tree` and the next unused leaf `q`.
///
/// `sign` advances `q` **before** it writes the signature and refuses with
/// `error.KeyExhausted` once `q == 2^h` (RFC 8554 §5.4.1). Making the new
/// `q` durable before the signature leaves the process is the caller's job:
/// there is no persistence hook here — for a signer that needs one, use HSS
/// with `L = 1` (`SigningKey`), whose signatures are the LMS ones behind a
/// four-byte prefix. Not thread-safe.
pub const LmsSecretKey = struct {
    tree: Tree,
    /// Next unused leaf.
    q: u32,

    /// Builds the key into `out` (see `Tree.init`; the seed goes in by pointer).
    // secret-api-ok: a thin wrapper -- the seed goes by pointer into `Tree.init` (-> `initCached`, burned) and is never copied in this frame
    pub fn init(out: *LmsSecretKey, gpa: Allocator, lms: ParamSet, ots: OtsParamSet, id: [id_len]u8, seed: *const [n]u8) Allocator.Error!void {
        out.q = 0;
        return Tree.init(&out.tree, gpa, lms, ots, id, seed);
    }

    pub fn deinit(self: *LmsSecretKey) void {
        self.tree.deinit();
    }

    pub fn publicKey(self: *const LmsSecretKey) LmsPublicKey {
        return self.tree.publicKey();
    }

    pub fn signatureLength(self: *const LmsSecretKey) usize {
        return core.lmsSignatureLength(self.tree.lms, self.tree.ots);
    }

    /// Sign `msg`; returns `out[0..signatureLength()]`.
    // secret-api-ok: delegates to `Tree.sign` (burned, `burn.sign_burn`); this frame holds only the leaf index, `self` is a pointer
    pub fn sign(self: *LmsSecretKey, msg: []const u8, out: []u8) SignError![]u8 {
        const len = self.signatureLength();
        if (self.q >= self.tree.lms.leaves()) return error.KeyExhausted;
        if (out.len < len) return error.OutputTooSmall;
        const q = self.q;
        self.q += 1; // advanced before any signature byte exists
        self.tree.sign(q, msg, out[0..len]);
        return out[0..len];
    }
};

/// The durable state of an HSS key: which leaf of each level's current tree
/// signs next. `q[L-1]` is the message leaf, `q[i]` the leaf that certified
/// the level `i+1` tree. Persist this (with the secret seed, `I_0` and the
/// level list) before releasing each signature.
pub const Position = struct {
    q: [max_levels]u32 = @splat(0),
    /// Set once the last leaf of the last tree has been used.
    exhausted: bool = false,

    /// The position after one more signature (mixed-radix increment).
    pub fn next(self: Position, levels: []const Level) Position {
        var p = self;
        var i = levels.len;
        while (i > 0) {
            i -= 1;
            p.q[i] += 1;
            if (p.q[i] < levels[i].lms.leaves()) return p;
            p.q[i] = 0;
        }
        p.exhausted = true;
        return p;
    }
};

pub const InitError = Allocator.Error || error{
    /// `levels.len` is not in 1..8.
    InvalidLevels,
    /// A restored position has a leaf index beyond its tree.
    InvalidPosition,
};

pub const Persist = struct {
    ctx: *anyopaque,
    /// Called with the position that must be on stable storage before the
    /// signature at the *previous* position is released.
    write: *const fn (ctx: *anyopaque, next: Position) anyerror!void,
    /// The `std.Io` that `write` blocks in, if any. `SigningKey.sign` holds
    /// its guard across `write`; with an `Io` a second signer parks on an
    /// `std.Io.Mutex` instead of spinning, which is required when the `Io`
    /// runs several tasks on one thread (a spinning signer would starve one
    /// suspended in `write` forever).
    io: ?std.Io = null,
};

pub const HssError = SignError || Allocator.Error || error{
    /// The `Persist.write` hook failed. No leaf was consumed.
    PersistFailed,
};

/// HSS private key (RFC 8554 §6). Bare form: **not thread-safe**, no copy
/// guard, no persistence hook — see `SigningKey` for those.
pub const SecretKey = struct {
    gpa: Allocator,
    /// Secret. Every tree's SEED derives from it.
    seed: [n]u8,
    levels: [max_levels]Level,
    n_levels: u8,
    /// Position of the next signature.
    pos: Position,
    /// Trees of the current path; `trees[0]` is always present.
    trees: [max_levels]?Tree = @splat(null),
    /// `sigs[i]`: LMS signature of `pubs[i + 1]` by `trees[i]`.
    sigs: [max_levels]?[]u8 = @splat(null),
    pubs: [max_levels]LmsPublicKey = undefined,
    /// Number of levels currently built (>= 1) and the path they were built for.
    built: u8 = 0,
    path: [max_levels]u32 = @splat(0),

    /// Generate the key into `out`: builds only the top tree (RFC 8554 §6.1
    /// says the lower ones may wait for the first signature, and they do).
    /// `seed` is the secret (by pointer, so no frame holds a copy) and `id`
    /// the 16-byte identifier of the top tree, both per Appendix A; the caller
    /// supplies them (no RNG in this module) from a CSPRNG. `restore_at`
    /// restores an existing key; null starts at 0. On error `out` holds no
    /// secret.
    // secret-api-ok: the seed arrives by pointer, is copied only into the caller's `out`, and the tree build runs under `Tree.initCached`'s burn
    pub fn init(out: *SecretKey, gpa: Allocator, levels: []const Level, seed: *const [n]u8, id: [id_len]u8, restore_at: ?Position) InitError!void {
        out.seed = @splat(0); // stays zero on every error return
        if (levels.len < 1 or levels.len > max_levels) return error.InvalidLevels;
        const pos = restore_at orelse Position{};
        if (!pos.exhausted) {
            for (levels, 0..) |lv, i| if (pos.q[i] >= lv.lms.leaves()) return error.InvalidPosition;
        }
        out.* = .{
            .gpa = gpa,
            .seed = seed.*,
            .levels = undefined,
            .n_levels = @intCast(levels.len),
            .pos = pos,
        };
        @memcpy(out.levels[0..levels.len], levels);
        out.trees[0] = @as(Tree, undefined);
        Tree.init(&out.trees[0].?, gpa, levels[0].lms, levels[0].ots, id, seed) catch |e| {
            out.trees[0] = null;
            std.crypto.secureZero(u8, &out.seed);
            return e;
        };
        out.pubs[0] = out.trees[0].?.publicKey();
        out.built = 1;
    }

    /// Wipes the seeds and frees the caches.
    pub fn deinit(self: *SecretKey) void {
        for (&self.trees) |*t| if (t.*) |*tree| {
            tree.deinit();
            t.* = null;
        };
        for (&self.sigs) |*s| if (s.*) |buf| {
            self.gpa.free(buf);
            s.* = null;
        };
        std.crypto.secureZero(u8, &self.seed);
        self.built = 0;
    }

    pub fn publicKey(self: *const SecretKey) HssPublicKey {
        return .{ .levels = self.n_levels, .top = self.pubs[0] };
    }

    pub fn position(self: *const SecretKey) Position {
        return self.pos;
    }

    pub fn levelList(self: *const SecretKey) []const Level {
        return self.levels[0..self.n_levels];
    }

    /// Length of every signature this key produces (§6.2).
    pub fn signatureLength(self: *const SecretKey) usize {
        var len: usize = 4;
        for (self.levelList(), 0..) |lv, i| {
            len += core.lmsSignatureLength(lv.lms, lv.ots);
            if (i + 1 < self.n_levels) len += LmsPublicKey.encoded_len;
        }
        return len;
    }

    /// The SEED and I of the tree at level `level` for the path `path`
    /// (`path.len == level`, the parents' leaf indices), written to the
    /// out-params. Level 0 is the key itself and is not derived.
    fn deriveChild(seed_out: *[n]u8, id_out: *[id_len]u8, master: *const [n]u8, level: u8, path: []const u32) void {
        var out: [2][n]u8 = undefined;
        for (&out, 0..) |*o, tag| {
            var h = Sha256.init(.{});
            h.update("zig-libs lms hss child v1");
            h.update(&[_]u8{ @intCast(tag), level });
            for (path) |d| h.update(&std.mem.toBytes(std.mem.nativeToBig(u32, d)));
            h.update(master);
            o.* = h.finalResult();
        }
        seed_out.* = out[0];
        id_out.* = out[1][0..id_len].*;
        std.crypto.secureZero(u8, std.mem.asBytes(&out));
    }

    fn dropFrom(self: *SecretKey, keep: u8) void {
        var i: u8 = keep;
        while (i < self.built) : (i += 1) {
            if (self.trees[i]) |*t| t.deinit();
            self.trees[i] = null;
            if (self.sigs[i - 1]) |buf| self.gpa.free(buf);
            self.sigs[i - 1] = null;
        }
        self.built = keep;
    }

    /// Make trees `1 .. L-1` match the leaf path `d`. Pure with respect to
    /// the signing state: the certificates it creates are deterministic
    /// functions of the key, so repeating this after a crash is harmless.
    fn ensureTrees(self: *SecretKey, d: [max_levels]u32) Allocator.Error!void {
        // The child seeds live in this body's frame: run it one frame down and
        // zero what it dirtied.
        return burn.run(burn.hss_burn, Allocator.Error!void, ensureTreesBody, .{ self, d });
    }

    fn ensureTreesBody(self: *SecretKey, d: [max_levels]u32) Allocator.Error!void {
        const total = self.n_levels;
        var keep: u8 = 1;
        while (keep < self.built and keep < total and self.path[keep - 1] == d[keep - 1]) keep += 1;
        if (keep < self.built) self.dropFrom(keep);
        var i: u8 = self.built;
        while (i < total) : (i += 1) {
            var child_seed: [n]u8 = undefined;
            var child_id: [id_len]u8 = undefined;
            deriveChild(&child_seed, &child_id, &self.seed, i, d[0..i]);
            defer std.crypto.secureZero(u8, &child_seed);
            const lv = self.levels[i];
            self.trees[i] = @as(Tree, undefined);
            const tree = &self.trees[i].?;
            Tree.init(tree, self.gpa, lv.lms, lv.ots, child_id, &child_seed) catch |e| {
                self.trees[i] = null;
                return e;
            };
            const parent = self.levels[i - 1];
            const buf = self.gpa.alloc(u8, core.lmsSignatureLength(parent.lms, parent.ots)) catch |e| {
                tree.deinit();
                self.trees[i] = null;
                return e;
            };
            const child_pub = tree.publicKey();
            self.trees[i - 1].?.sign(d[i - 1], &child_pub.toBytes(), buf);
            self.pubs[i] = child_pub;
            self.sigs[i - 1] = buf;
            self.path[i - 1] = d[i - 1];
            self.built = i + 1;
        }
    }

    /// Sign `msg` (§6.2, Algorithm 8); returns `out[0..signatureLength()]`.
    /// The position is advanced before the message signature is produced.
    /// May run `O(2^h)` hashing when the position enters a new lower tree.
    /// An `OutOfMemory` while building a tree burns no leaf.
    pub fn sign(self: *SecretKey, msg: []const u8, out: []u8) HssError![]u8 {
        return self.signPersisting(msg, out, null);
    }

    /// `sign` with a durability hook: `persist.write` receives the next
    /// position after the trees are ready and before the position advances,
    /// so a failure leaves the key untouched.
    pub fn signPersisting(self: *SecretKey, msg: []const u8, out: []u8, persist: ?Persist) HssError![]u8 {
        if (self.pos.exhausted) return error.KeyExhausted;
        const total = self.signatureLength();
        if (out.len < total) return error.OutputTooSmall;
        const d = self.pos.q;
        try self.ensureTrees(d);
        const next = self.pos.next(self.levelList());
        if (persist) |p| p.write(p.ctx, next) catch return error.PersistFailed;
        self.pos = next; // before any bytes of the message signature exist

        const last = self.n_levels - 1;
        std.mem.writeInt(u32, out[0..4], last, .big);
        var off: usize = 4;
        var i: u8 = 0;
        while (i < last) : (i += 1) {
            const s = self.sigs[i].?;
            @memcpy(out[off..][0..s.len], s);
            off += s.len;
            @memcpy(out[off..][0..LmsPublicKey.encoded_len], &self.pubs[i + 1].toBytes());
            off += LmsPublicKey.encoded_len;
        }
        const bl = core.lmsSignatureLength(self.levels[last].lms, self.levels[last].ots);
        self.trees[last].?.sign(d[last], msg, out[off..][0..bl]);
        std.debug.assert(off + bl == total);
        return out[0..total];
    }
};

/// The hardened handle, in the style of `xmss.SigningKey`: one lock over the
/// whole exhaustion-check → tree-build → persist → advance → sign sequence,
/// a durable-position hook called before any signature byte is produced, and
/// a copy guard. Written in place (`init` on the final address) because it
/// records that address.
pub const SigningKey = struct {
    sk: SecretKey,
    home: *const SigningKey,
    busy: std.atomic.Value(bool),
    /// The guard when `persist.io` is set (see `Persist.io`).
    io_mu: std.Io.Mutex = .init,
    persist: ?Persist,

    pub const Error = HssError || error{
        /// This handle was copied or moved after `init`.
        KeyHandleCopied,
    };

    /// Takes ownership of `*sk` (moved into `dst`, the source then wiped and
    /// not to be used again); `dst` must already be at its final address.
    pub fn init(dst: *SigningKey, sk: *SecretKey, persist: ?Persist) void {
        dst.* = .{ .sk = sk.*, .home = dst, .busy = .init(false), .persist = persist };
        std.crypto.secureZero(u8, std.mem.asBytes(sk));
    }

    pub fn deinit(self: *SigningKey) void {
        self.sk.deinit();
    }

    /// Racy progress indicator while another thread signs.
    pub fn position(self: *const SigningKey) Position {
        return self.sk.pos;
    }

    // secret-api-ok: thin guard around `SecretKey.signPersisting`, whose secret-touching steps (`ensureTrees`, `Tree.sign`) are burned; this frame holds pointers and the guard flag only
    pub fn sign(self: *SigningKey, msg: []const u8, out: []u8) Error![]u8 {
        if (self.home != self) return error.KeyHandleCopied;
        if (self.persist) |p| if (p.io) |io| {
            self.io_mu.lockUncancelable(io);
            defer self.io_mu.unlock(io);
            return self.sk.signPersisting(msg, out, self.persist);
        };
        while (self.busy.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
        defer self.busy.store(false, .release);
        return self.sk.signPersisting(msg, out, self.persist);
    }
};

test "cacheHeight: nodes are cached whole up to H15, and capped at 2^16 - 1 above" {
    try std.testing.expectEqual(@as(u5, 0), cacheHeight(.sha256_m32_h5));
    try std.testing.expectEqual(@as(u5, 0), cacheHeight(.sha256_m32_h10));
    try std.testing.expectEqual(@as(u5, 0), cacheHeight(.sha256_m32_h15));
    try std.testing.expectEqual(@as(u5, 5), cacheHeight(.sha256_m32_h20));
    try std.testing.expectEqual(@as(u5, 10), cacheHeight(.sha256_m32_h25));
}
