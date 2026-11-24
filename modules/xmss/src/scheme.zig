// SPDX-License-Identifier: MIT
//! Single-tree XMSS (RFC 8391 §4.1) over any hash suite of `suite.zig`, at a
//! comptime tree height: keygen with BDS traversal state, sign, verify and the
//! wire formats. `root.zig` documents the scheme and the stateful hazard.

const std = @import("std");
const burn = @import("burn.zig");
const suite = @import("suite.zig");
const Adrs = suite.Adrs;
const toByte32 = suite.toByte32;

/// XMSS over the suite `cfg` at a comptime tree height. `oid` is the 4-byte
/// IANA identifier written into the wire public key (use the assigned value
/// for standard sets; anything in 0xDDDDDDDD..0xFFFFFFFF is free for
/// private/test use).
pub fn Xmss(comptime cfg: suite.Config, comptime tree_height: u5, comptime wire_oid: u32) type {
    // 2, not 1: at h == 1 the BDS `keep` array is `[h >> 1] == [0]` and
    // `bdsRound`'s `keep[(tau - 1) >> 1]` is a compile error the moment `sign`
    // is instantiated — so h == 1 type-checked and then failed on use. The
    // documented range is now the effective one.
    std.debug.assert(tree_height >= 2 and tree_height <= 30);
    return struct {
        const Self = @This();

        /// The hash suite's primitives (`suite.zig`).
        pub const S = suite.Suite(cfg);
        const n = S.n;
        const wots_len = S.wots_len;
        const prf = S.prf;
        const hashMsg = S.hashMsg;
        const chain = S.chain;
        const randHash = S.randHash;
        const wotsSkGen = S.wotsSkGen;
        const wotsPkGen = S.wotsPkGen;
        const wotsSign = S.wotsSign;
        const wotsPkFromSig = S.wotsPkFromSig;
        const ltree = S.ltree;
        const genLeaf = S.genLeaf;

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

            /// Wipe the two secret seeds. `SecretKey` is a value type with no
            /// `deinit`, so this is opt-in: call it on every copy you made
            /// once the key is retired. `root`/`pub_seed`/`idx` are public
            /// values and are deliberately left alone — a zeroed `idx` would
            /// look like a fresh key, which is the opposite of safe here.
            ///
            /// The WOTS+ chain values a signature derived are not this
            /// function's job: `sign` (like `keyGen`) zeroes the stack its
            /// computation used before returning (see `burn.zig`). The raw
            /// WOTS+ primitives (`wotsSkGen`, `wotsSign`, `wotsPkGen`,
            /// `genLeaf`, `chain`) do not burn — a caller using them directly
            /// owns that stack.
            pub fn zeroize(sk: *SecretKey) void {
                std.crypto.secureZero(u8, &sk.sk_seed);
                std.crypto.secureZero(u8, &sk.sk_prf);
            }
        };

        /// A hardened handle around a `SecretKey`, for the two hazards a
        /// value-type stateful key cannot defend against on its own (audit
        /// F1). Entirely opt-in: `SecretKey` + `sign` keep working exactly as
        /// before for callers that own the state discipline themselves.
        ///
        /// It defends three things, none of which the bare API can:
        ///
        ///  1. **Concurrent `sign` on one key.** Bare `sign` reads `sk.idx`
        ///     and writes it back with no interlock, so two threads sharing
        ///     one `*SecretKey` can both observe the same index — the same
        ///     WOTS+ one-time key signs two messages, which is a *key
        ///     recovery* break, not a mere reuse. Here the whole
        ///     read-persist-sign-advance sequence runs under a lock, so leaf
        ///     indices are handed out exactly once.
        ///  2. **Struct copy.** A `SigningKey` records the address it was
        ///     initialized at; a copy (or a move) lands at a different
        ///     address and `sign` returns `error.KeyHandleCopied` instead of
        ///     quietly forking the counter into two keys that both think they
        ///     are at leaf `k`. This is the whole reason `init` writes through
        ///     a `*SigningKey` rather than returning one by value.
        ///  3. **Crash between signing and persisting.** The optional
        ///     `persist` hook is invoked with the NEXT index *before* any
        ///     signature bytes are produced, and a failure aborts the sign
        ///     with the leaf UNCONSUMED. So the durable index is never behind
        ///     the emitted signatures — the direction that would allow reuse
        ///     after a restart. (NIST SP 800-208 §7 makes exactly this the
        ///     deployer's obligation; this hook is where it attaches.)
        ///
        /// What it deliberately does NOT do: prevent you from also holding a
        /// `*SecretKey` into `handle.sk` and signing with it directly, or from
        /// restoring an old serialized key. Rollback across process lifetimes
        /// is a storage property, not an API one.
        pub const SigningKey = struct {
            sk: SecretKey,
            /// The address `init` was called on. `sign` refuses to run
            /// anywhere else — see hazard 2 above.
            home: *const SigningKey,
            /// Test-and-set guard over the whole sign sequence. A tiny local
            /// spin lock rather than `std.Thread.Mutex` so this module keeps
            /// `meta.platform = .any` and `deps = .{}` (std hashing only): the
            /// critical section is one XMSS signature, and the contended case
            /// is a caller doing something they were told not to.
            busy: std.atomic.Value(bool),
            /// The guard when `persist.io` is set (see `Persist.io`).
            io_mu: std.Io.Mutex = .init,
            persist: ?Persist,

            /// Durable-index hook. `write` is called with the index that must
            /// already be on stable storage before the signature at index
            /// `next_idx - 1` is released.
            pub const Persist = struct {
                ctx: *anyopaque,
                write: *const fn (ctx: *anyopaque, next_idx: u32) anyerror!void,
                /// The `std.Io` that `write` blocks in, if any. `sign` holds
                /// its guard across `write`; with an `Io` a second signer
                /// parks on an `std.Io.Mutex` instead of spinning, which is
                /// required when the `Io` runs several tasks on one thread
                /// (a spinning signer would starve one suspended in `write`).
                io: ?std.Io = null,
            };

            pub const Error = error{
                /// All 2^h one-time keys are spent.
                KeyExhausted,
                /// This handle is not at the address it was initialized at —
                /// it was copied or moved. Re-`init` it at its new home if the
                /// move was intended, having made sure the OLD handle is dead.
                KeyHandleCopied,
                /// The `persist` hook failed. No leaf was consumed.
                PersistFailed,
            };

            /// Takes ownership of `*sk`: moved into `dst` (the seeds travel by
            /// pointer, never by value), then the source is retired — its two
            /// seeds wiped (`zeroize`) and its `idx` set to `max_signatures`,
            /// so a stale `sign` on it is `error.KeyExhausted` rather than a
            /// second signer at the same leaf (as `lms.SigningKey.init` wipes
            /// its source). `dst` must already be at its final address.
            pub fn init(dst: *SigningKey, sk: *SecretKey, persist: ?Persist) void {
                dst.* = .{ .sk = sk.*, .home = dst, .busy = .init(false), .persist = persist };
                sk.zeroize();
                sk.idx = @intCast(max_signatures);
            }

            /// Next unused leaf. Racy to read while another thread signs —
            /// it is a progress indicator, not a claim.
            pub fn index(self: *const SigningKey) u32 {
                return self.sk.idx;
            }

            /// Wipe the underlying secret seeds (see `SecretKey.zeroize`).
            pub fn zeroize(self: *SigningKey) void {
                self.sk.zeroize();
            }

            // secret-api-ok: thin guard around `Self.sign` (burned, `burn.burn_size`) via `signGuarded`; this frame holds pointers and the guard flag only
            pub fn sign(self: *SigningKey, out: *[signature_length]u8, msg: []const u8) Error!void {
                if (self.home != self) return error.KeyHandleCopied;
                if (self.persist) |p| if (p.io) |io| {
                    self.io_mu.lockUncancelable(io);
                    defer self.io_mu.unlock(io);
                    return self.signGuarded(out, msg);
                };
                while (self.busy.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
                    std.atomic.spinLoopHint();
                }
                defer self.busy.store(false, .release);
                return self.signGuarded(out, msg);
            }

            /// `sign` with its guard held.
            fn signGuarded(self: *SigningKey, out: *[signature_length]u8, msg: []const u8) Error!void {
                // Check exhaustion BEFORE persisting: a rejected sign must not
                // move the durable index either.
                if (self.sk.idx >= max_signatures) return error.KeyExhausted;
                if (self.persist) |p| {
                    p.write(p.ctx, self.sk.idx + 1) catch return error.PersistFailed;
                }
                Self.sign(&self.sk, out, msg) catch |e| switch (e) {
                    error.KeyExhausted => unreachable, // checked above, under the lock
                };
            }
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

        /// `BdsState.covered_idx` value meaning "this state authenticates no
        /// leaf yet". Not a valid index: `max_signatures` is at most 2^30.
        pub const not_synced: u32 = std.math.maxInt(u32);

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
            ///
            /// The default is the **not-synchronised sentinel**, not 0. A
            /// `SecretKey` built as a literal — which is exactly what a caller
            /// restoring a key does, and what SPEC.md described the private
            /// key as being — gets `.bds = .{}`, and with a 0 default that
            /// read as "already synchronised for leaf 0". So a key restored at
            /// index 0, the single most likely restore point, skipped the
            /// resync, signed with an all-zero auth path, returned success,
            /// and **consumed the leaf** for a signature that does not verify.
            /// It never recovered either: `covered_idx` then tracks `idx` in
            /// lockstep, so the mismatch is never seen again. Every other
            /// index self-heals, which is what made it hard to notice.
            /// `maxInt(u32)` cannot be a valid leaf (`h <= 30`), so the
            /// unsynchronised state is now unrepresentable as "in sync".
            covered_idx: u32 = not_synced,
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
        /// Not `pub`: its `t <= h` bound is an assert, and the stack it
        /// indexes is `[h + 1]`, so a caller passing `t > h` overflowed a
        /// fixed array — `unreachable` in Debug, and in ReleaseFast an
        /// out-of-bounds write that corrupted the loop state and never
        /// returned (killed at 600 s). No internal caller can reach that, and
        /// nothing outside the module needs the function.
        fn treeHash(sk_seed: *const [n]u8, pub_seed: *const [n]u8, s: u32, t: u5) [n]u8 {
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
        /// public), written to `kp` — the private key never travels by value.
        /// Deterministic; O(2^h) hashing. Zeroes the stack the computation
        /// used before returning (see `burn.zig`).
        pub fn keyGen(kp: *KeyPair, sk_seed: *const [n]u8, sk_prf: *const [n]u8, pub_seed: *const [n]u8) void {
            burn.run(burn.burn_size, void, keyGenInner, .{ kp, sk_seed, sk_prf, pub_seed });
        }

        fn keyGenInner(kp: *KeyPair, sk_seed: *const [n]u8, sk_prf: *const [n]u8, pub_seed: *const [n]u8) void {
            kp.sk.bds = .{};
            const root = bdsInit(&kp.sk.bds, sk_seed, pub_seed);
            kp.sk.idx = 0;
            kp.sk.sk_seed = sk_seed.*;
            kp.sk.sk_prf = sk_prf.*;
            kp.sk.root = root;
            kp.sk.pub_seed = pub_seed.*;
            kp.pk = .{ .root = root, .seed = pub_seed.* };
        }

        /// buildAuth (§4.1.9): auth[j] = root of the height-j subtree that
        /// is the sibling of the path from leaf `idx` — naive recompute
        /// (O(2^h) total), no state beyond the seeds. Retained as the
        /// from-scratch reference that the BDS traversal is differential-
        /// tested against (both must yield the identical auth path).
        pub fn buildAuth(sk_seed: *const [n]u8, pub_seed: *const [n]u8, idx: u32, auth: *[h][n]u8) void {
            burn.run(burn.burn_size, void, buildAuthInner, .{ sk_seed, pub_seed, idx, auth });
        }

        fn buildAuthInner(sk_seed: *const [n]u8, pub_seed: *const [n]u8, idx: u32, auth: *[h][n]u8) void {
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
        ///
        /// Zeroes the stack the computation used before returning, on the
        /// error path too (see `burn.zig`).
        pub fn sign(sk: *SecretKey, out: *[signature_length]u8, msg: []const u8) error{KeyExhausted}!void {
            return burn.run(burn.burn_size, error{KeyExhausted}!void, signInner, .{ sk, out, msg });
        }

        fn signInner(sk: *SecretKey, out: *[signature_length]u8, msg: []const u8) error{KeyExhausted}!void {
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
        // secret-api-ok: the verify path; `seed` is the PUBLIC SEED of the key, `sig_ots` / `auth` are parts of a published signature
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
