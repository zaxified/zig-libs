// SPDX-License-Identifier: MIT
//! mls.secrettree — RFC 9420 §9, the Secret Tree: the half of the key
//! schedule that turns ONE per-epoch value (`encryption_secret`) into a
//! private, forward-secret key stream for every sender in the group,
//! without any of them ever exchanging another message.
//!
//! **Why a tree and not a per-sender KDF call.** The secret tree has the
//! same shape as the group's ratchet tree, and a member is only ever given
//! the secrets on the path from the root to their OWN leaf. That is what
//! makes the construction interesting: knowing your own leaf's secret tells
//! you nothing about your sibling's subtree, so a member cannot forge
//! another member's message keys even though every key in the epoch derives
//! from a single shared root. `nodeSecret` therefore derives DOWNWARD from
//! the root on demand rather than materializing the whole tree — the same
//! computation a real client does, and the only one that has the deletion
//! properties §9.2 asks for.
//!
//! **Two ratchets per leaf, and why the split matters.** Each leaf seeds a
//! `handshake` and an `application` ratchet (§9's Figure 26). They are
//! separate so that an implementation can retain application keys for
//! out-of-order delivery while advancing handshake keys eagerly — the two
//! traffic classes have genuinely different reordering tolerance, and
//! sharing one ratchet between them would force the stricter policy on
//! both.
//!
//! **The out-of-order window is the part that is easy to get subtly
//! wrong.** A ratchet is forward-only: generation `j+1`'s secret is derived
//! from generation `j`'s and `j`'s is then destroyed (§9.2). But messages
//! arrive out of order, so a receiver that has already ratcheted past
//! generation `j` must have kept `j`'s key/nonce somewhere or it can never
//! decrypt that message. `Window` is that "somewhere": a fixed-size ring of
//! retained, not-yet-used key/nonce pairs, with two hard limits that both
//! exist for security rather than for memory —
//!
//! * a key is **erased the moment it is returned** (`get` consumes), so the
//!   same generation can never be accepted twice; replay of a captured
//!   message fails with `error.GenerationConsumed` rather than decrypting a
//!   second time.
//! * a bounded **forward jump** (`max_forward_jump`), so a forged sender
//!   claiming generation 2^32-1 costs one error return instead of four
//!   billion KDF invocations. Without this an attacker needs a single
//!   4-byte field to hang a receiver.
//!
//! Neither limit is spelled out as a MUST in §9.2 — the RFC says members
//! "MAY keep unconsumed values around for some reasonable amount of time" —
//! so both are this module's policy, exposed as parameters rather than
//! buried.
//!
//! Model: RFC 9420 §9 (Secret Tree) + §9.1 (Encryption Keys, including
//! `DeriveTreeSecret` and §6.3.2's sender-data key/nonce) + §9.2 (Deletion
//! Schedule). Verified byte-exact against the official
//! `mlswg/mls-implementations` `secret-tree.json` vectors — see
//! `kat_secrettree_test.zig` and `NOTICE`.

const std = @import("std");
const suite = @import("suite.zig");
const crypto = @import("crypto.zig");
const treemath = @import("treemath.zig");

pub const Error = error{
    /// A node/leaf index that does not exist in a tree of this size.
    NodeIndexOutOfRange,
    /// `Window.get` was asked for a generation the ratchet has already
    /// passed AND whose key/nonce is no longer retained — either it was
    /// already used (replay) or it fell out of the window.
    GenerationConsumed,
    /// `Window.get` was asked for a generation further ahead than
    /// `max_forward_jump`. Ratcheting there would be unbounded work driven
    /// by an unauthenticated field.
    GenerationTooFarAhead,
    /// The ratchet reached generation 2^32-1; the epoch must end (RFC 9420
    /// §9.1: generation is a `uint32`).
    RatchetExhausted,
} || crypto.Error;

// ── §9: labels ────────────────────────────────────────────────────────────

/// RFC 9420 §9's Figure 25/26 and §9.1's Figure 28 labels, named once so
/// the derivation and its KAT cannot disagree about a string literal.
pub const label_tree = "tree";
pub const context_left = "left";
pub const context_right = "right";
pub const label_handshake = "handshake";
pub const label_application = "application";
pub const label_key = "key";
pub const label_nonce = "nonce";
pub const label_secret = "secret";

/// Which of a leaf's two ratchets (§9's Figure 26) — handshake messages
/// (Proposal/Commit) or application messages.
pub const RatchetKind = enum {
    handshake,
    application,

    fn label(self: RatchetKind) []const u8 {
        return switch (self) {
            .handshake => label_handshake,
            .application => label_application,
        };
    }
};

// ── §9: deriving down the tree ────────────────────────────────────────────

/// RFC 9420 §9 Figure 25, one step: a child's secret from its parent's.
pub fn childSecret(comptime S: type, parent_secret: [S.Nh]u8, is_left: bool) Error![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    try crypto.ExpandWithLabel(
        S,
        parent_secret,
        label_tree,
        if (is_left) context_left else context_right,
        &out,
    );
    return out;
}

/// The secret at array-based tree index `node_index` in the secret tree
/// rooted at `encryption_secret`, for a tree of `n_leaves` leaves (RFC 9420
/// §9).
///
/// Derives DOWNWARD from the root along the direct path, which is what a
/// real client does — it never holds a sibling subtree's secret even
/// transiently. The tree shape is `treemath`'s, i.e. the same left-balanced
/// (possibly truncated) tree as the group's ratchet tree, so a group whose
/// size is not a power of two derives over the truncated tree rather than a
/// padded one.
pub fn nodeSecret(
    comptime S: type,
    encryption_secret: [S.Nh]u8,
    n_leaves: usize,
    node_index: usize,
) Error![S.Nh]u8 {
    if (n_leaves == 0 or node_index >= treemath.node_width(n_leaves)) return error.NodeIndexOutOfRange;

    // Path from `node_index` up to (but excluding) the root. `max_path_len`
    // is treemath's own bound on a direct path, so this cannot overflow for
    // any tree treemath will accept.
    var path: [treemath.max_path_len]usize = undefined;
    var depth: usize = 0;
    const r = treemath.root(n_leaves);
    var x = node_index;
    while (x != r) : (depth += 1) {
        path[depth] = x;
        x = treemath.parent(x, n_leaves) orelse return error.NodeIndexOutOfRange;
    }

    var secret = encryption_secret;
    while (depth > 0) {
        depth -= 1;
        const child = path[depth];
        const p = treemath.parent(child, n_leaves).?;
        secret = try childSecret(S, secret, treemath.left(p).? == child);
    }
    return secret;
}

/// RFC 9420 §9 Figure 26: the generation-0 secret of one of a leaf's two
/// ratchets. `leaf_index` is a LEAF index (0-based among members), which is
/// node index `2 * leaf_index` in the array-based tree.
pub fn ratchetBaseSecret(
    comptime S: type,
    encryption_secret: [S.Nh]u8,
    n_leaves: usize,
    leaf_index: usize,
    kind: RatchetKind,
) Error![S.Nh]u8 {
    if (leaf_index >= n_leaves) return error.NodeIndexOutOfRange;
    const leaf_secret = try nodeSecret(S, encryption_secret, n_leaves, leaf_index * 2);
    var out: [S.Nh]u8 = undefined;
    try crypto.ExpandWithLabel(S, leaf_secret, kind.label(), "", &out);
    return out;
}

// ── §9.1: the sender ratchet ──────────────────────────────────────────────

/// One generation's AEAD key and nonce (RFC 9420 §9.1's Figure 28).
pub fn KeyNonce(comptime S: type) type {
    return struct {
        const Self = @This();
        key: [S.Nk]u8,
        nonce: [S.Nn]u8,

        /// RFC 9420 §9.2: erase as soon as the value is consumed.
        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, &self.key);
            std.crypto.secureZero(u8, &self.nonce);
        }
    };
}

/// RFC 9420 §9.1's forward-only sender ratchet: a secret plus the
/// generation it currently sits at. Deriving the key/nonce for a generation
/// does NOT advance it; `advance` does, and destroys the secret it came
/// from.
pub fn Ratchet(comptime S: type) type {
    return struct {
        const Self = @This();

        secret: [S.Nh]u8,
        generation: u32,

        pub fn init(base_secret: [S.Nh]u8) Self {
            return .{ .secret = base_secret, .generation = 0 };
        }

        /// The key/nonce for the CURRENT generation. Pure — call `advance`
        /// to move on.
        pub fn current(self: *const Self) Error!KeyNonce(S) {
            var out: KeyNonce(S) = undefined;
            try crypto.DeriveTreeSecret(S, self.secret, label_key, self.generation, &out.key);
            try crypto.DeriveTreeSecret(S, self.secret, label_nonce, self.generation, &out.nonce);
            return out;
        }

        /// Steps to the next generation, overwriting the consumed secret in
        /// place (RFC 9420 §9.2 — the ratchet must not be rewindable, so
        /// the old secret cannot merely be dropped).
        pub fn advance(self: *Self) Error!void {
            if (self.generation == std.math.maxInt(u32)) return error.RatchetExhausted;
            var next: [S.Nh]u8 = undefined;
            try crypto.DeriveTreeSecret(S, self.secret, label_secret, self.generation, &next);
            std.crypto.secureZero(u8, &self.secret);
            self.secret = next;
            self.generation += 1;
        }

        pub fn wipe(self: *Self) void {
            std.crypto.secureZero(u8, &self.secret);
        }
    };
}

/// The default bound on how far ahead of the ratchet's current position a
/// single `Window.get` will ratchet. 1024 is generous for real reordering
/// and still trivially cheap to reject past; see this file's module doc
/// comment for why the bound exists at all.
pub const default_max_forward_jump: u32 = 1024;

/// A generation-indexed view of a `Ratchet` that tolerates out-of-order
/// delivery: it retains up to `capacity` skipped-over key/nonce pairs so a
/// late message can still be decrypted, consumes each one exactly once, and
/// refuses unbounded forward jumps.
///
/// Fixed-size — no allocator, so the retained-key memory is a compile-time
/// constant a caller can reason about rather than an attacker-controlled
/// heap growth.
pub fn Window(comptime S: type, comptime capacity: usize) type {
    return struct {
        const Self = @This();
        const Entry = struct { generation: u32, kn: KeyNonce(S) };

        ratchet: Ratchet(S),
        /// Retained generations, oldest-first ring. `null` = free slot.
        held: [capacity]?Entry = @splat(null),
        next_slot: usize = 0,
        max_forward_jump: u32 = default_max_forward_jump,

        pub fn init(base_secret: [S.Nh]u8) Self {
            return .{ .ratchet = Ratchet(S).init(base_secret) };
        }

        /// The key/nonce for `generation`, CONSUMING it: a second call for
        /// the same generation fails with `error.GenerationConsumed`.
        ///
        /// * `generation` behind the ratchet → served from the retained
        ///   ring, or `error.GenerationConsumed` if it was already used or
        ///   has been evicted.
        /// * `generation` at or ahead of the ratchet → ratchets forward,
        ///   retaining each skipped generation, then consumes the target.
        ///   Refuses jumps beyond `max_forward_jump`.
        pub fn get(self: *Self, generation: u32) Error!KeyNonce(S) {
            if (generation < self.ratchet.generation) {
                for (&self.held) |*slot| {
                    if (slot.*) |*e| {
                        if (e.generation == generation) {
                            const kn = e.kn;
                            e.kn.wipe();
                            slot.* = null;
                            return kn;
                        }
                    }
                }
                return error.GenerationConsumed;
            }

            if (generation - self.ratchet.generation > self.max_forward_jump) {
                return error.GenerationTooFarAhead;
            }

            while (self.ratchet.generation < generation) {
                self.retain(.{ .generation = self.ratchet.generation, .kn = try self.ratchet.current() });
                try self.ratchet.advance();
            }

            const kn = try self.ratchet.current();
            // Advancing past the generation we just served is what makes it
            // unrepeatable: it is neither the current generation any more
            // nor retained.
            self.ratchet.advance() catch |err| switch (err) {
                // The last generation of the epoch is still usable once.
                error.RatchetExhausted => {},
                else => return err,
            };
            return kn;
        }

        /// RFC 9420 §9.2: drop everything this window still holds.
        pub fn wipe(self: *Self) void {
            for (&self.held) |*slot| {
                if (slot.*) |*e| e.kn.wipe();
                slot.* = null;
            }
            self.ratchet.wipe();
        }

        fn retain(self: *Self, entry: Entry) void {
            if (capacity == 0) return;
            if (self.held[self.next_slot]) |*evicted| evicted.kn.wipe();
            self.held[self.next_slot] = entry;
            self.next_slot = (self.next_slot + 1) % capacity;
        }
    };
}

// ── §6.3.2: sender-data key and nonce ─────────────────────────────────────

/// RFC 9420 §6.3.2's key and nonce for the `SenderData` AEAD.
pub fn SenderDataKeys(comptime S: type) type {
    return KeyNonce(S);
}

/// RFC 9420 §6.3.2:
///
/// ```text
/// ciphertext_sample = ciphertext[0..KDF.Nh-1]
/// sender_data_key   = ExpandWithLabel(sender_data_secret, "key",
///                                     ciphertext_sample, AEAD.Nk)
/// sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce",
///                                     ciphertext_sample, AEAD.Nn)
/// ```
///
/// The sample is the first `KDF.Nh` bytes of the message ciphertext, or the
/// WHOLE ciphertext if it is shorter — the RFC states the short case in
/// prose ("If the length of the ciphertext is less than KDF.Nh, the whole
/// ciphertext is used"), which its `[0..KDF.Nh-1]` slice notation on its own
/// does not convey.
///
/// This binds the sender-data key to the message it describes, so a
/// sender-data blob cannot be lifted onto a different ciphertext.
pub fn senderDataKeys(
    comptime S: type,
    sender_data_secret: [S.Nh]u8,
    ciphertext: []const u8,
) Error!SenderDataKeys(S) {
    const sample = ciphertext[0..@min(ciphertext.len, S.Nh)];
    var out: SenderDataKeys(S) = undefined;
    try crypto.ExpandWithLabel(S, sender_data_secret, label_key, sample, &out.key);
    try crypto.ExpandWithLabel(S, sender_data_secret, label_nonce, sample, &out.nonce);
    return out;
}

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

test "nodeSecret: a one-leaf tree's only node IS the root, so its secret is encryption_secret" {
    const es = [_]u8{0x42} ** TestSuite.Nh;
    const got = try nodeSecret(TestSuite, es, 1, 0);
    try testing.expectEqualSlices(u8, &es, &got);
}

test "nodeSecret: children differ from each other and from the parent; out-of-range is rejected" {
    const es = [_]u8{0x11} ** TestSuite.Nh;
    // n_leaves = 4 -> node_width 7, root 3, children 1 and 5.
    try testing.expectEqual(@as(usize, 7), treemath.node_width(4));
    const root_secret = try nodeSecret(TestSuite, es, 4, 3);
    try testing.expectEqualSlices(u8, &es, &root_secret);

    const l = try nodeSecret(TestSuite, es, 4, 1);
    const r = try nodeSecret(TestSuite, es, 4, 5);
    try testing.expect(!std.mem.eql(u8, &l, &r));
    try testing.expect(!std.mem.eql(u8, &l, &es));

    // Derived stepwise, the "left" child must match the tree walk.
    const l_direct = try childSecret(TestSuite, es, true);
    try testing.expectEqualSlices(u8, &l_direct, &l);

    try testing.expectError(error.NodeIndexOutOfRange, nodeSecret(TestSuite, es, 4, 7));
    try testing.expectError(error.NodeIndexOutOfRange, nodeSecret(TestSuite, es, 0, 0));
}

test "ratchetBaseSecret: handshake and application ratchets are independent per leaf" {
    const es = [_]u8{0x21} ** TestSuite.Nh;
    const h0 = try ratchetBaseSecret(TestSuite, es, 4, 0, .handshake);
    const a0 = try ratchetBaseSecret(TestSuite, es, 4, 0, .application);
    const h1 = try ratchetBaseSecret(TestSuite, es, 4, 1, .handshake);
    try testing.expect(!std.mem.eql(u8, &h0, &a0));
    try testing.expect(!std.mem.eql(u8, &h0, &h1));
    try testing.expectError(error.NodeIndexOutOfRange, ratchetBaseSecret(TestSuite, es, 4, 4, .handshake));
}

test "Ratchet: current() is pure, advance() moves forward and destroys the old secret" {
    const base = [_]u8{0x31} ** TestSuite.Nh;
    var r = Ratchet(TestSuite).init(base);

    const g0a = try r.current();
    const g0b = try r.current();
    try testing.expectEqualSlices(u8, &g0a.key, &g0b.key);
    try testing.expectEqual(@as(u32, 0), r.generation);

    const before = r.secret;
    try r.advance();
    try testing.expectEqual(@as(u32, 1), r.generation);
    try testing.expect(!std.mem.eql(u8, &before, &r.secret));

    const g1 = try r.current();
    try testing.expect(!std.mem.eql(u8, &g0a.key, &g1.key));
    try testing.expect(!std.mem.eql(u8, &g0a.nonce, &g1.nonce));

    r.wipe();
    try testing.expectEqualSlices(u8, &[_]u8{0} ** TestSuite.Nh, &r.secret);
}

test "Window: in-order delivery matches the bare ratchet generation for generation" {
    const base = [_]u8{0x41} ** TestSuite.Nh;
    var w = Window(TestSuite, 8).init(base);
    var r = Ratchet(TestSuite).init(base);

    var g: u32 = 0;
    while (g < 5) : (g += 1) {
        const want = try r.current();
        try r.advance();
        const got = try w.get(g);
        try testing.expectEqualSlices(u8, &want.key, &got.key);
        try testing.expectEqualSlices(u8, &want.nonce, &got.nonce);
    }
}

test "Window: a skipped generation is retained and later served exactly once" {
    const base = [_]u8{0x51} ** TestSuite.Nh;
    var w = Window(TestSuite, 8).init(base);
    var r = Ratchet(TestSuite).init(base);

    // Generation 3 arrives first.
    const g3 = try w.get(3);
    var i: u32 = 0;
    while (i < 3) : (i += 1) try r.advance();
    const want3 = try r.current();
    try testing.expectEqualSlices(u8, &want3.key, &g3.key);

    // The three it jumped over are still available, out of order.
    const g1 = try w.get(1);
    const g0 = try w.get(0);
    try testing.expect(!std.mem.eql(u8, &g0.key, &g1.key));
    _ = try w.get(2);

    // ...but each exactly once, and generation 3 itself is not replayable.
    try testing.expectError(error.GenerationConsumed, w.get(1));
    try testing.expectError(error.GenerationConsumed, w.get(3));
}

test "Window: eviction past capacity, and a huge forward jump is refused not computed" {
    const base = [_]u8{0x61} ** TestSuite.Nh;
    var w = Window(TestSuite, 2).init(base);

    _ = try w.get(4); // retains generations 0..3 into a 2-slot ring
    // The two oldest fell out; the two newest survive.
    try testing.expectError(error.GenerationConsumed, w.get(0));
    try testing.expectError(error.GenerationConsumed, w.get(1));
    _ = try w.get(2);
    _ = try w.get(3);

    // An unauthenticated uint32 generation must not buy 4 billion KDF calls.
    var w2 = Window(TestSuite, 2).init(base);
    try testing.expectError(error.GenerationTooFarAhead, w2.get(std.math.maxInt(u32)));
    w2.max_forward_jump = 4;
    try testing.expectError(error.GenerationTooFarAhead, w2.get(5));
    _ = try w2.get(4);

    w.wipe();
    try testing.expectEqualSlices(u8, &[_]u8{0} ** TestSuite.Nh, &w.ratchet.secret);
}

test "senderDataKeys: bound to the ciphertext sample, and a short ciphertext uses all of it" {
    const sds = [_]u8{0x71} ** TestSuite.Nh;
    const ct_a = [_]u8{0xaa} ** 64;
    var ct_b = ct_a;
    ct_b[0] ^= 0x01; // inside the first KDF.Nh bytes

    const a = try senderDataKeys(TestSuite, sds, &ct_a);
    const b = try senderDataKeys(TestSuite, sds, &ct_b);
    try testing.expect(!std.mem.eql(u8, &a.key, &b.key));
    try testing.expect(!std.mem.eql(u8, &a.nonce, &b.nonce));

    // Beyond the sample the ciphertext does not matter — that is the spec's
    // behaviour, not an oversight: only the first KDF.Nh bytes are sampled.
    var ct_c = ct_a;
    ct_c[TestSuite.Nh] ^= 0xff;
    const c = try senderDataKeys(TestSuite, sds, &ct_c);
    try testing.expectEqualSlices(u8, &a.key, &c.key);

    // A ciphertext shorter than KDF.Nh samples the whole thing.
    const short = [_]u8{0xbb} ** 8;
    const s1 = try senderDataKeys(TestSuite, sds, &short);
    const s2 = try senderDataKeys(TestSuite, sds, short[0..8]);
    try testing.expectEqualSlices(u8, &s1.key, &s2.key);
    try testing.expect(!std.mem.eql(u8, &s1.key, &a.key));
}
