// SPDX-License-Identifier: MIT

//! types — the GJKR DKG protocol's configuration, wire messages, and their
//! byte codecs. All REAL and mechanical (fixed-layout big-endian encodings
//! composed from `Scalar`/`Element`'s own sub-codecs); round-trip tested.
//!
//! The DKG is a synchronous multi-round message protocol; these are the
//! four message shapes that cross the (simulated) broadcast / point-to-point
//! channels, plus the per-party `DkgShareOutput` the protocol finally emits.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

pub const Scalar = tecdsa.Scalar;
pub const Element = tecdsa.Element;
pub const Ns = tecdsa.Ns; // 32 — scalar bytes
pub const Ne = tecdsa.Ne; // 33 — compressed point bytes

/// (t, n): a `t`-of-`n` sharing. The sharing polynomials have degree
/// `t - 1`, so any `t` valid shares reconstruct the group secret and any
/// `t - 1` reveal nothing. `1 <= t <= n`.
pub const Config = struct {
    t: u32,
    n: u32,

    pub fn valid(self: Config) bool {
        return self.t >= 1 and self.t <= self.n and self.n >= 1;
    }
};

pub const CodecError = error{InvalidEncoding} || tecdsa.ElementError;

/// Round 1 broadcast: dealer `i`'s Pedersen commitments to the `t`
/// coefficients of its sharing pair `(f_i, f'_i)` —
/// `C_ik = g^{a_ik} · h^{b_ik}`, `k = 0..t-1`. `commitments[0]` commits to
/// `a_i0` (the dealer's contributed secret). Owned slice; free with the
/// allocator passed to `fromBytesAlloc`.
pub const PedersenBroadcast = struct {
    dealer: u32,
    /// length `t`.
    commitments: []Element,

    pub fn deinit(self: PedersenBroadcast, allocator: std.mem.Allocator) void {
        allocator.free(self.commitments);
    }

    /// `dealer(4) || t(4) || commitments[t]·(33)`.
    pub fn toBytesAlloc(self: PedersenBroadcast, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const out = try allocator.alloc(u8, 8 + self.commitments.len * Ne);
        std.mem.writeInt(u32, out[0..4], self.dealer, .big);
        std.mem.writeInt(u32, out[4..8], @intCast(self.commitments.len), .big);
        var off: usize = 8;
        for (self.commitments) |c| {
            @memcpy(out[off..][0..Ne], &c.toBytes());
            off += Ne;
        }
        return out;
    }

    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || CodecError)!PedersenBroadcast {
        if (bytes.len < 8) return error.InvalidEncoding;
        const dealer = std.mem.readInt(u32, bytes[0..4], .big);
        const t = std.mem.readInt(u32, bytes[4..8], .big);
        if (bytes.len != 8 + @as(usize, t) * Ne) return error.InvalidEncoding;
        const commitments = try allocator.alloc(Element, t);
        errdefer allocator.free(commitments);
        var off: usize = 8;
        for (commitments) |*c| {
            c.* = try Element.fromBytes(bytes[off..][0..Ne].*);
            off += Ne;
        }
        return .{ .dealer = dealer, .commitments = commitments };
    }
};

/// Extraction-phase broadcast: QUAL dealer `i`'s Feldman commitments
/// `A_ik = g^{a_ik}`, `k = 0..t-1`. Broadcast ONLY after QUAL is fixed
/// (the bias-prevention crux). Structurally identical to
/// `PedersenBroadcast` on the wire but semantically distinct (no `h`
/// term), so it is its own type to keep the two phases unmixable.
pub const FeldmanBroadcast = struct {
    dealer: u32,
    /// length `t`.
    commitments: []Element,

    pub fn deinit(self: FeldmanBroadcast, allocator: std.mem.Allocator) void {
        allocator.free(self.commitments);
    }

    pub fn toBytesAlloc(self: FeldmanBroadcast, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const pb: PedersenBroadcast = .{ .dealer = self.dealer, .commitments = self.commitments };
        return pb.toBytesAlloc(allocator);
    }

    pub fn fromBytesAlloc(allocator: std.mem.Allocator, bytes: []const u8) (std.mem.Allocator.Error || CodecError)!FeldmanBroadcast {
        const pb = try PedersenBroadcast.fromBytesAlloc(allocator, bytes);
        return .{ .dealer = pb.dealer, .commitments = pb.commitments };
    }
};

/// Round 1 point-to-point: dealer `i`'s Pedersen-VSS shares for receiver
/// `j` — `s_ij = f_i(j)` and `s'_ij = f'_i(j)`. A Byzantine dealer may send
/// a pair that does not satisfy the verification equation against its
/// broadcast `C_i`; detecting exactly that is the core's job.
pub const ShareMsg = struct {
    dealer: u32,
    receiver: u32,
    s: Scalar,
    s_prime: Scalar,

    pub const encoded_length = 8 + Ns + Ns;

    pub fn toBytes(self: ShareMsg) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.dealer, .big);
        std.mem.writeInt(u32, out[4..8], self.receiver, .big);
        @memcpy(out[8..][0..Ns], &self.s.toBytes(.big));
        @memcpy(out[8 + Ns ..][0..Ns], &self.s_prime.toBytes(.big));
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) CodecError!ShareMsg {
        const s = Scalar.fromBytes(bytes[8..][0..Ns].*, .big) catch return error.InvalidEncoding;
        const s_prime = Scalar.fromBytes(bytes[8 + Ns ..][0..Ns].*, .big) catch return error.InvalidEncoding;
        return .{
            .dealer = std.mem.readInt(u32, bytes[0..4], .big),
            .receiver = std.mem.readInt(u32, bytes[4..8], .big),
            .s = s,
            .s_prime = s_prime,
        };
    }
};

/// Round 2 broadcast: `complainant` asserts that dealer `accused`'s
/// round-1 share failed the Pedersen verification equation. The presence
/// of a complaint does not by itself disqualify — `computeQual` weighs
/// complaints (and, in the full protocol, the accused's defense) into the
/// QUAL decision.
pub const Complaint = struct {
    complainant: u32,
    accused: u32,

    pub const encoded_length = 8;

    pub fn toBytes(self: Complaint) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.complainant, .big);
        std.mem.writeInt(u32, out[4..8], self.accused, .big);
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) Complaint {
        return .{
            .complainant = std.mem.readInt(u32, bytes[0..4], .big),
            .accused = std.mem.readInt(u32, bytes[4..8], .big),
        };
    }
};

/// One party's final DKG output — the secret-key material the trusted
/// dealer used to hand out, now jointly generated:
///   - `index` (public): this party's Shamir evaluation point `j`.
///   - `secret_share` (SECRET): `x_j = Σ_{i∈QUAL} s_ij` — this party's
///     share of the group ECDSA secret `x`.
///   - `group_public_key` (public): `Q = Σ_{i∈QUAL} A_i0 = x·G` — the
///     shared ECDSA public key. Identical across all honest parties.
///   - `verifying_share` (public): `X_j = x_j·G`.
///
/// A caller assembles a full `threshold_ecdsa.KeyShare` from this by
/// attaching that party's independently-generated Paillier keypair + aux
/// params (see `root.assembleKeyShare` and the end-to-end anchor).
pub const DkgShareOutput = struct {
    index: u32,
    secret_share: Scalar,
    group_public_key: Element,
    verifying_share: Element,

    pub const encoded_length = 4 + Ns + Ne + Ne;

    pub fn toBytes(self: DkgShareOutput) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], self.index, .big);
        @memcpy(out[4..][0..Ns], &self.secret_share.toBytes(.big));
        @memcpy(out[4 + Ns ..][0..Ne], &self.group_public_key.toBytes());
        @memcpy(out[4 + Ns + Ne ..][0..Ne], &self.verifying_share.toBytes());
        return out;
    }

    pub fn fromBytes(bytes: [encoded_length]u8) CodecError!DkgShareOutput {
        const secret_share = Scalar.fromBytes(bytes[4..][0..Ns].*, .big) catch return error.InvalidEncoding;
        return .{
            .index = std.mem.readInt(u32, bytes[0..4], .big),
            .secret_share = secret_share,
            .group_public_key = try Element.fromBytes(bytes[4 + Ns ..][0..Ne].*),
            .verifying_share = try Element.fromBytes(bytes[4 + Ns + Ne ..][0..Ne].*),
        };
    }

    /// Zero the SECRET field (`secret_share`) in place at end-of-life.
    /// `index`, `group_public_key`, `verifying_share` are public and left
    /// untouched. Idempotent — safe to call more than once.
    pub fn deinit(self: *DkgShareOutput) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.secret_share));
    }
};

test "ShareMsg / Complaint / DkgShareOutput codecs round-trip" {
    const testing = std.testing;
    const Secp256k1 = tecdsa.Secp256k1;

    const s = Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{7}, .big) catch unreachable;
    const sp = Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{9}, .big) catch unreachable;
    const m: ShareMsg = .{ .dealer = 2, .receiver = 5, .s = s, .s_prime = sp };
    const back = try ShareMsg.fromBytes(m.toBytes());
    try testing.expectEqual(m.dealer, back.dealer);
    try testing.expectEqual(m.receiver, back.receiver);
    try testing.expectEqualSlices(u8, &m.s.toBytes(.big), &back.s.toBytes(.big));
    try testing.expectEqualSlices(u8, &m.s_prime.toBytes(.big), &back.s_prime.toBytes(.big));

    const c: Complaint = .{ .complainant = 3, .accused = 1 };
    const cb = Complaint.fromBytes(c.toBytes());
    try testing.expectEqual(c.complainant, cb.complainant);
    try testing.expectEqual(c.accused, cb.accused);

    const g = try Element.fromPoint(Secp256k1.basePoint);
    const out: DkgShareOutput = .{ .index = 4, .secret_share = s, .group_public_key = g, .verifying_share = g };
    const ob = try DkgShareOutput.fromBytes(out.toBytes());
    try testing.expectEqual(out.index, ob.index);
    try testing.expectEqualSlices(u8, &out.group_public_key.toBytes(), &ob.group_public_key.toBytes());
}

test "DkgShareOutput.deinit zeroes the secret share, leaves public fields intact" {
    const testing = std.testing;
    const Secp256k1 = tecdsa.Secp256k1;

    const s = Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{7}, .big) catch unreachable;
    const g = try Element.fromPoint(Secp256k1.basePoint);
    var out: DkgShareOutput = .{ .index = 4, .secret_share = s, .group_public_key = g, .verifying_share = g };

    out.deinit();
    try testing.expectEqualSlices(u8, &([_]u8{0} ** Ns), &out.secret_share.toBytes(.big));
    // Public fields survive deinit.
    try testing.expectEqual(@as(u32, 4), out.index);
    try testing.expectEqualSlices(u8, &g.toBytes(), &out.group_public_key.toBytes());

    // Idempotent: calling again on already-zeroed state is a no-op, not UB.
    out.deinit();
    try testing.expectEqualSlices(u8, &([_]u8{0} ** Ns), &out.secret_share.toBytes(.big));
}

test "PedersenBroadcast / FeldmanBroadcast codecs round-trip" {
    const testing = std.testing;
    const Secp256k1 = tecdsa.Secp256k1;
    const allocator = testing.allocator;

    const commits = try allocator.alloc(Element, 3);
    defer allocator.free(commits);
    var p = Secp256k1.basePoint;
    for (commits) |*c| {
        c.* = try Element.fromPoint(p);
        p = p.dbl();
    }
    const pb: PedersenBroadcast = .{ .dealer = 2, .commitments = commits };
    const enc = try pb.toBytesAlloc(allocator);
    defer allocator.free(enc);
    const dec = try PedersenBroadcast.fromBytesAlloc(allocator, enc);
    defer dec.deinit(allocator);
    try testing.expectEqual(pb.dealer, dec.dealer);
    try testing.expectEqual(pb.commitments.len, dec.commitments.len);
    for (pb.commitments, dec.commitments) |a, b| {
        try testing.expectEqualSlices(u8, &a.toBytes(), &b.toBytes());
    }

    const fb: FeldmanBroadcast = .{ .dealer = 7, .commitments = commits };
    const fenc = try fb.toBytesAlloc(allocator);
    defer allocator.free(fenc);
    const fdec = try FeldmanBroadcast.fromBytesAlloc(allocator, fenc);
    defer fdec.deinit(allocator);
    try testing.expectEqual(fb.dealer, fdec.dealer);
}

// ── fuzz: untrusted inter-party wire decoders never panic/OOB ─────────────

/// 512 holds `t = 15` commitments (`8 + t*33`), comfortably over any threshold
/// this module's own tests or examples build. ⚠ Checked deliberately: a seed
/// longer than the buffer does not arrive truncated, it reads back EMPTY.
const broadcast_buf_len = 512;

/// The broadcast frames the corpus is cut from.
///
/// ⛔ These cannot be literals. A `secp256k1` point in the form
/// `Element.fromBytes` accepts is structurally unreachable from arbitrary
/// bytes — the compressed encoding has to land on the curve — so a drawn
/// buffer produces refusals and only the module's own encoder produces
/// acceptances. `commitments[0]` is the base point, then successive doublings.
const BroadcastCorpus = struct {
    store: [10 * (4 + broadcast_buf_len)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *BroadcastCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = self.store[self.used..][0..sd.len];
        self.used += sd.len;
        self.n += 1;
    }

    fn build(self: *BroadcastCorpus, a: std.mem.Allocator) []const []const u8 {
        var commits: [8]Element = undefined;
        var p = tecdsa.Secp256k1.basePoint;
        for (&commits) |*c| {
            c.* = Element.fromPoint(p) catch unreachable;
            p = p.dbl();
        }
        const three: PedersenBroadcast = .{ .dealer = 2, .commitments = commits[0..3] };
        const enc3 = three.toBytesAlloc(a) catch unreachable;
        self.push(enc3); // t = 3, the shape the round-trip test above uses
        const eight: PedersenBroadcast = .{ .dealer = 0xffff_ffff, .commitments = &commits };
        const enc8 = eight.toBytesAlloc(a) catch unreachable;
        self.push(enc8); // t = 8, and the largest dealer index a u32 holds
        const zero: PedersenBroadcast = .{ .dealer = 1, .commitments = commits[0..0] };
        self.push(zero.toBytesAlloc(a) catch unreachable); // t = 0: header only
        // ⛔ The finding this decoder's own comment is about: `t` is
        // attacker-controlled and the length check has to fire before the
        // `alloc`. `t` here claims 2^32-1 commitments over 107 octets.
        var lying = a.dupe(u8, enc3) catch unreachable;
        std.mem.writeInt(u32, lying[4..8], 0xffff_ffff, .big);
        self.push(lying);
        // `t` one too large, and one too small: both are length mismatches.
        var off_by_one = a.dupe(u8, enc3) catch unreachable;
        std.mem.writeInt(u32, off_by_one[4..8], 4, .big);
        self.push(off_by_one);
        var short = a.dupe(u8, enc3) catch unreachable;
        std.mem.writeInt(u32, short[4..8], 2, .big);
        self.push(short);
        // A correct length whose third commitment is not a curve point.
        // ⚠ The prefix octet, not a coordinate octet: flipping a bit inside x
        // lands on the curve about half the time, and the first version of
        // this seed DID decode — the guard caught it by disagreeing with the
        // accepted count pinned for it. `0x04` is the uncompressed marker,
        // which a 33-octet compressed field can never carry.
        var bad_point = a.dupe(u8, enc3) catch unreachable;
        bad_point[8 + 2 * Ne] = 0x04;
        self.push(bad_point);
        self.push(enc3[0..7]); // one octet short of the 8-octet header
        self.push(""); // and the input these targets used to run for ever
        return self.entries[0..self.n];
    }
};

fn fuzzPedersenBroadcastDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [broadcast_buf_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input the ordinary lane ever ran (a
    // ranged draw needs eight octets and `bytes` had eaten them), so this
    // target returned `InvalidEncoding` off the `bytes.len < 8` check every
    // round, with the broadcast sitting unread in `buf`.
    const len: usize = smith.slice(&buf);
    // The `t` count (bytes[4..8]) is attacker-controlled; the decoder must
    // reject any length mismatch (`bytes.len != 8 + t*Ne`) BEFORE
    // allocating — never panic/OOB regardless of the claimed `t`.
    const pb = PedersenBroadcast.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch return;
    defer pb.deinit(std.testing.allocator);
}
test "fuzz PedersenBroadcast.fromBytesAlloc never panics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: BroadcastCorpus = .{};
    try std.testing.fuzz({}, fuzzPedersenBroadcastDecode, .{ .corpus = corpus.build(arena.allocator()) });
}

fn fuzzFeldmanBroadcastDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [broadcast_buf_len]u8 = undefined;
    // ⚠ Same as above: this target's length draw was 0 on every input.
    const len: usize = smith.slice(&buf);
    const fb = FeldmanBroadcast.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch return;
    defer fb.deinit(std.testing.allocator);
}
test "fuzz FeldmanBroadcast.fromBytesAlloc never panics" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: BroadcastCorpus = .{};
    // The two frames are byte-identical on the wire (`FeldmanBroadcast`
    // delegates to `PedersenBroadcast`), so the same corpus is the right one.
    try std.testing.fuzz({}, fuzzFeldmanBroadcastDecode, .{ .corpus = corpus.build(arena.allocator()) });
}

test "corpus: every broadcast seed reaches the decoder, and the counts are pinned" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: BroadcastCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the empty replay cannot produce, and that `accepted > 0`
    // could not have held up: commitments actually decoded off the wire. The
    // header-only `t = 0` frame is accepted while decoding no point at all,
    // which is exactly the "legality is not reach" trap.
    var commitments: usize = 0;
    for (corpus.build(arena.allocator())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [broadcast_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const pb = PedersenBroadcast.fromBytesAlloc(std.testing.allocator, buf[0..len]) catch continue;
        defer pb.deinit(std.testing.allocator);
        accepted += 1;
        commitments += pb.commitments.len;
    }
    try std.testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try std.testing.expectEqual(@as(usize, 3), accepted);
    try std.testing.expectEqual(@as(usize, 11), commitments);
}

fn fuzzShareMsgDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [ShareMsg.encoded_length]u8 = undefined;
    smith.bytes(&buf);
    const msg = ShareMsg.fromBytes(buf) catch return;
    _ = msg.toBytes();
}
test "fuzz ShareMsg.fromBytes never panics" {
    try std.testing.fuzz({}, fuzzShareMsgDecode, .{});
}
