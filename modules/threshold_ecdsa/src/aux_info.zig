// SPDX-License-Identifier: MIT
//! aux_info — the Paillier and ring-Pedersen half of DEALER-FREE keygen:
//! what each party generates, broadcasts and proves so the others can run
//! MtA against a key they did not make, and how a party's `KeyShare` is
//! assembled once the secret-sharing half (a DKG, e.g. the sibling `dkg`
//! module's GJKR) has given it `x_i` and the group's Feldman commitments.
//!
//! ```text
//! each party i:  LocalAux.generate        Paillier-Blum N_i (p, q kept), aux (Ñ_i, h1, h2) + trapdoor
//! broadcast:     Announcement             N_i, aux_i, Πprm+Πmod(Ñ_i), Πmod(N_i) bound to ctx_i
//! every j:       verifyAnnouncement       floor, Γ = N+1, proofs; findDuplicate over all of them
//! i → j (p2p):   LocalAux.proveFactors    Πfac(N_i) under j's aux, bound to ctx_i
//! j:             verifyFactors            with its own aux
//! after the DKG: assembleKeyShare         x_i, F_0..F_{t-1}, every Announcement -> KeyShare
//! ```
//!
//! `ctx_i` is the caller's `session id || u32-BE i`, the same shape the
//! signing proofs use: a proof can be neither replayed into another session
//! nor claimed by another party. The ring-Pedersen proofs (Πprm/Πmod over
//! `Ñ`, `aux_proofs.verifyWellFormed`) predate that binding; a party that
//! copies another's `Ñ` together with its proofs is caught by
//! `findDuplicate` instead (every party sees every announcement — the
//! transport's reliable broadcast).
//!
//! Why each check (CGGMP21 §4, the BitForge disclosure): a Paillier `N`
//! with small factors, or one that is not a product of two primes, lets
//! its owner read an honest peer's share off the MtA responses (Πmod,
//! Πfac); an `Ñ` whose `h2` is not in `⟨h1⟩`, or whose factorization the
//! prover knows, voids the range proofs that keep MtA honest (Πprm, Πmod,
//! distinctness).

const std = @import("std");
const paillier = @import("paillier");
const root = @import("root.zig");
const aux_proofs = @import("aux_proofs.zig");
const fac_proof = @import("fac_proof.zig");

/// One party's own secret material for the aux half of keygen.
pub const LocalAux = struct {
    paillier: root.PaillierBlumKey,
    aux: root.AuxParams,
    trapdoor: root.AuxTrapdoor,

    /// Generate a 2048-bit Paillier-Blum key and a 2048-bit ring-Pedersen
    /// tuple with its trapdoor. Slow (two safe primes); `random` MUST be a
    /// CSPRNG. Free with `deinit`.
    pub fn generate(allocator: std.mem.Allocator, random: std.Random) (root.GeneratePaillierBlumError || std.mem.Allocator.Error)!LocalAux {
        var key = try root.generatePaillierBlum(random, paillier.modulus_bits);
        errdefer key.wipe();
        const at = try root.generateAuxParamsWithTrapdoor(allocator, random, root.aux_modulus_bits);
        return .{ .paillier = key, .aux = at.params, .trapdoor = at.trapdoor };
    }

    /// From material generated earlier (precomputed primes). Takes
    /// ownership of `trapdoor`.
    pub fn fromParts(key: root.PaillierBlumKey, aux: root.AuxParams, trapdoor: root.AuxTrapdoor) LocalAux {
        return .{ .paillier = key, .aux = aux, .trapdoor = trapdoor };
    }

    /// Wipes the Paillier factors and secret key and the aux trapdoor. A
    /// `KeyShare` assembled from this party holds its own copy of the
    /// Paillier secret key; wipe that with `share.paillier_secret.deinit()`.
    pub fn deinit(self: *LocalAux, allocator: std.mem.Allocator) void {
        self.paillier.wipe();
        std.crypto.secureZero(u8, @constCast(self.trapdoor.p));
        std.crypto.secureZero(u8, @constCast(self.trapdoor.q));
        self.trapdoor.deinit(allocator);
    }

    /// The broadcast: public keys and the three generation proofs.
    /// `context` = `session id || u32-BE own index`.
    pub fn announce(self: *const LocalAux, allocator: std.mem.Allocator, context: []const u8, random: std.Random) aux_proofs.ProveError!Announcement {
        return .{
            .paillier_pk = self.paillier.key.public,
            .aux = self.aux,
            .aux_proof = try aux_proofs.proveWellFormed(allocator, self.aux, self.trapdoor, random),
            .paillier_proof = try aux_proofs.Pimod.provePaillier(allocator, self.paillier.modulus(), self.paillier.p(), self.paillier.q(), context, random),
        };
    }

    /// Πfac for one peer, under that peer's (already verified) aux tuple.
    /// `context` = `session id || u32-BE own index`.
    pub fn proveFactors(self: *const LocalAux, verifier_aux: root.AuxParams, context: []const u8, random: std.Random) fac_proof.ProveError!fac_proof.FacProof {
        return fac_proof.prove(self.paillier.modulus(), self.paillier.p(), self.paillier.q(), verifier_aux, context, random);
    }
};

pub const Announcement = struct {
    paillier_pk: paillier.PublicKey,
    aux: root.AuxParams,
    aux_proof: aux_proofs.WellFormedProof,
    paillier_proof: aux_proofs.ModProof,

    pub const AllocError = std.mem.Allocator.Error || paillier.PublicKey.ByteError || root.AuxParams.AllocError || aux_proofs.ModProof.AllocError || aux_proofs.PrmProof.AllocError;

    /// `len-prefixed` each of: Paillier `N`, `aux.toBytesAlloc()`, Πprm(Ñ),
    /// Πmod(Ñ), Πmod(N).
    pub fn toBytesAlloc(self: Announcement, allocator: std.mem.Allocator) AllocError![]u8 {
        var list: std.ArrayList(u8) = .empty;
        errdefer list.deinit(allocator);

        var n_buf: [paillier.modulus_bytes]u8 = undefined;
        const n_len = self.paillier_pk.nByteLen();
        try self.paillier_pk.nToBytes(n_buf[0..n_len]);
        try appendLenPrefixed(&list, allocator, n_buf[0..n_len]);

        inline for (.{ "aux", "prm", "mod_aux", "mod_n" }) |which| {
            const part = if (comptime std.mem.eql(u8, which, "aux"))
                try self.aux.toBytesAlloc(allocator)
            else if (comptime std.mem.eql(u8, which, "prm"))
                try self.aux_proof.prm.toBytesAlloc(allocator)
            else if (comptime std.mem.eql(u8, which, "mod_aux"))
                try self.aux_proof.mod.toBytesAlloc(allocator)
            else
                try self.paillier_proof.toBytesAlloc(allocator);
            defer allocator.free(part);
            try appendLenPrefixed(&list, allocator, part);
        }
        return list.toOwnedSlice(allocator);
    }

    pub const FromBytesError = error{InvalidEncoding};

    /// Inverse of `toBytesAlloc`. Parsing proves nothing: run
    /// `verifyAnnouncement` before using any of it.
    pub fn fromBytes(bytes: []const u8) FromBytesError!Announcement {
        var off: usize = 0;
        const n_bytes = try readLenPrefixed(bytes, &off);
        const pk = paillier.PublicKey.fromBytes(n_bytes, null) catch return error.InvalidEncoding;
        const n_mod = root.paillierModulusAsAux(pk) orelse return error.InvalidEncoding;
        const aux = root.AuxParams.fromBytesAlloc(try readLenPrefixed(bytes, &off)) catch return error.InvalidEncoding;
        const prm = aux_proofs.PrmProof.fromBytesAlloc(aux.n_tilde, try readLenPrefixed(bytes, &off)) catch return error.InvalidEncoding;
        const mod_aux = aux_proofs.ModProof.fromBytesAlloc(aux.n_tilde, try readLenPrefixed(bytes, &off)) catch return error.InvalidEncoding;
        const mod_n = aux_proofs.ModProof.fromBytesAlloc(n_mod, try readLenPrefixed(bytes, &off)) catch return error.InvalidEncoding;
        if (off != bytes.len) return error.InvalidEncoding;
        return .{ .paillier_pk = pk, .aux = aux, .aux_proof = .{ .prm = prm, .mod = mod_aux }, .paillier_proof = mod_n };
    }
};

pub const AnnouncementError = error{
    /// `N` not exactly `paillier.modulus_bits` (2048) wide, or `Γ ≠ N+1`.
    /// (The `q⁷` floor alone would admit ~1793 bits, where Πfac's bound
    /// only guarantees factors of ~2^127; at 2048 it is ~2^253.)
    InvalidPaillierKey,
    /// The ring-Pedersen tuple failed `validate` or its Πprm/Πmod.
    InvalidAuxParams,
    /// Πmod over `N` failed: not a Paillier-Blum modulus (or not bound to
    /// this sender's context).
    InvalidPaillierProof,
};

/// Everything a receiver checks on one peer's broadcast, `context` being
/// that PEER's (`session id || u32-BE peer index`). `random` feeds
/// `AuxParams.validate`'s Miller-Rabin and must be a CSPRNG.
pub fn verifyAnnouncement(a: Announcement, context: []const u8, random: std.Random) AnnouncementError!void {
    if (!root.paillierNMeetsFloor(a.paillier_pk) or !root.paillierGeneratorIsStandard(a.paillier_pk))
        return error.InvalidPaillierKey;
    const n = root.paillierModulusAsAux(a.paillier_pk) orelse return error.InvalidPaillierKey;
    if (n.bits() != paillier.modulus_bits) return error.InvalidPaillierKey;
    aux_proofs.verifyWellFormed(a.aux, a.aux_proof, random) catch return error.InvalidAuxParams;
    if (!aux_proofs.Pimod.verifyPaillier(n, context, a.paillier_proof)) return error.InvalidPaillierProof;
}

/// Πfac from peer `prover` (its announcement already verified), made for
/// this party: `own_aux` is this party's tuple, `context` the PROVER's.
pub fn verifyFactors(prover: Announcement, own_aux: root.AuxParams, context: []const u8, proof: fac_proof.FacProof) bool {
    const n = root.paillierModulusAsAux(prover.paillier_pk) orelse return false;
    return fac_proof.verify(n, own_aux, context, proof);
}

/// Two announcements that share a modulus — any of `N_i`, `Ñ_i` equal to
/// any other `N_j` or `Ñ_j` (`N_i = Ñ_i` included). Someone copied a key
/// (or its factorization is known to two parties); which one cannot be told
/// from the bytes, so the run must abort. Indices are into `all`.
pub fn findDuplicate(all: []const Announcement) ?struct { usize, usize } {
    for (all, 0..) |a, i| {
        const ai = [2][root.aux_modulus_bytes]u8{ modulusBytes(a.paillier_pk), auxModulusBytes(a.aux.n_tilde) };
        if (std.mem.eql(u8, &ai[0], &ai[1])) return .{ i, i };
        for (all[i + 1 ..], i + 1..) |b, j| {
            const bj = [2][root.aux_modulus_bytes]u8{ modulusBytes(b.paillier_pk), auxModulusBytes(b.aux.n_tilde) };
            for (ai) |x| {
                for (bj) |y| {
                    if (std.mem.eql(u8, &x, &y)) return .{ i, j };
                }
            }
        }
    }
    return null;
}

fn modulusBytes(pk: paillier.PublicKey) [root.aux_modulus_bytes]u8 {
    var out = [_]u8{0} ** root.aux_modulus_bytes;
    const len = pk.nByteLen();
    if (len <= out.len) pk.nToBytes(out[out.len - len ..]) catch {};
    return out;
}

fn feBytesEql(a: root.AuxFe, b: root.AuxFe) bool {
    var ab: [root.aux_modulus_bytes]u8 = undefined;
    var bb: [root.aux_modulus_bytes]u8 = undefined;
    a.toBytes(&ab, .big) catch return false;
    b.toBytes(&bb, .big) catch return false;
    return std.mem.eql(u8, &ab, &bb);
}

fn auxModulusBytes(m: root.AuxModulus) [root.aux_modulus_bytes]u8 {
    var out: [root.aux_modulus_bytes]u8 = undefined;
    m.toBytes(&out, .big) catch unreachable;
    return out;
}

pub const AssembleError = error{
    /// `announcements.len != n`, `index` outside `1..=n`, or a commitment
    /// count outside `1..=n` (that count is the threshold `t`).
    InvalidParameters,
    /// `x_i·G` is not the `X_i` the commitments give: the DKG output and
    /// the commitments do not belong together.
    ShareMismatch,
    /// This party's own announcement is not its own key.
    NotOwnAnnouncement,
} || root.DerivePublicKeyShareError || std.mem.Allocator.Error;

/// Builds party `index`'s `KeyShare` from a finished DKG — its share
/// `secret_share`, the group's Feldman commitments `group_commitments`
/// (`F_0 = Q`, length `t`) — and every party's VERIFIED announcement,
/// `announcements[j-1]` for party `j` (this party's own included). The
/// returned share owns `public_keys.entries`: free it with
/// `allocator.free(share.public_keys.entries)`.
pub fn assembleKeyShare(
    allocator: std.mem.Allocator,
    index: u32,
    secret_share: root.Scalar,
    group_commitments: []const root.Element,
    own: *const LocalAux,
    announcements: []const Announcement,
) AssembleError!root.KeyShare {
    const n: u32 = @intCast(announcements.len);
    if (index == 0 or index > n or group_commitments.len == 0 or group_commitments.len > n) return error.InvalidParameters;
    const vvec: root.FeldmanCommitments = .{ .commitments = group_commitments };

    const own_ann = announcements[index - 1];
    if (!std.mem.eql(u8, &modulusBytes(own_ann.paillier_pk), &modulusBytes(own.paillier.key.public)) or
        !std.mem.eql(u8, &auxModulusBytes(own_ann.aux.n_tilde), &auxModulusBytes(own.aux.n_tilde)) or
        !feBytesEql(own_ann.aux.h1, own.aux.h1) or !feBytesEql(own_ann.aux.h2, own.aux.h2))
        return error.NotOwnAnnouncement;

    const own_x = try root.derivePublicKeyShare(vvec, index);
    const x_g = root.Secp256k1.basePoint.mul(secret_share.toBytes(.big), .big) catch return error.ShareMismatch;
    if (!x_g.equivalent(try own_x.point())) return error.ShareMismatch;

    const entries = try allocator.alloc(root.PartyPublicKeys, n);
    errdefer allocator.free(entries);
    for (entries, announcements, 1..) |*e, a, j| {
        e.* = .{
            .index = @intCast(j),
            .paillier_pk = a.paillier_pk,
            .aux = a.aux,
            .verifying_share = try root.derivePublicKeyShare(vvec, @intCast(j)),
        };
    }
    return .{
        .index = index,
        .t = @intCast(group_commitments.len),
        .n = n,
        .secret_share = secret_share,
        .group_public_key = root.groupPublicKey(vvec),
        .verifying_share = own_x,
        .paillier_secret = own.paillier.key.secret,
        .public_keys = .{ .entries = entries },
    };
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

fn readLenPrefixed(bytes: []const u8, offset: *usize) error{InvalidEncoding}![]const u8 {
    if (bytes.len - offset.* < 4) return error.InvalidEncoding;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return error.InvalidEncoding;
    const out = bytes[offset.*..][0..len];
    offset.* += len;
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const vectors = @import("tsslib_vectors.zig");

fn unhexAlloc(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, (hex.len + 1) / 2);
    errdefer allocator.free(out);
    if (hex.len % 2 == 1) {
        out[0] = try std.fmt.parseInt(u8, hex[0..1], 16);
        _ = try std.fmt.hexToBytes(out[1..], hex[1..]);
    } else {
        _ = try std.fmt.hexToBytes(out, hex);
    }
    return out;
}

/// tss-lib party `i`'s Paillier primes and aux tuple (with trapdoor) as a
/// `LocalAux` — real 2048-bit material without a minutes-long prime search.
fn tssLocal(allocator: std.mem.Allocator, i: usize) !LocalAux {
    const p = vectors.tsslib_keygen.parties[i];
    const pp = try unhexAlloc(allocator, p.paillier_p);
    defer allocator.free(pp);
    const pq = try unhexAlloc(allocator, p.paillier_q);
    defer allocator.free(pq);
    var key = try root.paillierBlumFromPrimes(pp, pq);
    errdefer key.wipe();
    const nt_bytes = try unhexAlloc(allocator, p.n_tilde);
    defer allocator.free(nt_bytes);
    const nt = try root.AuxModulus.fromBytes(nt_bytes, .big);
    const fe = struct {
        fn f(a: std.mem.Allocator, m: root.AuxModulus, hex: []const u8) !root.AuxFe {
            const b = try unhexAlloc(a, hex);
            defer a.free(b);
            return root.AuxFe.fromBytes(m, b, .big);
        }
    }.f;
    const tp = try unhexAlloc(allocator, p.aux_p_safe);
    errdefer allocator.free(tp);
    const tq = try unhexAlloc(allocator, p.aux_q_safe);
    errdefer allocator.free(tq);
    return LocalAux.fromParts(
        key,
        .{ .n_tilde = nt, .h1 = try fe(allocator, nt, p.h1), .h2 = try fe(allocator, nt, p.h2) },
        .{ .p = tp, .q = tq, .lambda = try fe(allocator, nt, p.aux_lambda) },
    );
}

fn ctxFor(i: u32) [12]u8 {
    var out: [12]u8 = "sid-test".* ++ [_]u8{ 0, 0, 0, 0 };
    std.mem.writeInt(u32, out[8..12], i, .big);
    return out;
}

test "aux_info: three parties announce, check each other, prove factors pairwise, assemble shares" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7831);
    const random = prng.random();

    var locals: [3]LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 3) : (made += 1) locals[made] = try tssLocal(allocator, made);

    // Broadcast, through the codec, as a receiver would see it.
    var anns: [3]Announcement = undefined;
    for (&anns, &locals, 1..) |*a, *l, i| {
        const ctx = ctxFor(@intCast(i));
        const sent = try l.announce(allocator, &ctx, random);
        const bytes = try sent.toBytesAlloc(allocator);
        defer allocator.free(bytes);
        a.* = try Announcement.fromBytes(bytes);
        try verifyAnnouncement(a.*, &ctx, random);
    }
    // Bound to its sender: party 2 cannot present party 1's Πmod(N) as its own.
    try testing.expectError(error.InvalidPaillierProof, verifyAnnouncement(anns[0], &ctxFor(2), random));
    try testing.expectEqual(@as(?struct { usize, usize }, null), findDuplicate(&anns));

    // Πfac, every ordered pair.
    for (&locals, anns, 1..) |*prover, prover_ann, i| {
        for (&locals, anns, 1..) |*verifier, verifier_ann, j| {
            if (i == j) continue;
            const ctx = ctxFor(@intCast(i));
            const proof = try prover.proveFactors(verifier_ann.aux, &ctx, random);
            try testing.expect(verifyFactors(prover_ann, verifier.aux, &ctx, proof));
            try testing.expect(!verifyFactors(prover_ann, verifier.aux, &ctxFor(@intCast(j)), proof));
        }
    }

    // A 2-of-3 sharing stands in for the DKG's output here (the `dkg`
    // module's own test runs the real protocol end to end).
    const secret = try root.Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{42}, .big);
    const coeff = [_]root.Scalar{try root.Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{7}, .big)};
    const split = try root.splitSecretKey(allocator, secret, 2, 3, &coeff);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);
    const commits = split.commitments.commitments;

    for (split.shares, 1..) |sh, i| {
        const share = try assembleKeyShare(allocator, @intCast(i), sh.scalar, commits, &locals[i - 1], &anns);
        defer allocator.free(share.public_keys.entries);
        try testing.expectEqual(@as(u32, 2), share.t);
        try testing.expectEqual(@as(u32, 3), share.n);
        try testing.expect((try share.group_public_key.point()).equivalent(try commits[0].point()));
        for (share.public_keys.entries, 1..) |e, j| {
            const want = try root.derivePublicKeyShare(split.commitments, @intCast(j));
            try testing.expect((try e.verifying_share.point()).equivalent(try want.point()));
        }
    }
    // A share that does not belong to the commitments, and someone else's
    // announcement in this party's slot.
    try testing.expectError(error.ShareMismatch, assembleKeyShare(allocator, 1, split.shares[1].scalar, commits, &locals[0], &anns));
    try testing.expectError(error.NotOwnAnnouncement, assembleKeyShare(allocator, 1, split.shares[0].scalar, commits, &locals[1], &anns));
}

test "aux_info: a copied Ñ passes its (unbound) proofs — findDuplicate is what catches it" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7832);
    const random = prng.random();
    var a = try tssLocal(allocator, 0);
    defer a.deinit(allocator);
    var b = try tssLocal(allocator, 1);
    defer b.deinit(allocator);

    const ann_a = try a.announce(allocator, &ctxFor(1), random);
    var ann_b = try b.announce(allocator, &ctxFor(2), random);
    ann_b.aux = ann_a.aux;
    ann_b.aux_proof = ann_a.aux_proof;
    try verifyAnnouncement(ann_b, &ctxFor(2), random); // the gap
    const dup = findDuplicate(&.{ ann_a, ann_b }) orelse return error.TestExpectedDuplicate;
    try testing.expectEqual(@as(usize, 0), dup[0]);
    try testing.expectEqual(@as(usize, 1), dup[1]);
}

test "aux_info: verifyAnnouncement refuses a Paillier key below the floor" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7833);
    const random = prng.random();
    var full = try tssLocal(allocator, 0);
    defer full.deinit(allocator);
    // 1808 bits: above the q⁷ floor (~1792), below the 2048 Πfac is sized for.
    var small = try root.generatePaillierBlum(random, 1808);
    defer small.wipe();
    try testing.expect(root.paillierNMeetsFloor(small.key.public));
    const ctx = ctxFor(1);
    const ann: Announcement = .{
        .paillier_pk = small.key.public,
        .aux = full.aux,
        .aux_proof = try aux_proofs.proveWellFormed(allocator, full.aux, full.trapdoor, random),
        .paillier_proof = try aux_proofs.Pimod.provePaillier(allocator, small.modulus(), small.p(), small.q(), &ctx, random),
    };
    try testing.expectError(error.InvalidPaillierKey, verifyAnnouncement(ann, &ctx, random));

    // The full-size key, but with a generator other than N+1 (an in-process
    // caller can build one; the codec always yields N+1).
    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    const n_len = full.paillier.key.public.nByteLen();
    try full.paillier.key.public.nToBytes(n_buf[0..n_len]);
    var good = ann;
    good.paillier_pk = full.paillier.key.public;
    good.paillier_proof = try aux_proofs.Pimod.provePaillier(allocator, full.paillier.modulus(), full.paillier.p(), full.paillier.q(), &ctx, random);
    try verifyAnnouncement(good, &ctx, random);
    var odd_g = good;
    odd_g.paillier_pk = try paillier.PublicKey.fromBytes(n_buf[0..n_len], &[_]u8{2});
    try testing.expectError(error.InvalidPaillierKey, verifyAnnouncement(odd_g, &ctx, random));

    // A ring-Pedersen proof that does not hold for this tuple.
    var bad_prm = good;
    bad_prm.aux_proof.prm.entries[0].z = full.aux.n_tilde.add(bad_prm.aux_proof.prm.entries[0].z, full.aux.n_tilde.one());
    try testing.expectError(error.InvalidAuxParams, verifyAnnouncement(bad_prm, &ctx, random));
}

test "findDuplicate: a party whose Paillier N doubles as its own Ñ" {
    var prng = std.Random.DefaultPrng.init(0x6175_7834);
    const random = prng.random();
    var k1 = try root.generatePaillierBlum(random, 512);
    defer k1.wipe();
    var k2 = try root.generatePaillierBlum(random, 512);
    defer k2.wipe();
    var k3 = try root.generatePaillierBlum(random, 512);
    defer k3.wipe();
    const h = k1.modulus().one();
    var a: Announcement = undefined;
    a.paillier_pk = k1.key.public;
    a.aux = .{ .n_tilde = k2.modulus(), .h1 = h, .h2 = h };
    var b: Announcement = undefined;
    b.paillier_pk = k3.key.public;
    b.aux = .{ .n_tilde = k3.modulus(), .h1 = h, .h2 = h }; // N = Ñ
    try testing.expectEqual(@as(?struct { usize, usize }, null), findDuplicate(&.{a}));
    const dup = findDuplicate(&.{ a, b }) orelse return error.TestExpectedDuplicate;
    try testing.expectEqual(@as(usize, 1), dup[0]);
    try testing.expectEqual(@as(usize, 1), dup[1]);
    // And a cross-party one: b's N is a's Ñ.
    b.aux.n_tilde = k1.modulus();
    b.paillier_pk = k2.key.public;
    const dup2 = findDuplicate(&.{ a, b }) orelse return error.TestExpectedDuplicate;
    try testing.expectEqual(@as(usize, 0), dup2[0]);
    try testing.expectEqual(@as(usize, 1), dup2[1]);
}
