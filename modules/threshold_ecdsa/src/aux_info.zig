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
//! nor claimed by another party. That includes the ring-Pedersen proofs
//! (Πprm/Πmod over `Ñ`, `aux_proofs.proveWellFormedBound`, since
//! 2026-10-02): a party that copies another's `Ñ` together with its proofs
//! fails `verifyAnnouncement` under its own context. `findDuplicate` stays as
//! the second line (two announcements sharing a modulus are refused even if
//! someone re-proved a copied one — impossible without its trapdoor).
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
    /// SECRET: the Ed25519 seed this party will sign its presigning
    /// messages with (`root.KeyShare.message_seed`).
    message_seed: [32]u8,

    /// Generate a 2048-bit Paillier-Blum key, a 2048-bit ring-Pedersen
    /// tuple with its trapdoor and a message-signing seed. Slow (two safe
    /// primes); `random` MUST be a CSPRNG. Free with `deinit`.
    pub fn generate(allocator: std.mem.Allocator, random: std.Random, out: *LocalAux) (root.GeneratePaillierBlumError || std.mem.Allocator.Error)!void {
        const result = generateUnburned(allocator, random, out);
        burn.stack(generate_stack_burn);
        return result;
    }

    noinline fn generateUnburned(allocator: std.mem.Allocator, random: std.Random, out: *LocalAux) (root.GeneratePaillierBlumError || std.mem.Allocator.Error)!void {
        out.* = try generateByValue(allocator, random);
    }

    fn generateByValue(allocator: std.mem.Allocator, random: std.Random) (root.GeneratePaillierBlumError || std.mem.Allocator.Error)!LocalAux {
        var key: root.PaillierBlumKey = undefined;
        try root.generatePaillierBlum(random, paillier.modulus_bits, &key);
        errdefer key.wipe();
        var at: root.AuxParamsWithTrapdoor = undefined;
        try root.generateAuxParamsWithTrapdoor(allocator, random, root.aux_modulus_bits, &at);
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        return .{ .paillier = key, .aux = at.params, .trapdoor = at.trapdoor, .message_seed = seed };
    }

    /// From material generated earlier (precomputed primes), written to
    /// `out`. MOVES the secrets: `key` and `message_seed` are wiped and
    /// `trapdoor` is emptied (its `p`/`q` buffers now belong to `out`, its
    /// `lambda` is zeroed). Pointers in and out because these values passed
    /// or returned by value leave copies in the caller's frame
    /// (`stackprobe_test.zig`).
    pub fn fromParts(key: *root.PaillierBlumKey, aux: root.AuxParams, trapdoor: *root.AuxTrapdoor, message_seed: *[32]u8, out: *LocalAux) void {
        out.* = .{ .paillier = key.*, .aux = aux, .trapdoor = trapdoor.*, .message_seed = message_seed.* };
        key.wipe();
        std.crypto.secureZero(u8, message_seed);
        std.crypto.secureZero(u8, std.mem.asBytes(&trapdoor.lambda));
        trapdoor.p = &.{};
        trapdoor.q = &.{};
    }

    /// Wipes the Paillier factors and secret key and the aux trapdoor. A
    /// `KeyShare` assembled from this party holds its own copy of the
    /// Paillier secret key; wipe that with `share.paillier_secret.deinit()`.
    pub fn deinit(self: *LocalAux, allocator: std.mem.Allocator) void {
        self.paillier.wipe();
        std.crypto.secureZero(u8, @constCast(self.trapdoor.p));
        std.crypto.secureZero(u8, @constCast(self.trapdoor.q));
        std.crypto.secureZero(u8, &self.message_seed);
        self.trapdoor.deinit(allocator);
    }

    /// The broadcast: public keys and the three generation proofs.
    /// `context` = `session id || u32-BE own index`.
    pub fn announce(self: *const LocalAux, allocator: std.mem.Allocator, context: []const u8, random: std.Random) aux_proofs.ProveError!Announcement {
        return .{
            .paillier_pk = self.paillier.key.public,
            // A clamped Ed25519 scalar is never zero: no seed fails here.
            .message_key = root.messagePublicKey(&self.message_seed) catch unreachable,
            .aux = self.aux,
            .aux_proof = try aux_proofs.proveWellFormedBound(allocator, self.aux, &self.trapdoor, context, random),
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
    /// Ed25519 key of this party's presigning messages
    /// (`root.PartyPublicKeys.message_key`).
    message_key: [32]u8,
    aux: root.AuxParams,
    aux_proof: aux_proofs.WellFormedProof,
    paillier_proof: aux_proofs.ModProof,

    pub const AllocError = std.mem.Allocator.Error || paillier.PublicKey.ByteError || root.AuxParams.AllocError || aux_proofs.ModProof.AllocError || aux_proofs.PrmProof.AllocError;

    /// `len-prefixed` each of: Paillier `N`, `aux.toBytesAlloc()`, Πprm(Ñ),
    /// Πmod(Ñ), Πmod(N); then the 32-byte message key.
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
        try list.appendSlice(allocator, &self.message_key);
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
        if (bytes.len - off != 32) return error.InvalidEncoding;
        const message_key = bytes[off..][0..32].*;
        _ = try root.decodeMessageKey(message_key);
        return .{ .paillier_pk = pk, .message_key = message_key, .aux = aux, .aux_proof = .{ .prm = prm, .mod = mod_aux }, .paillier_proof = mod_n };
    }
};

pub const AnnouncementError = error{
    /// `N` not exactly `paillier.modulus_bits` (2048) wide, or `Γ ≠ N+1`.
    /// (The `q⁷` floor alone would admit ~1793 bits, where Πfac's bound
    /// only guarantees factors of ~2^127; at 2048 it is ~2^253.)
    InvalidPaillierKey,
    /// `Ñ` not exactly `root.aux_modulus_bits` (2048) wide, or the
    /// ring-Pedersen tuple failed `validate` or its Πprm/Πmod.
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
    // Ñ is held to the same width as N (review F6): the q⁷ floor alone
    // admits ~1793 bits, and the range proofs' hiding leans on Ñ as much as
    // their soundness leans on N.
    if (a.aux.n_tilde.bits() != root.aux_modulus_bits) return error.InvalidAuxParams;
    aux_proofs.verifyWellFormedBound(a.aux, context, a.aux_proof, random) catch return error.InvalidAuxParams;
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
    // A shared message key would let one party's signed message be pinned
    // on another: the keys must be distinct too.
    for (all, 0..) |a, i| {
        for (all[i + 1 ..], i + 1..) |b, j| if (std.mem.eql(u8, &a.message_key, &b.message_key)) return .{ i, j };
    }
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

/// True when `new` reuses any of `old`'s published material: its Paillier
/// `N` or ring-Pedersen `Ñ` equal to either of `old`'s moduli, or the same
/// message key. A key refresh must refuse it — renewed shares under a
/// Paillier key or `Ñ` that was already exposed are not renewed (review
/// 2026-10-03 F14; `dkg.EcdsaRefresh` checks every announcement against
/// every entry of the old table).
pub fn reusesMaterial(new: Announcement, old: root.PartyPublicKeys) bool {
    if (std.mem.eql(u8, &new.message_key, &old.message_key)) return true;
    const a = [2][root.aux_modulus_bytes]u8{ modulusBytes(new.paillier_pk), auxModulusBytes(new.aux.n_tilde) };
    const b = [2][root.aux_modulus_bytes]u8{ modulusBytes(old.paillier_pk), auxModulusBytes(old.aux.n_tilde) };
    for (a) |x| for (b) |y| if (std.mem.eql(u8, &x, &y)) return true;
    return false;
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
    /// `announcements.len != n`, `index` outside `1..=n`, a commitment
    /// count outside `1..=n` (that count is the threshold `t`), or a
    /// `Verified` that `AnnouncementSet.verified` did not make.
    InvalidParameters,
    /// `x_i·G` is not the `X_i` the commitments give: the DKG output and
    /// the commitments do not belong together.
    ShareMismatch,
    /// This party's own announcement is not its own key.
    NotOwnAnnouncement,
} || root.DerivePublicKeyShareError || std.mem.Allocator.Error;

/// Every party's announcement as party `me` sees them, with a record of
/// which checks have passed: each peer's `verifyAnnouncement`, the
/// distinct-moduli check, and each peer's Πfac made for `me`. Only
/// `verified` turns it into the `Verified` that `assembleKeyShare` takes, so
/// a key share cannot be assembled from announcements nobody checked
/// (review F5, 2026-10-03; it used to be a doc-comment precondition).
pub const AnnouncementSet = struct {
    all: []Announcement,
    me: u32,
    announced: []bool,
    factored: []bool,
    distinct: bool = false,

    pub const InitError = error{InvalidParameters} || std.mem.Allocator.Error;

    /// `all[j-1]` is party `j`'s announcement, `me`'s own included (it
    /// counts as checked). Copies `all`.
    pub fn init(allocator: std.mem.Allocator, all: []const Announcement, me: u32) InitError!AnnouncementSet {
        if (me == 0 or me > all.len) return error.InvalidParameters;
        const copy = try allocator.dupe(Announcement, all);
        errdefer allocator.free(copy);
        const announced = try allocator.alloc(bool, all.len);
        errdefer allocator.free(announced);
        const factored = try allocator.alloc(bool, all.len);
        @memset(announced, false);
        @memset(factored, false);
        announced[me - 1] = true;
        factored[me - 1] = true;
        return .{ .all = copy, .me = me, .announced = announced, .factored = factored };
    }

    pub fn deinit(self: *AnnouncementSet, allocator: std.mem.Allocator) void {
        allocator.free(self.all);
        allocator.free(self.announced);
        allocator.free(self.factored);
        self.* = undefined;
    }

    /// `verifyAnnouncement` on peer `j`'s announcement, `context` being
    /// `j`'s; records the pass.
    pub fn verifyPeer(self: *AnnouncementSet, j: u32, context: []const u8, random: std.Random) AnnouncementError!void {
        std.debug.assert(j >= 1 and j <= self.all.len and j != self.me);
        try verifyAnnouncement(self.all[j - 1], context, random);
        self.announced[j - 1] = true;
    }

    /// `findDuplicate` over the set; records the pass when there is none.
    pub fn checkDistinct(self: *AnnouncementSet) ?struct { usize, usize } {
        const dup = findDuplicate(self.all);
        self.distinct = dup == null;
        return dup;
    }

    /// `verifyFactors` on peer `j`'s Πfac made for this party (against this
    /// party's own announced `Ñ`), `context` being `j`'s. False also when
    /// `j`'s announcement has not passed yet.
    pub fn verifyPeerFactors(self: *AnnouncementSet, j: u32, context: []const u8, proof: fac_proof.FacProof) bool {
        std.debug.assert(j >= 1 and j <= self.all.len and j != self.me);
        if (!self.announced[j - 1]) return false;
        if (!verifyFactors(self.all[j - 1], self.all[self.me - 1].aux, context, proof)) return false;
        self.factored[j - 1] = true;
        return true;
    }

    /// The set as `Verified`, once every check has passed for every peer.
    pub fn verified(self: *const AnnouncementSet) ?Verified {
        if (!self.distinct) return null;
        for (self.announced, self.factored) |a, f| if (!a or !f) return null;
        return .{ .all = self.all, .me = self.me, .seal = &verified_token };
    }
};

/// Announcements that passed every check of an `AnnouncementSet`, as party
/// `me` saw them. Borrowed from the set: keep the set alive while using it.
pub const Verified = struct {
    all: []const Announcement,
    me: u32,
    /// The address of a declaration private to this file, set only by
    /// `AnnouncementSet.verified`: a `Verified` cannot be written by hand
    /// from outside (review 2026-10-03 F13 — the old `enum { checked }` seal
    /// took any `.checked` literal). `assembleKeyShare` refuses another.
    seal: *const u8,
};

/// Only its address is used (`Verified.seal`); not `pub`, so no other file
/// can name it.
var verified_token: u8 = 0;

/// Builds party `verified.me`'s `KeyShare` from a finished DKG — its share
/// `secret_share`, the group's Feldman commitments `group_commitments`
/// (`F_0 = Q`, length `t`) — and the announcements as `verified` holds
/// them. The returned share owns `public_keys.entries`: free it with
/// `allocator.free(share.public_keys.entries)`.
pub fn assembleKeyShare(
    allocator: std.mem.Allocator,
    verified: Verified,
    secret_share: *const root.Scalar,
    group_commitments: []const root.Element,
    own: *const LocalAux,
    out: *root.KeyShare,
) AssembleError!void {
    const result = assembleKeyShareUnburned(allocator, verified, secret_share, group_commitments, own, out);
    burn.stack(assemble_key_share_stack_burn);
    return result;
}

noinline fn assembleKeyShareUnburned(
    allocator: std.mem.Allocator,
    verified: Verified,
    secret_share: *const root.Scalar,
    group_commitments: []const root.Element,
    own: *const LocalAux,
    out: *root.KeyShare,
) AssembleError!void {
    out.* = try assembleKeyShareByValue(allocator, verified, secret_share.*, group_commitments, own);
}

fn assembleKeyShareByValue(
    allocator: std.mem.Allocator,
    verified: Verified,
    secret_share: root.Scalar,
    group_commitments: []const root.Element,
    own: *const LocalAux,
) AssembleError!root.KeyShare {
    if (verified.seal != &verified_token) return error.InvalidParameters;
    const announcements = verified.all;
    const index = verified.me;
    const n: u32 = @intCast(announcements.len);
    if (index == 0 or index > n or group_commitments.len == 0 or group_commitments.len > n) return error.InvalidParameters;
    const vvec: root.FeldmanCommitments = .{ .commitments = group_commitments };

    const own_ann = announcements[index - 1];
    if (!std.mem.eql(u8, &modulusBytes(own_ann.paillier_pk), &modulusBytes(own.paillier.key.public)) or
        !std.mem.eql(u8, &auxModulusBytes(own_ann.aux.n_tilde), &auxModulusBytes(own.aux.n_tilde)) or
        !feBytesEql(own_ann.aux.h1, own.aux.h1) or !feBytesEql(own_ann.aux.h2, own.aux.h2) or
        !std.mem.eql(u8, &own_ann.message_key, &(root.messagePublicKey(&own.message_seed) catch return error.NotOwnAnnouncement)))
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
            .message_key = a.message_key,
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
        .message_seed = own.message_seed,
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
const burn = @import("burn.zig");

// Dead-stack burns of the secret entry points (`burn.zig`), each a little
// above the depth its body reached in `stackprobe_test.zig` (ReleaseFast,
// x86_64, 2026-10-08; `verbose = true` prints the depths). The probe asserts
// that no secret survives, which a body outgrowing its burn would break.
const generate_stack_burn = 16 * 1024;
const assemble_key_share_stack_burn = 576 * 1024;
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
    var key: root.PaillierBlumKey = undefined;
    try root.paillierBlumFromPrimes(pp, pq, &key);
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
    // tss-lib ships Alpha = log_{h1} h2; this module's trapdoor is its inverse.
    const alpha = try fe(allocator, nt, p.aux_lambda);
    var lambda: root.AuxFe = undefined;
    try root.auxLogInverse(nt, tp, tq, &alpha, &lambda);
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = try fe(allocator, nt, p.h1), .h2 = try fe(allocator, nt, p.h2) };
    var trapdoor: root.AuxTrapdoor = .{ .p = tp, .q = tq, .lambda = lambda };
    var seed: [32]u8 = @splat(@intCast(i + 1)); // distinct per party; a test seed
    var local: LocalAux = undefined;
    LocalAux.fromParts(&key, aux, &trapdoor, &seed, &local);
    return local;
}

fn ctxFor(i: u32) [12]u8 {
    var out: [12]u8 = "sid-test".* ++ [_]u8{ 0, 0, 0, 0 };
    std.mem.writeInt(u32, out[8..12], i, .big);
    return out;
}

/// Three parties' aux material and their announcements, made once per test
/// binary and shared by the `aux_info:` tests below. Announcing is ~28 s of
/// ReleaseSafe (Πmod and the ring-Pedersen proofs over 2048-bit moduli); the
/// one test that used to do it together with every check took ~100 s and
/// exceeded `--test-timeout` (3 min) on a loaded CI runner.
const AnnFixture = struct { locals: [3]LocalAux, anns: [3]Announcement };
var ann_fixture: ?AnnFixture = null;

fn annFixture() !*AnnFixture {
    if (ann_fixture) |*f| return f;
    const pa = std.heap.page_allocator; // global-alloc-ok: process-lifetime test fixture shared by several tests, outlives testing.allocator's per-test teardown
    var prng = std.Random.DefaultPrng.init(0x6175_7831);
    ann_fixture = @as(AnnFixture, undefined);
    errdefer ann_fixture = null;
    const f = &ann_fixture.?;
    for (&f.locals, 0..) |*l, i| l.* = try tssLocal(pa, i);
    for (&f.anns, &f.locals, 1..) |*a, *l, i| {
        const ctx = ctxFor(@intCast(i));
        a.* = try l.announce(pa, &ctx, prng.random());
    }
    return f;
}

test "aux_info: announcements survive the codec, verify, and are bound to their sender" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7832);
    const random = prng.random();
    const f = try annFixture();

    // Broadcast, through the codec, as a receiver would see it.
    var anns: [3]Announcement = undefined;
    for (&anns, f.anns, 1..) |*a, sent, i| {
        const ctx = ctxFor(@intCast(i));
        const bytes = try sent.toBytesAlloc(allocator);
        defer allocator.free(bytes);
        a.* = try Announcement.fromBytes(bytes);
        try verifyAnnouncement(a.*, &ctx, random);
        // Mutation audit: the codec takes exactly the 32-byte message key
        // after the proofs (no trailing byte), and refuses a small-order one.
        const longer = try allocator.alloc(u8, bytes.len + 1);
        defer allocator.free(longer);
        @memcpy(longer[0..bytes.len], bytes);
        longer[bytes.len] = 0;
        try testing.expectError(error.InvalidEncoding, Announcement.fromBytes(longer));
        const weak = try allocator.dupe(u8, bytes);
        defer allocator.free(weak);
        @memset(weak[weak.len - 32 ..], 0);
        weak[weak.len - 32] = 1; // the identity point
        try testing.expectError(error.InvalidEncoding, Announcement.fromBytes(weak));
    }
    // Bound to its sender: party 2 cannot present party 1's announcement as
    // its own — the Ñ proofs refuse first (bound since 2026-10-02), and the
    // Πmod(N) on its own refuses too.
    try testing.expectError(error.InvalidAuxParams, verifyAnnouncement(anns[0], &ctxFor(2), random));
    try testing.expect(!aux_proofs.Pimod.verifyPaillier(root.paillierModulusAsAux(anns[0].paillier_pk).?, &ctxFor(2), anns[0].paillier_proof));
    try testing.expect(aux_proofs.Pimod.verifyPaillier(root.paillierModulusAsAux(anns[0].paillier_pk).?, &ctxFor(1), anns[0].paillier_proof));
    try testing.expectEqual(@as(?struct { usize, usize }, null), findDuplicate(&anns));
    // Πmod(N) alone failing (another party's proof for another modulus) is its own error (mutation audit).
    var wrong_mod = anns[1];
    wrong_mod.paillier_proof = anns[0].paillier_proof;
    try testing.expectError(error.InvalidPaillierProof, verifyAnnouncement(wrong_mod, &ctxFor(2), random));
}

test "aux_info: each party checks its peers, Πfac pairwise, then assembles its share" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7833);
    const random = prng.random();
    const f = try annFixture();
    const locals = &f.locals;
    const anns = f.anns;

    // Each party's view: announcements, distinct moduli, then Πfac from
    // every peer made for it (every ordered pair).
    var sets: [3]AnnouncementSet = undefined;
    for (&sets, 1..) |*set, me| {
        set.* = try AnnouncementSet.init(allocator, &anns, @intCast(me));
        for (1..4) |j| if (j != me) try set.verifyPeer(@intCast(j), &ctxFor(@intCast(j)), random);
        try testing.expect(set.verified() == null); // Πfac still missing
        try testing.expectEqual(@as(?struct { usize, usize }, null), set.checkDistinct());
    }
    defer for (&sets) |*set| set.deinit(allocator);
    for (locals, anns, 1..) |*prover, prover_ann, i| {
        for (locals, anns, 1..) |*verifier, verifier_ann, j| {
            if (i == j) continue;
            const ctx = ctxFor(@intCast(i));
            const proof = try prover.proveFactors(verifier_ann.aux, &ctx, random);
            try testing.expect(verifyFactors(prover_ann, verifier.aux, &ctx, proof));
            try testing.expect(!verifyFactors(prover_ann, verifier.aux, &ctxFor(@intCast(j)), proof));
            try testing.expect(!sets[j - 1].verifyPeerFactors(@intCast(i), &ctxFor(@intCast(j)), proof));
            try testing.expect(sets[j - 1].verifyPeerFactors(@intCast(i), &ctx, proof));
        }
    }

    // A 2-of-3 sharing stands in for the DKG's output here (the `dkg`
    // module's own test runs the real protocol end to end).
    const secret = try root.Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{42}, .big);
    const coeff = [_]root.Scalar{try root.Scalar.fromBytes([_]u8{0} ** 31 ++ [_]u8{7}, .big)};
    const split = try root.splitSecretKey(allocator, &secret, 2, 3, &coeff);
    defer allocator.free(split.shares);
    defer allocator.free(split.commitments.commitments);
    const commits = split.commitments.commitments;

    for (split.shares, 1..) |sh, i| {
        var share: root.KeyShare = undefined;
        try assembleKeyShare(allocator, sets[i - 1].verified().?, &sh.scalar, commits, &locals[i - 1], &share);
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
    var scratch_ks: root.KeyShare = undefined;
    try testing.expectError(error.ShareMismatch, assembleKeyShare(allocator, sets[0].verified().?, &split.shares[1].scalar, commits, &locals[0], &scratch_ks));
    try testing.expectError(error.NotOwnAnnouncement, assembleKeyShare(allocator, sets[0].verified().?, &split.shares[0].scalar, commits, &locals[1], &scratch_ks));
    // Same moduli and ring-Pedersen tuple, another message-signing seed (mutation audit).
    var other_seed = locals[0];
    other_seed.message_seed = @splat(0x55);
    try testing.expectError(error.NotOwnAnnouncement, assembleKeyShare(allocator, sets[0].verified().?, &split.shares[0].scalar, commits, &other_seed, &scratch_ks));
    // A `Verified` written by hand over the same announcements (review F13).
    var not_the_token: u8 = 0;
    const forged: Verified = .{ .all = sets[0].verified().?.all, .me = 1, .seal = &not_the_token };
    try testing.expectError(error.InvalidParameters, assembleKeyShare(allocator, forged, &split.shares[0].scalar, commits, &locals[0], &scratch_ks));
}

test "aux_info: a set counts only what was checked (mutation audit)" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7834);
    const random = prng.random();
    const f = try annFixture();
    const locals = &f.locals;
    const anns = f.anns;

    // A valid Πfac from a
    // peer whose announcement was not verified is refused (94); with every
    // announcement and Πfac in, the set is still not verified before the
    // distinctness check has run (95), and not before every Πfac is in (96).
    {
        var fresh = try AnnouncementSet.init(allocator, &anns, 1);
        defer fresh.deinit(allocator);
        var proofs: [2]fac_proof.FacProof = undefined;
        for (&proofs, 2..) |*pr, j| pr.* = try locals[j - 1].proveFactors(anns[0].aux, &ctxFor(@intCast(j)), random);
        try testing.expect(!fresh.verifyPeerFactors(2, &ctxFor(2), proofs[0]));
        for (2..4) |j| try fresh.verifyPeer(@intCast(j), &ctxFor(@intCast(j)), random);
        try testing.expect(fresh.verifyPeerFactors(2, &ctxFor(2), proofs[0]));
        try testing.expect(fresh.checkDistinct() == null);
        try testing.expect(fresh.verified() == null); // Πfac of party 3 missing
        try testing.expect(fresh.verifyPeerFactors(3, &ctxFor(3), proofs[1]));
        try testing.expect(fresh.verified() != null);

        var fresh2 = try AnnouncementSet.init(allocator, &anns, 1);
        defer fresh2.deinit(allocator);
        for (2..4) |j| try fresh2.verifyPeer(@intCast(j), &ctxFor(@intCast(j)), random);
        for ([_]usize{ 0, 1 }, 2..) |pi, j| try testing.expect(fresh2.verifyPeerFactors(@intCast(j), &ctxFor(@intCast(j)), proofs[pi]));
        try testing.expect(fresh2.verified() == null); // everything in, but never checked for distinctness
    }
}

test "aux_info: a copied Ñ with its proofs fails under the copier's context; findDuplicate is the second line" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7832);
    const random = prng.random();
    var a = try tssLocal(allocator, 0);
    defer a.deinit(allocator);
    var b = try tssLocal(allocator, 1);
    defer b.deinit(allocator);

    const ann_a = try a.announce(allocator, &ctxFor(1), random);
    var ann_b = try b.announce(allocator, &ctxFor(2), random);
    try verifyAnnouncement(ann_b, &ctxFor(2), random);
    ann_b.aux = ann_a.aux;
    ann_b.aux_proof = ann_a.aux_proof;
    // Was the gap until 2026-10-02 (the Ñ proofs were unbound): now the
    // copied proofs are bound to party 1's context, not party 2's.
    try testing.expectError(error.InvalidAuxParams, verifyAnnouncement(ann_b, &ctxFor(2), random));
    try verifyAnnouncement(ann_a, &ctxFor(1), random);
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
    var small: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 1808, &small);
    defer small.wipe();
    try testing.expect(root.paillierNMeetsFloor(small.key.public));
    const ctx = ctxFor(1);
    const ann: Announcement = .{
        .paillier_pk = small.key.public,
        .message_key = try root.messagePublicKey(&full.message_seed),
        .aux = full.aux,
        .aux_proof = try aux_proofs.proveWellFormedBound(allocator, full.aux, &full.trapdoor, &ctx, random),
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
    var k1: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k1);
    defer k1.wipe();
    var k2: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k2);
    defer k2.wipe();
    var k3: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k3);
    defer k3.wipe();
    const h = k1.modulus().one();
    var a: Announcement = undefined;
    a.paillier_pk = k1.key.public;
    a.aux = .{ .n_tilde = k2.modulus(), .h1 = h, .h2 = h };
    a.message_key = @splat(1);
    var b: Announcement = undefined;
    b.paillier_pk = k3.key.public;
    b.aux = .{ .n_tilde = k3.modulus(), .h1 = h, .h2 = h }; // N = Ñ
    b.message_key = @splat(2);
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
    // Only a's Ñ equals b's N (b's Ñ is a stranger): both of a's moduli are compared (mutation audit).
    var k4: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k4);
    defer k4.wipe();
    b.aux.n_tilde = k4.modulus();
    b.paillier_pk = k2.key.public;
    const dup3 = findDuplicate(&.{ a, b }) orelse return error.TestExpectedDuplicate;
    try testing.expectEqual(@as(usize, 0), dup3[0]);
    try testing.expectEqual(@as(usize, 1), dup3[1]);
}

test "aux_info: verifyAnnouncement refuses a ring-Pedersen modulus that is not 2048 bits (review F6)" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6175_7836);
    const random = prng.random();
    var full = try tssLocal(allocator, 0);
    defer full.deinit(allocator);

    // A 1808-bit Blum Ñ (above the q⁷ floor) with a real trapdoor:
    // h2 = r², h1 = h2^λ, so Πprm and Πmod are genuinely valid.
    var small: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 1808, &small);
    defer small.wipe();
    const nt = small.modulus();
    const r = try root.AuxFe.fromBytes(nt, &[_]u8{ 0x05, 0x39 }, .big);
    const h2 = nt.sq(r);
    var lam_bytes: [32]u8 = undefined;
    random.bytes(&lam_bytes);
    const lambda = try root.AuxFe.fromBytes(nt, &lam_bytes, .big);
    const h1 = try nt.pow(h2, lambda);
    const aux: root.AuxParams = .{ .n_tilde = nt, .h1 = h1, .h2 = h2 };
    const td: root.AuxTrapdoor = .{ .p = small.p(), .q = small.q(), .lambda = lambda };
    const ctx = ctxFor(1);
    const aux_proof = try aux_proofs.proveWellFormedBound(allocator, aux, &td, &ctx, random);
    // The proofs hold; only the width is wrong.
    try aux_proofs.verifyWellFormedBound(aux, &ctx, aux_proof, random);

    const ann: Announcement = .{
        .paillier_pk = full.paillier.key.public,
        .message_key = try root.messagePublicKey(&full.message_seed),
        .aux = aux,
        .aux_proof = aux_proof,
        .paillier_proof = try aux_proofs.Pimod.provePaillier(allocator, full.paillier.modulus(), full.paillier.p(), full.paillier.q(), &ctx, random),
    };
    try testing.expectError(error.InvalidAuxParams, verifyAnnouncement(ann, &ctx, random));
}

test "findDuplicate: two parties announcing one message key" {
    var prng = std.Random.DefaultPrng.init(0x6175_7837);
    const random = prng.random();
    var k1: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k1);
    defer k1.wipe();
    var k2: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k2);
    defer k2.wipe();
    var k3: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k3);
    defer k3.wipe();
    var k4: root.PaillierBlumKey = undefined;
    try root.generatePaillierBlum(random, 512, &k4);
    defer k4.wipe();
    const h = k1.modulus().one();
    var a: Announcement = undefined;
    a.paillier_pk = k1.key.public;
    a.aux = .{ .n_tilde = k2.modulus(), .h1 = h, .h2 = h };
    a.message_key = @splat(1);
    var b: Announcement = undefined;
    b.paillier_pk = k3.key.public;
    b.aux = .{ .n_tilde = k4.modulus(), .h1 = h, .h2 = h };
    b.message_key = @splat(2);
    try testing.expectEqual(@as(?struct { usize, usize }, null), findDuplicate(&.{ a, b }));
    // Distinct moduli, one message key: one party's signed message could be
    // pinned on the other.
    b.message_key = a.message_key;
    const dup = findDuplicate(&.{ a, b }) orelse return error.TestExpectedDuplicate;
    try testing.expectEqual(@as(usize, 0), dup[0]);
    try testing.expectEqual(@as(usize, 1), dup[1]);
}
