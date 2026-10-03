// SPDX-License-Identifier: MIT

//! ecdsa_keygen — dealer-free keygen for `threshold_ecdsa`, one party as a
//! sans-I/O state machine: the GJKR `Participant` for the secret sharing,
//! wrapped in the two rounds that make every party's Paillier key safe to
//! run MtA against (CGGMP21 §4; without them a party that picks its own
//! Paillier key can read an honest peer's share off the MtA responses —
//! the BitForge class).
//!
//! ```text
//! start()    -> broadcast ecdsa_announcement: N_i, Ñ_i, Πprm+Πmod(Ñ_i), Πmod(N_i)
//! .announce    collect every peer's announcement
//! advance()  -> verify each (floor, Γ, proofs), refuse a shared modulus;
//!               send ecdsa_fac_proof Πfac(N_i) to each peer, under ITS Ñ
//! .factors     collect every peer's Πfac
//! advance()  -> verify each; start the GJKR run
//! .dkg         GJKR frames go to the inner `Participant`; `advance` drives it
//! advance()  -> (when GJKR is done) assemble the `threshold_ecdsa.KeyShare`
//! .done        `takeKeyShare()`
//! ```
//!
//! Every proof is bound to `session_id || u32-BE t || u32-BE n || u32-BE
//! prover index`, so the caller must give each run a session id no other run
//! uses.
//!
//! **Early frames.** A frame for a later round (a fast peer's Πfac while we
//! are still in `.announce`, its first GJKR frame while we are in
//! `.factors`) is refused with `WrongRound`, as `Participant` refuses them:
//! the caller holds it and redelivers it after `advance`. A caller that
//! drops it instead will see that peer as missing (and abort, or in GJKR
//! disqualify it). All `n`
//! parties must take part in the aux rounds: a missing or failing
//! announcement or Πfac aborts the run and names the party (`culprit`).
//! The GJKR rounds keep their own rules (a disqualified dealer does not stop
//! them). Transport duties are the inner `Participant`'s: reliable broadcast,
//! authenticated senders, confidential point-to-point frames.
//!
//! The caller owns the party's `threshold_ecdsa.aux_info.LocalAux` (its
//! Paillier factors and aux trapdoor) and keeps it alive for the run.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const participant = @import("participant.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");

const aux_info = tecdsa.aux_info;
const fac_proof = tecdsa.fac_proof;
const Participant = participant.Participant;
const Outgoing = wire.Outgoing;
const MessageError = wire.MessageError;

pub const Phase = enum { new, announce, factors, dkg, done, aborted };

pub const InitError = participant.InitError || error{EmptySessionId};
pub const StartError = error{WrongRound} || tecdsa.aux_proofs.ProveError || aux_info.Announcement.AllocError;
pub const AdvanceError = error{
    WrongRound,
    Finished,
    Aborted,
    /// A peer's announcement or Πfac never came (`culprit`).
    MissingMessage,
    /// A peer's announcement failed `verifyAnnouncement` (`culprit`).
    InvalidAnnouncement,
    /// Two announcements share a modulus; who copied whom cannot be told.
    DuplicateModulus,
    /// A peer's Πfac did not verify (`culprit`).
    InvalidFactorProof,
} || participant.AdvanceError || participant.StartError || fac_proof.ProveError ||
    fac_proof.FacProof.AllocError || aux_info.AssembleError || std.mem.Allocator.Error;

pub const EcdsaKeygen = struct {
    allocator: std.mem.Allocator,
    cfg: types.Config,
    me: u32,
    session_id: []u8,
    local: *const aux_info.LocalAux,
    random: std.Random,
    inner: Participant,
    phase_: Phase = .new,

    /// `announcements[j - 1]`; this party's own is filled by `start`.
    announcements: []?aux_info.Announcement,
    /// Πfac received from peer `j`, `fac[j - 1]`.
    fac: []?fac_proof.FacProof,

    /// The announcements and the checks they passed, from the end of the
    /// announce round on.
    checked: ?aux_info.AnnouncementSet = null,

    outbox: std.ArrayList(Outgoing) = .empty,
    share: ?tecdsa.KeyShare = null,
    culprit_: ?u32 = null,

    /// Party `index` (1-based) of a `cfg` run. `session_id` is copied;
    /// `local` is borrowed; `random` (a CSPRNG) feeds the GJKR polynomials
    /// now and the proofs later.
    pub fn init(
        allocator: std.mem.Allocator,
        cfg: types.Config,
        index: u32,
        session_id: []const u8,
        local: *const aux_info.LocalAux,
        random: std.Random,
    ) InitError!EcdsaKeygen {
        if (session_id.len == 0) return error.EmptySessionId;
        var inner = try Participant.init(allocator, cfg, index, random);
        errdefer inner.deinit();
        const sid = try allocator.dupe(u8, session_id);
        errdefer allocator.free(sid);
        const anns = try allocator.alloc(?aux_info.Announcement, cfg.n);
        errdefer allocator.free(anns);
        @memset(anns, null);
        const fac = try allocator.alloc(?fac_proof.FacProof, cfg.n);
        @memset(fac, null);
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .me = index,
            .session_id = sid,
            .local = local,
            .random = random,
            .inner = inner,
            .announcements = anns,
            .fac = fac,
        };
    }

    /// Releases everything, wiping the secrets this struct holds (the inner
    /// party's, queued frames, an untaken `KeyShare`'s `x_i`).
    pub fn deinit(self: *EcdsaKeygen) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        if (self.share) |*s| {
            std.crypto.secureZero(u8, std.mem.asBytes(&s.secret_share));
            s.paillier_secret.deinit();
            self.allocator.free(s.public_keys.entries);
        }
        if (self.checked) |*c| c.deinit(self.allocator);
        self.inner.deinit();
        self.allocator.free(self.session_id);
        self.allocator.free(self.announcements);
        self.allocator.free(self.fac);
        self.* = undefined;
    }

    pub fn phase(self: *const EcdsaKeygen) Phase {
        return self.phase_;
    }

    /// The party that made the run abort, when that is known.
    pub fn culprit(self: *const EcdsaKeygen) ?u32 {
        return self.culprit_ orelse self.inner.culprit();
    }

    /// The finished `KeyShare`, handed over once (null before `.done` and
    /// after the first call). The caller frees
    /// `share.public_keys.entries` with the allocator given to `init`.
    pub fn takeKeyShare(self: *EcdsaKeygen) ?tecdsa.KeyShare {
        const s = self.share orelse return null;
        self.share = null;
        return s;
    }

    /// True when every frame this phase waits for is in (`.dkg` defers to
    /// the inner party, whose deadline-ended rounds never say so).
    pub fn allReceived(self: *const EcdsaKeygen) bool {
        return switch (self.phase_) {
            .announce => self.missing(.announce) == null,
            .factors => self.missing(.factors) == null,
            .dkg => self.inner.allReceived(),
            else => false,
        };
    }

    /// Everything queued to send; free with `wire.freeOutgoing(allocator,
    /// msgs)`.
    pub fn takeOutgoing(self: *EcdsaKeygen) std.mem.Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    /// Round 1: broadcast this party's announcement.
    pub fn start(self: *EcdsaKeygen) StartError!void {
        if (self.phase_ != .new) return error.WrongRound;
        var ctx_buf: [ctx_max]u8 = undefined;
        const ann = try self.local.announce(self.allocator, self.context(&ctx_buf, self.me), self.random);
        const bytes = try ann.toBytesAlloc(self.allocator);
        defer self.allocator.free(bytes);
        try wire.pushFrame(&self.outbox, self.allocator, .broadcast, .ecdsa_announcement, bytes);
        self.announcements[self.me - 1] = ann;
        self.phase_ = .announce;
    }

    /// Feed one frame from the authenticated peer `from`. A refused frame
    /// changes nothing.
    pub fn handle(self: *EcdsaKeygen, from: u32, bytes: []const u8) MessageError!void {
        switch (self.phase_) {
            .done => return error.Finished,
            .aborted => return error.Aborted,
            else => {},
        }
        if (bytes.len == 0) return error.Malformed;
        const kind = wire.kindFromByte(bytes[0]) orelse return error.UnknownKind;
        if (from < 1 or from > self.cfg.n or from == self.me) return error.UnknownSender;
        const body = bytes[1..];
        switch (kind) {
            .ecdsa_announcement => {
                if (self.phase_ != .announce) return error.WrongRound;
                if (self.announcements[from - 1] != null) return error.DuplicateMessage;
                self.announcements[from - 1] = aux_info.Announcement.fromBytes(body) catch return error.Malformed;
            },
            .ecdsa_fac_proof => {
                if (self.phase_ != .factors) return error.WrongRound;
                if (self.fac[from - 1] != null) return error.DuplicateMessage;
                self.fac[from - 1] = fac_proof.FacProof.fromBytes(self.local.aux.n_tilde, body) catch return error.Malformed;
            },
            else => {
                if (self.phase_ != .dkg) return error.WrongRound;
                try self.inner.handle(from, bytes);
                // The frame is consumed; losing its replies would desync us.
                self.drainInner() catch |e| {
                    self.phase_ = .aborted;
                    return e;
                };
            },
        }
    }

    /// Close the current round and move on. Any error leaves the party
    /// `.aborted`.
    pub fn advance(self: *EcdsaKeygen) AdvanceError!void {
        const r = switch (self.phase_) {
            .new => return error.WrongRound,
            .announce => self.advanceAnnounce(),
            .factors => self.advanceFactors(),
            .dkg => self.advanceDkg(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        };
        r catch |e| {
            self.phase_ = .aborted;
            return e;
        };
    }

    // ── rounds ───────────────────────────────────────────────────────────

    fn advanceAnnounce(self: *EcdsaKeygen) AdvanceError!void {
        if (self.missing(.announce)) |j| {
            self.culprit_ = j;
            return error.MissingMessage;
        }
        var ctx_buf: [ctx_max]u8 = undefined;
        const all = try self.allocator.alloc(aux_info.Announcement, self.cfg.n);
        defer self.allocator.free(all);
        for (all, self.announcements) |*d, a| d.* = a.?;
        self.checked = aux_info.AnnouncementSet.init(self.allocator, all, self.me) catch |e| switch (e) {
            error.InvalidParameters => unreachable, // me is 1..=n by `init`
            error.OutOfMemory => return error.OutOfMemory,
        };
        const checked = &self.checked.?;
        for (1..self.cfg.n + 1) |j| {
            if (j == self.me) continue;
            checked.verifyPeer(@intCast(j), self.context(&ctx_buf, @intCast(j)), self.random) catch {
                self.culprit_ = @intCast(j);
                return error.InvalidAnnouncement;
            };
        }
        if (checked.checkDistinct() != null) return error.DuplicateModulus;

        const own_ctx = self.context(&ctx_buf, self.me);
        for (self.announcements, 1..) |a, j| {
            if (j == self.me) continue;
            const proof = try self.local.proveFactors(a.?.aux, own_ctx, self.random);
            const bytes = try proof.toBytesAlloc(self.allocator);
            defer self.allocator.free(bytes);
            try wire.pushFrame(&self.outbox, self.allocator, .{ .party = @intCast(j) }, .ecdsa_fac_proof, bytes);
        }
        self.phase_ = .factors;
    }

    fn advanceFactors(self: *EcdsaKeygen) AdvanceError!void {
        if (self.missing(.factors)) |j| {
            self.culprit_ = j;
            return error.MissingMessage;
        }
        var ctx_buf: [ctx_max]u8 = undefined;
        const checked = &self.checked.?;
        for (self.fac, 1..) |f, j| {
            if (j == self.me) continue;
            if (!checked.verifyPeerFactors(@intCast(j), self.context(&ctx_buf, @intCast(j)), f.?)) {
                self.culprit_ = @intCast(j);
                return error.InvalidFactorProof;
            }
        }
        try self.inner.start();
        try self.drainInner();
        self.phase_ = .dkg;
    }

    fn advanceDkg(self: *EcdsaKeygen) AdvanceError!void {
        try self.inner.advance();
        try self.drainInner();
        if (self.inner.phase() != .done) return;
        var out = self.inner.output().?;
        defer out.deinit();
        self.share = try aux_info.assembleKeyShare(
            self.allocator,
            self.checked.?.verified().?, // every check passed in the earlier rounds
            out.secret_share,
            self.inner.publicCommitments().?,
            self.local,
        );
        self.phase_ = .done;
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// Longest session id `context` keeps raw; longer ones are hashed down.
    pub const ctx_max = 1 + 64 + 12;

    /// `form || session id || u32-BE t || u32-BE n || u32-BE index`, `form`
    /// 0 for a raw session id and 1 for a session id longer than 64 bytes
    /// replaced by its SHA-256 (every party does the same, so contexts
    /// agree). The form byte keeps a raw 32-byte session id from equalling
    /// another session id's digest (review F8, 2026-10-03).
    fn context(self: *const EcdsaKeygen, buf: *[ctx_max]u8, index: u32) []const u8 {
        return keygenContext(buf, self.session_id, self.cfg.t, self.cfg.n, index);
    }

    fn missing(self: *const EcdsaKeygen, which: enum { announce, factors }) ?u32 {
        for (0..self.cfg.n) |i| {
            const j: u32 = @intCast(i + 1);
            if (j == self.me) continue;
            const have = switch (which) {
                .announce => self.announcements[i] != null,
                .factors => self.fac[i] != null,
            };
            if (!have) return j;
        }
        return null;
    }

    fn drainInner(self: *EcdsaKeygen) std.mem.Allocator.Error!void {
        const msgs = try self.inner.takeOutgoing();
        defer self.allocator.free(msgs);
        var moved: usize = 0;
        errdefer for (msgs[moved..]) |m| m.deinit(self.allocator);
        while (moved < msgs.len) : (moved += 1) try self.outbox.append(self.allocator, msgs[moved]);
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test-only `LocalAux` from Blum primes: a second Paillier-Blum modulus
/// stands in for `Ñ` (production uses safe primes — `LocalAux.generate` —
/// which take minutes; Πprm/Πmod hold over any Blum modulus with a known
/// `λ`, so the proofs and every check run for real).
fn quickLocal(allocator: std.mem.Allocator, random: std.Random) !aux_info.LocalAux {
    var key = try tecdsa.generatePaillierBlum(random, 2048);
    errdefer key.wipe();
    var ring = try tecdsa.generatePaillierBlum(random, 2048);
    defer ring.wipe();
    const nt = ring.modulus();
    var buf: [tecdsa.aux_modulus_bytes]u8 = undefined;
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const h2 = nt.sq(try tecdsa.AuxFe.fromBytes(nt, &buf, .big));
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const lambda = try tecdsa.AuxFe.fromBytes(nt, &buf, .big);
    const h1 = try nt.pow(h2, lambda); // h1 ∈ ⟨h2⟩, the relation Πprm proves
    const p = try allocator.dupe(u8, ring.p());
    errdefer allocator.free(p);
    const q = try allocator.dupe(u8, ring.q());
    var seed: [32]u8 = undefined;
    random.bytes(&seed);
    return aux_info.LocalAux.fromParts(key, .{ .n_tilde = nt, .h1 = h1, .h2 = h2 }, .{ .p = p, .q = q, .lambda = lambda }, seed);
}

const Rig = struct {
    parties: []EcdsaKeygen,
    refused: usize = 0,

    /// Delivers everything queued (a broadcast to every other party).
    fn deliver(self: *Rig, allocator: std.mem.Allocator, filter: ?*const fn (from: u32, to: u32, bytes: []u8) bool) !void {
        for (self.parties, 1..) |*src, from| {
            const msgs = try src.takeOutgoing();
            defer wire.freeOutgoing(allocator, msgs);
            for (msgs) |m| {
                for (self.parties, 1..) |*dst, to| {
                    if (to == from) continue;
                    switch (m.to) {
                        .broadcast => {},
                        .party => |p| if (p != to) continue,
                    }
                    if (filter) |f| if (!f(@intCast(from), @intCast(to), m.bytes)) continue;
                    dst.handle(@intCast(from), m.bytes) catch {
                        self.refused += 1;
                    };
                }
            }
        }
    }
};

test "dealer-free keygen: 2-of-3 over frames -> KeyShares -> threshold sign -> std ECDSA verify" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0001);
    const random = prng.random();
    const cfg: types.Config = .{ .t = 2, .n = 3 };

    var locals: [3]aux_info.LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 3) : (made += 1) locals[made] = try quickLocal(allocator, random);

    var parties: [3]EcdsaKeygen = undefined;
    var inited: usize = 0;
    defer for (parties[0..inited]) |*p| p.deinit();
    while (inited < 3) : (inited += 1) parties[inited] = try EcdsaKeygen.init(allocator, cfg, @intCast(inited + 1), "test-session-1", &locals[inited], random);

    var rig: Rig = .{ .parties = &parties };
    for (&parties) |*p| try p.start();
    try rig.deliver(allocator, null);
    var rounds: usize = 0;
    while (parties[0].phase() != .done) : (rounds += 1) {
        try testing.expect(rounds < 16);
        for (&parties) |*p| try p.advance();
        try rig.deliver(allocator, null);
    }
    try testing.expectEqual(@as(usize, 0), rig.refused);

    var shares: [3]tecdsa.KeyShare = undefined;
    for (&parties, &shares) |*p, *s| {
        try testing.expectEqual(Phase.done, p.phase());
        s.* = p.takeKeyShare().?;
    }
    defer for (shares) |s| allocator.free(s.public_keys.entries);
    try testing.expect(parties[0].takeKeyShare() == null);
    for (shares[1..]) |s| try testing.expectEqualSlices(u8, &shares[0].group_public_key.toBytes(), &s.group_public_key.toBytes());

    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&shares[0].group_public_key.toBytes());
    const msg = "dealer-free keygen anchor";
    for ([_][2]usize{ .{ 0, 1 }, .{ 1, 2 }, .{ 0, 2 } }) |pair| {
        const sig = try tecdsa.signing.signWithShares(allocator, &.{ shares[pair[0]], shares[pair[1]] }, msg, random);
        try sig.verify(msg, pk);
    }
}

test "dealer-free keygen: a tampered Πfac aborts the receiver and names the prover" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0002);
    const random = prng.random();
    const cfg: types.Config = .{ .t = 2, .n = 3 };

    var locals: [3]aux_info.LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 3) : (made += 1) locals[made] = try quickLocal(allocator, random);

    var parties: [3]EcdsaKeygen = undefined;
    var inited: usize = 0;
    defer for (parties[0..inited]) |*p| p.deinit();
    while (inited < 3) : (inited += 1) parties[inited] = try EcdsaKeygen.init(allocator, cfg, @intCast(inited + 1), "test-session-2", &locals[inited], random);

    var rig: Rig = .{ .parties = &parties };
    for (&parties) |*p| try p.start();
    try rig.deliver(allocator, null);
    for (&parties) |*p| try p.advance();
    // Party 2's Πfac to party 3 has its last byte (inside `v`) flipped.
    try rig.deliver(allocator, struct {
        fn f(from: u32, to: u32, bytes: []u8) bool {
            if (from == 2 and to == 3 and bytes[0] == @intFromEnum(wire.Kind.ecdsa_fac_proof)) bytes[bytes.len - 1] ^= 1;
            return true;
        }
    }.f);
    try parties[0].advance();
    try testing.expectError(error.InvalidFactorProof, parties[2].advance());
    try testing.expectEqual(Phase.aborted, parties[2].phase());
    try testing.expectEqual(@as(?u32, 2), parties[2].culprit());
}

test "dealer-free keygen: an announcement bound to another party's context is refused, culprit named" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0003);
    const random = prng.random();
    const cfg: types.Config = .{ .t = 2, .n = 3 };

    var locals: [3]aux_info.LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 3) : (made += 1) locals[made] = try quickLocal(allocator, random);

    var parties: [3]EcdsaKeygen = undefined;
    var inited: usize = 0;
    defer for (parties[0..inited]) |*p| p.deinit();
    while (inited < 3) : (inited += 1) parties[inited] = try EcdsaKeygen.init(allocator, cfg, @intCast(inited + 1), "test-session-3", &locals[inited], random);
    for (&parties) |*p| try p.start();

    // Party 1 replays its own (valid, but party-1-bound) announcement as
    // if it came from party 2.
    const msgs = try parties[0].takeOutgoing();
    defer wire.freeOutgoing(allocator, msgs);
    try parties[2].handle(2, msgs[0].bytes);
    try parties[2].handle(1, msgs[0].bytes);
    try testing.expectError(error.InvalidAnnouncement, parties[2].advance());
    try testing.expectEqual(@as(?u32, 2), parties[2].culprit());
}

test "dealer-free keygen: a missing announcement aborts with the absent party named" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_D5A_0004);
    const random = prng.random();
    var local = try quickLocal(allocator, random);
    defer local.deinit(allocator);
    var p = try EcdsaKeygen.init(allocator, .{ .t = 2, .n = 3 }, 1, "s", &local, random);
    defer p.deinit();
    try p.start();
    try testing.expect(!p.allReceived());
    try testing.expectError(error.MissingMessage, p.advance());
    try testing.expectEqual(@as(?u32, 2), p.culprit());
    try testing.expectError(error.Aborted, p.advance());
    try testing.expectError(error.EmptySessionId, EcdsaKeygen.init(allocator, .{ .t = 2, .n = 3 }, 1, "", &local, random));
}

/// `form || session id || u32-BE t || u32-BE n || u32-BE index` (see
/// `EcdsaKeygen.context`); `EcdsaRefresh` binds its proofs the same way.
pub fn keygenContext(buf: *[EcdsaKeygen.ctx_max]u8, session_id: []const u8, t: u32, n: u32, index: u32) []const u8 {
    var sid: []const u8 = session_id;
    var digest: [32]u8 = undefined;
    buf[0] = 0;
    if (sid.len > 64) {
        std.crypto.hash.sha2.Sha256.hash(sid, &digest, .{});
        sid = &digest;
        buf[0] = 1;
    }
    @memcpy(buf[1..][0..sid.len], sid);
    const tail = buf[1 + sid.len ..];
    std.mem.writeInt(u32, tail[0..4], t, .big);
    std.mem.writeInt(u32, tail[4..8], n, .big);
    std.mem.writeInt(u32, tail[8..12], index, .big);
    return buf[0 .. 1 + sid.len + 12];
}

test "keygen context: a raw 32-byte session id never equals a long session id's digest (review F8)" {
    const long_sid = "a session id longer than sixty-four bytes, so the context hashes it down";
    try std.testing.expect(long_sid.len > 64);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(long_sid, &digest, .{});
    var buf_a: [EcdsaKeygen.ctx_max]u8 = undefined;
    var buf_b: [EcdsaKeygen.ctx_max]u8 = undefined;
    const a = keygenContext(&buf_a, long_sid, 2, 3, 1);
    const b = keygenContext(&buf_b, &digest, 2, 3, 1);
    try std.testing.expect(!std.mem.eql(u8, a, b));
    // Same input, same context (every party derives the same one).
    var buf_c: [EcdsaKeygen.ctx_max]u8 = undefined;
    try std.testing.expectEqualSlices(u8, a, keygenContext(&buf_c, long_sid, 2, 3, 1));
}
