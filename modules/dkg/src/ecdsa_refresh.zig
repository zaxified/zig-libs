// SPDX-License-Identifier: MIT

//! ecdsa_refresh — proactive refresh of a `threshold_ecdsa` key, one party as
//! a sans-I/O state machine: every party ends with a NEW share of the SAME
//! key (`Q` unchanged) and NEW Paillier, ring-Pedersen and message keys, so
//! shares and Paillier secrets stolen before the refresh are worth nothing
//! after it (provided their holders erase them — see `reshare.zig` on what
//! "worth nothing" means). The CGGMP21 key-refresh step, built from this
//! module's pieces:
//!
//! ```text
//! start()    -> broadcast ecdsa_announcement of the NEW LocalAux (as keygen)
//! .announce    collect every peer's announcement
//! advance()  -> verify each, refuse a shared modulus or message key; send
//!               Πfac(N_i) to each peer under ITS new Ñ
//! .factors     collect every peer's Πfac
//! advance()  -> verify each; deal this party's share (`ReshareDealer`: a
//!               fresh polynomial g_i with g_i(0) = x_i, Feldman broadcast,
//!               one share per party) — the same committee, t and n
//! .shares      collect every dealer's broadcast and share
//! advance()  -> check them (`ReshareReceiver`); broadcast complaints
//! .complaints  collect complaints
//! advance()  -> dealers open the shares they are accused over
//! .defenses    collect the openings
//! advance()  -> new x'_j = Σ λ_i g_i(j); assemble the new `KeyShare`
//! .done        `takeKeyShare()`
//! ```
//!
//! Every party is both a dealer (old committee) and a receiver (new
//! committee): its own dealer's frames reach its own receiver inside this
//! struct. All `n` parties must take part in the aux rounds; a dealer the
//! receivers exclude (bad share, `B_0 ≠ X_i`, undefended complaint) does not
//! stop the refresh as long as `t` dealers survive. Proofs are bound to
//! `session_id`, `t`, `n` and the prover's index exactly as in keygen
//! (`ecdsa_keygen.keygenContext`), so a refresh needs a session id no other
//! run used. Transport duties are as in keygen: reliable broadcast,
//! authenticated senders, confidential point-to-point frames.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const reshare = @import("reshare.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const ecdsa_keygen = @import("ecdsa_keygen.zig");

const aux_info = tecdsa.aux_info;
const fac_proof = tecdsa.fac_proof;
const Element = types.Element;
const Outgoing = wire.Outgoing;

pub const Phase = enum { new, announce, factors, shares, complaints, defenses, done, aborted };

pub const InitError = reshare.DealerInitError || reshare.ReceiverInitError || error{ EmptySessionId, InvalidKeyShare };
pub const StartError = error{WrongRound} || tecdsa.aux_proofs.ProveError || aux_info.Announcement.AllocError;
pub const AdvanceError = error{
    WrongRound,
    Finished,
    Aborted,
    /// A peer's announcement or Πfac never came (`culprit`).
    MissingMessage,
    /// A peer's announcement failed `verifyAnnouncement` (`culprit`).
    InvalidAnnouncement,
    /// Two announcements share a modulus or a message key.
    DuplicateModulus,
    /// A peer's Πfac did not verify (`culprit`).
    InvalidFactorProof,
    /// The refreshed share does not belong to the group key it refreshes.
    InvalidKeyShare,
} || reshare.ReceiverAdvanceError || reshare.DealerAdvanceError || reshare.MessageError ||
    fac_proof.ProveError || fac_proof.FacProof.AllocError || aux_info.AssembleError || std.mem.Allocator.Error;

pub const EcdsaRefresh = struct {
    allocator: std.mem.Allocator,
    cfg: types.Config,
    me: u32,
    session_id: []u8,
    /// The NEW aux material (borrowed).
    local: *const aux_info.LocalAux,
    random: std.Random,
    group_public_key: Element,
    /// Owned backing of the reshare configuration.
    dealer_ids: []u32,
    old_xs: []Element,
    dealer: reshare.ReshareDealer,
    receiver: reshare.ReshareReceiver,
    phase_: Phase = .new,

    announcements: []?aux_info.Announcement,
    fac: []?fac_proof.FacProof,
    checked: ?aux_info.AnnouncementSet = null,

    outbox: std.ArrayList(Outgoing) = .empty,
    share: ?tecdsa.KeyShare = null,
    culprit_: ?u32 = null,

    /// Refresh `current` (this party's key share; borrowed for the call, its
    /// secret is copied into the dealer) with the new aux material `local`
    /// (borrowed for the run). `session_id` is copied; `random` must be a
    /// CSPRNG.
    pub fn init(
        allocator: std.mem.Allocator,
        current: tecdsa.KeyShare,
        session_id: []const u8,
        local: *const aux_info.LocalAux,
        random: std.Random,
    ) InitError!EcdsaRefresh {
        if (session_id.len == 0) return error.EmptySessionId;
        const cfg: types.Config = .{ .t = current.t, .n = current.n };
        const old_xs = try allocator.alloc(Element, cfg.n);
        errdefer allocator.free(old_xs);
        for (old_xs, 1..) |*x, j| x.* = (current.public_keys.get(@intCast(j)) orelse return error.InvalidKeyShare).verifying_share;
        const dealer_ids = try allocator.alloc(u32, cfg.n);
        errdefer allocator.free(dealer_ids);
        for (dealer_ids, 1..) |*d, j| d.* = @intCast(j);
        const rc: reshare.ReshareConfig = .{
            .old = cfg,
            .new = cfg,
            .dealers = dealer_ids,
            .group_public_key = current.group_public_key,
            .old_verifying_shares = old_xs,
        };
        var dealer = try reshare.ReshareDealer.init(allocator, .{
            .index = current.index,
            .secret_share = current.secret_share,
            .group_public_key = current.group_public_key,
            .verifying_share = current.verifying_share,
        }, cfg, random);
        errdefer dealer.deinit();
        var receiver = try reshare.ReshareReceiver.init(allocator, rc, current.index);
        errdefer receiver.deinit();
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
            .me = current.index,
            .session_id = sid,
            .local = local,
            .random = random,
            .group_public_key = current.group_public_key,
            .dealer_ids = dealer_ids,
            .old_xs = old_xs,
            .dealer = dealer,
            .receiver = receiver,
            .announcements = anns,
            .fac = fac,
        };
    }

    /// Releases everything, wiping the secrets this struct holds (the
    /// dealer's polynomial, the receiver's shares, an untaken `KeyShare`).
    pub fn deinit(self: *EcdsaRefresh) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        if (self.share) |*s| {
            std.crypto.secureZero(u8, std.mem.asBytes(&s.secret_share));
            std.crypto.secureZero(u8, &s.message_seed);
            s.paillier_secret.deinit();
            self.allocator.free(s.public_keys.entries);
        }
        if (self.checked) |*c| c.deinit(self.allocator);
        self.dealer.deinit();
        self.receiver.deinit();
        self.allocator.free(self.dealer_ids);
        self.allocator.free(self.old_xs);
        self.allocator.free(self.session_id);
        self.allocator.free(self.announcements);
        self.allocator.free(self.fac);
        self.* = undefined;
    }

    pub fn phase(self: *const EcdsaRefresh) Phase {
        return self.phase_;
    }

    /// The party that made the run abort, when that is known.
    pub fn culprit(self: *const EcdsaRefresh) ?u32 {
        return self.culprit_;
    }

    /// The refreshed `KeyShare`, handed over once. The caller frees
    /// `share.public_keys.entries` with the allocator given to `init`, and
    /// erases the old share it replaces.
    pub fn takeKeyShare(self: *EcdsaRefresh) ?tecdsa.KeyShare {
        const s = self.share orelse return null;
        self.share = null;
        return s;
    }

    /// Everything queued to send; free with `wire.freeOutgoing(allocator, msgs)`.
    pub fn takeOutgoing(self: *EcdsaRefresh) std.mem.Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    /// Round 1: broadcast this party's new announcement.
    pub fn start(self: *EcdsaRefresh) StartError!void {
        if (self.phase_ != .new) return error.WrongRound;
        var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
        const ann = try self.local.announce(self.allocator, self.context(&ctx_buf, self.me), self.random);
        const bytes = try ann.toBytesAlloc(self.allocator);
        defer self.allocator.free(bytes);
        try wire.pushFrame(&self.outbox, self.allocator, .broadcast, .ecdsa_announcement, bytes);
        self.announcements[self.me - 1] = ann;
        self.phase_ = .announce;
    }

    /// Feed one frame from the authenticated peer `from`. A frame for a later
    /// round is refused with `WrongRound` (hold it, redeliver after
    /// `advance`); a refused frame changes nothing.
    pub fn handle(self: *EcdsaRefresh, from: u32, bytes: []const u8) reshare.MessageError!void {
        switch (self.phase_) {
            .done => return error.Finished,
            .aborted => return error.Aborted,
            else => {},
        }
        if (bytes.len == 0) return error.Malformed;
        const kind = wire.kindFromByte(bytes[0]) orelse return error.UnknownKind;
        if (from < 1 or from > self.cfg.n or from == self.me) return error.UnknownSender;
        switch (kind) {
            .ecdsa_announcement => {
                if (self.phase_ != .announce) return error.WrongRound;
                if (self.announcements[from - 1] != null) return error.DuplicateMessage;
                self.announcements[from - 1] = aux_info.Announcement.fromBytes(bytes[1..]) catch return error.Malformed;
            },
            .ecdsa_fac_proof => {
                if (self.phase_ != .factors) return error.WrongRound;
                if (self.fac[from - 1] != null) return error.DuplicateMessage;
                self.fac[from - 1] = fac_proof.FacProof.fromBytes(self.local.aux.n_tilde, bytes[1..]) catch return error.Malformed;
            },
            .reshare_broadcast, .reshare_share => {
                if (self.phase_ != .shares) return error.WrongRound;
                try self.receiver.handle(.{ .dealer = from }, bytes);
            },
            .reshare_complaint => {
                if (self.phase_ != .complaints) return error.WrongRound;
                try self.receiver.handle(.{ .receiver = from }, bytes);
                try self.dealer.handle(from, bytes);
            },
            .reshare_defense => {
                if (self.phase_ != .defenses) return error.WrongRound;
                try self.receiver.handle(.{ .dealer = from }, bytes);
            },
            else => return error.UnknownKind,
        }
    }

    /// Close the current round and move on. Any error leaves the party
    /// `.aborted`.
    pub fn advance(self: *EcdsaRefresh) AdvanceError!void {
        const r = switch (self.phase_) {
            .new => return error.WrongRound,
            .announce => self.advanceAnnounce(),
            .factors => self.advanceFactors(),
            .shares => self.advanceShares(),
            .complaints => self.advanceComplaints(),
            .defenses => self.advanceDefenses(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        };
        r catch |e| {
            self.phase_ = .aborted;
            return e;
        };
    }

    // ── rounds ───────────────────────────────────────────────────────────

    fn advanceAnnounce(self: *EcdsaRefresh) AdvanceError!void {
        if (self.missing(.announce)) |j| {
            self.culprit_ = j;
            return error.MissingMessage;
        }
        var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
        const all = try self.allocator.alloc(aux_info.Announcement, self.cfg.n);
        defer self.allocator.free(all);
        for (all, self.announcements) |*d, a| d.* = a.?;
        self.checked = aux_info.AnnouncementSet.init(self.allocator, all, self.me) catch |e| switch (e) {
            error.InvalidParameters => unreachable, // me is 1..=n
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

    fn advanceFactors(self: *EcdsaRefresh) AdvanceError!void {
        if (self.missing(.factors)) |j| {
            self.culprit_ = j;
            return error.MissingMessage;
        }
        var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
        const checked = &self.checked.?;
        for (self.fac, 1..) |f, j| {
            if (j == self.me) continue;
            if (!checked.verifyPeerFactors(@intCast(j), self.context(&ctx_buf, @intCast(j)), f.?)) {
                self.culprit_ = @intCast(j);
                return error.InvalidFactorProof;
            }
        }
        self.dealer.start() catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidKeyShare,
        };
        try self.routeDealer();
        self.phase_ = .shares;
    }

    fn advanceShares(self: *EcdsaRefresh) AdvanceError!void {
        try self.receiver.advance(); // shares -> complaints
        try self.routeReceiver();
        self.phase_ = .complaints;
    }

    fn advanceComplaints(self: *EcdsaRefresh) AdvanceError!void {
        try self.receiver.advance(); // complaints -> defenses
        try self.dealer.advance();
        try self.routeDealer();
        self.phase_ = .defenses;
    }

    fn advanceDefenses(self: *EcdsaRefresh) AdvanceError!void {
        try self.receiver.advance(); // defenses -> done
        const out = self.receiver.output() orelse return error.Inconsistent;
        const share = try aux_info.assembleKeyShare(
            self.allocator,
            self.checked.?.verified().?, // every check passed in the earlier rounds
            out.secret_share,
            self.receiver.publicCommitments().?,
            self.local,
        );
        if (!std.mem.eql(u8, &share.group_public_key.toBytes(), &self.group_public_key.toBytes())) {
            self.allocator.free(share.public_keys.entries);
            return error.InvalidKeyShare;
        }
        self.share = share;
        self.phase_ = .done;
    }

    // ── helpers ──────────────────────────────────────────────────────────

    fn context(self: *const EcdsaRefresh, buf: *[ecdsa_keygen.EcdsaKeygen.ctx_max]u8, index: u32) []const u8 {
        return ecdsa_keygen.keygenContext(buf, self.session_id, self.cfg.t, self.cfg.n, index);
    }

    fn missing(self: *const EcdsaRefresh, which: enum { announce, factors }) ?u32 {
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

    /// This party's dealer frames: to its own receiver (a frame addressed to
    /// this party or broadcast), and out (everything not addressed to this
    /// party alone).
    fn routeDealer(self: *EcdsaRefresh) AdvanceError!void {
        const msgs = try self.dealer.takeOutgoing();
        defer self.allocator.free(msgs);
        var moved: usize = 0;
        errdefer for (msgs[moved..]) |m| m.deinit(self.allocator);
        while (moved < msgs.len) : (moved += 1) {
            const m = msgs[moved];
            const to_me = switch (m.to) {
                .broadcast => true,
                .party => |j| j == self.me,
            };
            // A frame its own receiver refuses (its commitments are not the
            // published share — a bad local key share) excludes this dealer,
            // exactly as every other receiver does; it does not stop the party.
            if (to_me) self.receiver.handle(.{ .dealer = self.me }, m.bytes) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {},
            };
            switch (m.to) {
                .party => |j| if (j == self.me) {
                    m.deinit(self.allocator);
                    continue;
                },
                .broadcast => {},
            }
            try self.outbox.append(self.allocator, m);
        }
    }

    /// This party's receiver frames (complaints, broadcast): to its own
    /// dealer, and out.
    fn routeReceiver(self: *EcdsaRefresh) AdvanceError!void {
        const msgs = try self.receiver.takeOutgoing();
        defer self.allocator.free(msgs);
        var moved: usize = 0;
        errdefer for (msgs[moved..]) |m| m.deinit(self.allocator);
        while (moved < msgs.len) : (moved += 1) {
            const m = msgs[moved];
            try self.dealer.handle(self.me, m.bytes);
            try self.outbox.append(self.allocator, m);
        }
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Test-only `LocalAux` from Blum primes (see `ecdsa_keygen.zig`'s twin).
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
    const h1 = try nt.pow(h2, lambda);
    const p = try allocator.dupe(u8, ring.p());
    errdefer allocator.free(p);
    const q = try allocator.dupe(u8, ring.q());
    var seed: [32]u8 = undefined;
    random.bytes(&seed);
    return aux_info.LocalAux.fromParts(key, .{ .n_tilde = nt, .h1 = h1, .h2 = h2 }, .{ .p = p, .q = q, .lambda = lambda }, seed);
}

/// Lockstep driver over any party type with `start`/`advance`/`handle`/
/// `takeOutgoing`/`phase`; `drop` filters frames (true = drop).
fn runAll(comptime P: type, allocator: std.mem.Allocator, parties: []P, drop: ?*const fn (from: u32, bytes: []const u8) bool) !usize {
    var refused: usize = 0;
    for (parties) |*p| try p.start();
    var rounds: usize = 0;
    while (true) : (rounds += 1) {
        try testing.expect(rounds < 16);
        for (parties, 1..) |*src, from| {
            const msgs = try src.takeOutgoing();
            defer wire.freeOutgoing(allocator, msgs);
            for (msgs) |m| for (parties, 1..) |*dst, to| {
                if (to == from) continue;
                switch (m.to) {
                    .broadcast => {},
                    .party => |j| if (j != to) continue,
                }
                if (drop) |f| if (f(@intCast(from), m.bytes)) continue;
                dst.handle(@intCast(from), m.bytes) catch |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => refused += 1,
                };
            };
        }
        if (std.mem.eql(u8, @tagName(parties[0].phase()), "done")) break;
        for (parties) |*p| try p.advance();
    }
    return refused;
}

fn keygen(allocator: std.mem.Allocator, random: std.Random, locals: []aux_info.LocalAux, sid: []const u8) ![3]tecdsa.KeyShare {
    const cfg: types.Config = .{ .t = 2, .n = 3 };
    var parties: [3]ecdsa_keygen.EcdsaKeygen = undefined;
    var inited: usize = 0;
    defer for (parties[0..inited]) |*p| p.deinit();
    while (inited < 3) : (inited += 1) parties[inited] = try ecdsa_keygen.EcdsaKeygen.init(allocator, cfg, @intCast(inited + 1), sid, &locals[inited], random);
    try testing.expectEqual(@as(usize, 0), try runAll(ecdsa_keygen.EcdsaKeygen, allocator, &parties, null));
    var out: [3]tecdsa.KeyShare = undefined;
    for (&parties, &out) |*p, *s| s.* = p.takeKeyShare().?;
    return out;
}

fn refresh(allocator: std.mem.Allocator, random: std.Random, old: []const tecdsa.KeyShare, locals: []aux_info.LocalAux, sid: []const u8, excluded: ?u32) ![3]tecdsa.KeyShare {
    var parties: [3]EcdsaRefresh = undefined;
    var inited: usize = 0;
    defer for (parties[0..inited]) |*p| p.deinit();
    while (inited < 3) : (inited += 1) parties[inited] = try EcdsaRefresh.init(allocator, old[inited], sid, &locals[inited], random);
    const refused = try runAll(EcdsaRefresh, allocator, &parties, null);
    // Only the excluded dealer's frames are refused (its broadcast, and its
    // shares and anything after, by each of the two other receivers).
    if (excluded == null) try testing.expectEqual(@as(usize, 0), refused) else try testing.expect(refused > 0);
    for (&parties) |*p| {
        // Every receiver used the same dealers: all, or all but `excluded`.
        const used = p.receiver.usedDealers().?;
        try testing.expectEqual(@as(usize, if (excluded == null) 3 else 2), used.len);
        if (excluded) |x| try testing.expect(std.mem.indexOfScalar(u32, used, x) == null);
    }
    var out: [3]tecdsa.KeyShare = undefined;
    for (&parties, &out) |*p, *s| s.* = p.takeKeyShare().?;
    return out;
}

fn freeShares(allocator: std.mem.Allocator, shares: []tecdsa.KeyShare) void {
    for (shares) |*s| {
        s.paillier_secret.deinit();
        allocator.free(s.public_keys.entries);
    }
}

test "refresh 2-of-3: new shares and Paillier keys, the same key; new shares sign, old and new do not mix" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_0EF5_0001);
    const random = prng.random();
    var locals: [6]aux_info.LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 6) : (made += 1) locals[made] = try quickLocal(allocator, random);

    var old = try keygen(allocator, random, locals[0..3], "refresh-test-keygen");
    defer freeShares(allocator, &old);
    var new = try refresh(allocator, random, &old, locals[3..6], "refresh-test-epoch-1", null);
    // A refresh does not need the old Paillier keys any more.
    defer freeShares(allocator, &new);

    for (old, new) |o, n| {
        try testing.expectEqualSlices(u8, &o.group_public_key.toBytes(), &n.group_public_key.toBytes());
        try testing.expect(!o.secret_share.equivalent(n.secret_share));
        try testing.expect(!std.mem.eql(u8, &o.verifying_share.toBytes(), &n.verifying_share.toBytes()));
        try testing.expect(!std.mem.eql(u8, &o.message_seed, &n.message_seed));
        var ob: [tecdsa.paillier_blum_prime_bytes * 2]u8 = undefined;
        var nb: [tecdsa.paillier_blum_prime_bytes * 2]u8 = undefined;
        try o.paillier_secret.nToBytes(&ob);
        try n.paillier_secret.nToBytes(&nb);
        try testing.expect(!std.mem.eql(u8, &ob, &nb));
    }

    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&new[0].group_public_key.toBytes());
    const msg = "refreshed";
    for ([_][2]usize{ .{ 0, 1 }, .{ 1, 2 }, .{ 0, 2 } }) |pair| {
        const sig = try tecdsa.signing.signWithShares(allocator, &.{ new[pair[0]], new[pair[1]] }, msg, random);
        try sig.verify(msg, pk);
    }
    // An old share with a new one: refused or a signature that does not verify.
    if (tecdsa.signing.signWithShares(allocator, &.{ old[0], new[1] }, msg, random)) |sig| {
        try testing.expectError(error.SignatureVerificationFailed, sig.verify(msg, pk));
    } else |_| {}
}

test "refresh 2-of-3: a dealer dealing a share that is not its published one is excluded by everyone; the other two carry the key" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_0EF5_0002);
    const random = prng.random();
    var locals: [6]aux_info.LocalAux = undefined;
    var made: usize = 0;
    defer for (locals[0..made]) |*l| l.deinit(allocator);
    while (made < 6) : (made += 1) locals[made] = try quickLocal(allocator, random);

    var old = try keygen(allocator, random, locals[0..3], "refresh-test-keygen-2");
    defer freeShares(allocator, &old);
    // Dealer 2 deals x_2 + 1 (consistent with itself, not with the X_2 the
    // group published): every receiver, its own included, sees B_0 ≠ X_2.
    var input = old;
    input[1].secret_share = old[1].secret_share.add(tecdsa.Scalar.one);
    input[1].verifying_share = try tecdsa.Element.fromPoint(try tecdsa.Secp256k1.basePoint.mul(input[1].secret_share.toBytes(.big), .big));
    var new = try refresh(allocator, random, &input, locals[3..6], "refresh-test-epoch-2", 2);
    defer freeShares(allocator, &new);
    for (new) |n| try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &n.group_public_key.toBytes());
    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&new[0].group_public_key.toBytes());
    const sig = try tecdsa.signing.signWithShares(allocator, &.{ new[0], new[2] }, "two dealers", random);
    try sig.verify("two dealers", pk);
}
