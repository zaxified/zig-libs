// SPDX-License-Identifier: MIT

//! reshare — proactive refresh and redistribution of a DKG key to a new
//! committee (new size `n'`, new threshold `t'`) WITHOUT changing the group
//! public key `Q` and without ever assembling the secret `x`.
//!
//! **Construction** (Desmedt & Jajodia, "Redistributing Secret Shares to New
//! Access Structures and Its Applications", 1997; made verifiable with Feldman
//! commitments as in Wong, Wang & Wing, "Verifiable Secret Redistribution for
//! Archive Systems", 2002 — the same shape tss-lib's "resharing" and FROST
//! refresh use). The old committee holds a `t`-of-`n` sharing `x_i = F(i)` of
//! `x = F(0)`, with public `X_i = x_i·G` and `Q = x·G`.
//!
//! 1. A set `S` of at least `t` old parties (the *dealers*) each deal THEIR
//!    share: `P_i` picks a random polynomial `g_i` of degree `t'−1` with
//!    `g_i(0) = x_i`, broadcasts Feldman commitments `B_ik = g^{b_ik}`, and
//!    sends every new party `j` the value `g_i(j)`.
//! 2. New party `j` checks `g^{g_i(j)} = Π_k B_ik^{j^k}` and, the point that ties
//!    the new sharing to the OLD key, that `B_i0 = X_i` — the dealt secret really
//!    is the old share the old committee already published. A failure is a
//!    complaint, answered by the dealer opening the share in public (as in GJKR
//!    Fig. 2 step 3); a dealer with an undefended complaint, a wrong `B_i0`, or
//!    no broadcast is excluded.
//! 3. The surviving set `S'` (still at least `t`) fixes the Lagrange
//!    coefficients `λ_i = Π_{k∈S', k≠i} k/(k−i)`, and new party `j` outputs
//!    `x'_j = Σ_{i∈S'} λ_i·g_i(j)`.
//!
//! `x'_j` is a share of `Σ λ_i g_i(0) = Σ λ_i x_i = F(0) = x` on the degree-`t'−1`
//! polynomial `Σ λ_i g_i`, so any `t'` new shares reconstruct the SAME `x`, and
//! `Q` is unchanged. Each new party recomputes it publicly as
//! `Σ λ_i B_i0 = Σ λ_i X_i` and refuses (`GroupKeyMismatch`) if that differs
//! from the `Q` it was configured with. The new joint commitments
//! `F'_k = Σ λ_i B_ik` give every new verifying share `X'_j = Π F'_k^{j^k}`.
//!
//! **What "old shares become useless" means, and what it does not.** The new
//! polynomial is independent of the old one, so an old share mixed with new
//! shares reconstructs nothing (tested). But `t` old shares STILL reconstruct
//! `x` among themselves — nothing can revoke bytes an attacker already holds.
//! The proactive guarantee is therefore: an adversary needs `t` shares of ONE
//! epoch, so shares stolen before a refresh are worth nothing after it,
//! provided the old holders erase them (`DkgShareOutput.deinit`).
//!
//! **Two roles, two id spaces.** `ReshareDealer` (an old party) and
//! `ReshareReceiver` (a new party) are separate state machines; one process
//! that sits in both committees runs both. Dealer ids are the OLD committee's
//! ids, receiver ids the NEW committee's, and they may coincide numerically.
//! In `ReshareReceiver.handle` the `from` argument is an old id for
//! `reshare_broadcast`/`reshare_share`/`reshare_defense` and a new id for
//! `reshare_complaint`. Routing:
//!
//! ```text
//! dealer.start()      broadcast -> every receiver;  party(j) -> receiver j
//! receiver.advance()  complaints: broadcast -> every other receiver AND every dealer
//! dealer.advance()    defenses:   broadcast -> every receiver
//! receiver.advance()  x_j / Q / F'
//! ```
//!
//! Rounds mirror `participant.zig`: shares, complaints, defenses. As there,
//! the caller provides reliable broadcast, sender authentication and
//! confidentiality of the point-to-point frames.
//!
//! **Plain Feldman VSS, not Pedersen.** There is no key bias to prevent here:
//! the dealt secrets are fixed (old shares), not freshly chosen, and `Q` is
//! pinned. So the Pedersen-then-Feldman two-phase of GJKR is not needed.
//!
//! **Caveat.** A dealer answering complaints reveals `g_i(c)` publicly; more
//! than `t'−1` of those would reveal `x_i`. Dealers therefore refuse to defend
//! once `t'` distinct parties complain, and receivers exclude a dealer with
//! `t'` or more complaints (mirroring GJKR rule (b)). A coalition of `t'`
//! malicious new parties can already reconstruct everything, so this loses
//! nothing the model promises.

const std = @import("std");
const commit = @import("commit.zig");
const core = @import("core.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");

pub const Scalar = types.Scalar;
pub const Element = types.Element;
pub const Config = types.Config;
pub const Complaint = types.Complaint;
pub const DkgShareOutput = types.DkgShareOutput;
pub const Outgoing = wire.Outgoing;
pub const Target = wire.Target;

const Ne = types.Ne;
const Ns = types.Ns;
const Allocator = std.mem.Allocator;

/// Largest new threshold `t'` supported (the receiver accumulates `t'`
/// commitment sums on the stack); generous for any real committee.
pub const max_new_threshold = 64;
const max_t = max_new_threshold;

pub const MessageError = wire.MessageError || error{
    /// A dealer's `B_0` is not the old verifying share it must be dealing.
    CommitmentMismatch,
};

/// What every party of a resharing is configured with — all of it public.
pub const ReshareConfig = struct {
    /// The committee being replaced.
    old: Config,
    /// The committee it is replaced by.
    new: Config,
    /// Old party ids that deal: distinct, in `1..old.n`, at least `old.t`.
    dealers: []const u32,
    /// The group public key, which resharing keeps.
    group_public_key: Element,
    /// The old committee's public verifying shares `X_i` (length `old.n`, index
    /// `id - 1`), e.g. `Participant.publicCommitments` evaluated at each id, or
    /// the published `DkgShareOutput.verifying_share`s. Only the dealers'
    /// entries are used; a wrong one makes that dealer's `B_0` check fail, or
    /// `Q` not come out (`GroupKeyMismatch`).
    old_verifying_shares: []const Element,

    pub fn validate(self: ReshareConfig) error{InvalidConfig}!void {
        if (!self.old.valid() or !self.new.valid()) return error.InvalidConfig;
        if (self.new.t > max_new_threshold) return error.InvalidConfig;
        if (self.dealers.len < self.old.t or self.dealers.len > self.old.n) return error.InvalidConfig;
        if (self.old_verifying_shares.len != self.old.n) return error.InvalidConfig;
        for (self.dealers, 0..) |d, i| {
            if (d < 1 or d > self.old.n) return error.InvalidConfig;
            if (std.mem.indexOfScalar(u32, self.dealers[0..i], d) != null) return error.InvalidConfig;
        }
    }
};

// ── the old party ─────────────────────────────────────────────────────────

pub const DealerPhase = enum { new, complaints, done };

pub const DealerInitError = error{ InvalidConfig, InvalidShare } || Allocator.Error;
pub const DealerAdvanceError = error{ WrongRound, Finished } || Allocator.Error;

pub const ReshareDealer = struct {
    allocator: Allocator,
    arena: std.heap.ArenaAllocator,
    new: Config,
    me: u32,
    /// `g_i` coefficients, `g[0] = x_i`. SECRET.
    g: []Scalar,
    complainers: std.ArrayList(u32) = .empty,
    outbox: std.ArrayList(Outgoing) = .empty,
    phase_: DealerPhase = .new,

    /// Old party `old_share.index` reshares its share to the `new` committee;
    /// draws the `new.t − 1` random coefficients from `random`.
    pub fn init(allocator: Allocator, old_share: DkgShareOutput, new: Config, random: std.Random) DealerInitError!ReshareDealer {
        if (!new.valid()) return error.InvalidConfig;
        const coeffs = try allocator.alloc(Scalar, new.t - 1);
        defer {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(coeffs));
            allocator.free(coeffs);
        }
        for (coeffs) |*c| c.* = commit.randomScalar(random);
        return initWithCoefficients(allocator, old_share, new, coeffs);
    }

    /// Deterministic entry point (tests, recorded transcripts): `coeffs` are
    /// `g_i`'s coefficients above the constant term, length `new.t − 1`.
    pub fn initWithCoefficients(allocator: Allocator, old_share: DkgShareOutput, new: Config, coeffs: []const Scalar) DealerInitError!ReshareDealer {
        if (!new.valid() or coeffs.len != new.t - 1 or old_share.index < 1) return error.InvalidConfig;
        // The share must be the one its own verifying share commits to.
        const xg = commit.feldmanEvalShare(old_share.secret_share) catch return error.InvalidShare;
        if (!std.mem.eql(u8, &xg.toBytes(), &old_share.verifying_share.toBytes())) return error.InvalidShare;

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const g = try arena.allocator().alloc(Scalar, new.t);
        g[0] = old_share.secret_share;
        @memcpy(g[1..], coeffs);
        return .{ .allocator = allocator, .arena = arena, .new = new, .me = old_share.index, .g = g };
    }

    pub fn deinit(self: *ReshareDealer) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.g));
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn phase(self: *const ReshareDealer) DealerPhase {
        return self.phase_;
    }

    pub fn id(self: *const ReshareDealer) u32 {
        return self.me;
    }

    pub fn takeOutgoing(self: *ReshareDealer) Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    /// Deal: the Feldman broadcast and one share frame per new party.
    pub fn start(self: *ReshareDealer) (error{WrongRound} || commit.CommitError || Allocator.Error)!void {
        if (self.phase_ != .new) return error.WrongRound;
        const b = try commit.feldmanCommitVector(self.arena.allocator(), self.g);
        const fb: types.FeldmanBroadcast = .{ .dealer = self.me, .commitments = b };
        const body = try fb.toBytesAlloc(self.allocator);
        defer self.allocator.free(body);
        try wire.pushFrame(&self.outbox, self.allocator, .broadcast, .reshare_broadcast, body);
        var j: u32 = 1;
        while (j <= self.new.n) : (j += 1) {
            try self.pushShare(.{ .party = j }, .reshare_share, j);
        }
        self.phase_ = .complaints;
    }

    fn pushShare(self: *ReshareDealer, to: Target, kind: wire.Kind, receiver: u32) Allocator.Error!void {
        const sm: types.ScalarShareMsg = .{
            .dealer = self.me,
            .receiver = receiver,
            .s = commit.evalPoly(self.g, commit.scalarFromIndex(receiver)),
        };
        var bytes = sm.toBytes();
        defer std.crypto.secureZero(u8, &bytes);
        try wire.pushFrame(&self.outbox, self.allocator, to, kind, &bytes);
    }

    /// Feed a complaint frame from new party `from`.
    pub fn handle(self: *ReshareDealer, from: u32, bytes: []const u8) MessageError!void {
        switch (self.phase_) {
            .done => return error.Finished,
            .new => return error.WrongRound,
            .complaints => {},
        }
        if (bytes.len == 0) return error.Malformed;
        const kind = wire.kindFromByte(bytes[0]) orelse return error.UnknownKind;
        if (kind != .reshare_complaint) return error.UnknownKind;
        if (from < 1 or from > self.new.n) return error.UnknownSender;
        if (bytes.len != 1 + Complaint.encoded_length) return error.Malformed;
        const c = Complaint.fromBytes(bytes[1..][0..Complaint.encoded_length].*);
        if (c.complainant != from) return error.SenderMismatch;
        if (c.accused != self.me) return; // about another dealer: not ours to answer
        if (std.mem.indexOfScalar(u32, self.complainers.items, from) != null) return error.DuplicateMessage;
        try self.complainers.append(self.arena.allocator(), from);
    }

    /// Close the complaint round: open, in public, the share of each party that
    /// complained (unless `new.t` or more did — then this dealer is excluded
    /// anyway and must not leak).
    pub fn advance(self: *ReshareDealer) DealerAdvanceError!void {
        switch (self.phase_) {
            .new => return error.WrongRound,
            .done => return error.Finished,
            .complaints => {},
        }
        if (self.complainers.items.len < self.new.t) {
            for (self.complainers.items) |c| try self.pushShare(.broadcast, .reshare_defense, c);
        }
        self.phase_ = .done;
    }
};

// ── the new party ─────────────────────────────────────────────────────────

pub const ReceiverPhase = enum { shares, complaints, defenses, done, aborted };

pub const ReceiverInitError = error{ InvalidConfig, InvalidIndex } || Allocator.Error;
pub const ReceiverAdvanceError = error{
    WrongRound,
    Finished,
    Aborted,
    /// Fewer than `old.t` dealers survived.
    InsufficientDealers,
    /// `Σ λ_i B_i0` is not the configured group public key: the old
    /// verifying shares (or `Q`) the receiver was given are inconsistent.
    GroupKeyMismatch,
    /// The recomputed share does not match its publicly derived verifying share.
    ShareMismatch,
    /// Internal invariant broken.
    Inconsistent,
} || commit.CommitError || Allocator.Error;

pub const ReshareReceiver = struct {
    allocator: Allocator,
    arena: std.heap.ArenaAllocator,
    rc: ReshareConfig,
    me: u32,
    phase_: ReceiverPhase = .shares,

    // Per dealer position (index into rc.dealers).
    bcast: []?[]Element,
    wire_s: []?Scalar,
    accepted: []?Scalar,
    included: []bool,

    complaints: std.ArrayList(Complaint) = .empty,
    defense_valid: std.ArrayList(bool) = .empty,
    defense_seen: std.ArrayList(bool) = .empty,
    outbox: std.ArrayList(Outgoing) = .empty,

    result: ?DkgShareOutput = null,
    commitments_: ?[]Element = null,
    used: ?[]u32 = null,

    /// New party `index` (1-based in the NEW committee).
    pub fn init(allocator: Allocator, rc: ReshareConfig, index: u32) ReceiverInitError!ReshareReceiver {
        try rc.validate();
        if (index < 1 or index > rc.new.n) return error.InvalidIndex;
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const aa = arena.allocator();
        const nd = rc.dealers.len;
        var own = rc;
        own.dealers = try aa.dupe(u32, rc.dealers);
        own.old_verifying_shares = try aa.dupe(Element, rc.old_verifying_shares);
        const bcast = try aa.alloc(?[]Element, nd);
        @memset(bcast, null);
        const wire_s = try aa.alloc(?Scalar, nd);
        @memset(wire_s, null);
        const accepted = try aa.alloc(?Scalar, nd);
        @memset(accepted, null);
        const included = try aa.alloc(bool, nd);
        @memset(included, false);
        return .{
            .allocator = allocator,
            .arena = arena,
            .rc = own,
            .me = index,
            .bcast = bcast,
            .wire_s = wire_s,
            .accepted = accepted,
            .included = included,
        };
    }

    pub fn deinit(self: *ReshareReceiver) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.wire_s));
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.accepted));
        if (self.result) |*r| r.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn phase(self: *const ReshareReceiver) ReceiverPhase {
        return self.phase_;
    }

    pub fn id(self: *const ReshareReceiver) u32 {
        return self.me;
    }

    /// This party's new key material once `.done` (a copy; `deinit()` it).
    pub fn output(self: *const ReshareReceiver) ?DkgShareOutput {
        return self.result;
    }

    /// The new joint Feldman commitments `F'_k = Σ λ_i B_ik` (length `new.t`,
    /// `F'_0 = Q`); evaluating them at a new id gives that party's `X'_j`.
    pub fn publicCommitments(self: *const ReshareReceiver) ?[]const Element {
        return self.commitments_;
    }

    /// The old ids whose dealings were combined (the set `S'`), once `.done`.
    pub fn usedDealers(self: *const ReshareReceiver) ?[]const u32 {
        return self.used;
    }

    /// True when every dealer's broadcast and share have arrived (`.shares`).
    pub fn allReceived(self: *const ReshareReceiver) bool {
        if (self.phase_ != .shares) return false;
        for (self.bcast, self.wire_s) |b, s| if (b == null or s == null) return false;
        return true;
    }

    pub fn takeOutgoing(self: *ReshareReceiver) Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    fn dealerPos(self: *const ReshareReceiver, old_id: u32) ?usize {
        return std.mem.indexOfScalar(u32, self.rc.dealers, old_id);
    }

    fn readId(body: []const u8, at: usize) u32 {
        return std.mem.readInt(u32, body[at..][0..4], .big);
    }

    fn expect(self: *const ReshareReceiver, p: ReceiverPhase) error{WrongRound}!void {
        if (self.phase_ != p) return error.WrongRound;
    }

    /// Feed one frame. `from` is an OLD id for `reshare_broadcast`,
    /// `reshare_share` and `reshare_defense`, a NEW id for `reshare_complaint`.
    pub fn handle(self: *ReshareReceiver, from: u32, bytes: []const u8) MessageError!void {
        switch (self.phase_) {
            .done => return error.Finished,
            .aborted => return error.Aborted,
            else => {},
        }
        if (bytes.len == 0) return error.Malformed;
        const kind = wire.kindFromByte(bytes[0]) orelse return error.UnknownKind;
        const body = bytes[1..];
        switch (kind) {
            .reshare_broadcast => {
                try self.expect(.shares);
                return self.onBroadcast(self.dealerPos(from) orelse return error.UnknownSender, from, body);
            },
            .reshare_share => {
                try self.expect(.shares);
                return self.onShare(self.dealerPos(from) orelse return error.UnknownSender, from, body);
            },
            .reshare_complaint => {
                try self.expect(.complaints);
                if (from < 1 or from > self.rc.new.n or from == self.me) return error.UnknownSender;
                return self.onComplaint(from, body);
            },
            .reshare_defense => {
                try self.expect(.defenses);
                return self.onDefense(self.dealerPos(from) orelse return error.UnknownSender, from, body);
            },
            .pedersen_broadcast, .share, .complaint, .defense, .feldman_broadcast, .feldman_complaint, .reveal => return error.UnknownKind,
        }
    }

    fn onBroadcast(self: *ReshareReceiver, pos: usize, from: u32, body: []const u8) MessageError!void {
        if (self.bcast[pos] != null) return error.DuplicateMessage;
        if (body.len != 8 + @as(usize, self.rc.new.t) * Ne) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        const fb = types.FeldmanBroadcast.fromBytesAlloc(self.arena.allocator(), body) catch |e| return wire.codecError(e);
        // The dealt secret must be the old share the old committee published.
        const expected = self.rc.old_verifying_shares[from - 1].toBytes();
        if (!std.mem.eql(u8, &fb.commitments[0].toBytes(), &expected)) return error.CommitmentMismatch;
        self.bcast[pos] = fb.commitments;
    }

    fn onShare(self: *ReshareReceiver, pos: usize, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ScalarShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        if (readId(body, 4) != self.me) return error.WrongRecipient;
        if (self.wire_s[pos] != null) return error.DuplicateMessage;
        const m = types.ScalarShareMsg.fromBytes(body[0..types.ScalarShareMsg.encoded_length].*) catch return error.Malformed;
        self.wire_s[pos] = m.s;
    }

    fn findComplaint(self: *const ReshareReceiver, complainant: u32, accused: u32) ?usize {
        for (self.complaints.items, 0..) |c, k| {
            if (c.complainant == complainant and c.accused == accused) return k;
        }
        return null;
    }

    fn addComplaint(self: *ReshareReceiver, c: Complaint) Allocator.Error!void {
        const aa = self.arena.allocator();
        try self.complaints.append(aa, c);
        try self.defense_valid.append(aa, false);
        try self.defense_seen.append(aa, false);
    }

    fn onComplaint(self: *ReshareReceiver, from: u32, body: []const u8) MessageError!void {
        if (body.len != Complaint.encoded_length) return error.Malformed;
        const c = Complaint.fromBytes(body[0..Complaint.encoded_length].*);
        if (c.complainant != from) return error.SenderMismatch;
        if (self.dealerPos(c.accused) == null) return error.Malformed;
        if (self.findComplaint(c.complainant, c.accused) != null) return error.DuplicateMessage;
        try self.addComplaint(c);
    }

    fn onDefense(self: *ReshareReceiver, pos: usize, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ScalarShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        const complainant = readId(body, 4);
        if (complainant < 1 or complainant > self.rc.new.n) return error.Malformed;
        const k = self.findComplaint(complainant, from) orelse return error.Unsolicited;
        if (self.defense_seen.items[k]) return error.DuplicateMessage;
        const b = self.bcast[pos] orelse return error.Unsolicited;
        const m = types.ScalarShareMsg.fromBytes(body[0..types.ScalarShareMsg.encoded_length].*) catch return error.Malformed;
        self.defense_seen.items[k] = true;
        const ok = core.verifyFeldmanShare(b, complainant, m.s);
        self.defense_valid.items[k] = ok;
        if (ok and complainant == self.me) self.accepted[pos] = m.s;
    }

    /// Close the current round and move to the next.
    pub fn advance(self: *ReshareReceiver) ReceiverAdvanceError!void {
        switch (self.phase_) {
            .shares => return self.advanceShares(),
            .complaints => self.phase_ = .defenses,
            .defenses => return self.advanceDefenses(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        }
    }

    fn advanceShares(self: *ReshareReceiver) ReceiverAdvanceError!void {
        for (self.rc.dealers, 0..) |d, pos| {
            const b = self.bcast[pos] orelse continue; // never (validly) broadcast: excluded later
            const ok = if (self.wire_s[pos]) |s| core.verifyFeldmanShare(b, self.me, s) else false;
            if (ok) {
                self.accepted[pos] = self.wire_s[pos];
            } else {
                const c: Complaint = .{ .complainant = self.me, .accused = d };
                try self.addComplaint(c);
                const bytes = c.toBytes();
                try wire.pushFrame(&self.outbox, self.allocator, .broadcast, .reshare_complaint, &bytes);
            }
        }
        self.phase_ = .complaints;
    }

    fn abort(self: *ReshareReceiver, err: ReceiverAdvanceError) ReceiverAdvanceError {
        self.phase_ = .aborted;
        return err;
    }

    fn advanceDefenses(self: *ReshareReceiver) ReceiverAdvanceError!void {
        const aa = self.arena.allocator();
        var count: usize = 0;
        for (self.rc.dealers, 0..) |d, pos| {
            self.included[pos] = false;
            if (self.bcast[pos] == null) continue;
            var complainers: u32 = 0;
            var undefended = false;
            for (self.complaints.items, self.defense_valid.items) |c, valid| {
                if (c.accused != d) continue;
                complainers += 1;
                if (!valid) undefended = true;
            }
            if (undefended or complainers >= self.rc.new.t) continue;
            if (self.accepted[pos] == null) return self.abort(error.Inconsistent);
            self.included[pos] = true;
            count += 1;
        }
        if (count < self.rc.old.t) return self.abort(error.InsufficientDealers);

        const ids = try aa.alloc(u32, count);
        var w: usize = 0;
        for (self.rc.dealers, 0..) |d, pos| {
            if (!self.included[pos]) continue;
            ids[w] = d;
            w += 1;
        }
        std.debug.assert(w == count);

        // x'_j = Σ λ_i s_ij and F'_k = Σ λ_i B_ik over the surviving set.
        var x_new = Scalar.zero;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x_new));
        const t: usize = self.rc.new.t;
        const fk = try aa.alloc(Element, t);
        var acc: [max_t]?commit.Secp256k1 = @splat(null);
        for (self.rc.dealers, 0..) |d, pos| {
            if (!self.included[pos]) continue;
            const lam = commit.lagrangeAtZero(ids, d);
            x_new = x_new.add(lam.mul(self.accepted[pos].?));
            for (0..t) |k| {
                const term = try commit.scaleElement(self.bcast[pos].?[k], lam);
                const p = try term.point();
                acc[k] = if (acc[k]) |cur| cur.add(p) else p;
            }
        }
        for (0..t) |k| fk[k] = try Element.fromPoint(acc[k].?);

        // The point of the whole construction: Σ λ_i X_i is the OLD key.
        if (!std.mem.eql(u8, &fk[0].toBytes(), &self.rc.group_public_key.toBytes())) {
            return self.abort(error.GroupKeyMismatch);
        }
        const xg = try commit.feldmanEvalShare(x_new);
        const public = try commit.evalCommitmentAt(fk, self.me);
        if (!std.mem.eql(u8, &xg.toBytes(), &public.toBytes())) return self.abort(error.ShareMismatch);

        self.commitments_ = fk;
        self.used = ids;
        self.result = .{
            .index = self.me,
            .secret_share = x_new,
            .group_public_key = self.rc.group_public_key,
            .verifying_share = public,
        };
        self.phase_ = .done;
    }
};

// ── tests ─────────────────────────────────────────────────────────────────

const testing = std.testing;
const tecdsa = @import("threshold_ecdsa");
const protocol = @import("protocol.zig");
const checks = @import("checks.zig");
const tn = @import("testnet.zig");
const Action = tn.Action;

fn freeOutputs(allocator: Allocator, outs: []DkgShareOutput) void {
    for (outs) |*o| o.deinit();
    allocator.free(outs);
}

/// A whole resharing in memory: dealers and receivers wired per the routing
/// table in the module doc, with an optional tampering filter.
pub const Rig = struct {
    allocator: Allocator,
    dealers: []ReshareDealer,
    receivers: []ReshareReceiver,
    filter: ?tn.Filter = null,
    refused: usize = 0,

    pub fn init(allocator: Allocator, rc: ReshareConfig, old: []const DkgShareOutput, random: std.Random) !Rig {
        const dealers = try allocator.alloc(ReshareDealer, rc.dealers.len);
        var nd: usize = 0;
        errdefer {
            for (dealers[0..nd]) |*d| d.deinit();
            allocator.free(dealers);
        }
        for (rc.dealers) |id| {
            dealers[nd] = try ReshareDealer.init(allocator, old[id - 1], rc.new, random);
            nd += 1;
        }
        const receivers = try allocator.alloc(ReshareReceiver, rc.new.n);
        var nr: usize = 0;
        errdefer {
            for (receivers[0..nr]) |*r| r.deinit();
            allocator.free(receivers);
        }
        for (receivers, 0..) |*r, i| {
            r.* = try ReshareReceiver.init(allocator, rc, @intCast(i + 1));
            nr += 1;
        }
        return .{ .allocator = allocator, .dealers = dealers, .receivers = receivers };
    }

    pub fn deinit(self: *Rig) void {
        for (self.dealers) |*d| d.deinit();
        for (self.receivers) |*r| r.deinit();
        self.allocator.free(self.dealers);
        self.allocator.free(self.receivers);
    }

    fn send(self: *Rig, comptime Rcv: type, r: *Rcv, from: u32, bytes: []const u8) !void {
        const copy = try self.allocator.dupe(u8, bytes);
        defer self.allocator.free(copy);
        if (self.filter) |f| if (f(from, r.id(), copy) == .drop) return;
        r.handle(from, copy) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => self.refused += 1,
        };
    }

    fn dealersToReceivers(self: *Rig) !void {
        for (self.dealers) |*d| {
            const msgs = try d.takeOutgoing();
            defer wire.freeOutgoing(self.allocator, msgs);
            for (msgs) |m| switch (m.to) {
                .broadcast => for (self.receivers) |*r| try self.send(ReshareReceiver, r, d.id(), m.bytes),
                .party => |j| try self.send(ReshareReceiver, &self.receivers[j - 1], d.id(), m.bytes),
            };
        }
    }

    fn receiversToAll(self: *Rig) !void {
        for (self.receivers) |*r| {
            const msgs = try r.takeOutgoing();
            defer wire.freeOutgoing(self.allocator, msgs);
            for (msgs) |m| {
                for (self.receivers) |*q| if (q.id() != r.id()) try self.send(ReshareReceiver, q, r.id(), m.bytes);
                for (self.dealers) |*d| try self.send(ReshareDealer, d, r.id(), m.bytes);
            }
        }
    }

    pub fn run(self: *Rig) !void {
        for (self.dealers) |*d| try d.start();
        try self.dealersToReceivers();
        for (self.receivers) |*r| try r.advance(); // shares -> complaints
        try self.receiversToAll();
        for (self.receivers) |*r| try r.advance(); // complaints -> defenses
        for (self.dealers) |*d| try d.advance();
        try self.dealersToReceivers();
        for (self.receivers) |*r| try r.advance(); // defenses -> done
    }

    pub fn outputs(self: *Rig) ![]DkgShareOutput {
        const out = try self.allocator.alloc(DkgShareOutput, self.receivers.len);
        for (self.receivers, out) |*r, *o| o.* = r.output().?;
        return out;
    }
};

fn oldCommittee(allocator: Allocator, cfg: Config, seed: u64) ![]DkgShareOutput {
    var prng = std.Random.DefaultPrng.init(seed);
    return protocol.Dkg.run(allocator, cfg, .{}, prng.random());
}

fn configFor(old: []const DkgShareOutput, old_cfg: Config, new: Config, dealers: []const u32, xs: []Element) ReshareConfig {
    for (old, xs) |o, *x| x.* = o.verifying_share;
    return .{
        .old = old_cfg,
        .new = new,
        .dealers = dealers,
        .group_public_key = old[0].group_public_key,
        .old_verifying_shares = xs,
    };
}

test "reshare 3-of-3(t=2) to n'=5, t'=3: same key, new shares reconstruct it, mixing old and new fails" {
    const allocator = testing.allocator;
    const old_cfg: Config = .{ .t = 2, .n = 3 };
    const new_cfg: Config = .{ .t = 3, .n = 5 };
    const old = try oldCommittee(allocator, old_cfg, 0xD16_3001);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, old_cfg, new_cfg, &.{ 1, 3 }, &xs);

    var prng = std.Random.DefaultPrng.init(0xD16_3002);
    var rig = try Rig.init(allocator, rc, old, prng.random());
    defer rig.deinit();
    try rig.run();
    try testing.expectEqual(@as(usize, 0), rig.refused);
    const new = try rig.outputs();
    defer allocator.free(new); // the receivers own the secrets and wipe them

    // The group public key is unchanged, everywhere.
    for (new) |o| {
        try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &o.group_public_key.toBytes());
        try testing.expect(checks.verifyingShareConsistent(o));
    }
    // Any t' = 3 of the 5 new shares reconstruct the secret whose public point is Q.
    const idx = [_][3]usize{ .{ 0, 1, 2 }, .{ 0, 2, 4 }, .{ 1, 3, 4 }, .{ 2, 3, 4 }, .{ 0, 1, 4 } };
    for (idx) |s| {
        const sub = [_]DkgShareOutput{ new[s[0]], new[s[1]], new[s[2]] };
        try testing.expect(try checks.reconstructsToQ(allocator, &sub));
    }
    // ... and it is the SAME secret the old committee shared: compare scalars.
    var old_ss = [_]tecdsa.ShamirShare{
        .{ .index = old[0].index, .scalar = old[0].secret_share },
        .{ .index = old[1].index, .scalar = old[1].secret_share },
    };
    var new_ss = [_]tecdsa.ShamirShare{
        .{ .index = new[0].index, .scalar = new[0].secret_share },
        .{ .index = new[3].index, .scalar = new[3].secret_share },
        .{ .index = new[4].index, .scalar = new[4].secret_share },
    };
    const x_old = try tecdsa.reconstructSecret(&old_ss);
    const x_new = try tecdsa.reconstructSecret(&new_ss);
    try testing.expectEqualSlices(u8, &x_old.toBytes(.big), &x_new.toBytes(.big));

    // Below the new threshold nothing reconstructs.
    try testing.expect(!(try checks.reconstructsToQ(allocator, new[0..2])));
    // Old and new shares are different epochs: mixing them reconstructs nothing.
    try testing.expect(!(try checks.reconstructsToQ(allocator, &.{ old[0], new[1], new[2] })));
    try testing.expect(!(try checks.reconstructsToQ(allocator, &.{ old[0], old[1], new[2] })));
    try testing.expect(!(try checks.reconstructsToQ(allocator, &.{ new[0], new[1], old[2] })));
    // (t old shares still reconstruct among themselves: erasure is the caller's job.)
    try testing.expect(try checks.reconstructsToQ(allocator, old[0..2]));

    // The public commitments agree across receivers and give every X'_j.
    for (rig.receivers) |*r| {
        try testing.expectEqualSlices(u32, &.{ 1, 3 }, r.usedDealers().?);
        const fk = r.publicCommitments().?;
        try testing.expectEqual(@as(usize, 3), fk.len);
        try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &fk[0].toBytes());
        for (new) |o| {
            const xj = try commit.evalCommitmentAt(fk, o.index);
            try testing.expectEqualSlices(u8, &xj.toBytes(), &o.verifying_share.toBytes());
        }
    }
}

test "refresh (same committee, all old parties deal): Q unchanged, every share changed" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_3003);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, cfg, cfg, &.{ 1, 2, 3 }, &xs);
    var prng = std.Random.DefaultPrng.init(0xD16_3004);
    var rig = try Rig.init(allocator, rc, old, prng.random());
    defer rig.deinit();
    try rig.run();
    const new = try rig.outputs();
    defer allocator.free(new);
    try testing.expect(checks.allSameQ(new));
    try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &new[0].group_public_key.toBytes());
    for (old, new) |o, n| try testing.expect(!std.mem.eql(u8, &o.secret_share.toBytes(.big), &n.secret_share.toBytes(.big)));
    try testing.expect(try checks.reconstructsToQ(allocator, new[1..3]));
    try testing.expect(!(try checks.reconstructsToQ(allocator, &.{ old[0], new[1] })));
}

fn badShare1to2(from: u32, to: u32, bytes: []u8) Action {
    if (from == 1 and to == 2 and bytes[0] == @intFromEnum(wire.Kind.reshare_share)) bytes[1 + 8 + Ns - 1] ^= 1;
    return .deliver;
}

fn badShare1to2DropDefense(from: u32, to: u32, bytes: []u8) Action {
    if (bytes[0] == @intFromEnum(wire.Kind.reshare_defense) and from == 1) return .drop;
    return badShare1to2(from, to, bytes);
}

test "a dealer's bad share is defended in public and adopted; without a defense the dealer is excluded" {
    const allocator = testing.allocator;
    const old_cfg: Config = .{ .t = 2, .n = 3 };
    const new_cfg: Config = .{ .t = 2, .n = 4 };
    const old = try oldCommittee(allocator, old_cfg, 0xD16_3005);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, old_cfg, new_cfg, &.{ 1, 2, 3 }, &xs);

    // Clean run, for reference.
    var prng_a = std.Random.DefaultPrng.init(0xD16_3006);
    var clean = try Rig.init(allocator, rc, old, prng_a.random());
    defer clean.deinit();
    try clean.run();
    const c_out = try clean.outputs();
    defer allocator.free(c_out);

    // Defended: identical outputs.
    var prng_b = std.Random.DefaultPrng.init(0xD16_3006);
    var defended = try Rig.init(allocator, rc, old, prng_b.random());
    defer defended.deinit();
    defended.filter = badShare1to2;
    try defended.run();
    const d_out = try defended.outputs();
    defer allocator.free(d_out);
    for (c_out, d_out) |c, d| try testing.expectEqualSlices(u8, &c.toBytes(), &d.toBytes());

    // Undefended: dealer 1 is excluded by everybody; 2 and 3 are still >= t.
    var prng_c = std.Random.DefaultPrng.init(0xD16_3006);
    var excluded = try Rig.init(allocator, rc, old, prng_c.random());
    defer excluded.deinit();
    excluded.filter = badShare1to2DropDefense;
    try excluded.run();
    const e_out = try excluded.outputs();
    defer allocator.free(e_out);
    for (excluded.receivers) |*r| try testing.expectEqualSlices(u32, &.{ 2, 3 }, r.usedDealers().?);
    try testing.expect(checks.allSameQ(e_out));
    try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &e_out[0].group_public_key.toBytes());
    try testing.expect(try checks.reconstructsToQ(allocator, e_out[0..2]));
    try testing.expect(try checks.reconstructsToQ(allocator, e_out[2..4]));
}

test "too few honest dealers left: receivers abort with InsufficientDealers" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_3007);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, cfg, .{ .t = 2, .n = 3 }, &.{ 1, 2 }, &xs);
    var prng = std.Random.DefaultPrng.init(0xD16_3008);
    var rig = try Rig.init(allocator, rc, old, prng.random());
    defer rig.deinit();
    rig.filter = badShare1to2DropDefense;
    try testing.expectError(error.InsufficientDealers, rig.run());
    try testing.expectEqual(ReceiverPhase.aborted, rig.receivers[0].phase());
    try testing.expectError(error.Aborted, rig.receivers[0].advance());
}

test "a dealer that deals something other than its published share is refused (B_0 must equal X_i)" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_3009);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, cfg, cfg, &.{ 1, 2, 3 }, &xs);

    // A dealer whose secret is internally inconsistent cannot even start.
    var forged = old[0];
    forged.secret_share = forged.secret_share.add(Scalar.one);
    var prng = std.Random.DefaultPrng.init(0xD16_300A);
    try testing.expectError(error.InvalidShare, ReshareDealer.init(allocator, forged, cfg, prng.random()));

    // One that is self-consistent but not what was published (x_1 + 1 with its
    // own matching X): receivers see B_0 != X_1 and refuse the broadcast.
    forged.verifying_share = try commit.feldmanEvalShare(forged.secret_share);
    var rig = try Rig.init(allocator, rc, old, prng.random());
    defer rig.deinit();
    rig.dealers[0].deinit();
    rig.dealers[0] = try ReshareDealer.init(allocator, forged, cfg, prng.random());
    try rig.run();
    try testing.expect(rig.refused >= 3); // every receiver refused dealer 1's broadcast
    for (rig.receivers) |*r| try testing.expectEqualSlices(u32, &.{ 2, 3 }, r.usedDealers().?);
    const new = try rig.outputs();
    defer allocator.free(new);
    try testing.expect(try checks.reconstructsToQ(allocator, new[0..2]));
}

test "inconsistent old verifying shares: the receiver refuses (GroupKeyMismatch), never a wrong key" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_300B);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    var rc = configFor(old, cfg, cfg, &.{ 1, 2, 3 }, &xs);
    // Claim a different group key than the shares belong to.
    rc.group_public_key = old[0].verifying_share;
    var prng = std.Random.DefaultPrng.init(0xD16_300C);
    var rig = try Rig.init(allocator, rc, old, prng.random());
    defer rig.deinit();
    try testing.expectError(error.GroupKeyMismatch, rig.run());
}

test "config and role validation" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_300D);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const good = configFor(old, cfg, cfg, &.{ 1, 2 }, &xs);
    try good.validate();
    var bad = good;
    bad.dealers = &.{1}; // fewer than old.t
    try testing.expectError(error.InvalidConfig, ReshareReceiver.init(allocator, bad, 1));
    bad.dealers = &.{ 1, 1 };
    try testing.expectError(error.InvalidConfig, bad.validate());
    bad.dealers = &.{ 1, 4 };
    try testing.expectError(error.InvalidConfig, bad.validate());
    bad = good;
    bad.old_verifying_shares = xs[0..2];
    try testing.expectError(error.InvalidConfig, bad.validate());
    bad = good;
    bad.new = .{ .t = 5, .n = 3 };
    try testing.expectError(error.InvalidConfig, bad.validate());
    try testing.expectError(error.InvalidIndex, ReshareReceiver.init(allocator, good, 0));
    try testing.expectError(error.InvalidIndex, ReshareReceiver.init(allocator, good, 4));
    var prng = std.Random.DefaultPrng.init(1);
    try testing.expectError(error.InvalidConfig, ReshareDealer.init(allocator, old[0], .{ .t = 0, .n = 2 }, prng.random()));
}

test "receiver and dealer refuse malformed, misrouted, replayed and out-of-round frames" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const old = try oldCommittee(allocator, cfg, 0xD16_300E);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, cfg, cfg, &.{ 1, 2 }, &xs);
    var prng = std.Random.DefaultPrng.init(0xD16_300F);
    var d1 = try ReshareDealer.init(allocator, old[0], cfg, prng.random());
    defer d1.deinit();
    var r1 = try ReshareReceiver.init(allocator, rc, 1);
    defer r1.deinit();

    try testing.expectError(error.WrongRound, d1.advance());
    try testing.expectError(error.WrongRound, d1.handle(2, &.{}));
    try d1.start();
    try testing.expectError(error.WrongRound, d1.start());
    const msgs = try d1.takeOutgoing();
    defer wire.freeOutgoing(allocator, msgs);
    const bc = msgs[0].bytes;
    const share = msgs[1].bytes; // to party 1
    try testing.expectEqual(Target{ .party = 1 }, msgs[1].to);

    try testing.expectError(error.Malformed, r1.handle(1, &.{}));
    try testing.expectError(error.UnknownKind, r1.handle(1, &.{0}));
    try testing.expectError(error.UnknownKind, r1.handle(1, &.{@intFromEnum(wire.Kind.share)}));
    try testing.expectError(error.UnknownSender, r1.handle(3, bc)); // 3 is not a dealer
    try testing.expectError(error.UnknownSender, r1.handle(0, share));
    try testing.expectError(error.SenderMismatch, r1.handle(2, bc)); // says dealer 1
    try testing.expectError(error.SenderMismatch, r1.handle(2, share));
    try testing.expectError(error.Malformed, r1.handle(1, bc[0 .. bc.len - 1]));
    try testing.expectError(error.Malformed, r1.handle(1, share[0 .. share.len - 1]));
    var bad_pt = try allocator.dupe(u8, bc);
    defer allocator.free(bad_pt);
    bad_pt[1 + 8] = 0x04;
    try testing.expectError(error.Malformed, r1.handle(1, bad_pt));
    var bad_sc = try allocator.dupe(u8, share);
    defer allocator.free(bad_sc);
    @memset(bad_sc[1 + 8 ..][0..Ns], 0xff);
    try testing.expectError(error.Malformed, r1.handle(1, bad_sc));
    var wrong = try allocator.dupe(u8, share);
    defer allocator.free(wrong);
    std.mem.writeInt(u32, wrong[1 + 4 ..][0..4], 2, .big);
    try testing.expectError(error.WrongRecipient, r1.handle(1, wrong));
    // A commitment count that lies.
    var lie = try allocator.dupe(u8, bc);
    defer allocator.free(lie);
    std.mem.writeInt(u32, lie[1 + 4 ..][0..4], 0xffff_ffff, .big);
    try testing.expectError(error.Malformed, r1.handle(1, lie));

    try testing.expect(!r1.allReceived());
    try r1.handle(1, bc);
    try r1.handle(1, share);
    try testing.expectError(error.DuplicateMessage, r1.handle(1, bc));
    try testing.expectError(error.DuplicateMessage, r1.handle(1, share));
    // Wrong round while collecting shares.
    try testing.expectError(error.WrongRound, r1.handle(2, &.{@intFromEnum(wire.Kind.reshare_complaint)}));
    try testing.expectError(error.WrongRound, r1.handle(1, &.{@intFromEnum(wire.Kind.reshare_defense)}));

    // Dealer 2 never came: r1 excludes it later, and complains about nobody.
    try r1.advance();
    try testing.expectError(error.WrongRound, r1.handle(1, bc));
    var cf: [1 + Complaint.encoded_length]u8 = undefined;
    cf[0] = @intFromEnum(wire.Kind.reshare_complaint);
    @memcpy(cf[1..], &(Complaint{ .complainant = 2, .accused = 1 }).toBytes());
    try testing.expectError(error.UnknownSender, r1.handle(1, &cf)); // ourselves
    try testing.expectError(error.UnknownSender, r1.handle(9, &cf));
    try testing.expectError(error.SenderMismatch, r1.handle(3, &cf));
    var bad_acc = cf;
    std.mem.writeInt(u32, bad_acc[1 + 4 ..][0..4], 3, .big); // not a dealer
    try testing.expectError(error.Malformed, r1.handle(2, &bad_acc));
    try r1.handle(2, &cf);
    try testing.expectError(error.DuplicateMessage, r1.handle(2, &cf));
    try r1.advance();
    // A defense for a complaint that exists, from the right dealer, but that
    // dealer's broadcast was accepted above: it verifies and is recorded.
    var df: [1 + types.ScalarShareMsg.encoded_length]u8 = undefined;
    df[0] = @intFromEnum(wire.Kind.reshare_defense);
    const sm: types.ScalarShareMsg = .{ .dealer = 1, .receiver = 2, .s = commit.evalPoly(d1.g, commit.scalarFromIndex(2)) };
    @memcpy(df[1..], &sm.toBytes());
    try testing.expectError(error.SenderMismatch, r1.handle(2, &df)); // the frame names dealer 1
    var df2 = df;
    const sm2: types.ScalarShareMsg = .{ .dealer = 2, .receiver = 1, .s = Scalar.one };
    @memcpy(df2[1..], &sm2.toBytes());
    try testing.expectError(error.Unsolicited, r1.handle(2, &df2)); // nobody complained about dealer 2
    try r1.handle(1, &df);
    try testing.expectError(error.DuplicateMessage, r1.handle(1, &df));
    // Dealer: complaint handling.
    var d2 = try ReshareDealer.init(allocator, old[1], cfg, prng.random());
    defer d2.deinit();
    try d2.start();
    wire.freeOutgoing(allocator, try d2.takeOutgoing());
    try testing.expectError(error.UnknownSender, d2.handle(0, &cf));
    try testing.expectError(error.UnknownSender, d2.handle(4, &cf));
    try testing.expectError(error.UnknownKind, d2.handle(2, bc));
    try testing.expectError(error.Malformed, d2.handle(2, cf[0 .. cf.len - 1]));
    try testing.expectError(error.SenderMismatch, d2.handle(3, &cf));
    var about_2 = cf;
    std.mem.writeInt(u32, about_2[1 + 4 ..][0..4], 2, .big);
    try d2.handle(2, &about_2);
    try testing.expectError(error.DuplicateMessage, d2.handle(2, &about_2));
    try d2.advance();
    const defs = try d2.takeOutgoing();
    defer wire.freeOutgoing(allocator, defs);
    try testing.expectEqual(@as(usize, 1), defs.len);
    try testing.expectEqual(@as(u8, @intFromEnum(wire.Kind.reshare_defense)), defs[0].bytes[0]);
    try testing.expectError(error.Finished, d2.handle(2, &about_2));
    try testing.expectError(error.Finished, d2.advance());
}

// ── recorded transcript (independent oracle) ─────────────────────────────

test "replaying the recorded resharing transcript reproduces the oracle's commitments, shares and new key material" {
    const allocator = testing.allocator;
    const parsed = try tn.parseTranscript(allocator);
    defer parsed.deinit();
    const tr = parsed.value;
    const rs = tr.reshare;
    const old_cfg: Config = .{ .t = tr.t, .n = tr.n };
    const new_cfg: Config = .{ .t = rs.new_t, .n = rs.new_n };

    // The old committee, exactly as the oracle's DKG produced it.
    const old = try allocator.alloc(DkgShareOutput, tr.n);
    defer allocator.free(old);
    const xs = try allocator.alloc(Element, tr.n);
    defer allocator.free(xs);
    const q = try tn.hexElement(tr.group_public_key);
    for (tr.outputs, old, xs) |o, *d, *x| {
        x.* = try tn.hexElement(o.X);
        d.* = .{ .index = o.id, .secret_share = try tn.hexScalar(o.x), .group_public_key = q, .verifying_share = x.* };
    }
    const rc: ReshareConfig = .{
        .old = old_cfg,
        .new = new_cfg,
        .dealers = rs.dealers,
        .group_public_key = q,
        .old_verifying_shares = xs,
    };

    const dealers = try allocator.alloc(ReshareDealer, rs.dealers.len);
    var nd: usize = 0;
    defer {
        for (dealers[0..nd]) |*d| d.deinit();
        allocator.free(dealers);
    }
    for (rs.dealer_polys) |dp| {
        var c: [8]Scalar = undefined;
        for (dp.c, 0..) |hx, k| c[k] = try tn.hexScalar(hx);
        dealers[nd] = try ReshareDealer.initWithCoefficients(allocator, old[dp.id - 1], new_cfg, c[0 .. new_cfg.t - 1]);
        nd += 1;
    }
    const receivers = try allocator.alloc(ReshareReceiver, rs.new_n);
    var nr: usize = 0;
    defer {
        for (receivers[0..nr]) |*r| r.deinit();
        allocator.free(receivers);
    }
    for (receivers, 0..) |*r, i| {
        r.* = try ReshareReceiver.init(allocator, rc, @intCast(i + 1));
        nr += 1;
    }
    var rig: Rig = .{ .allocator = allocator, .dealers = dealers, .receivers = receivers };

    for (dealers) |*d| try d.start();
    for (dealers, rs.dealer_polys) |*d, dp| {
        for (d.outbox.items) |m| {
            if (m.bytes[0] == @intFromEnum(wire.Kind.reshare_broadcast)) {
                for (dp.commitments, 0..) |hx, k| try tn.expectHex(hx, m.bytes[1 + 8 + k * Ne ..][0..Ne]);
            } else {
                try tn.expectHex(dp.shares[m.to.party - 1], m.bytes[1 + 8 ..][0..Ns]);
            }
        }
    }
    try rig.dealersToReceivers();
    for (receivers) |*r| try r.advance();
    try rig.receiversToAll();
    for (receivers) |*r| try r.advance();
    for (dealers) |*d| try d.advance();
    try rig.dealersToReceivers();
    for (receivers) |*r| try r.advance();
    try testing.expectEqual(@as(usize, 0), rig.refused);

    for (receivers, rs.outputs) |*r, o| {
        const out = r.output().?;
        try tn.expectHex(o.x, &out.secret_share.toBytes(.big));
        try tn.expectHex(o.X, &out.verifying_share.toBytes());
        try tn.expectHex(tr.group_public_key, &out.group_public_key.toBytes());
        const fk = r.publicCommitments().?;
        for (rs.new_commitments, fk) |hx, e| try tn.expectHex(hx, &e.toBytes());
    }
    // The oracle's Lagrange coefficients are recomputed by the module too.
    for (rs.dealer_polys) |dp| {
        try tn.expectHex(dp.lambda, &commit.lagrangeAtZero(rs.dealers, dp.id).toBytes(.big));
    }
}

// ── fuzz: the receiver's frame handler never panics ──────────────────────

/// Bring a small resharing (2-of-3 -> 2-of-3, dealers 1 and 2, receiver 1
/// under test) to phase `steps` and hand back the receiver plus the frames it
/// would be sent in that phase. Used both by the harness and the corpus.
const FuzzWorld = struct {
    old: [3]DkgShareOutput,
    xs: [3]Element,
    rig: Rig,

    fn build(allocator: Allocator, steps: usize) !FuzzWorld {
        var w: FuzzWorld = undefined;
        // 2-of-3 sharing f(z) = 5 + 3z, built directly (no DKG run per input).
        const cfg: Config = .{ .t = 2, .n = 3 };
        const f = [_]Scalar{ commit.scalarFromIndex(5), commit.scalarFromIndex(3) };
        const gpk = try commit.feldmanEvalShare(f[0]);
        for (&w.old, &w.xs, 0..) |*o, *x, i| {
            const s = commit.evalPoly(&f, commit.scalarFromIndex(@intCast(i + 1)));
            x.* = try commit.feldmanEvalShare(s);
            o.* = .{ .index = @intCast(i + 1), .secret_share = s, .group_public_key = gpk, .verifying_share = x.* };
        }
        const rc: ReshareConfig = .{
            .old = cfg,
            .new = cfg,
            .dealers = &.{ 1, 2 },
            .group_public_key = gpk,
            .old_verifying_shares = &w.xs,
        };
        var prng = std.Random.DefaultPrng.init(0xF022);
        w.rig = try Rig.init(allocator, rc, &w.old, prng.random());
        errdefer w.rig.deinit();
        // Dealer 1's share to receiver 2 is bad, so a complaint and a defense exist.
        w.rig.filter = badShare1to2;
        for (w.rig.dealers) |*d| try d.start();
        if (steps >= 1) {
            try w.rig.dealersToReceivers();
            for (w.rig.receivers) |*r| try r.advance();
        }
        if (steps >= 2) {
            try w.rig.receiversToAll();
            for (w.rig.receivers) |*r| try r.advance();
            for (w.rig.dealers) |*d| try d.advance();
        }
        if (steps >= 3) {
            try w.rig.dealersToReceivers();
            for (w.rig.receivers) |*r| try r.advance();
        }
        return w;
    }
};

fn fuzzReceiverHandle(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const from: u32 = @intCast(smith.value(u64) % 5);
    const steps: usize = @intCast(smith.value(u64) % 4);
    var w = try FuzzWorld.build(testing.allocator, steps);
    defer w.rig.deinit();
    w.rig.receivers[0].handle(from, buf[0..len]) catch {};
    w.rig.receivers[0].advance() catch {};
}

fn seedFrame(out: []u8, frame: []const u8, from: u64, steps: u64) []const u8 {
    std.mem.writeInt(u32, out[0..4], @intCast(frame.len), .little);
    @memcpy(out[4..][0..frame.len], frame);
    std.mem.writeInt(u64, out[4 + frame.len ..][0..8], from, .little);
    std.mem.writeInt(u64, out[12 + frame.len ..][0..8], steps, .little);
    return out[0 .. 20 + frame.len];
}

test "fuzz: ReshareReceiver.handle never panics, in any round" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var seeds: std.ArrayList([]const u8) = .empty;
    // Real frames captured from the same world, one per (kind, round).
    for (0..4) |steps| {
        var w = try FuzzWorld.build(testing.allocator, steps);
        defer w.rig.deinit();
        const senders_dealers = steps == 0 or steps == 2;
        if (senders_dealers) {
            for (w.rig.dealers) |*d| for (d.outbox.items) |m| {
                switch (m.to) {
                    .party => |j| if (j != 1) continue,
                    .broadcast => {},
                }
                const buf = try aa.alloc(u8, 20 + m.bytes.len);
                try seeds.append(aa, seedFrame(buf, m.bytes, d.id(), steps));
            };
        } else {
            for (w.rig.receivers) |*r| {
                if (r.id() == 1) continue;
                for (r.outbox.items) |m| {
                    const buf = try aa.alloc(u8, 20 + m.bytes.len);
                    try seeds.append(aa, seedFrame(buf, m.bytes, r.id(), steps));
                }
            }
        }
    }
    try std.testing.fuzz({}, fuzzReceiverHandle, .{ .corpus = seeds.items });
}

fn badShare1toBoth(from: u32, to: u32, bytes: []u8) Action {
    if (from == 1 and to <= 2 and bytes[0] == @intFromEnum(wire.Kind.reshare_share)) bytes[1 + 8 + Ns - 1] ^= 1;
    return .deliver;
}

test "t' complaints: the dealer does not defend, and receivers exclude it even if it does" {
    // Both sides of one rule: `t'` public openings would reveal the dealer's
    // share, so at `t'` complaints it refuses, and receivers exclude a dealer
    // with `t'` complaints however they were answered.
    const allocator = testing.allocator;
    const old_cfg: Config = .{ .t = 2, .n = 3 };
    const new_cfg: Config = .{ .t = 2, .n = 4 };
    const old = try oldCommittee(allocator, old_cfg, 0xD16_3011);
    defer freeOutputs(allocator, old);
    var xs: [3]Element = undefined;
    const rc = configFor(old, old_cfg, new_cfg, &.{ 1, 2, 3 }, &xs);

    for ([_]bool{ false, true }) |defend_anyway| {
        var prng = std.Random.DefaultPrng.init(0xD16_3012);
        var rig = try Rig.init(allocator, rc, old, prng.random());
        defer rig.deinit();
        rig.filter = badShare1toBoth; // receivers 1 and 2 complain: t' = 2
        for (rig.dealers) |*d| try d.start();
        try rig.dealersToReceivers();
        for (rig.receivers) |*r| try r.advance();
        try rig.receiversToAll();
        for (rig.receivers) |*r| try r.advance();
        for (rig.dealers) |*d| try d.advance();
        // Dealer 1 queued no defense.
        try testing.expectEqual(@as(usize, 0), rig.dealers[0].outbox.items.len);
        if (defend_anyway) {
            // A dealer that opens both shares regardless (correctly).
            rig.filter = null;
            for (rig.dealers[0].complainers.items) |c| try rig.dealers[0].pushShare(.broadcast, .reshare_defense, c);
        }
        try rig.dealersToReceivers();
        for (rig.receivers) |*r| try r.advance();
        for (rig.receivers) |*r| try testing.expectEqualSlices(u32, &.{ 2, 3 }, r.usedDealers().?);
    }
}
