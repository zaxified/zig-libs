// SPDX-License-Identifier: MIT

//! participant — one GJKR party as its own state machine: bytes in, bytes out,
//! no shared memory with the other parties, nothing that assumes they live in
//! the same process. The lockstep driver in `protocol.zig` runs all parties
//! inside one function; this is the shape a real deployment needs.
//!
//! **Sans-I/O.** A `Participant` never touches a socket or a clock. The caller
//! (1) feeds every frame that arrives with the authenticated sender id
//! (`handle`), (2) closes the round when it has everything it waits for or the
//! round's deadline passes (`advance`), and (3) sends what
//! `takeOutgoing` returns. GJKR assumes a synchronous network with reliable
//! broadcast; how the caller provides that (a bulletin board, an echo-broadcast
//! layer, a consensus log) is out of scope, as is encrypting the point-to-point
//! `share` frames and authenticating the sender.
//!
//! **Rounds** (GJKR Fig. 2; the phases are lockstep-synchronous, a frame for a
//! different phase is refused with `WrongRound` and may be redelivered later):
//!
//! ```text
//! start()    -> broadcast pedersen_broadcast, point-to-point share to every peer
//! .shares      collect the peers' broadcasts + shares
//! advance()  -> verify every share against its Pedersen commitment; broadcast a
//!               `complaint` per failure (a peer whose broadcast never came is
//!               treated as absent = disqualified)
//! .complaints  collect complaints
//! advance()  -> a dealer that was complained about broadcasts a `defense`
//!               (opens the disputed share publicly)
//! .defenses    collect defenses
//! advance()  -> QUAL is fixed from complaints + defenses ONLY (core.computeQual);
//!               each QUAL dealer broadcasts its Feldman commitments
//! .feldman     collect Feldman commitments
//! advance()  -> verify every accepted share against them, derive Q and x_j
//! .done        `output()` is this party's `DkgShareOutput`
//! ```
//!
//! The complaint and defense rounds cannot say "everyone spoke" (silence is the
//! honest case), so they end by deadline; `allReceived` reports completeness
//! for the two rounds where it is knowable.
//!
//! **What aborts.** A QUAL dealer whose Feldman commitments are missing or fail
//! the share check makes `advance` return `FeldmanCheckFailed`/`MissingFeldman`
//! with `culprit()` set, and the run is dead — the same hard error the lockstep
//! driver has. GJKR's recovery branch (reconstructing that dealer's polynomial
//! from the honest shares) is not implemented (SPEC Backlog).
//!
//! **Randomness** is caller-supplied and drawn once, in `init`, in the same
//! order as the lockstep driver (`a_0..a_{t-1}`, then `b_0..b_{t-1}`), so the
//! same seed gives the same key material in both. Every secret this struct
//! holds is wiped by `deinit`.

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
pub const MessageError = wire.MessageError;

const Ne = types.Ne;
const Ns = types.Ns;

pub const Phase = enum { new, shares, complaints, defenses, feldman, done, aborted };

pub const InitError = error{ InvalidConfig, InvalidIndex } || std.mem.Allocator.Error;
pub const StartError = error{WrongRound} || commit.CommitError || std.mem.Allocator.Error;
pub const AdvanceError = error{
    /// `advance` before `start`.
    WrongRound,
    /// The run is complete.
    Finished,
    /// The run was aborted earlier.
    Aborted,
    /// A QUAL dealer never delivered its Feldman commitments.
    MissingFeldman,
    /// A QUAL dealer's Feldman commitments do not match the share it dealt us.
    FeldmanCheckFailed,
    /// Internal invariant broken (a QUAL dealer with no accepted share).
    Inconsistent,
} || core.Error || std.mem.Allocator.Error;

pub const Participant = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    cfg: Config,
    me: u32,
    h: Element,
    phase_: Phase = .new,

    // Own dealing: the two secret polynomials.
    a: []Scalar,
    b: []Scalar,

    // Per-dealer state, indexed by dealer id - 1.
    ped: []?[]Element,
    fel: []?[]Element,
    wire_s: []?Scalar,
    wire_sp: []?Scalar,
    accepted: []?Scalar,
    present: []bool,
    qualified: []bool,

    // Complaints (ours and received) with parallel defense bookkeeping.
    complaints: std.ArrayList(Complaint) = .empty,
    defense_valid: std.ArrayList(bool) = .empty,
    defense_seen: std.ArrayList(bool) = .empty,

    outbox: std.ArrayList(Outgoing) = .empty,
    result: ?DkgShareOutput = null,
    group_commitments: ?[]Element = null,
    culprit_: ?u32 = null,

    /// Party `index` (1-based) of a `cfg` run; draws its two secret polynomials
    /// from `random`.
    pub fn init(allocator: std.mem.Allocator, cfg: Config, index: u32, random: std.Random) InitError!Participant {
        if (!cfg.valid()) return error.InvalidConfig;
        const t: usize = cfg.t;
        const a = try allocator.alloc(Scalar, t);
        defer {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(a));
            allocator.free(a);
        }
        const b = try allocator.alloc(Scalar, t);
        defer {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(b));
            allocator.free(b);
        }
        for (a) |*c| c.* = commit.randomScalar(random);
        for (b) |*c| c.* = commit.randomScalar(random);
        return initWithPolynomials(allocator, cfg, index, a, b);
    }

    /// Deterministic entry point: the caller supplies the coefficients
    /// (`a` = the contributed secret polynomial, `b` = its blinding
    /// polynomial, both of length `cfg.t`). For tests and recorded
    /// transcripts; a deployment uses `init`.
    pub fn initWithPolynomials(
        allocator: std.mem.Allocator,
        cfg: Config,
        index: u32,
        a_in: []const Scalar,
        b_in: []const Scalar,
    ) InitError!Participant {
        if (!cfg.valid()) return error.InvalidConfig;
        if (index < 1 or index > cfg.n) return error.InvalidIndex;
        if (a_in.len != cfg.t or b_in.len != cfg.t) return error.InvalidConfig;
        const n: usize = cfg.n;

        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const aa = arena.allocator();

        const a = try aa.dupe(Scalar, a_in);
        const b = try aa.dupe(Scalar, b_in);
        errdefer {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(a));
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(b));
        }
        const ped = try aa.alloc(?[]Element, n);
        @memset(ped, null);
        const fel = try aa.alloc(?[]Element, n);
        @memset(fel, null);
        const wire_s = try aa.alloc(?Scalar, n);
        @memset(wire_s, null);
        const wire_sp = try aa.alloc(?Scalar, n);
        @memset(wire_sp, null);
        const accepted = try aa.alloc(?Scalar, n);
        @memset(accepted, null);
        const present = try aa.alloc(bool, n);
        @memset(present, false);
        const qualified = try aa.alloc(bool, n);
        @memset(qualified, false);

        return .{
            .allocator = allocator,
            .arena = arena,
            .cfg = cfg,
            .me = index,
            .h = commit.pedersenH(),
            .a = a,
            .b = b,
            .ped = ped,
            .fel = fel,
            .wire_s = wire_s,
            .wire_sp = wire_sp,
            .accepted = accepted,
            .present = present,
            .qualified = qualified,
        };
    }

    /// Wipe every secret and release everything. Frames not yet taken are wiped
    /// and freed too.
    pub fn deinit(self: *Participant) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.a));
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.b));
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.wire_s));
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.wire_sp));
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.accepted));
        if (self.result) |*r| r.deinit();
        self.arena.deinit();
        self.* = undefined;
    }

    // ── observers ────────────────────────────────────────────────────────

    pub fn phase(self: *const Participant) Phase {
        return self.phase_;
    }

    /// This party's protocol id.
    pub fn id(self: *const Participant) u32 {
        return self.me;
    }

    /// The finished key material (a copy; `deinit()` it when done with it), or
    /// null until the run is `.done`.
    pub fn output(self: *const Participant) ?DkgShareOutput {
        return self.result;
    }

    /// The QUAL set as a `qualified[id - 1]` slice, once it is fixed (from the
    /// `.feldman` phase on).
    pub fn qual(self: *const Participant) ?[]const bool {
        return switch (self.phase_) {
            .feldman, .done => self.qualified,
            else => null,
        };
    }

    /// The dealer that made the run abort, if that is known.
    pub fn culprit(self: *const Participant) ?u32 {
        return self.culprit_;
    }

    /// The public Feldman commitments of the joint sharing polynomial,
    /// `F_k = Σ_{i∈QUAL} A_ik` (length `t`, `F_0 = Q`), available when `.done`.
    /// `derivePublicKeyShare`-style evaluation at any id `j` gives `X_j`.
    pub fn publicCommitments(self: *const Participant) ?[]const Element {
        return self.group_commitments;
    }

    /// True when every message this phase waits for has arrived. Only knowable
    /// in `.shares` and `.feldman`; the complaint and defense rounds end by
    /// deadline, so this is always false there.
    pub fn allReceived(self: *const Participant) bool {
        const n: u32 = self.cfg.n;
        switch (self.phase_) {
            .shares => {
                var d: u32 = 1;
                while (d <= n) : (d += 1) {
                    if (d == self.me) continue;
                    if (self.ped[d - 1] == null or self.wire_s[d - 1] == null) return false;
                }
                return true;
            },
            .feldman => {
                var d: u32 = 1;
                while (d <= n) : (d += 1) {
                    if (d == self.me or !self.qualified[d - 1]) continue;
                    if (self.fel[d - 1] == null) return false;
                }
                return true;
            },
            else => return false,
        }
    }

    /// Hand over everything queued to send. The caller frees it with
    /// `wire.freeOutgoing(allocator, msgs)` using the allocator given to `init`.
    pub fn takeOutgoing(self: *Participant) std.mem.Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    // ── driving the protocol ─────────────────────────────────────────────

    /// Round 1: deal. Queues the Pedersen broadcast and one `share` frame per
    /// peer.
    pub fn start(self: *Participant) StartError!void {
        if (self.phase_ != .new) return error.WrongRound;
        const aa = self.arena.allocator();
        const me = self.me;
        const mi: usize = me - 1;

        self.ped[mi] = try commit.pedersenCommitVector(aa, self.a, self.b, self.h);
        self.fel[mi] = try commit.feldmanCommitVector(aa, self.a);
        self.present[mi] = true;
        self.accepted[mi] = commit.evalPoly(self.a, commit.scalarFromIndex(me));

        const pb: types.PedersenBroadcast = .{ .dealer = me, .commitments = self.ped[mi].? };
        const body = try pb.toBytesAlloc(self.allocator);
        defer self.allocator.free(body);
        try self.push(.broadcast, .pedersen_broadcast, body);

        var j: u32 = 1;
        while (j <= self.cfg.n) : (j += 1) {
            if (j == me) continue;
            const x = commit.scalarFromIndex(j);
            const sm: types.ShareMsg = .{
                .dealer = me,
                .receiver = j,
                .s = commit.evalPoly(self.a, x),
                .s_prime = commit.evalPoly(self.b, x),
            };
            var bytes = sm.toBytes();
            defer std.crypto.secureZero(u8, &bytes);
            try self.push(.{ .party = j }, .share, &bytes);
        }
        self.phase_ = .shares;
    }

    /// Feed one frame from the authenticated peer `from`. A refused frame
    /// changes nothing.
    pub fn handle(self: *Participant, from: u32, bytes: []const u8) MessageError!void {
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
            .pedersen_broadcast => {
                try self.expect(.shares);
                return self.onPedersen(from, body);
            },
            .share => {
                try self.expect(.shares);
                return self.onShare(from, body);
            },
            .complaint => {
                try self.expect(.complaints);
                return self.onComplaint(from, body);
            },
            .defense => {
                try self.expect(.defenses);
                return self.onDefense(from, body);
            },
            .feldman_broadcast => {
                try self.expect(.feldman);
                return self.onFeldman(from, body);
            },
            .reshare_broadcast, .reshare_share, .reshare_complaint, .reshare_defense => return error.UnknownKind,
        }
    }

    /// Close the current round (all expected frames are in, or the deadline
    /// passed) and move to the next; queues that round's outgoing frames.
    pub fn advance(self: *Participant) AdvanceError!void {
        switch (self.phase_) {
            .new => return error.WrongRound,
            .shares => return self.advanceShares(),
            .complaints => return self.advanceComplaints(),
            .defenses => return self.advanceDefenses(),
            .feldman => return self.advanceFeldman(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        }
    }

    // ── message handlers ─────────────────────────────────────────────────

    fn expect(self: *const Participant, p: Phase) error{WrongRound}!void {
        if (self.phase_ != p) return error.WrongRound;
    }

    fn push(self: *Participant, to: Target, kind: wire.Kind, body: []const u8) std.mem.Allocator.Error!void {
        try wire.pushFrame(&self.outbox, self.allocator, to, kind, body);
    }

    fn readId(body: []const u8, at: usize) u32 {
        return std.mem.readInt(u32, body[at..][0..4], .big);
    }

    /// Parse a commitment-vector broadcast body (`dealer || t || t points`).
    fn parseCommitments(self: *Participant, from: u32, body: []const u8) MessageError![]Element {
        if (body.len != 8 + @as(usize, self.cfg.t) * Ne) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        const pb = types.PedersenBroadcast.fromBytesAlloc(self.arena.allocator(), body) catch |e| return wire.codecError(e);
        return pb.commitments;
    }

    fn onPedersen(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (self.ped[from - 1] != null) return error.DuplicateMessage;
        self.ped[from - 1] = try self.parseCommitments(from, body);
    }

    fn onShare(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        if (readId(body, 4) != self.me) return error.WrongRecipient;
        if (self.wire_s[from - 1] != null) return error.DuplicateMessage;
        const m = types.ShareMsg.fromBytes(body[0..types.ShareMsg.encoded_length].*) catch return error.Malformed;
        self.wire_s[from - 1] = m.s;
        self.wire_sp[from - 1] = m.s_prime;
    }

    fn onComplaint(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (body.len != Complaint.encoded_length) return error.Malformed;
        const c = Complaint.fromBytes(body[0..Complaint.encoded_length].*);
        if (c.complainant != from) return error.SenderMismatch;
        if (c.accused < 1 or c.accused > self.cfg.n or c.accused == c.complainant) return error.Malformed;
        if (self.findComplaint(c.complainant, c.accused) != null) return error.DuplicateMessage;
        try self.addComplaint(c);
    }

    fn addComplaint(self: *Participant, c: Complaint) std.mem.Allocator.Error!void {
        const aa = self.arena.allocator();
        try self.complaints.append(aa, c);
        try self.defense_valid.append(aa, false);
        try self.defense_seen.append(aa, false);
    }

    fn findComplaint(self: *const Participant, complainant: u32, accused: u32) ?usize {
        for (self.complaints.items, 0..) |c, k| {
            if (c.complainant == complainant and c.accused == accused) return k;
        }
        return null;
    }

    fn onDefense(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 0) != from) return error.SenderMismatch;
        const complainant = readId(body, 4);
        if (complainant < 1 or complainant > self.cfg.n) return error.Malformed;
        const k = self.findComplaint(complainant, from) orelse return error.Unsolicited;
        if (self.defense_seen.items[k]) return error.DuplicateMessage;
        const ped = self.ped[from - 1] orelse return error.Unsolicited;
        const m = types.ShareMsg.fromBytes(body[0..types.ShareMsg.encoded_length].*) catch return error.Malformed;
        self.defense_seen.items[k] = true;
        const ok = core.verifyPedersenShare(ped, complainant, m.s, m.s_prime, self.h);
        self.defense_valid.items[k] = ok;
        // A defense opens the disputed share in public: if it was ours, that
        // opening replaces the bad wire share.
        if (ok and complainant == self.me) self.accepted[from - 1] = m.s;
    }

    fn onFeldman(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (!self.qualified[from - 1]) return error.Unsolicited;
        if (self.fel[from - 1] != null) return error.DuplicateMessage;
        self.fel[from - 1] = try self.parseCommitments(from, body);
    }

    // ── round transitions ────────────────────────────────────────────────

    fn abort(self: *Participant, culprit_id: u32, err: AdvanceError) AdvanceError {
        self.phase_ = .aborted;
        self.culprit_ = culprit_id;
        return err;
    }

    fn advanceShares(self: *Participant) AdvanceError!void {
        var d: u32 = 1;
        while (d <= self.cfg.n) : (d += 1) {
            if (d == self.me) continue;
            const di: usize = d - 1;
            const ped = self.ped[di] orelse {
                self.present[di] = false; // never broadcast: absent = disqualified
                continue;
            };
            self.present[di] = true;
            const ok = if (self.wire_s[di]) |s|
                core.verifyPedersenShare(ped, self.me, s, self.wire_sp[di].?, self.h)
            else
                false;
            if (ok) {
                self.accepted[di] = self.wire_s[di];
            } else {
                const c: Complaint = .{ .complainant = self.me, .accused = d };
                try self.addComplaint(c);
                const bytes = c.toBytes();
                try self.push(.broadcast, .complaint, &bytes);
            }
        }
        self.phase_ = .complaints;
    }

    fn advanceComplaints(self: *Participant) AdvanceError!void {
        for (self.complaints.items, 0..) |c, k| {
            if (c.accused != self.me) continue;
            // Defend by opening the disputed share publicly.
            const x = commit.scalarFromIndex(c.complainant);
            const sm: types.ShareMsg = .{
                .dealer = self.me,
                .receiver = c.complainant,
                .s = commit.evalPoly(self.a, x),
                .s_prime = commit.evalPoly(self.b, x),
            };
            const bytes = sm.toBytes();
            try self.push(.broadcast, .defense, &bytes);
            // Our own broadcast is never delivered back to us.
            self.defense_seen.items[k] = true;
            self.defense_valid.items[k] = true;
        }
        self.phase_ = .defenses;
    }

    fn advanceDefenses(self: *Participant) AdvanceError!void {
        const n: usize = self.cfg.n;
        core.computeQual(self.qualified, self.cfg, self.complaints.items, self.defense_valid.items) catch |e| {
            self.phase_ = .aborted;
            return e;
        };
        var any = false;
        for (0..n) |d| {
            self.qualified[d] = self.qualified[d] and self.present[d];
            any = any or self.qualified[d];
            if (self.qualified[d] and self.accepted[d] == null) return self.abort(@intCast(d + 1), error.Inconsistent);
        }
        if (!any) {
            self.phase_ = .aborted;
            return error.EmptyQual;
        }
        if (self.qualified[self.me - 1]) {
            const pb: types.FeldmanBroadcast = .{ .dealer = self.me, .commitments = self.fel[self.me - 1].? };
            const body = try pb.toBytesAlloc(self.allocator);
            defer self.allocator.free(body);
            try self.push(.broadcast, .feldman_broadcast, body);
        }
        self.phase_ = .feldman;
    }

    fn advanceFeldman(self: *Participant) AdvanceError!void {
        const n: usize = self.cfg.n;
        const aa = self.arena.allocator();
        // Extraction check: every QUAL dealer's accepted share against its
        // Feldman commitments.
        for (0..n) |d| {
            if (!self.qualified[d]) continue;
            const did: u32 = @intCast(d + 1);
            const fel = self.fel[d] orelse return self.abort(did, error.MissingFeldman);
            if (!core.verifyFeldmanShare(fel, self.me, self.accepted[d].?)) {
                return self.abort(did, error.FeldmanCheckFailed);
            }
        }

        const filler = self.fel[self.me - 1].?[0];
        const a0 = try aa.alloc(Element, n);
        const received = try aa.alloc(?Scalar, n);
        for (0..n) |d| {
            a0[d] = if (self.qualified[d]) self.fel[d].?[0] else filler;
            received[d] = if (self.qualified[d]) self.accepted[d] else null;
        }
        const q = try core.deriveGroupPublicKey(self.qualified, a0);
        var x_j = try core.combineKeyShare(self.qualified, received);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x_j));
        const xg = commit.Secp256k1.basePoint.mul(x_j.toBytes(.big), .big) catch return error.IdentityElement;

        // F_k = Σ_{i∈QUAL} A_ik.
        const t: usize = self.cfg.t;
        const fk = try aa.alloc(Element, t);
        for (0..t) |k| {
            var acc: ?commit.Secp256k1 = null;
            for (0..n) |d| {
                if (!self.qualified[d]) continue;
                const p = try self.fel[d].?[k].point();
                acc = if (acc) |cur| cur.add(p) else p;
            }
            fk[k] = try Element.fromPoint(acc.?);
        }
        self.group_commitments = fk;
        self.result = .{
            .index = self.me,
            .secret_share = x_j,
            .group_public_key = q,
            .verifying_share = try Element.fromPoint(xg),
        };
        self.phase_ = .done;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const protocol = @import("protocol.zig");
const checks = @import("checks.zig");
const tn = @import("testnet.zig");
const TestNet = tn.TestNet;
const Action = tn.Action;
const freeOutputs = tn.freeOutputs;

test "per-participant run reproduces the lockstep driver for the same randomness (n in 2,3,5,7)" {
    const allocator = testing.allocator;
    const cases = [_]Config{
        .{ .t = 1, .n = 2 },
        .{ .t = 2, .n = 2 },
        .{ .t = 2, .n = 3 },
        .{ .t = 3, .n = 3 },
        .{ .t = 2, .n = 5 },
        .{ .t = 3, .n = 5 },
        .{ .t = 5, .n = 5 },
        .{ .t = 3, .n = 7 },
        .{ .t = 4, .n = 7 },
    };
    for (cases, 0..) |cfg, ci| {
        const seed: u64 = 0xD16_2000 + ci;
        var prng_a = std.Random.DefaultPrng.init(seed);
        const lock = try protocol.Dkg.run(allocator, cfg, .{}, prng_a.random());
        defer freeOutputs(allocator, lock);

        var prng_b = std.Random.DefaultPrng.init(seed);
        var net = try TestNet.init(allocator, cfg, prng_b.random());
        defer net.deinit();
        try net.run();
        try testing.expectEqual(@as(usize, 0), net.refused);
        const outs = try net.outputs();
        defer freeOutputs(allocator, outs);

        try testing.expectEqual(lock.len, outs.len);
        for (lock, outs) |l, o| try testing.expectEqualSlices(u8, &l.toBytes(), &o.toBytes());
        try testing.expect(checks.allSameQ(outs));
        for (outs) |o| try testing.expect(checks.verifyingShareConsistent(o));
        try testing.expect(try checks.reconstructsToQ(allocator, outs[0..cfg.t]));
        try testing.expect(try checks.reconstructsToQ(allocator, outs[cfg.n - cfg.t ..]));
        for (net.parties) |*p| {
            try testing.expectEqual(Phase.done, p.phase());
            const fk = p.publicCommitments().?;
            try testing.expectEqual(@as(usize, cfg.t), fk.len);
            try testing.expectEqualSlices(u8, &outs[0].group_public_key.toBytes(), &fk[0].toBytes());
            // X_j is publicly derivable from the joint commitments.
            const xj = try commit.evalCommitmentAt(fk, p.id());
            try testing.expectEqualSlices(u8, &xj.toBytes(), &outs[p.id() - 1].verifying_share.toBytes());
        }
    }
}

fn tamperShare1to2(from: u32, to: u32, bytes: []u8) Action {
    if (from == 1 and to == 2 and bytes[0] == @intFromEnum(wire.Kind.share)) bytes[1 + 8 + Ns - 1] ^= 1;
    return .deliver;
}

test "a bad share is complained about and DEFENDED by an honest dealer: same key as a clean run" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    var prng_a = std.Random.DefaultPrng.init(7);
    var clean = try TestNet.init(allocator, cfg, prng_a.random());
    defer clean.deinit();
    try clean.run();
    const c_out = try clean.outputs();
    defer freeOutputs(allocator, c_out);

    var prng_b = std.Random.DefaultPrng.init(7);
    var net = try TestNet.init(allocator, cfg, prng_b.random());
    defer net.deinit();
    net.filter = tamperShare1to2;
    try net.run();
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    for (c_out, outs) |c, o| try testing.expectEqualSlices(u8, &c.toBytes(), &o.toBytes());
    // Everyone (dealer 1 included) stayed in QUAL.
    for (net.parties) |*p| for (p.qual().?) |q| try testing.expect(q);
}

fn tamperShareAndDropDefense(from: u32, to: u32, bytes: []u8) Action {
    if (from == 3 and to == 1 and bytes[0] == @intFromEnum(wire.Kind.share)) bytes[1 + 8 + Ns - 1] ^= 1;
    if (from == 3 and bytes[0] == @intFromEnum(wire.Kind.defense)) return .drop;
    return .deliver;
}

test "a dealer that cheats and stays silent is disqualified; the rest agree on a usable key" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 4 };
    var prng = std.Random.DefaultPrng.init(11);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = tamperShareAndDropDefense;
    try net.run();
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    // Party 3 is the cheat: its own view is not meaningful. The honest parties
    // 1, 2 and 4 all excluded it, and agree on a key that its share never enters.
    const honest = [_]usize{ 0, 1, 3 };
    var hs: [3]DkgShareOutput = undefined;
    for (honest, 0..) |i, k| {
        const q = net.parties[i].qual().?;
        try testing.expect(q[0] and q[1] and !q[2] and q[3]);
        hs[k] = outs[i];
    }
    try testing.expect(checks.allSameQ(&hs));
    try testing.expect(try checks.reconstructsToQ(allocator, hs[0..2]));
    try testing.expect(try checks.reconstructsToQ(allocator, hs[1..3]));
    // Its Feldman broadcast (it believes it qualified) was refused as unsolicited.
    try testing.expect(net.refused > 0);
}

test "a crashed party (never broadcasts) is treated as absent and excluded" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 4 };
    var prng = std.Random.DefaultPrng.init(13);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.crashed = &.{4};
    try net.run();
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    try testing.expectEqual(@as(usize, 3), outs.len);
    for (net.parties[0..3]) |*p| {
        const q = p.qual().?;
        try testing.expect(q[0] and q[1] and q[2] and !q[3]);
    }
    try testing.expect(checks.allSameQ(outs));
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
}

fn tamperFeldman2to1(from: u32, to: u32, bytes: []u8) Action {
    if (from == 2 and to == 1 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) {
        // Replace commitment 1 by commitment 0: a valid point, the wrong one.
        @memcpy(bytes[1 + 8 + Ne ..][0..Ne], bytes[1 + 8 ..][0..Ne]);
    }
    return .deliver;
}

test "a QUAL dealer whose Feldman commitments do not match its share aborts the run, naming it" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    var prng = std.Random.DefaultPrng.init(17);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = tamperFeldman2to1;
    try net.startAll();
    for (0..3) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    try net.deliverAll();
    try testing.expectError(error.FeldmanCheckFailed, net.parties[0].advance());
    try testing.expectEqual(@as(?u32, 2), net.parties[0].culprit());
    try testing.expectEqual(Phase.aborted, net.parties[0].phase());
    try testing.expectError(error.Aborted, net.parties[0].handle(2, &.{@intFromEnum(wire.Kind.complaint)}));
    try testing.expectError(error.Aborted, net.parties[0].advance());
    // The other parties were not lied to and finish.
    try net.parties[1].advance();
    try net.parties[2].advance();
    try testing.expectEqual(Phase.done, net.parties[1].phase());
    try testing.expect(net.parties[0].output() == null);
}

test "a QUAL dealer that never sends its Feldman commitments aborts the run (MissingFeldman)" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    var prng = std.Random.DefaultPrng.init(19);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = struct {
        fn f(from: u32, _: u32, bytes: []u8) Action {
            return if (from == 3 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) .drop else .deliver;
        }
    }.f;
    try net.startAll();
    for (0..3) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    try net.deliverAll();
    try testing.expect(!net.parties[0].allReceived());
    try testing.expectError(error.MissingFeldman, net.parties[0].advance());
    try testing.expectEqual(@as(?u32, 3), net.parties[0].culprit());
}

/// Two parties of a 2-of-3 run, driven by hand to the point where party 1 holds
/// party 2's round-1 frames — the fixture for the refusal tests.
const Pair = struct {
    p1: Participant,
    p2: Participant,
    msgs2: []Outgoing,

    fn init(allocator: std.mem.Allocator) !Pair {
        var prng = std.Random.DefaultPrng.init(23);
        const cfg: Config = .{ .t = 2, .n = 3 };
        var p1 = try Participant.init(allocator, cfg, 1, prng.random());
        errdefer p1.deinit();
        var p2 = try Participant.init(allocator, cfg, 2, prng.random());
        errdefer p2.deinit();
        try p1.start();
        try p2.start();
        const m1 = try p1.takeOutgoing();
        wire.freeOutgoing(allocator, m1);
        // (Taken BEFORE the struct is built: the literal copies `p2` by value.)
        const msgs2 = try p2.takeOutgoing();
        return .{ .p1 = p1, .p2 = p2, .msgs2 = msgs2 };
    }

    fn deinit(self: *Pair, allocator: std.mem.Allocator) void {
        wire.freeOutgoing(allocator, self.msgs2);
        self.p1.deinit();
        self.p2.deinit();
    }

    /// The frame party 2 sent to party 1 of the given kind.
    fn frameOf(self: *const Pair, kind: wire.Kind) []const u8 {
        for (self.msgs2) |m| {
            if (m.bytes[0] != @intFromEnum(kind)) continue;
            switch (m.to) {
                .party => |j| if (j != 1) continue,
                .broadcast => {},
            }
            return m.bytes;
        }
        unreachable;
    }
};

test "refusals: malformed, wrong sender, replay, wrong round, unknown kind, after finish" {
    const allocator = testing.allocator;
    var pair = try Pair.init(allocator);
    defer pair.deinit(allocator);
    const ped = pair.frameOf(.pedersen_broadcast);
    const share = pair.frameOf(.share);
    const p1 = &pair.p1;

    // Structure.
    try testing.expectError(error.Malformed, p1.handle(2, &.{}));
    try testing.expectError(error.UnknownKind, p1.handle(2, &.{ 0, 1, 2 }));
    try testing.expectError(error.UnknownKind, p1.handle(2, &.{ 255, 1, 2 }));
    try testing.expectError(error.UnknownKind, p1.handle(2, &.{@intFromEnum(wire.Kind.reshare_share)}));
    try testing.expectError(error.UnknownSender, p1.handle(0, ped));
    try testing.expectError(error.UnknownSender, p1.handle(4, ped));
    try testing.expectError(error.UnknownSender, p1.handle(1, ped)); // ourselves
    try testing.expectError(error.UnknownSender, p1.handle(std.math.maxInt(u32), ped));
    try testing.expectError(error.SenderMismatch, p1.handle(3, ped)); // frame says dealer 2
    try testing.expectError(error.SenderMismatch, p1.handle(3, share));
    try testing.expectError(error.Malformed, p1.handle(2, ped[0 .. ped.len - 1]));
    try testing.expectError(error.Malformed, p1.handle(2, share[0 .. share.len - 1]));

    // A point that is not on the curve: 0x04 is the uncompressed marker.
    var bad_point = try allocator.dupe(u8, ped);
    defer allocator.free(bad_point);
    bad_point[1 + 8] = 0x04;
    try testing.expectError(error.Malformed, p1.handle(2, bad_point));
    // A scalar >= n: all-ones.
    var bad_scalar = try allocator.dupe(u8, share);
    defer allocator.free(bad_scalar);
    @memset(bad_scalar[1 + 8 ..][0..Ns], 0xff);
    try testing.expectError(error.Malformed, p1.handle(2, bad_scalar));
    // A share addressed to somebody else.
    var wrong_rcpt = try allocator.dupe(u8, share);
    defer allocator.free(wrong_rcpt);
    std.mem.writeInt(u32, wrong_rcpt[1 + 4 ..][0..4], 3, .big);
    try testing.expectError(error.WrongRecipient, p1.handle(2, wrong_rcpt));
    // A commitment count that lies: claims 2^32-1 commitments.
    var lying = try allocator.dupe(u8, ped);
    defer allocator.free(lying);
    std.mem.writeInt(u32, lying[1 + 4 ..][0..4], 0xffff_ffff, .big);
    try testing.expectError(error.Malformed, p1.handle(2, lying));

    // Refused frames changed nothing: the good ones still go in, once.
    try testing.expect(!p1.allReceived());
    try p1.handle(2, ped);
    try p1.handle(2, share);
    try testing.expectError(error.DuplicateMessage, p1.handle(2, ped));
    try testing.expectError(error.DuplicateMessage, p1.handle(2, share));

    // Wrong round: a complaint / defense / Feldman frame while collecting shares.
    const c: Complaint = .{ .complainant = 2, .accused = 3 };
    var cf: [1 + Complaint.encoded_length]u8 = undefined;
    cf[0] = @intFromEnum(wire.Kind.complaint);
    @memcpy(cf[1..], &c.toBytes());
    try testing.expectError(error.WrongRound, p1.handle(2, &cf));
    try testing.expectError(error.WrongRound, p1.handle(2, &.{@intFromEnum(wire.Kind.defense)}));
    try testing.expectError(error.WrongRound, p1.handle(2, &.{@intFromEnum(wire.Kind.feldman_broadcast)}));

    // Move on: now the shares frame is the wrong round.
    try p1.advance(); // party 3 never spoke -> absent, no complaint about 2
    try testing.expectError(error.WrongRound, p1.handle(2, ped));
    // Complaints: bad ids, self-accusation, then a good one, then a replay.
    var bad_c = cf;
    std.mem.writeInt(u32, bad_c[1 + 4 ..][0..4], 9, .big);
    try testing.expectError(error.Malformed, p1.handle(2, &bad_c));
    std.mem.writeInt(u32, bad_c[1 + 4 ..][0..4], 2, .big);
    try testing.expectError(error.Malformed, p1.handle(2, &bad_c));
    try testing.expectError(error.SenderMismatch, p1.handle(3, &cf));
    try p1.handle(2, &cf);
    try testing.expectError(error.DuplicateMessage, p1.handle(2, &cf));
    try testing.expectError(error.Malformed, p1.handle(2, cf[0 .. cf.len - 1]));
    // A defense nobody asked for.
    var df: [1 + types.ShareMsg.encoded_length]u8 = undefined;
    df[0] = @intFromEnum(wire.Kind.defense);
    @memcpy(df[1..], share[1..]);
    try testing.expectError(error.WrongRound, p1.handle(2, &df));
    try p1.advance();
    try testing.expectError(error.Unsolicited, p1.handle(2, &df)); // nobody complained about party 2
    try testing.expectError(error.WrongRound, p1.handle(2, &cf));
}

test "start and advance are ordered" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(29);
    var p = try Participant.init(allocator, .{ .t = 1, .n = 2 }, 1, prng.random());
    defer p.deinit();
    try testing.expectError(error.WrongRound, p.advance());
    try testing.expectError(error.WrongRound, p.handle(2, &.{@intFromEnum(wire.Kind.share)}));
    try testing.expectEqual(Phase.new, p.phase());
    try p.start();
    try testing.expectError(error.WrongRound, p.start());
    try testing.expectEqual(Phase.shares, p.phase());
}

test "finished run: handle and advance refuse; init validates its arguments" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(31);
    const cfg: Config = .{ .t = 2, .n = 3 };
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    try net.run();
    const p = &net.parties[0];
    try testing.expectEqual(Phase.done, p.phase());
    try testing.expectError(error.Finished, p.handle(2, &.{@intFromEnum(wire.Kind.share)}));
    try testing.expectError(error.Finished, p.advance());
    try testing.expectError(error.InvalidConfig, Participant.init(allocator, .{ .t = 4, .n = 3 }, 1, prng.random()));
    try testing.expectError(error.InvalidConfig, Participant.init(allocator, .{ .t = 0, .n = 3 }, 1, prng.random()));
    try testing.expectError(error.InvalidIndex, Participant.init(allocator, cfg, 0, prng.random()));
    try testing.expectError(error.InvalidIndex, Participant.init(allocator, cfg, 4, prng.random()));
}

test "more than t distinct complaints evict a dealer even when every one is defended (GJKR rule b)" {
    // Rule (b) of GJKR Fig. 2, driven through the state machines: three
    // parties (t = 1) all accuse dealer 4 with a bad share each, all defended.
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 1, .n = 4 };
    var prng = std.Random.DefaultPrng.init(37);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = struct {
        fn f(from: u32, to: u32, bytes: []u8) Action {
            if (from == 4 and to <= 3 and bytes[0] == @intFromEnum(wire.Kind.share)) bytes[1 + 8 + Ns - 1] ^= 1;
            return .deliver;
        }
    }.f;
    try net.run();
    for (net.parties) |*p| {
        const q = p.qual().?;
        try testing.expect(q[0] and q[1] and q[2] and !q[3]); // 3 > t = 1 complainers
    }
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    try testing.expect(checks.allSameQ(outs));
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..1]));
}

test "replaying the recorded transcript (secrets revealed) reproduces the oracle's public outputs" {
    const allocator = testing.allocator;
    const parsed = try tn.parseTranscript(allocator);
    defer parsed.deinit();
    const tr = parsed.value;
    const cfg: Config = .{ .t = tr.t, .n = tr.n };

    try tn.expectHex(tr.h, &commit.pedersenH().toBytes());

    const parties = try allocator.alloc(Participant, cfg.n);
    var built: usize = 0;
    defer {
        for (parties[0..built]) |*p| p.deinit();
        allocator.free(parties);
    }
    for (tr.dealers, 0..) |d, i| {
        var a: [8]Scalar = undefined;
        var b: [8]Scalar = undefined;
        for (d.a, 0..) |hx, k| a[k] = try tn.hexScalar(hx);
        for (d.b, 0..) |hx, k| b[k] = try tn.hexScalar(hx);
        parties[i] = try Participant.initWithPolynomials(allocator, cfg, d.id, a[0..cfg.t], b[0..cfg.t]);
        built += 1;
    }
    var net: TestNet = .{ .allocator = allocator, .parties = parties };
    try net.startAll();

    // Round-1 broadcasts on the wire carry the oracle's Pedersen commitments.
    for (parties, tr.dealers) |*p, d| {
        for (p.outbox.items) |m| {
            if (m.bytes[0] == @intFromEnum(wire.Kind.pedersen_broadcast)) {
                for (d.pedersen, 0..) |hx, k| try tn.expectHex(hx, m.bytes[1 + 8 + k * Ne ..][0..Ne]);
            } else {
                // The share frame for party j carries the oracle's (s, s').
                const j = m.to.party;
                try tn.expectHex(d.shares[j - 1][0], m.bytes[1 + 8 ..][0..Ns]);
                try tn.expectHex(d.shares[j - 1][1], m.bytes[1 + 8 + Ns ..][0..Ns]);
            }
        }
    }
    try net.deliverAll();
    try net.advanceAll();
    try net.deliverAll();
    try net.advanceAll();
    try net.deliverAll();
    try net.advanceAll();
    // The Feldman broadcasts carry the oracle's Feldman commitments.
    for (parties, tr.dealers) |*p, d| {
        try testing.expectEqual(@as(usize, 1), p.outbox.items.len);
        for (d.feldman, 0..) |hx, k| try tn.expectHex(hx, p.outbox.items[0].bytes[1 + 8 + k * Ne ..][0..Ne]);
    }
    try net.deliverAll();
    try net.advanceAll();
    try testing.expectEqual(@as(usize, 0), net.refused);

    for (parties, tr.outputs) |*p, o| {
        const out = p.output().?;
        try testing.expectEqual(o.id, out.index);
        try tn.expectHex(o.x, &out.secret_share.toBytes(.big));
        try tn.expectHex(o.X, &out.verifying_share.toBytes());
        try tn.expectHex(tr.group_public_key, &out.group_public_key.toBytes());
    }
}

// ── fuzz: the frame handler never panics, in any round ───────────────────

fn tamperShare2to3(from: u32, to: u32, bytes: []u8) Action {
    if (from == 2 and to == 3 and bytes[0] == @intFromEnum(wire.Kind.share)) bytes[1 + 8 + Ns - 1] ^= 1;
    return .deliver;
}

/// A 3-party 2-of-3 run, party 2's share to party 3 corrupted (so a complaint
/// and a defense exist), brought to phase `steps` (0 = just started, 4 = done).
fn buildFuzzNet(allocator: std.mem.Allocator, steps: usize) !TestNet {
    var prng = std.Random.DefaultPrng.init(0xF033);
    var net = try TestNet.init(allocator, .{ .t = 2, .n = 3 }, prng.random());
    errdefer net.deinit();
    net.filter = tamperShare2to3;
    try net.startAll();
    for (0..steps) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    return net;
}

fn fuzzParticipantHandle(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ `slice` first, ranged draws after: see modules/testkit/src/fuzz.zig.
    const len: usize = smith.slice(&buf);
    const from: u32 = @intCast(smith.value(u64) % 5);
    const steps: usize = @intCast(smith.value(u64) % 5);
    var net = try buildFuzzNet(testing.allocator, steps);
    defer net.deinit();
    net.parties[0].handle(from, buf[0..len]) catch {};
    // Whatever was refused or accepted, the party must still be drivable.
    net.parties[0].advance() catch {};
}

fn fuzzSeed(out: []u8, frame: []const u8, from: u64, steps: u64) []const u8 {
    std.mem.writeInt(u32, out[0..4], @intCast(frame.len), .little);
    @memcpy(out[4..][0..frame.len], frame);
    std.mem.writeInt(u64, out[4 + frame.len ..][0..8], from, .little);
    std.mem.writeInt(u64, out[12 + frame.len ..][0..8], steps, .little);
    return out[0 .. 20 + frame.len];
}

test "fuzz: Participant.handle never panics, in any round" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();
    var seeds: std.ArrayList([]const u8) = .empty;
    // Real frames, captured per round from the same deterministic run.
    for (0..5) |steps| {
        var net = try buildFuzzNet(testing.allocator, steps);
        defer net.deinit();
        for (net.parties[1..]) |*p| for (p.outbox.items) |m| {
            switch (m.to) {
                .party => |j| if (j != 1) continue,
                .broadcast => {},
            }
            const buf = try aa.alloc(u8, 20 + m.bytes.len);
            try seeds.append(aa, fuzzSeed(buf, m.bytes, p.id(), steps));
        };
    }
    try std.testing.fuzz({}, fuzzParticipantHandle, .{ .corpus = seeds.items });
}
