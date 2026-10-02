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
//! advance()  -> check every accepted share against them; broadcast a
//!               `feldman_complaint` (opening the share) per failure
//! .feldman_complaints  collect Feldman complaints
//! advance()  -> a QUAL dealer with a valid complaint or no Feldman broadcast
//!               is EXPOSED; with none exposed, derive Q and x_j (.done);
//!               else broadcast a `reveal` of our share of each exposed dealer
//! .reveals     collect reveals
//! advance()  -> reconstruct each exposed dealer's polynomial from `t` verified
//!               shares, then derive Q and x_j
//! .done        `output()` is this party's `DkgShareOutput`
//! ```
//!
//! The complaint, defense and Feldman-complaint rounds cannot say "everyone
//! spoke" (silence is the honest case), so they end by deadline;
//! `allReceived` reports completeness for the rounds where it is knowable.
//!
//! **A cheating QUAL dealer cannot stop the run** (GJKR Fig. 2 step 4). A
//! complaint opens the disputed share, so every party checks it itself: it
//! must verify against the dealer's Pedersen commitments and fail its Feldman
//! ones. Given reliable broadcast, every honest party therefore exposes the
//! same dealers, reveals its shares of them, and reconstructs the same
//! polynomials — the ones the dealers committed to before QUAL was fixed. So
//! withholding or bending the Feldman commitments neither splits the honest
//! parties (some done, some aborted) nor lets a rushing dealer veto a `Q` it
//! dislikes. This needs `n >= 2t - 1` (`Config.honestMajority`), which `init`
//! enforces. What still aborts: fewer than `t` verified shares of an exposed
//! dealer (impossible with an honest majority) and internal failures; any
//! error from `advance` leaves the party `.aborted`.
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

pub const Phase = enum { new, shares, complaints, defenses, feldman, feldman_complaints, reveals, done, aborted };

pub const InitError = error{
    InvalidConfig,
    InvalidIndex,
    /// `n < 2t - 1`: see `Config.honestMajority`.
    NoHonestMajority,
} || std.mem.Allocator.Error;
pub const StartError = error{WrongRound} || commit.CommitError || std.mem.Allocator.Error;
pub const AdvanceError = error{
    /// `advance` before `start`.
    WrongRound,
    /// The run is complete.
    Finished,
    /// The run was aborted earlier.
    Aborted,
    /// Fewer than `t` verified shares of an exposed dealer were revealed, so
    /// its polynomial cannot be reconstructed (`culprit()` names it). Cannot
    /// happen while at least `t` parties are honest.
    ReconstructionFailed,
    /// Internal invariant broken (a QUAL dealer with no accepted share, a
    /// reconstruction that misses our own verified share).
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
    /// The blinding half `s'` of each accepted share: a Feldman complaint
    /// and a reveal open the pair, so that the receivers can check it.
    accepted_sp: []?Scalar,
    present: []bool,
    qualified: []bool,

    // GJKR step 4: QUAL dealers whose Feldman commitments failed or never
    // came, the shares revealed of them (`revealed[(d - 1) * n + holder - 1]`),
    // and their reconstructed polynomials (public once reconstructed).
    exposed: []bool,
    revealed: []?Scalar,
    recovered: []?[]Scalar,

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
        if (!cfg.honestMajority()) return error.NoHonestMajority;
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
        if (!cfg.honestMajority()) return error.NoHonestMajority;
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
        const accepted_sp = try aa.alloc(?Scalar, n);
        @memset(accepted_sp, null);
        const present = try aa.alloc(bool, n);
        @memset(present, false);
        const qualified = try aa.alloc(bool, n);
        @memset(qualified, false);
        const exposed = try aa.alloc(bool, n);
        @memset(exposed, false);
        const revealed = try aa.alloc(?Scalar, n * n);
        @memset(revealed, null);
        const recovered = try aa.alloc(?[]Scalar, n);
        @memset(recovered, null);

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
            .accepted_sp = accepted_sp,
            .present = present,
            .qualified = qualified,
            .exposed = exposed,
            .revealed = revealed,
            .recovered = recovered,
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
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.accepted_sp));
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
            .feldman, .feldman_complaints, .reveals, .done => self.qualified,
            else => null,
        };
    }

    /// The QUAL dealers whose polynomial was reconstructed in public, as an
    /// `exposed[id - 1]` slice, once that is decided (from `.reveals` on).
    pub fn exposedDealers(self: *const Participant) ?[]const bool {
        return switch (self.phase_) {
            .reveals, .done => self.exposed,
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

    /// True when every message this phase waits for has arrived. Knowable in
    /// `.shares` and `.feldman`, and in `.reveals`, where it means "`t`
    /// verified shares of every exposed dealer are in"; the complaint, defense
    /// and Feldman-complaint rounds end by deadline, so it is false there.
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
            .reveals => {
                for (0..self.cfg.n) |d| {
                    if (self.exposed[d] and self.revealedCount(d) < self.cfg.t) return false;
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
            var sm_wipe = sm;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sm_wipe));
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
            .feldman_complaint => {
                try self.expect(.feldman_complaints);
                return self.onFeldmanComplaint(from, body);
            },
            .reveal => {
                try self.expect(.reveals);
                return self.onReveal(from, body);
            },
            .reshare_broadcast, .reshare_share, .reshare_complaint, .reshare_defense, .ecdsa_announcement, .ecdsa_fac_proof => return error.UnknownKind,
        }
    }

    /// Close the current round (all expected frames are in, or the deadline
    /// passed) and move to the next; queues that round's outgoing frames.
    /// Any error from a round transition leaves the party `.aborted`: a
    /// half-done transition (say, an allocation failure midway) is never
    /// retried, so it cannot queue a frame twice.
    pub fn advance(self: *Participant) AdvanceError!void {
        const r = switch (self.phase_) {
            .new => return error.WrongRound,
            .shares => self.advanceShares(),
            .complaints => self.advanceComplaints(),
            .defenses => self.advanceDefenses(),
            .feldman => self.advanceFeldman(),
            .feldman_complaints => self.advanceFeldmanComplaints(),
            .reveals => self.advanceReveals(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        };
        r catch |e| {
            self.phase_ = .aborted;
            return e;
        };
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
        var m = types.ShareMsg.fromBytes(body[0..types.ShareMsg.encoded_length].*) catch return error.Malformed;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&m));
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
        if (ok and complainant == self.me) {
            self.accepted[from - 1] = m.s;
            self.accepted_sp[from - 1] = m.s_prime;
        }
    }

    fn onFeldman(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (!self.qualified[from - 1]) return error.Unsolicited;
        if (self.fel[from - 1] != null) return error.DuplicateMessage;
        self.fel[from - 1] = try self.parseCommitments(from, body);
    }

    /// A Feldman complaint opens the complainant's share of the accused
    /// dealer. It is valid when that share verifies against the dealer's
    /// Pedersen commitments (so it is the committed share) and not against
    /// its Feldman ones, or those never came; then the dealer is exposed.
    /// Every party checks this itself, so nobody can expose an honest dealer.
    fn onFeldmanComplaint(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 4) != from) return error.SenderMismatch;
        const accused = readId(body, 0);
        if (accused < 1 or accused > self.cfg.n or accused == from) return error.Malformed;
        if (!self.qualified[accused - 1]) return error.Unsolicited;
        const m = types.ShareMsg.fromBytes(body[0..types.ShareMsg.encoded_length].*) catch return error.Malformed;
        const ped = self.ped[accused - 1] orelse return error.Unsolicited;
        if (!core.verifyPedersenShare(ped, from, m.s, m.s_prime, self.h)) return error.Unverified;
        if (self.fel[accused - 1]) |fel| {
            if (core.verifyFeldmanShare(fel, from, m.s)) return error.Unverified;
        }
        self.exposed[accused - 1] = true;
    }

    /// A reveal: the sender's share of an exposed dealer, kept only if it is
    /// the committed one.
    fn onReveal(self: *Participant, from: u32, body: []const u8) MessageError!void {
        if (body.len != types.ShareMsg.encoded_length) return error.Malformed;
        if (readId(body, 4) != from) return error.SenderMismatch;
        const dealer = readId(body, 0);
        if (dealer < 1 or dealer > self.cfg.n) return error.Malformed;
        if (!self.exposed[dealer - 1]) return error.Unsolicited;
        const slot = &self.revealed[(dealer - 1) * @as(usize, self.cfg.n) + (from - 1)];
        if (slot.* != null) return error.DuplicateMessage;
        const m = types.ShareMsg.fromBytes(body[0..types.ShareMsg.encoded_length].*) catch return error.Malformed;
        if (!core.verifyPedersenShare(self.ped[dealer - 1].?, from, m.s, m.s_prime, self.h)) return error.Unverified;
        slot.* = m.s;
    }

    fn revealedCount(self: *const Participant, d: usize) usize {
        const n: usize = self.cfg.n;
        var k: usize = 0;
        for (self.revealed[d * n ..][0..n]) |r| {
            if (r != null) k += 1;
        }
        return k;
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
                self.accepted_sp[di] = self.wire_sp[di];
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

    /// Extraction check (GJKR step 4(b)): every QUAL dealer's accepted share
    /// against its Feldman commitments. A dealer whose broadcast never came is
    /// exposed outright (reliable broadcast: everybody saw it missing); one
    /// whose commitments fail our share gets a public complaint that opens
    /// the share.
    fn advanceFeldman(self: *Participant) AdvanceError!void {
        for (0..self.cfg.n) |d| {
            if (!self.qualified[d] or d == self.me - 1) continue;
            const fel = self.fel[d] orelse {
                self.exposed[d] = true;
                continue;
            };
            const s = self.accepted[d] orelse return self.abort(@intCast(d + 1), error.Inconsistent);
            if (core.verifyFeldmanShare(fel, self.me, s)) continue;
            self.exposed[d] = true;
            var sm: types.ShareMsg = .{ .dealer = @intCast(d + 1), .receiver = self.me, .s = s, .s_prime = self.accepted_sp[d].? };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sm));
            var bytes = sm.toBytes();
            defer std.crypto.secureZero(u8, &bytes);
            try self.push(.broadcast, .feldman_complaint, &bytes);
        }
        self.phase_ = .feldman_complaints;
    }

    /// GJKR step 4(c), first half: if any dealer is exposed, reveal our
    /// share of it so that everybody can reconstruct its polynomial.
    fn advanceFeldmanComplaints(self: *Participant) AdvanceError!void {
        const n: usize = self.cfg.n;
        var any = false;
        for (0..n) |d| any = any or self.exposed[d];
        if (!any) return self.finish();
        // An honest dealer's commitments are consistent, so no valid
        // complaint can name us; if one did, our own state is broken.
        if (self.exposed[self.me - 1]) return self.abort(self.me, error.Inconsistent);
        for (0..n) |d| {
            if (!self.exposed[d]) continue;
            const s = self.accepted[d].?;
            self.revealed[d * n + (self.me - 1)] = s;
            const sm: types.ShareMsg = .{ .dealer = @intCast(d + 1), .receiver = self.me, .s = s, .s_prime = self.accepted_sp[d].? };
            const bytes = sm.toBytes();
            try self.push(.broadcast, .reveal, &bytes);
        }
        self.phase_ = .reveals;
    }

    /// GJKR step 4(c), second half: each exposed dealer's polynomial from `t`
    /// revealed shares. Every revealed share passed the Pedersen check, so it
    /// lies on the polynomial the dealer committed to before QUAL was fixed
    /// (binding), whichever `t` are used.
    fn advanceReveals(self: *Participant) AdvanceError!void {
        const n: usize = self.cfg.n;
        const t: usize = self.cfg.t;
        const aa = self.arena.allocator();
        for (0..n) |d| {
            if (!self.exposed[d]) continue;
            const xs = try aa.alloc(u32, t);
            const ys = try aa.alloc(Scalar, t);
            var k: usize = 0;
            for (self.revealed[d * n ..][0..n], 0..) |r, holder| {
                if (k == t) break;
                const s = r orelse continue;
                xs[k] = @intCast(holder + 1);
                ys[k] = s;
                k += 1;
            }
            if (k < t) return self.abort(@intCast(d + 1), error.ReconstructionFailed);
            const coeffs = try interpolate(aa, xs, ys);
            if (!commit.evalPoly(coeffs, commit.scalarFromIndex(self.me)).equivalent(self.accepted[d].?)) {
                return self.abort(@intCast(d + 1), error.Inconsistent);
            }
            self.recovered[d] = coeffs;
        }
        return self.finish();
    }

    /// `A_dk` of QUAL dealer `d` as a point, or null for the identity (a
    /// reconstructed coefficient of zero — a cheating dealer may pick one,
    /// and the identity cannot travel as an `Element`).
    fn dealerCommitment(self: *const Participant, d: usize, k: usize) AdvanceError!?commit.Secp256k1 {
        if (self.recovered[d]) |coeffs| {
            if (coeffs[k].isZero()) return null;
            return commit.Secp256k1.basePoint.mul(coeffs[k].toBytes(.big), .big) catch return error.IdentityElement;
        }
        return try self.fel[d].?[k].point();
    }

    /// Q, x_j and `F_k = Σ_{i∈QUAL} A_ik`, over the broadcast commitments
    /// and, for exposed dealers, the reconstructed ones.
    fn finish(self: *Participant) AdvanceError!void {
        const n: usize = self.cfg.n;
        const t: usize = self.cfg.t;
        const aa = self.arena.allocator();

        // `core.deriveGroupPublicKey` sums `A_i0` over a mask; a dealer whose
        // reconstructed constant term is zero contributes the identity, so it
        // leaves the mask (Q is unchanged by it).
        const q_mask = try aa.alloc(bool, n);
        const a0 = try aa.alloc(Element, n);
        var filler: ?Element = null;
        for (0..n) |d| {
            q_mask[d] = false;
            if (!self.qualified[d]) continue;
            const p = try self.dealerCommitment(d, 0) orelse continue;
            a0[d] = try Element.fromPoint(p);
            q_mask[d] = true;
            filler = filler orelse a0[d];
        }
        const fill = filler orelse return error.IdentityElement;
        for (0..n) |d| {
            if (!q_mask[d]) a0[d] = fill;
        }
        const q = try core.deriveGroupPublicKey(q_mask, a0);

        const received = try aa.alloc(?Scalar, n);
        defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(received));
        for (0..n) |d| received[d] = if (self.qualified[d]) self.accepted[d] else null;
        var x_j = try core.combineKeyShare(self.qualified, received);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x_j));
        const xg = commit.Secp256k1.basePoint.mul(x_j.toBytes(.big), .big) catch return error.IdentityElement;

        const fk = try aa.alloc(Element, t);
        for (0..t) |k| {
            var acc: ?commit.Secp256k1 = null;
            for (0..n) |d| {
                if (!self.qualified[d]) continue;
                const p = try self.dealerCommitment(d, k) orelse continue;
                acc = if (acc) |cur| cur.add(p) else p;
            }
            fk[k] = try Element.fromPoint(acc orelse return error.IdentityElement);
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

/// The coefficients of the polynomial of degree `< xs.len` through the
/// points `(xs[i], ys[i])`: Lagrange's formula expanded into coefficient form,
/// `Σ_i y_i · Π_{m≠i} (X − x_m) / (x_i − x_m)`. `xs` must be distinct and
/// non-zero (party ids). Used on PUBLIC values only (the shares of an exposed
/// dealer, already broadcast), so it need not be constant-time.
fn interpolate(allocator: std.mem.Allocator, xs: []const u32, ys: []const Scalar) std.mem.Allocator.Error![]Scalar {
    const t = xs.len;
    const out = try allocator.alloc(Scalar, t);
    @memset(out, Scalar.zero);
    const basis = try allocator.alloc(Scalar, t);
    defer allocator.free(basis);
    for (0..t) |i| {
        // basis = Π_{m≠i} (X − x_m), one factor at a time.
        @memset(basis, Scalar.zero);
        basis[0] = Scalar.one;
        var deg: usize = 0;
        var den = Scalar.one;
        const xi = commit.scalarFromIndex(xs[i]);
        for (0..t) |m| {
            if (m == i) continue;
            const xm = commit.scalarFromIndex(xs[m]);
            var k = deg + 1;
            while (k > 0) : (k -= 1) basis[k] = basis[k - 1].sub(xm.mul(basis[k]));
            basis[0] = Scalar.zero.sub(xm.mul(basis[0]));
            deg += 1;
            den = den.mul(xi.sub(xm));
        }
        const scale = ys[i].mul(den.invert());
        for (0..t) |k| out[k] = out[k].add(basis[k].mul(scale));
    }
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const protocol = @import("protocol.zig");
const checks = @import("checks.zig");
const tn = @import("testnet.zig");
const TestNet = tn.TestNet;
const Action = tn.Action;
const freeOutputs = tn.freeOutputs;

test "per-participant run reproduces the lockstep driver for the same randomness (n in 2..7)" {
    const allocator = testing.allocator;
    const cases = [_]Config{
        .{ .t = 1, .n = 2 },
        .{ .t = 2, .n = 3 },
        .{ .t = 2, .n = 4 },
        .{ .t = 2, .n = 5 },
        .{ .t = 3, .n = 5 },
        .{ .t = 3, .n = 6 },
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

/// Dealer 2's Feldman broadcast with commitment 1 replaced by commitment 0:
/// valid points, the wrong ones, and the SAME bytes for every receiver (the
/// reliable broadcast GJKR assumes; a cheating dealer cannot do better).
fn tamperFeldmanOf2(from: u32, _: u32, bytes: []u8) Action {
    if (from == 2 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) {
        @memcpy(bytes[1 + 8 + Ne ..][0..Ne], bytes[1 + 8 ..][0..Ne]);
    }
    return .deliver;
}

/// Outputs of a clean run for `cfg` and `seed` (caller frees).
fn cleanOutputs(allocator: std.mem.Allocator, cfg: Config, seed: u64) ![]DkgShareOutput {
    var prng = std.Random.DefaultPrng.init(seed);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    try net.run();
    return net.outputs();
}

fn expectSameOutputs(want: []const DkgShareOutput, got: []const DkgShareOutput) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| try testing.expectEqualSlices(u8, &w.toBytes(), &g.toBytes());
}

test "a QUAL dealer whose Feldman commitments are wrong is exposed and reconstructed: same key as a clean run" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const clean = try cleanOutputs(allocator, cfg, 17);
    defer freeOutputs(allocator, clean);

    var prng = std.Random.DefaultPrng.init(17);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = tamperFeldmanOf2;
    try net.run();
    for (net.parties) |*p| try testing.expectEqual(Phase.done, p.phase());
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    // The reconstructed polynomial is the one dealer 2 committed to.
    try expectSameOutputs(clean, outs);
    for ([_]usize{ 0, 2 }) |i| {
        const ex = net.parties[i].exposedDealers().?;
        try testing.expect(!ex[0] and ex[1] and !ex[2]);
    }
    try testing.expect(try checks.reconstructsToQ(allocator, outs[0..2]));
}

test "a QUAL dealer that withholds its Feldman commitments is reconstructed, not a veto" {
    // GJKR's point: a rushing dealer that dislikes the Q it sees coming
    // cannot stop the run by staying silent — before, MissingFeldman aborted
    // it and a restart gave the dealer a fresh draw.
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    const clean = try cleanOutputs(allocator, cfg, 19);
    defer freeOutputs(allocator, clean);

    var prng = std.Random.DefaultPrng.init(19);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = struct {
        fn f(from: u32, _: u32, bytes: []u8) Action {
            return if (from == 3 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) .drop else .deliver;
        }
    }.f;
    try net.startAll();
    for (0..5) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    // Parties 1 and 2 exposed the silent dealer and reveal; dealer 3 itself
    // saw nothing missing and is done.
    try testing.expectEqual(Phase.reveals, net.parties[0].phase());
    try testing.expectEqual(Phase.done, net.parties[2].phase());
    try net.finish();
    for (net.parties) |*p| try testing.expectEqual(Phase.done, p.phase());
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    try expectSameOutputs(clean, outs);
}

fn dropFeldmanOf3(from: u32, _: u32, bytes: []u8) Action {
    return if (from == 3 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) .drop else .deliver;
}

test "reveals that do not verify, or come twice, are refused; too few verified shares abort the party" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    var prng = std.Random.DefaultPrng.init(53);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = dropFeldmanOf3;
    try net.startAll();
    for (0..5) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    const p1 = &net.parties[0];
    const p2 = &net.parties[1];
    try testing.expectEqual(Phase.reveals, p1.phase());
    try testing.expectEqual(Phase.reveals, p2.phase());
    try testing.expect(!p1.allReceived()); // only its own share of dealer 3 so far

    // Party 2's reveal of dealer 3, first with a share that is not the
    // committed one, then the real one, then again.
    var m: types.ShareMsg = .{ .dealer = 3, .receiver = 2, .s = p2.accepted[2].?.add(Scalar.one), .s_prime = p2.accepted_sp[2].? };
    var fr: [1 + types.ShareMsg.encoded_length]u8 = undefined;
    fr[0] = @intFromEnum(wire.Kind.reveal);
    @memcpy(fr[1..], &m.toBytes());
    try testing.expectError(error.Unverified, p1.handle(2, &fr));
    try testing.expectError(error.SenderMismatch, p1.handle(3, &fr));
    // A reveal of a dealer nobody exposed.
    var other = m;
    other.dealer = 1;
    @memcpy(fr[1..], &other.toBytes());
    try testing.expectError(error.Unsolicited, p1.handle(2, &fr));
    m.s = p2.accepted[2].?;
    @memcpy(fr[1..], &m.toBytes());
    try p1.handle(2, &fr);
    try testing.expectError(error.DuplicateMessage, p1.handle(2, &fr));
    try testing.expect(p1.allReceived());
    try p1.advance();
    try testing.expectEqual(Phase.done, p1.phase());

    // Party 2 never hears party 1's reveal: one share of a 2-of-3 polynomial
    // is not enough. It aborts naming dealer 3, and stays aborted.
    for (p1.outbox.items) |o| o.deinit(allocator);
    p1.outbox.clearRetainingCapacity();
    try testing.expectError(error.ReconstructionFailed, p2.advance());
    try testing.expectEqual(Phase.aborted, p2.phase());
    try testing.expectEqual(@as(?u32, 3), p2.culprit());
    try testing.expectError(error.Aborted, p2.advance());
    try testing.expect(p2.output() == null);
}

test "a reconstructed coefficient of zero is the identity, summed as such" {
    // Only a cheating dealer has one (an honest `start` cannot even commit
    // to it), and it must not turn into an abort it could use as a veto.
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(59);
    var p = try Participant.init(allocator, .{ .t = 2, .n = 3 }, 1, prng.random());
    defer p.deinit();
    var coeffs = [_]Scalar{ commit.scalarFromIndex(5), Scalar.zero };
    p.recovered[1] = &coeffs;
    try testing.expect((try p.dealerCommitment(1, 1)) == null);
    try testing.expect((try p.dealerCommitment(1, 0)) != null);
}

test "a Feldman complaint about a dealer outside QUAL is refused (it would have no share to reveal)" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 4 };
    var prng = std.Random.DefaultPrng.init(61);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    net.filter = tamperShareAndDropDefense; // dealer 3 cheats party 1 and stays silent
    try net.startAll();
    for (0..4) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    const p1 = &net.parties[0];
    const p2 = &net.parties[1];
    try testing.expectEqual(Phase.feldman_complaints, p1.phase());
    try testing.expect(!p1.qual().?[2]);
    // Party 2 holds a share of dealer 3 that verifies against its Pedersen
    // commitments (the cheat was only toward party 1), and dealer 3 never
    // sent Feldman commitments (it was disqualified): as a complaint this
    // would look valid, but dealer 3 is not in QUAL.
    const m: types.ShareMsg = .{ .dealer = 3, .receiver = 2, .s = p2.wire_s[2].?, .s_prime = p2.wire_sp[2].? };
    var fr: [1 + types.ShareMsg.encoded_length]u8 = undefined;
    fr[0] = @intFromEnum(wire.Kind.feldman_complaint);
    @memcpy(fr[1..], &m.toBytes());
    try testing.expectError(error.Unsolicited, p1.handle(2, &fr));
    try net.finish();
    try testing.expectEqual(Phase.done, p1.phase());
}

test "an allocation failure inside advance leaves the party aborted, never half-advanced" {
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{});
    const allocator = failing.allocator();
    var prng = std.Random.DefaultPrng.init(67);
    var p = try Participant.init(allocator, .{ .t = 1, .n = 2 }, 1, prng.random());
    defer p.deinit();
    try p.start();
    wire.freeOutgoing(allocator, try p.takeOutgoing());
    try p.advance(); // party 2 never spoke: absent
    try p.advance(); // no complaints
    try testing.expectEqual(Phase.defenses, p.phase());
    // The next transition queues our Feldman broadcast: make that fail.
    failing.fail_index = failing.alloc_index;
    try testing.expectError(error.OutOfMemory, p.advance());
    try testing.expectEqual(Phase.aborted, p.phase());
    failing.fail_index = std.math.maxInt(usize);
    try testing.expectError(error.Aborted, p.advance());
}

/// For the next test: dealer 5's Feldman vector, bent to agree with its true
/// shares at parties 1 and 2 only (set before the run).
var bent_feldman: [1 + 8 + 3 * Ne]u8 = undefined;

test "a dealer cannot make some honest parties finish with a wrong key while the others abort (review F1)" {
    // n = 5, t = 3. Dealer 5 broadcasts — identically to everyone — Feldman
    // commitments of a polynomial g with g(1) = f(1), g(2) = f(2) but a
    // constant term of its choosing. Parties 1 and 2 see their shares check
    // out; 3 and 4 do not. With a local abort, 1 and 2 finished with a Q
    // nobody can sign for while 3 and 4 aborted, and neither half knew. Now 3
    // and 4 complain in public, everybody exposes dealer 5, and the run ends
    // with the key dealer 5 committed to.
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 3, .n = 5 };
    const clean = try cleanOutputs(allocator, cfg, 41);
    defer freeOutputs(allocator, clean);

    var prng = std.Random.DefaultPrng.init(41);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    {
        const f = net.parties[4].a;
        const xs = [_]u32{ 0, 1, 2 };
        const ys = [_]Scalar{ commit.scalarFromIndex(7777), commit.evalPoly(f, commit.scalarFromIndex(1)), commit.evalPoly(f, commit.scalarFromIndex(2)) };
        const g = try interpolate(allocator, &xs, &ys);
        defer allocator.free(g);
        const vec = try commit.feldmanCommitVector(allocator, g);
        defer allocator.free(vec);
        const body = try (types.FeldmanBroadcast{ .dealer = 5, .commitments = vec }).toBytesAlloc(allocator);
        defer allocator.free(body);
        bent_feldman[0] = @intFromEnum(wire.Kind.feldman_broadcast);
        @memcpy(bent_feldman[1..], body);
    }
    net.filter = struct {
        fn f(from: u32, _: u32, bytes: []u8) Action {
            if (from == 5 and bytes[0] == @intFromEnum(wire.Kind.feldman_broadcast)) @memcpy(bytes, &bent_feldman);
            return .deliver;
        }
    }.f;
    try net.run();
    for (net.parties) |*p| try testing.expectEqual(Phase.done, p.phase());
    const outs = try net.outputs();
    defer freeOutputs(allocator, outs);
    try expectSameOutputs(clean, outs);
    // Parties 1 and 2 were satisfied themselves and exposed dealer 5 on the
    // others' complaints.
    for (net.parties[0..4]) |*p| try testing.expect(p.exposedDealers().?[4]);
}

test "Feldman complaints and reveals that do not verify are refused" {
    const allocator = testing.allocator;
    const cfg: Config = .{ .t = 2, .n = 3 };
    var prng = std.Random.DefaultPrng.init(43);
    var net = try TestNet.init(allocator, cfg, prng.random());
    defer net.deinit();
    try net.startAll();
    for (0..4) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    const p1 = &net.parties[0];
    const p2 = &net.parties[1];
    try testing.expectEqual(Phase.feldman_complaints, p1.phase());

    // Party 2 "complains" about honest dealer 3 with its true share: the
    // Feldman check passes, so the complaint is refused and exposes nobody.
    var m: types.ShareMsg = .{ .dealer = 3, .receiver = 2, .s = p2.accepted[2].?, .s_prime = p2.accepted_sp[2].? };
    var fr: [1 + types.ShareMsg.encoded_length]u8 = undefined;
    fr[0] = @intFromEnum(wire.Kind.feldman_complaint);
    @memcpy(fr[1..], &m.toBytes());
    try testing.expectError(error.Unverified, p1.handle(2, &fr));
    // ... and with a share that is not the committed one: Pedersen fails.
    m.s = m.s.add(Scalar.one);
    @memcpy(fr[1..], &m.toBytes());
    try testing.expectError(error.Unverified, p1.handle(2, &fr));
    // Framing: a complainant that is not the sender, self-accusation, an
    // accused outside the run.
    try testing.expectError(error.SenderMismatch, p1.handle(3, &fr));
    std.mem.writeInt(u32, fr[1..][0..4], 2, .big);
    try testing.expectError(error.Malformed, p1.handle(2, &fr));
    std.mem.writeInt(u32, fr[1..][0..4], 9, .big);
    try testing.expectError(error.Malformed, p1.handle(2, &fr));
    try testing.expectError(error.Malformed, p1.handle(2, fr[0 .. fr.len - 1]));
    // A reveal belongs to the next round.
    fr[0] = @intFromEnum(wire.Kind.reveal);
    try testing.expectError(error.WrongRound, p1.handle(2, &fr));

    // Nobody was exposed: the run finishes without a reveal round.
    try net.deliverAll();
    try net.advanceAll();
    for (net.parties) |*p| try testing.expectEqual(Phase.done, p.phase());
}

test "the DKG refuses n < 2t - 1: without an honest majority one dealer could choose Q" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(47);
    for ([_]Config{ .{ .t = 2, .n = 2 }, .{ .t = 3, .n = 4 }, .{ .t = 5, .n = 5 }, .{ .t = 4, .n = 6 } }) |cfg| {
        try testing.expect(!cfg.honestMajority());
        try testing.expectError(error.NoHonestMajority, Participant.init(allocator, cfg, 1, prng.random()));
        try testing.expectError(error.NoHonestMajority, protocol.Dkg.run(allocator, cfg, .{}, prng.random()));
    }
    for ([_]Config{ .{ .t = 1, .n = 1 }, .{ .t = 2, .n = 3 }, .{ .t = 3, .n = 5 }, .{ .t = 4, .n = 7 } }) |cfg| {
        try testing.expect(cfg.honestMajority());
    }
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
    // The Feldman-complaint round: nothing to complain about.
    for (parties) |*p| try testing.expectEqual(@as(usize, 0), p.outbox.items.len);
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
/// and a defense exist) and its Feldman commitments bent (so it is exposed and
/// rebuilt), brought to phase `steps` (0 = just started, 5 = party 1 in
/// `.reveals`, 6 = done).
fn buildFuzzNet(allocator: std.mem.Allocator, steps: usize) !TestNet {
    var prng = std.Random.DefaultPrng.init(0xF033);
    var net = try TestNet.init(allocator, .{ .t = 2, .n = 3 }, prng.random());
    errdefer net.deinit();
    // A defended bad share AND bent Feldman commitments from dealer 2, so the
    // world passes through every round, the reveal round included (party 1
    // is in `.reveals` after five steps).
    net.filter = struct {
        fn f(from: u32, to: u32, bytes: []u8) Action {
            _ = tamperShare2to3(from, to, bytes);
            return tamperFeldmanOf2(from, to, bytes);
        }
    }.f;
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
    const steps: usize = @intCast(smith.value(u64) % 7);
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
    for (0..7) |steps| {
        var net = try buildFuzzNet(testing.allocator, steps);
        defer net.deinit();
        // The world really reaches the reveal round and finishes.
        if (steps == 5) try testing.expectEqual(Phase.reveals, net.parties[0].phase());
        if (steps == 6) try testing.expectEqual(Phase.done, net.parties[0].phase());
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
