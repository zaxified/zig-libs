// SPDX-License-Identifier: MIT

//! ecdsa_reshare — redistribution of a `threshold_ecdsa` key to a NEW
//! committee (`n'` parties, threshold `t'`), one process as a sans-I/O state
//! machine. The group key `Q` stays; the new committee ends with new shares
//! of it AND its own proven Paillier, ring-Pedersen and message keys, so it
//! can sign — parties that held no `KeyShare` before included. It is
//! `EcdsaRefresh` with the two committees apart: the old committee deals its
//! shares (`reshare.zig`'s `ReshareDealer`), the new committee runs keygen's
//! aux rounds (announcements, Πmod/Πprm, Πfac) among itself and receives
//! (`ReshareReceiver`). tss-lib's "resharing" has the same split (old
//! committee: commitments and shares; new committee: Paillier proofs, then
//! an acknowledgement the old committee waits for before it erases).
//!
//! A process is an OLD party (it holds a `KeyShare` and deals), a NEW party
//! (it has a seat in the new committee and its fresh `LocalAux`), or both:
//!
//! ```text
//! start()    -> new: broadcast ecdsa_announcement of its LocalAux
//! .announce    new: collect every new peer's announcement
//! advance()  -> new: verify each, refuse a shared modulus or message key and
//!               material of the OLD table; send Πfac(N) to each new peer
//! .factors     new: collect every new peer's Πfac
//! advance()  -> new: verify each. old: deal (a fresh g_i of degree t'−1 with
//!               g_i(0) = x_i, Feldman broadcast, one share per NEW id)
//! .shares      new: collect every dealer's broadcast and share
//! advance()  -> new: check them; broadcast complaints
//! .complaints  old: collect complaints against itself
//! advance()  -> old: open the shares it is accused over
//! .defenses    new: collect the openings
//! advance()  -> new: x'_j = Σ λ_i g_i(j); assemble the new `KeyShare`;
//!               broadcast ecdsa_confirm: SHA-256 of its public part
//! .confirm     everyone: collect every NEW party's confirmation
//! advance()  -> every new party confirmed the same digest (its own, for a
//!               new party), or abort
//! .done        new: `takeKeyShare()`; old: the old share may be erased
//! ```
//!
//! **Erase the old share only after `.done`.** An old party reaches `.done`
//! once all `n'` new parties confirmed the same key table — tss-lib's old
//! committee waits for the same acknowledgement. On an abort the old shares
//! still form the key.
//!
//! **Ids.** The two committees have their own id spaces (old `1..n`, new
//! `1..n'`); a process in both has one id in each. `handle` takes the
//! sender's `Member` (its old and/or new id, as the transport authenticated
//! it), and the frame's kind says which id counts: dealing and defenses come
//! from an OLD id, announcements, Πfac, complaints and confirmations from a
//! NEW id; a frame whose sender lacks that id is `UnknownSender`.
//! `Outgoing.to` is `.broadcast` (every OTHER process of the run, in either
//! committee) or `.party = j` with `j` a NEW id (shares and Πfac only go to
//! new parties). A broadcast a role does not use (an old-only process gets
//! the announcements, the dealing and the defenses) is dropped without
//! error. `culprit()` is a NEW id (the aux and confirmation rounds name new
//! parties); a dealer the receivers exclude (`B_0 ≠ X_i`, an undefended
//! complaint, nothing dealt) does not stop the run while `t` dealers remain.
//!
//! **Binding.** Every frame carries the run tag (`ecdsa_keygen.Protocol`
//! `.reshare`, over the session id and BOTH configurations), and the aux
//! proofs are bound to that tag, `t'`, `n'` and the prover's new id, so
//! frames and proofs of a keygen, a refresh or another resharing are
//! refused (`WrongSession`). Transport duties are as in keygen: reliable
//! broadcast, authenticated senders, confidential point-to-point frames.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const reshare = @import("reshare.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const ecdsa_keygen = @import("ecdsa_keygen.zig");
const ecdsa_refresh = @import("ecdsa_refresh.zig");
const burn = @import("burn.zig");

// Dead-stack burns of the secret entry points (`burn.zig`): `EcdsaRefresh`'s,
// whose bodies these mirror call for call.
const init_stack_burn = 192 * 1024;
const start_stack_burn = 1984 * 1024;
const handle_stack_burn = 768 * 1024;
const advance_stack_burn = 1408 * 1024;
const take_key_share_stack_burn = 2 * 1024;

const aux_info = tecdsa.aux_info;
const fac_proof = tecdsa.fac_proof;
const Element = types.Element;
const Outgoing = wire.Outgoing;

pub const Phase = ecdsa_refresh.Phase;
pub const StartError = ecdsa_refresh.StartError;
pub const AdvanceError = ecdsa_refresh.AdvanceError;
pub const InitError = reshare.DealerInitError || reshare.ReceiverInitError || error{
    EmptySessionId,
    /// The old share does not belong to `Params` (another `t`/`n`, another
    /// group key, a verifying share that is not its entry of
    /// `old_public_keys`).
    InvalidKeyShare,
};

/// What every process of one resharing is configured with — all public, and
/// the same everywhere.
pub const Params = struct {
    /// The committee being replaced.
    old: types.Config,
    /// The committee it is replaced by.
    new: types.Config,
    /// Old ids that deal: distinct, in `1..old.n`, at least `old.t`.
    dealers: []const u32,
    /// The key, which resharing keeps.
    group_public_key: Element,
    /// The old committee's public-key table (`KeyShare.public_keys` of any
    /// old party; entries for ids `1..old.n`): its verifying shares check
    /// the dealing, its moduli and message keys may not be reused by the new
    /// committee. Copied by `init`.
    old_public_keys: tecdsa.PublicKeys,
};

/// This process's seat in the new committee: its new id and its fresh aux
/// material (borrowed for the run).
pub const NewSeat = struct {
    index: u32,
    local: *const aux_info.LocalAux,
};

/// A sender as the transport authenticated it: its id in the old committee,
/// in the new one, or both.
pub const Member = struct {
    old: ?u32 = null,
    new: ?u32 = null,
};

pub const EcdsaReshare = struct {
    allocator: std.mem.Allocator,
    old_cfg: types.Config,
    new_cfg: types.Config,
    me_old: ?u32,
    me_new: ?u32,
    /// The NEW aux material (borrowed); null for an old-only process.
    local: ?*const aux_info.LocalAux,
    random: std.Random,
    group_public_key: Element,
    dealer_ids: []u32,
    old_xs: []Element,
    old_keys: []tecdsa.PartyPublicKeys,
    dealer: ?reshare.ReshareDealer,
    receiver: ?reshare.ReshareReceiver,
    phase_: Phase = .new,

    announcements: []?aux_info.Announcement,
    fac: []?fac_proof.FacProof,
    checked: ?aux_info.AnnouncementSet = null,

    outbox: std.ArrayList(Outgoing) = .empty,
    share: ?tecdsa.KeyShare = null,
    culprit_: ?u32 = null,
    tag: ecdsa_keygen.RunTag,
    own_confirm: [32]u8 = undefined,
    confirms: []?[32]u8,

    /// `old_share` (borrowed for the call; its secret is copied into the
    /// dealer) makes this process a dealer, `seat` a new party; at least one
    /// must be given. `session_id` is copied; `random` must be a CSPRNG.
    pub fn init(
        allocator: std.mem.Allocator,
        params: Params,
        session_id: []const u8,
        old_share: ?*const tecdsa.KeyShare,
        seat: ?NewSeat,
        random: std.Random,
    ) InitError!EcdsaReshare {
        const result = initUnburned(allocator, params, session_id, old_share, seat, random);
        burn.stack(init_stack_burn);
        return result;
    }

    noinline fn initUnburned(
        allocator: std.mem.Allocator,
        params: Params,
        session_id: []const u8,
        old_share: ?*const tecdsa.KeyShare,
        seat: ?NewSeat,
        random: std.Random,
    ) InitError!EcdsaReshare {
        if (session_id.len == 0) return error.EmptySessionId;
        if (old_share == null and seat == null) return error.InvalidConfig;
        const old = params.old;
        const new = params.new;
        if (!old.valid() or params.old_public_keys.entries.len != old.n) return error.InvalidConfig;

        const old_xs = try allocator.alloc(Element, old.n);
        errdefer allocator.free(old_xs);
        for (old_xs, 1..) |*x, j| x.* = (params.old_public_keys.get(@intCast(j)) orelse return error.InvalidConfig).verifying_share;
        const old_keys = try allocator.dupe(tecdsa.PartyPublicKeys, params.old_public_keys.entries);
        errdefer allocator.free(old_keys);
        const dealer_ids = try allocator.dupe(u32, params.dealers);
        errdefer allocator.free(dealer_ids);
        const rc: reshare.ReshareConfig = .{
            .old = old,
            .new = new,
            .dealers = dealer_ids,
            .group_public_key = params.group_public_key,
            .old_verifying_shares = old_xs,
        };
        try rc.validate();

        var dealer: ?reshare.ReshareDealer = null;
        errdefer if (dealer) |*d| d.deinit();
        if (old_share) |s| {
            if (s.t != old.t or s.n != old.n or s.index < 1 or s.index > old.n or
                !std.mem.eql(u8, &s.group_public_key.toBytes(), &params.group_public_key.toBytes()) or
                !std.mem.eql(u8, &s.verifying_share.toBytes(), &old_xs[s.index - 1].toBytes()))
                return error.InvalidKeyShare;
            // An old party that does not deal has nothing to do as one.
            if (std.mem.findScalar(u32, dealer_ids, s.index) == null) return error.InvalidConfig;
            var old_out: types.DkgShareOutput = .{
                .index = s.index,
                .secret_share = s.secret_share,
                .group_public_key = s.group_public_key,
                .verifying_share = s.verifying_share,
            };
            defer std.crypto.secureZero(u8, std.mem.asBytes(&old_out));
            dealer = try reshare.ReshareDealer.init(allocator, &old_out, new, random);
        }
        var receiver: ?reshare.ReshareReceiver = null;
        errdefer if (receiver) |*r| r.deinit();
        if (seat) |st| receiver = try reshare.ReshareReceiver.init(allocator, rc, st.index);

        const anns = try allocator.alloc(?aux_info.Announcement, new.n);
        errdefer allocator.free(anns);
        @memset(anns, null);
        const fac = try allocator.alloc(?fac_proof.FacProof, new.n);
        errdefer allocator.free(fac);
        @memset(fac, null);
        const confirms = try allocator.alloc(?[32]u8, new.n);
        @memset(confirms, null);
        return .{
            .allocator = allocator,
            .old_cfg = old,
            .new_cfg = new,
            .me_old = if (old_share) |s| s.index else null,
            .me_new = if (seat) |st| st.index else null,
            .local = if (seat) |st| st.local else null,
            .random = random,
            .group_public_key = params.group_public_key,
            .dealer_ids = dealer_ids,
            .old_xs = old_xs,
            .old_keys = old_keys,
            .dealer = dealer,
            .receiver = receiver,
            .announcements = anns,
            .fac = fac,
            .tag = runTag(session_id, old, new),
            .confirms = confirms,
        };
    }

    /// Releases everything, wiping the secrets this struct holds (the
    /// dealer's polynomial, the receiver's shares, an untaken `KeyShare`).
    pub fn deinit(self: *EcdsaReshare) void {
        for (self.outbox.items) |m| m.deinit(self.allocator);
        self.outbox.deinit(self.allocator);
        if (self.share) |*s| {
            std.crypto.secureZero(u8, std.mem.asBytes(&s.secret_share));
            std.crypto.secureZero(u8, &s.message_seed);
            s.paillier_secret.deinit();
            self.allocator.free(s.public_keys.entries);
        }
        if (self.checked) |*c| c.deinit(self.allocator);
        if (self.dealer) |*d| d.deinit();
        if (self.receiver) |*r| r.deinit();
        self.allocator.free(self.dealer_ids);
        self.allocator.free(self.old_xs);
        self.allocator.free(self.old_keys);
        self.allocator.free(self.announcements);
        self.allocator.free(self.fac);
        self.allocator.free(self.confirms);
        self.* = undefined;
    }

    pub fn phase(self: *const EcdsaReshare) Phase {
        return self.phase_;
    }

    /// The NEW-committee id of the party that made the run abort, when known.
    pub fn culprit(self: *const EcdsaReshare) ?u32 {
        return self.culprit_;
    }

    /// The new `KeyShare` of a new party, handed over once, and only in
    /// `.done` (after every new party confirmed the same key table); false
    /// for an old-only process. As `EcdsaRefresh.takeKeyShare`: moved into
    /// `out`, the copy kept here wiped; the caller frees
    /// `share.public_keys.entries` with the allocator given to `init`.
    pub fn takeKeyShare(self: *EcdsaReshare, out: *tecdsa.KeyShare) bool {
        const result = takeKeyShareUnburned(self, out);
        burn.stack(take_key_share_stack_burn);
        return result;
    }

    noinline fn takeKeyShareUnburned(self: *EcdsaReshare, out: *tecdsa.KeyShare) bool {
        if (self.phase_ != .done) return false;
        if (self.share == null) return false;
        out.* = self.share.?;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.share.?));
        self.share = null;
        return true;
    }

    /// Everything queued to send; free with `wire.freeOutgoing(allocator, msgs)`.
    pub fn takeOutgoing(self: *EcdsaReshare) std.mem.Allocator.Error![]Outgoing {
        return self.outbox.toOwnedSlice(self.allocator);
    }

    /// Round 1: a new party broadcasts its announcement; an old-only one
    /// only moves on.
    pub fn start(self: *EcdsaReshare) StartError!void {
        const result = startUnburned(self);
        burn.stack(start_stack_burn);
        return result;
    }

    noinline fn startUnburned(self: *EcdsaReshare) StartError!void {
        if (self.phase_ != .new) return error.WrongRound;
        if (self.me_new) |me| {
            var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
            const ann = try self.local.?.announce(self.allocator, self.context(&ctx_buf, me), self.random);
            if (self.reusesOld(ann)) return error.StaleAuxMaterial;
            const bytes = try ann.toBytesAlloc(self.allocator);
            defer self.allocator.free(bytes);
            try ecdsa_keygen.pushTagged(&self.outbox, self.allocator, self.tag, .broadcast, .ecdsa_announcement, bytes);
            self.announcements[me - 1] = ann;
        }
        self.phase_ = .announce;
    }

    /// Feed one frame from the authenticated sender `from`. A frame for a
    /// later round is refused with `WrongRound` (hold it, redeliver after
    /// `advance`); a refused frame changes nothing.
    pub fn handle(self: *EcdsaReshare, from: Member, tagged: []const u8) reshare.MessageError!void {
        const result = handleUnburned(self, from, tagged);
        burn.stack(handle_stack_burn);
        return result;
    }

    noinline fn handleUnburned(self: *EcdsaReshare, from: Member, tagged: []const u8) reshare.MessageError!void {
        switch (self.phase_) {
            .done => return error.Finished,
            .aborted => return error.Aborted,
            else => {},
        }
        const bytes = try ecdsa_keygen.untag(self.tag, tagged);
        if (bytes.len == 0) return error.Malformed;
        const kind = wire.kindFromByte(bytes[0]) orelse return error.UnknownKind;
        switch (kind) {
            .ecdsa_announcement => {
                const j = try self.newSender(from);
                if (self.me_new == null) return; // not used by an old-only process
                if (self.phase_ != .announce) return error.WrongRound;
                if (self.announcements[j - 1] != null) return error.DuplicateMessage;
                self.announcements[j - 1] = aux_info.Announcement.fromBytes(bytes[1..]) catch return error.Malformed;
            },
            .ecdsa_fac_proof => {
                const j = try self.newSender(from);
                const local = self.local orelse return error.WrongRecipient;
                if (self.phase_ != .factors) return error.WrongRound;
                if (self.fac[j - 1] != null) return error.DuplicateMessage;
                self.fac[j - 1] = fac_proof.FacProof.fromBytes(local.aux.n_tilde, bytes[1..]) catch return error.Malformed;
            },
            .reshare_broadcast, .reshare_share => {
                const i = try self.oldSender(from);
                const r = if (self.receiver) |*r| r else return if (kind == .reshare_share) error.WrongRecipient else {};
                if (self.phase_ != .shares) return error.WrongRound;
                try r.handle(.{ .dealer = i }, bytes);
            },
            .reshare_complaint => {
                const j = try self.newSender(from);
                if (self.phase_ != .complaints) return error.WrongRound;
                if (self.receiver) |*r| try r.handle(.{ .receiver = j }, bytes);
                if (self.dealer) |*d| try d.handle(j, bytes);
            },
            .reshare_defense => {
                const i = try self.oldSender(from);
                const r = if (self.receiver) |*r| r else return;
                if (self.phase_ != .defenses) return error.WrongRound;
                try r.handle(.{ .dealer = i }, bytes);
            },
            .ecdsa_confirm => {
                const j = try self.newSender(from);
                if (self.phase_ != .confirm) return error.WrongRound;
                if (self.confirms[j - 1] != null) return error.DuplicateMessage;
                if (bytes.len != 1 + 32) return error.Malformed;
                self.confirms[j - 1] = bytes[1..33].*;
            },
            else => return error.UnknownKind,
        }
    }

    /// Close the current round and move on. Any error leaves the process
    /// `.aborted`.
    pub fn advance(self: *EcdsaReshare) AdvanceError!void {
        const result = advanceUnburned(self);
        burn.stack(advance_stack_burn);
        return result;
    }

    noinline fn advanceUnburned(self: *EcdsaReshare) AdvanceError!void {
        const r = switch (self.phase_) {
            .new => return error.WrongRound,
            .announce => self.advanceAnnounce(),
            .factors => self.advanceFactors(),
            .shares => self.advanceShares(),
            .complaints => self.advanceComplaints(),
            .defenses => self.advanceDefenses(),
            .confirm => self.advanceConfirm(),
            .done => return error.Finished,
            .aborted => return error.Aborted,
        };
        r catch |e| {
            self.phase_ = .aborted;
            return e;
        };
    }

    // ── rounds ───────────────────────────────────────────────────────────

    fn advanceAnnounce(self: *EcdsaReshare) AdvanceError!void {
        if (self.me_new) |me| {
            if (self.missing(.announce)) |j| {
                self.culprit_ = j;
                return error.MissingMessage;
            }
            var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
            const all = try self.allocator.alloc(aux_info.Announcement, self.new_cfg.n);
            defer self.allocator.free(all);
            for (all, self.announcements) |*d, a| d.* = a.?;
            self.checked = aux_info.AnnouncementSet.init(self.allocator, all, me) catch |e| switch (e) {
                error.InvalidParameters => unreachable, // me is 1..=n'
                error.OutOfMemory => return error.OutOfMemory,
            };
            const checked = &self.checked.?;
            for (1..self.new_cfg.n + 1) |j| {
                if (j == me) continue;
                checked.verifyPeer(@intCast(j), self.context(&ctx_buf, @intCast(j)), self.random) catch {
                    self.culprit_ = @intCast(j);
                    return error.InvalidAnnouncement;
                };
            }
            if (checked.checkDistinct() != null) return error.DuplicateModulus;
            for (self.announcements, 1..) |a, j| {
                if (j != me and self.reusesOld(a.?)) {
                    self.culprit_ = @intCast(j);
                    return error.StaleAuxMaterial;
                }
            }
            const own_ctx = self.context(&ctx_buf, me);
            for (self.announcements, 1..) |a, j| {
                if (j == me) continue;
                const proof = try self.local.?.proveFactors(a.?.aux, own_ctx, self.random);
                const bytes = try proof.toBytesAlloc(self.allocator);
                defer self.allocator.free(bytes);
                try ecdsa_keygen.pushTagged(&self.outbox, self.allocator, self.tag, .{ .party = @intCast(j) }, .ecdsa_fac_proof, bytes);
            }
        }
        self.phase_ = .factors;
    }

    fn advanceFactors(self: *EcdsaReshare) AdvanceError!void {
        if (self.me_new) |me| {
            if (self.missing(.factors)) |j| {
                self.culprit_ = j;
                return error.MissingMessage;
            }
            var ctx_buf: [ecdsa_keygen.EcdsaKeygen.ctx_max]u8 = undefined;
            const checked = &self.checked.?;
            for (self.fac, 1..) |f, j| {
                if (j == me) continue;
                if (!checked.verifyPeerFactors(@intCast(j), self.context(&ctx_buf, @intCast(j)), f.?)) {
                    self.culprit_ = @intCast(j);
                    return error.InvalidFactorProof;
                }
            }
        }
        if (self.dealer) |*d| {
            d.start() catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidKeyShare,
            };
            try self.routeDealer();
        }
        self.phase_ = .shares;
    }

    fn advanceShares(self: *EcdsaReshare) AdvanceError!void {
        if (self.receiver) |*r| {
            try r.advance(); // shares -> complaints
            try self.routeReceiver();
        }
        self.phase_ = .complaints;
    }

    fn advanceComplaints(self: *EcdsaReshare) AdvanceError!void {
        if (self.receiver) |*r| try r.advance(); // complaints -> defenses
        if (self.dealer) |*d| {
            try d.advance();
            try self.routeDealer();
        }
        self.phase_ = .defenses;
    }

    fn advanceDefenses(self: *EcdsaReshare) AdvanceError!void {
        if (self.receiver) |*r| {
            try r.advance(); // defenses -> done
            const out = r.output() orelse return error.Inconsistent;
            var share: tecdsa.KeyShare = undefined;
            try aux_info.assembleKeyShare(
                self.allocator,
                self.checked.?.verified().?, // every check passed in the earlier rounds
                &out.secret_share,
                r.publicCommitments().?,
                self.local.?,
                &share,
            );
            if (!std.mem.eql(u8, &share.group_public_key.toBytes(), &self.group_public_key.toBytes())) {
                self.allocator.free(share.public_keys.entries);
                return error.InvalidKeyShare;
            }
            self.share = share;
            self.own_confirm = try confirmDigest(self.allocator, self.tag, share);
            try ecdsa_keygen.pushTagged(&self.outbox, self.allocator, self.tag, .broadcast, .ecdsa_confirm, &self.own_confirm);
        }
        self.phase_ = .confirm;
    }

    fn advanceConfirm(self: *EcdsaReshare) AdvanceError!void {
        // A new party compares with its own digest; an old-only process
        // with the first one it holds — all n' must agree either way.
        var want: ?[32]u8 = if (self.me_new != null) self.own_confirm else null;
        for (self.confirms, 1..) |c, j| {
            if (self.me_new != null and j == self.me_new.?) continue;
            const d = c orelse {
                self.culprit_ = @intCast(j);
                return error.MissingMessage;
            };
            const w = want orelse {
                want = d;
                continue;
            };
            if (!std.mem.eql(u8, &d, &w)) {
                self.culprit_ = @intCast(j);
                return error.ConfirmationMismatch;
            }
        }
        self.phase_ = .done;
    }

    // ── helpers ──────────────────────────────────────────────────────────

    /// `SHA-256(domain || run tag || group key || u32-BE t' || u32-BE n' ||
    /// public-key table)`, as `EcdsaRefresh`'s, under its own domain.
    fn confirmDigest(allocator: std.mem.Allocator, tag: ecdsa_keygen.RunTag, share: tecdsa.KeyShare) AdvanceError![32]u8 {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("dkg/ecdsa/reshare-confirm/v1");
        h.update(&tag);
        h.update(&share.group_public_key.toBytes());
        var u: [4]u8 = undefined;
        std.mem.writeInt(u32, &u, share.t, .big);
        h.update(&u);
        std.mem.writeInt(u32, &u, share.n, .big);
        h.update(&u);
        const table = share.public_keys.toBytesAlloc(allocator) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidKeyShare,
        };
        defer allocator.free(table);
        h.update(table);
        return h.finalResult();
    }

    /// The new committee's proofs are bound to the run tag (session id and
    /// both configurations), `t'`, `n'` and the prover's new id.
    fn context(self: *const EcdsaReshare, buf: *[ecdsa_keygen.EcdsaKeygen.ctx_max]u8, index: u32) []const u8 {
        return ecdsa_keygen.keygenContext(buf, &self.tag, self.new_cfg.t, self.new_cfg.n, index);
    }

    fn reusesOld(self: *const EcdsaReshare, a: aux_info.Announcement) bool {
        for (self.old_keys) |old| if (aux_info.reusesMaterial(a, old)) return true;
        return false;
    }

    fn newSender(self: *const EcdsaReshare, from: Member) reshare.MessageError!u32 {
        const j = from.new orelse return error.UnknownSender;
        if (j < 1 or j > self.new_cfg.n) return error.UnknownSender;
        if (self.me_new != null and j == self.me_new.?) return error.UnknownSender;
        return j;
    }

    fn oldSender(self: *const EcdsaReshare, from: Member) reshare.MessageError!u32 {
        const i = from.old orelse return error.UnknownSender;
        if (i < 1 or i > self.old_cfg.n) return error.UnknownSender;
        if (self.me_old != null and i == self.me_old.?) return error.UnknownSender;
        return i;
    }

    fn missing(self: *const EcdsaReshare, which: enum { announce, factors }) ?u32 {
        for (0..self.new_cfg.n) |i| {
            const j: u32 = @intCast(i + 1);
            if (j == self.me_new.?) continue;
            const have = switch (which) {
                .announce => self.announcements[i] != null,
                .factors => self.fac[i] != null,
            };
            if (!have) return j;
        }
        return null;
    }

    /// This process's dealer frames: to its own receiver (a broadcast, or a
    /// share for its own new id), and out (everything else). A frame its own
    /// receiver refuses excludes this dealer as every other receiver does.
    fn routeDealer(self: *EcdsaReshare) AdvanceError!void {
        const msgs = try self.dealer.?.takeOutgoing();
        defer self.allocator.free(msgs);
        var moved: usize = 0;
        errdefer for (msgs[moved..]) |m| m.deinit(self.allocator);
        while (moved < msgs.len) : (moved += 1) {
            const m = msgs[moved];
            if (self.receiver) |*r| {
                const to_me = switch (m.to) {
                    .broadcast => true,
                    .party => |j| j == self.me_new.?,
                };
                if (to_me) r.handle(.{ .dealer = self.me_old.? }, m.bytes) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {},
                };
                switch (m.to) {
                    .party => |j| if (j == self.me_new.?) {
                        m.deinit(self.allocator);
                        continue;
                    },
                    .broadcast => {},
                }
            }
            try ecdsa_keygen.appendTagged(&self.outbox, self.allocator, self.tag, m);
        }
    }

    /// This process's receiver frames (complaints, broadcast): to its own
    /// dealer, and out.
    fn routeReceiver(self: *EcdsaReshare) AdvanceError!void {
        const msgs = try self.receiver.?.takeOutgoing();
        defer self.allocator.free(msgs);
        var moved: usize = 0;
        errdefer for (msgs[moved..]) |m| m.deinit(self.allocator);
        while (moved < msgs.len) : (moved += 1) {
            const m = msgs[moved];
            if (self.dealer) |*d| try d.handle(self.me_new.?, m.bytes);
            try ecdsa_keygen.appendTagged(&self.outbox, self.allocator, self.tag, m);
        }
    }
};

/// `ecdsa_keygen.runTag` for a resharing: protocol `.reshare`, the new
/// configuration, and as the session id `SHA-256(domain || u32-BE old t ||
/// u32-BE old n || u32-BE len || session id)` — so the tag binds both
/// configurations.
pub fn runTag(session_id: []const u8, old: types.Config, new: types.Config) ecdsa_keygen.RunTag {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("dkg/ecdsa/reshare-session/v1");
    var u: [4]u8 = undefined;
    std.mem.writeInt(u32, &u, old.t, .big);
    h.update(&u);
    std.mem.writeInt(u32, &u, old.n, .big);
    h.update(&u);
    std.mem.writeInt(u32, &u, @intCast(session_id.len), .big);
    h.update(&u);
    h.update(session_id);
    const bound = h.finalResult();
    return ecdsa_keygen.runTag(.reshare, &bound, new);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const quickLocal = @import("testaux.zig").quickLocal;

/// One process of a test run and the ids it is known by.
const Proc = struct {
    m: Member,
    p: EcdsaReshare,
};

/// `filter` sees each delivered copy (it may change the bytes) and returns
/// false to drop it.
const Filter = *const fn (from: Member, to: Member, bytes: []u8) bool;

fn sameMember(a: Member, b: Member) bool {
    return std.meta.eql(a, b);
}

/// Everything queued, delivered: a broadcast to every other process, a
/// `.party = j` frame to the process whose NEW id is `j`. Returns the number
/// of refused copies.
fn deliver(allocator: std.mem.Allocator, procs: []Proc, filter: ?Filter) !usize {
    var refused: usize = 0;
    for (procs) |*src| {
        const msgs = try src.p.takeOutgoing();
        defer wire.freeOutgoing(allocator, msgs);
        for (msgs) |m| for (procs) |*dst| {
            if (sameMember(src.m, dst.m)) continue;
            switch (m.to) {
                .broadcast => {},
                .party => |j| if (dst.m.new == null or dst.m.new.? != j) continue,
            }
            const copy = try allocator.dupe(u8, m.bytes);
            defer allocator.free(copy);
            if (filter) |f| if (!f(src.m, dst.m, copy)) continue;
            dst.p.handle(src.m, copy) catch |e| switch (e) {
                error.OutOfMemory => return e,
                else => refused += 1,
            };
        };
    }
    return refused;
}

/// Lockstep to the end; returns the refused copies.
fn runAll(allocator: std.mem.Allocator, procs: []Proc, filter: ?Filter) !usize {
    for (procs) |*x| try x.p.start();
    var refused: usize = 0;
    var rounds: usize = 0;
    while (true) : (rounds += 1) {
        try testing.expect(rounds < 16);
        refused += try deliver(allocator, procs, filter);
        if (procs[0].p.phase() == .done) break;
        for (procs) |*x| try x.p.advance();
        // Nobody queues a frame for its own new id.
        for (procs) |*x| for (x.p.outbox.items) |m| switch (m.to) {
            .party => |to| try testing.expect(x.m.new == null or to != x.m.new.?),
            .broadcast => {},
        };
    }
    for (procs) |*x| try testing.expectEqual(Phase.done, x.p.phase());
    return refused;
}

fn kindOf(bytes: []const u8) wire.Kind {
    return wire.kindFromByte(bytes[ecdsa_keygen.run_tag_len]).?;
}

/// The old committee (trusted-dealer 2-of-3), fresh aux material for three
/// new seats, and the four processes of a resharing to `new`: P1 = old 1 /
/// new 1, P2 = old 2 / new 2, P3 = old 3 only (it leaves), P4 = new 3 only
/// (it joins with no `KeyShare`).
const Run = struct {
    kg: tecdsa.signing.TestKeygen,
    locals: [3]aux_info.LocalAux,
    procs: [4]Proc = undefined,
    inited: usize = 0,

    fn init(self: *Run, allocator: std.mem.Allocator, random: std.Random, new: types.Config, sid: []const u8) !void {
        self.kg = try tecdsa.signing.testKeygen(allocator, random, 2, 3);
        errdefer self.kg.deinit(allocator);
        var made: usize = 0;
        errdefer for (self.locals[0..made]) |*l| l.deinit(allocator);
        while (made < 3) : (made += 1) self.locals[made] = try quickLocal(allocator, random);
        self.inited = 0;
        errdefer for (self.procs[0..self.inited]) |*x| x.p.deinit();
        const ps = self.params(new);
        const ks = self.kg.key_shares;
        const roles = [4]struct { old: ?u32, new: ?u32 }{ .{ .old = 1, .new = 1 }, .{ .old = 2, .new = 2 }, .{ .old = 3, .new = null }, .{ .old = null, .new = 3 } };
        for (roles) |r| {
            const seat: ?NewSeat = if (r.new) |j| .{ .index = j, .local = &self.locals[j - 1] } else null;
            self.procs[self.inited] = .{
                .m = .{ .old = r.old, .new = r.new },
                .p = try EcdsaReshare.init(allocator, ps, sid, if (r.old) |i| &ks[i - 1] else null, seat, random),
            };
            self.inited += 1;
        }
    }

    fn params(self: *const Run, new: types.Config) Params {
        const S = struct {
            const dealers = [_]u32{ 1, 2, 3 };
        };
        return .{
            .old = .{ .t = 2, .n = 3 },
            .new = new,
            .dealers = &S.dealers,
            .group_public_key = self.kg.key_shares[0].group_public_key,
            .old_public_keys = self.kg.key_shares[0].public_keys,
        };
    }

    fn deinit(self: *Run, allocator: std.mem.Allocator) void {
        for (self.procs[0..self.inited]) |*x| x.p.deinit();
        for (&self.locals) |*l| l.deinit(allocator);
        self.kg.deinit(allocator);
    }

    /// The new shares of new ids 1, 2, 3 (P1, P2, P4).
    fn take(self: *Run) ![3]tecdsa.KeyShare {
        var out: [3]tecdsa.KeyShare = undefined;
        for ([_]usize{ 0, 1, 3 }, &out) |i, *s| try testing.expect(self.procs[i].p.takeKeyShare(s));
        var none: tecdsa.KeyShare = undefined;
        try testing.expect(!self.procs[2].p.takeKeyShare(&none)); // old-only: no share
        return out;
    }
};

fn freeShares(allocator: std.mem.Allocator, shares: []tecdsa.KeyShare) void {
    for (shares) |*s| {
        s.paillier_secret.deinit();
        allocator.free(s.public_keys.entries);
    }
}

test "reshare (2,3) -> (3,3): one old party leaves, a newcomer with no KeyShare joins; the new committee signs under Q; old shares do not mix" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_5E5A_0001);
    const random = prng.random();
    var run: Run = undefined;
    try run.init(allocator, random, .{ .t = 3, .n = 3 }, "reshare-test-1");
    defer run.deinit(allocator);
    try testing.expectEqual(@as(usize, 0), try runAll(allocator, &run.procs, null));
    var new = try run.take();
    defer freeShares(allocator, &new);

    const old = run.kg.key_shares;
    for (new, 1..) |n, j| {
        try testing.expectEqualSlices(u8, &old[0].group_public_key.toBytes(), &n.group_public_key.toBytes());
        try testing.expectEqual(@as(u32, 3), n.t);
        try testing.expectEqual(@as(u32, 3), n.n);
        try testing.expectEqual(@as(u32, @intCast(j)), n.index);
        // A new table: no Paillier or ring-Pedersen modulus or message key
        // of the old one (only the fields `reusesMaterial` reads are set).
        for (n.public_keys.entries) |e| for (old[0].public_keys.entries) |o| try testing.expect(!aux_info.reusesMaterial(.{
            .paillier_pk = e.paillier_pk,
            .aux = e.aux,
            .message_key = e.message_key,
            .aux_proof = undefined,
            .paillier_proof = undefined,
        }, o));
    }
    // Every receiver used all three dealers.
    for (run.procs) |x| if (x.p.receiver) |r| try testing.expectEqual(@as(usize, 3), r.usedDealers().?.len);

    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&new[0].group_public_key.toBytes());
    const msg = "reshared";
    const sig = try tecdsa.signing.signWithShares(allocator, &new, msg, random);
    try sig.verify(msg, pk);
    // Fewer than t' = 3 new shares do not sign.
    try testing.expect(std.meta.isError(tecdsa.signing.signWithShares(allocator, new[0..2], msg, random)));
    // Old shares are useless next to new ones: refused, or a signature that
    // does not verify.
    if (tecdsa.signing.signWithShares(allocator, &.{ old[0], new[1], new[2] }, msg, random)) |s| {
        try testing.expectError(error.SignatureVerificationFailed, s.verify(msg, pk));
    } else |_| {}
    // And the new shares interpolate to the key's secret, the old ones mixed
    // in do not (Shamir at x = 0).
    var x_old: tecdsa.Scalar = undefined;
    try tecdsa.reconstructSecret(&.{ .{ .index = 1, .scalar = old[0].secret_share }, .{ .index = 2, .scalar = old[1].secret_share } }, &x_old);
    var x_new: tecdsa.Scalar = undefined;
    try tecdsa.reconstructSecret(&.{ .{ .index = 1, .scalar = new[0].secret_share }, .{ .index = 2, .scalar = new[1].secret_share }, .{ .index = 3, .scalar = new[2].secret_share } }, &x_new);
    try testing.expect(x_old.equivalent(x_new));
    var x_mix: tecdsa.Scalar = undefined;
    try tecdsa.reconstructSecret(&.{ .{ .index = 1, .scalar = old[0].secret_share }, .{ .index = 2, .scalar = new[1].secret_share }, .{ .index = 3, .scalar = new[2].secret_share } }, &x_mix);
    try testing.expect(!x_old.equivalent(x_mix));
}

test "reshare: a dealer whose share to one new party is bad and who leaves the complaint undefended is excluded by everyone; two dealers carry the key" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_5E5A_0002);
    const random = prng.random();
    var run: Run = undefined;
    try run.init(allocator, random, .{ .t = 2, .n = 3 }, "reshare-test-2");
    defer run.deinit(allocator);
    // Old party 3 (the one leaving) sends new party 1 a share off its
    // polynomial and never opens it.
    const malicious = struct {
        fn f(from: Member, to: Member, bytes: []u8) bool {
            if (from.old == null or from.old.? != 3) return true;
            switch (kindOf(bytes)) {
                .reshare_share => if (to.new != null and to.new.? == 1) {
                    bytes[bytes.len - 1] ^= 1;
                },
                .reshare_defense => return false,
                else => {},
            }
            return true;
        }
    }.f;
    _ = try runAll(allocator, &run.procs, malicious);
    for (run.procs) |x| if (x.p.receiver) |r| {
        const used = r.usedDealers().?;
        try testing.expectEqual(@as(usize, 2), used.len);
        try testing.expect(std.mem.findScalar(u32, used, 3) == null);
    };
    var new = try run.take();
    defer freeShares(allocator, &new);
    const ecdsa = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
    const pk = try ecdsa.PublicKey.fromSec1(&new[0].group_public_key.toBytes());
    const sig = try tecdsa.signing.signWithShares(allocator, &.{ new[0], new[2] }, "two dealers", random);
    try sig.verify("two dealers", pk);
}

test "reshare: a confirmation that differs aborts every party, old-only ones included; nobody hands out a share" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_5E5A_0003);
    const random = prng.random();
    var run: Run = undefined;
    try run.init(allocator, random, .{ .t = 2, .n = 3 }, "reshare-test-3");
    defer run.deinit(allocator);
    // New party 3's confirmation is altered on its way to everyone.
    const bend = struct {
        fn f(from: Member, _: Member, bytes: []u8) bool {
            if (from.new != null and from.new.? == 3 and kindOf(bytes) == .ecdsa_confirm) bytes[bytes.len - 1] ^= 1;
            return true;
        }
    }.f;
    for (&run.procs) |*x| try x.p.start();
    while (run.procs[0].p.phase() != .confirm) {
        _ = try deliver(allocator, &run.procs, bend);
        for (&run.procs) |*x| try x.p.advance();
    }
    _ = try deliver(allocator, &run.procs, bend);
    for (&run.procs) |*x| {
        if (x.m.new != null and x.m.new.? == 3) {
            // P4 holds the others' honest digests, which equal its own: it
            // alone finishes (and its peers will not use the key without it).
            try x.p.advance();
            continue;
        }
        try testing.expectError(error.ConfirmationMismatch, x.p.advance());
        try testing.expectEqual(@as(?u32, 3), x.p.culprit());
        var none: tecdsa.KeyShare = undefined;
        try testing.expect(!x.p.takeKeyShare(&none));
    }
}

test "reshare: init and frame guards — roles, ids of the wrong committee, frames of another run" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xEC_5E5A_0004);
    const random = prng.random();
    const kg = try tecdsa.signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    var local = try quickLocal(allocator, random);
    defer local.deinit(allocator);
    const ks = kg.key_shares;
    const dealers = [_]u32{ 1, 2 };
    const params: Params = .{
        .old = .{ .t = 2, .n = 3 },
        .new = .{ .t = 2, .n = 3 },
        .dealers = &dealers,
        .group_public_key = ks[0].group_public_key,
        .old_public_keys = ks[0].public_keys,
    };
    const seat: NewSeat = .{ .index = 1, .local = &local };
    try testing.expectError(error.EmptySessionId, EcdsaReshare.init(allocator, params, "", &ks[0], seat, random));
    // No role at all; an old party that does not deal; a bad new id.
    try testing.expectError(error.InvalidConfig, EcdsaReshare.init(allocator, params, "g", null, null, random));
    try testing.expectError(error.InvalidConfig, EcdsaReshare.init(allocator, params, "g", &ks[2], null, random));
    try testing.expectError(error.InvalidIndex, EcdsaReshare.init(allocator, params, "g", null, .{ .index = 4, .local = &local }, random));
    // Fewer dealers than the old threshold.
    var thin = params;
    thin.dealers = dealers[0..1];
    try testing.expectError(error.InvalidConfig, EcdsaReshare.init(allocator, thin, "g", &ks[0], null, random));
    // A share of another key, or whose verifying share is not its table entry.
    var other = ks[0];
    other.group_public_key = ks[1].verifying_share;
    try testing.expectError(error.InvalidKeyShare, EcdsaReshare.init(allocator, params, "g", &other, null, random));
    other = ks[0];
    other.verifying_share = ks[1].verifying_share;
    try testing.expectError(error.InvalidKeyShare, EcdsaReshare.init(allocator, params, "g", &other, null, random));

    // An old-only process and a new-only one.
    var old_only = try EcdsaReshare.init(allocator, params, "guards", &ks[1], null, random);
    defer old_only.deinit();
    var new_only = try EcdsaReshare.init(allocator, params, "guards", null, seat, random);
    defer new_only.deinit();
    try old_only.start();
    try testing.expectEqual(@as(usize, 0), old_only.outbox.items.len); // nothing to announce
    try new_only.start();
    const ann = try new_only.takeOutgoing();
    defer wire.freeOutgoing(allocator, ann);
    // The announcement needs a NEW id; the old-only process drops it.
    try testing.expectError(error.UnknownSender, old_only.handle(.{ .old = 1 }, ann[0].bytes));
    try old_only.handle(.{ .new = 1 }, ann[0].bytes);
    try testing.expectError(error.UnknownSender, old_only.handle(.{ .new = 4 }, ann[0].bytes));
    // Its own ids are not a peer's.
    try testing.expectError(error.UnknownSender, new_only.handle(.{ .new = 1 }, ann[0].bytes));
    var list: std.ArrayList(Outgoing) = .empty;
    defer {
        for (list.items) |m| m.deinit(allocator);
        list.deinit(allocator);
    }
    try ecdsa_keygen.pushTagged(&list, allocator, new_only.tag, .{ .party = 1 }, .reshare_share, "x");
    try ecdsa_keygen.pushTagged(&list, allocator, new_only.tag, .{ .party = 1 }, .ecdsa_fac_proof, "x");
    try ecdsa_keygen.pushTagged(&list, allocator, new_only.tag, .broadcast, .reshare_broadcast, "x");
    // Dealing from a NEW id is not dealing; a share or a Πfac for an
    // old-only process went to the wrong place; dealing out of round waits.
    try testing.expectError(error.UnknownSender, new_only.handle(.{ .new = 2 }, list.items[0].bytes));
    try testing.expectError(error.WrongRecipient, old_only.handle(.{ .old = 1 }, list.items[0].bytes));
    try testing.expectError(error.WrongRecipient, old_only.handle(.{ .new = 2 }, list.items[1].bytes));
    try old_only.handle(.{ .old = 1 }, list.items[2].bytes); // a broadcast it does not use
    try testing.expectError(error.WrongRound, new_only.handle(.{ .old = 1 }, list.items[0].bytes));

    // The run tag binds the protocol, the session id and both configs.
    try testing.expect(!std.mem.eql(u8, &new_only.tag, &runTag("guards", .{ .t = 2, .n = 4 }, .{ .t = 2, .n = 3 })));
    try testing.expect(!std.mem.eql(u8, &new_only.tag, &runTag("guards", .{ .t = 2, .n = 3 }, .{ .t = 3, .n = 3 })));
    try testing.expect(!std.mem.eql(u8, &new_only.tag, &ecdsa_keygen.runTag(.refresh, "guards", .{ .t = 2, .n = 3 })));
    const fixed = try allocator.dupe(u8, ann[0].bytes);
    defer allocator.free(fixed);
    fixed[0..ecdsa_keygen.run_tag_len].* = ecdsa_keygen.runTag(.refresh, "guards", .{ .t = 2, .n = 3 });
    var peer = try EcdsaReshare.init(allocator, params, "guards", &ks[1], .{ .index = 2, .local = &local }, random);
    defer peer.deinit();
    peer.phase_ = .announce;
    try testing.expectError(error.WrongSession, peer.handle(.{ .new = 1 }, fixed));
    try peer.handle(.{ .new = 1 }, ann[0].bytes);
    try testing.expectError(error.DuplicateMessage, peer.handle(.{ .new = 1 }, ann[0].bytes));
}
