// SPDX-License-Identifier: MIT
//! presign — GG20 threshold-ECDSA signing as one state machine per signer.
//!
//! R. Gennaro, S. Goldfeder, "One Round Threshold ECDSA with Identifiable
//! Abort" (IACR ePrint 2020/540) §3.2. Each signer runs its own `Party`
//! holding nothing but its own `root.KeyShare`; parties talk only through
//! the byte messages `advance` returns and accepts. Phases 1–6 do not depend
//! on the message, so they run ahead of time and end in a `Presignature`;
//! signing a message is then ONE round (Phase 7): every signer broadcasts
//! `s_i = m·k_i + r·σ_i` and anyone holding the public half combines.
//!
//! ## Rounds (the paper's phases, one `advance` call each)
//!
//! | call | consumes | emits |
//! |---|---|---|
//! | `advance` #1 | — | bc `C_i = H(sid,i,Γ_i,ρ_i)`, `c_i = Enc_i(k_i)`; p2p range proof of `c_i` under each verifier's aux (Phase 1 + MtA msg 1) |
//! | `advance` #2 | #1 | p2p MtA response for `k_j·γ_i` + Π^MtA, MtAwc response for `k_j·w_i` + Π^MtAwc (Phase 2) |
//! | `advance` #3 | #2 | bc `δ_i`, `T_i = σ_i·G + ℓ_i·H`, proof of `(σ_i, ℓ_i)` (Phase 3) |
//! | `advance` #4 | #3 | bc `Γ_i`, `ρ_i`, Schnorr proof of `γ_i` (Phase 4) |
//! | `advance` #5 | #4 | bc `R̄_i = k_i·R`; p2p proof that `R̄_i` matches `c_i` (Phase 5) |
//! | `advance` #6 | #5 | bc `S_i = σ_i·R`, proof that `S_i` and `T_i` share `σ_i` (Phase 6) |
//! | `finish` | #6 | — → `Presignature` |
//! | `Presignature.signShare` | — | bc `s_i` (Phase 7) |
//! | `PresignaturePublic.combine` | Phase 7 shares | the signature |
//!
//! Every check the paper lists is made before anything secret-dependent is
//! sent on: Phase 5 checks `Σ R̄_j = G` (so `R = k⁻¹·G` for the `k` inside the
//! ciphertexts), Phase 6 checks `Σ S_j = X` (so the `σ_j` add up to `k·x`).
//! Once both hold the signature is guaranteed to verify, which is what makes
//! releasing `s_i` safe — an `s_i` released against a wrong `R` would leak
//! the signer's key share (paper §4.3). The in-process driver this replaced
//! (`signing.signWithShares` before 2026-10-02) had neither check; it relied
//! on the final self-check, which is enough only when one process holds
//! every share.
//!
//! ## Identifiable abort
//!
//! Any failed check aborts the party: the call returns `error.ProtocolAbort`
//! and `Party.abort` names the fault and, where the paper's §4.2 can, the
//! culprit's index — every proof failure (types 1, 2, 3, 4, 6), every
//! malformed, misaddressed, duplicate or missing message, and in Phase 7 a
//! signature share failing `s_j·R == m·R̄_j + r·S_j` (type 8). Types 5 and 7
//! (`Σ R̄_j ≠ G`, `Σ S_j ≠ X` with every proof valid) abort with
//! `culprit == null`: naming the party there needs the paper's §4.3 opening
//! protocol, which is not implemented (SPEC.md backlog).
//!
//! ## Broadcast consistency (in the protocol, not assumed)
//!
//! GG20 assumes a reliable broadcast channel. Here every message after
//! round 1 starts with the sender's running hash of every broadcast it has
//! processed (its own included, in signer order); a receiver whose own hash
//! differs aborts with `equivocation` (unattributed) before it uses anything
//! from that round. Without it, a signer showing different broadcasts to
//! different peers would make the honest ones fail each other's proofs —
//! and blame each other. Phase-7 shares carry the final hash, `combine`
//! compares it.
//!
//! ## What the caller must provide
//!
//! - **Authenticated delivery.** The header's `from` is taken as the sender:
//!   the transport must check it against the authenticated peer
//!   (`peekHeader`) before handing a message in, and hand in only the
//!   messages of the round being run (`peekHeader().round`), buffering early
//!   ones. A party's own messages coming back are ignored.
//! - **A fresh session id** per presigning session, agreed by all signers.
//!   The id on the wire is `SHA-256(session_domain || sid || X || t ||
//!   signers)`, so a signer configured with another set or key is refused at
//!   the first header; it is bound into every message and every proof of this
//!   file.
//! - **Timeouts.** A peer that never sends is the caller's to detect; once
//!   the inbox is handed in, a missing message is a `missing_message` fault.
//! - **One presignature, one message.** `signShare` wipes `k_i`/`σ_i` and
//!   refuses a second call; a presignature must never be copied (two
//!   messages under one `R` reveal the key).

const std = @import("std");
const paillier = @import("paillier");
const root = @import("root.zig");
const mta = @import("mta.zig");
const zkproofs = @import("zkproofs.zig");
const ecproofs = @import("ecproofs.zig");
const signing = @import("signing.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Scalar = root.Scalar;
const Secp256k1 = root.Secp256k1;
const Element = root.Element;
const Ns = root.Ns;
const Ne = root.Ne;

pub const SessionId = [32]u8;

pub const wire_version: u8 = 1;
/// `version(1) || round(1) || sid(32) || from(4) || to(4)`; `to == 0` marks a
/// broadcast (party indices start at 1). From round 2 on, the payload starts
/// with the `echo_length`-byte broadcast transcript hash.
pub const header_length = 1 + 1 + 32 + 4 + 4;
/// Phase 7 messages carry this round number.
pub const sign_round: u8 = 7;

pub const gamma_commit_domain = "threshold_ecdsa/presign/gamma-commit/v1";
pub const session_domain = "threshold_ecdsa/presign/session/v1";
pub const transcript_domain = "threshold_ecdsa/presign/broadcast-transcript/v1";
/// Every message after round 1 starts its payload with the sender's running
/// hash of all broadcasts so far (see `Party.transcript`).
pub const echo_length = 32;

pub const Header = struct {
    round: u8,
    sid: SessionId,
    from: u32,
    /// `null`: broadcast.
    to: ?u32,

    fn write(self: Header, out: *[header_length]u8) void {
        out[0] = wire_version;
        out[1] = self.round;
        out[2..34].* = self.sid;
        std.mem.writeInt(u32, out[34..38], self.from, .big);
        std.mem.writeInt(u32, out[38..42], self.to orelse 0, .big);
    }
};

/// The header of a message, so the transport can check `from` against the
/// authenticated sender and route `to` before handing the bytes in.
pub fn peekHeader(bytes: []const u8) error{InvalidEncoding}!Header {
    if (bytes.len < header_length or bytes[0] != wire_version) return error.InvalidEncoding;
    const from = std.mem.readInt(u32, bytes[34..38], .big);
    const to = std.mem.readInt(u32, bytes[38..42], .big);
    if (from == 0) return error.InvalidEncoding;
    return .{ .round = bytes[1], .sid = bytes[2..34].*, .from = from, .to = if (to == 0) null else to };
}

pub const Fault = enum {
    /// A message that does not decode (bad header, bad length, bad field).
    malformed_message,
    /// Wrong session, wrong round, wrong recipient, or a sender outside the
    /// signing set.
    unexpected_message,
    duplicate_message,
    missing_message,
    /// A peer's published Paillier key or aux tuple failed the checks every
    /// prover runs before committing a secret under it (audit F1/F2/F3).
    invalid_peer_keys,
    /// Phase 2: range proof on `c_j` (type 1).
    range_proof,
    /// Phase 2: Bob's proof on the `k·γ` response (type 1).
    mta_proof,
    /// Phase 2: Bob's proof on the `k·w` response (type 1).
    mtawc_proof,
    /// Phase 3: proof of `(σ_j, ℓ_j)` behind `T_j` (type 2).
    pedersen_proof,
    /// Phase 4: `Γ_j` does not open `C_j` (type 3).
    gamma_decommitment,
    /// Phase 4: proof of `γ_j` (type 3).
    gamma_proof,
    /// Phase 5: proof that `R̄_j` matches `c_j` (type 4).
    pdl_proof,
    /// Phase 5: `Σ R̄_j ≠ G` with every proof valid (type 5, unattributed).
    r_bar_sum,
    /// Phase 6: proof that `S_j` and `T_j` share `σ_j` (type 6).
    st_proof,
    /// Phase 6: `Σ S_j ≠ X` with every proof valid (type 7, unattributed).
    s_sum,
    /// Phase 7: `s_j·R ≠ m·R̄_j + r·S_j` (type 8).
    sig_share,
    /// A peer's running hash of the broadcasts so far differs from this
    /// party's: someone showed different broadcasts to different signers (or
    /// lied about what it saw). Unattributed — the transport's signatures
    /// would be needed to tell which — but it stops the session BEFORE the
    /// inconsistent views make honest signers blame each other.
    equivocation,
    /// `δ = 0`, `R` = identity, `r = 0` or `s = 0` — probability ~2⁻²⁵⁶
    /// unless someone cheated in a way no single check pins on them.
    degenerate,
};

pub const Abort = struct {
    /// The party the fault is attributed to, or null (types 5 and 7, and
    /// `degenerate`).
    culprit: ?u32,
    fault: Fault,
};

pub const Error = std.mem.Allocator.Error || error{
    /// A check failed; `Party.abort` / the `abort` out-parameter says which.
    ProtocolAbort,
    /// A call out of order, or on a party that already aborted or finished.
    InvalidState,
    /// Bad local input: signer set, session, key share inconsistent with
    /// itself or with the public keys.
    InvalidParameters,
    /// `signShare` on a presignature that was already used.
    PresignatureUsed,
};

pub const Outgoing = struct {
    /// `null`: broadcast to every other signer.
    to: ?u32,
    bytes: []u8,
};

pub const Outbox = struct {
    messages: []Outgoing,

    pub fn deinit(self: Outbox, allocator: std.mem.Allocator) void {
        for (self.messages) |m| allocator.free(m.bytes);
        allocator.free(self.messages);
    }
};

const State = enum { round1, round2, round3, round4, round5, round6, finish, done, aborted };

/// `sid || u32 index`: the context every proof of `index` is bound to.
fn proofContext(sid: SessionId, index: u32) [36]u8 {
    var out: [36]u8 = undefined;
    out[0..32].* = sid;
    std.mem.writeInt(u32, out[32..36], index, .big);
    return out;
}

fn commitGamma(sid: SessionId, index: u32, big_gamma: Element, blind: [32]u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(gamma_commit_domain);
    h.update(&sid);
    var idx: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx, index, .big);
    h.update(&idx);
    h.update(&big_gamma.toBytes());
    h.update(&blind);
    return h.finalResult();
}

fn randomScalar(random: std.Random) Scalar {
    var buf: [48]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    random.bytes(&buf);
    return Scalar.fromBytes48(buf, .big);
}

/// `int(bytes32) mod q`, the reduction `std.crypto.sign.ecdsa` applies to
/// both the message digest and `R.x`, so `m` and `r` here are the values
/// std's verifier recomputes.
fn scalarFromHash32(bytes32: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    wide[16..48].* = bytes32;
    return Scalar.fromBytes48(wide, .big);
}

fn decodeScalar(bytes: [Ns]u8) ?Scalar {
    return Scalar.fromBytes(bytes, .big) catch null;
}

fn ciphertextBytes(c: paillier.Ciphertext) [paillier.modulus_sq_bytes]u8 {
    var buf: [paillier.modulus_sq_bytes]u8 = undefined;
    c.toBytes(&buf) catch unreachable; // fixed-width buffer
    return buf;
}

fn appendLenPrefixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) std.mem.Allocator.Error!void {
    var len_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &len_buf, @intCast(data.len), .big);
    try list.appendSlice(allocator, &len_buf);
    try list.appendSlice(allocator, data);
}

/// Reads one length-prefixed field; null when it runs off the end.
fn readLenPrefixed(bytes: []const u8, offset: *usize) ?[]const u8 {
    if (bytes.len - offset.* < 4) return null;
    const len = std.mem.readInt(u32, bytes[offset.*..][0..4], .big);
    offset.* += 4;
    if (bytes.len - offset.* < len) return null;
    const out = bytes[offset.*..][0..len];
    offset.* += len;
    return out;
}

/// What one signer knows about another (and about itself, at its own slot).
const Peer = struct {
    index: u32,
    pk: paillier.PublicKey,
    aux: root.AuxParams,
    /// `W_j = λ_j·X_j`.
    w_point: Element,
    commitment: [32]u8 = undefined,
    c_k: paillier.Ciphertext = undefined,
    delta: Scalar = undefined,
    t_point: Element = undefined,
    big_gamma: Element = undefined,
    r_bar: Element = undefined,
    s_point: Element = undefined,
};

/// The secret state of one signer. Wiped by `deinit`, by an abort, and when
/// it moves into the `Presignature`.
const Secrets = struct {
    k: Scalar,
    gamma: Scalar,
    w: Scalar,
    ell: Scalar,
    delta: Scalar,
    sigma: Scalar,
    gamma_blind: [32]u8,
    /// Paillier randomness of `c_k`: the range and PDL proofs' witness.
    r_k: paillier.Fe,
};

/// One signer's side of one GG20 presigning session.
pub const Party = struct {
    allocator: std.mem.Allocator,
    share: root.KeyShare,
    sid: SessionId,
    /// Ascending signer indices, owned.
    signers: []u32,
    /// Position of this party in `signers` (and in `peers`).
    me: usize,
    peers: []Peer,
    state: State = .round1,
    secrets: Secrets = undefined,
    r_point: Element = undefined,
    r: Scalar = undefined,
    /// Running hash of every broadcast this party has processed, its own
    /// included, in signer order. Sent at the head of every later message
    /// and compared on receipt: the in-protocol substitute for the reliable
    /// broadcast GG20 assumes (review F1, 2026-10-02).
    transcript: [32]u8 = undefined,
    /// Hash of this party's own broadcast payload of the current round.
    own_bc_hash: [32]u8 = undefined,
    /// Set when a call returns `error.ProtocolAbort`.
    abort: ?Abort = null,

    /// `signers` is the signing set (any order, no duplicates, containing
    /// `share.index`, at least `share.t` and at least 2 members); every
    /// signer must pass the same set and the same `sid`. Checks that the
    /// public keys cover every signer and that `Σ λ_j·X_j` over the set is
    /// the group key, so inconsistent key material fails here rather than
    /// as an unattributed abort later. `share` is borrowed: its
    /// `public_keys` must outlive the party.
    pub fn init(allocator: std.mem.Allocator, share: root.KeyShare, signers: []const u32, sid: SessionId) Error!Party {
        if (signers.len < 2 or signers.len < share.t or signers.len > share.n) return error.InvalidParameters;
        const sorted = try allocator.dupe(u32, signers);
        errdefer allocator.free(sorted);
        std.mem.sort(u32, sorted, {}, std.sort.asc(u32));
        for (sorted[1..], 0..) |s, i| if (s == sorted[i]) return error.InvalidParameters;
        if (sorted[0] == 0) return error.InvalidParameters;
        const me = std.mem.indexOfScalar(u32, sorted, share.index) orelse return error.InvalidParameters;
        for (sorted) |idx| {
            var count: usize = 0;
            for (share.public_keys.entries) |e| count += @intFromBool(e.index == idx);
            if (count != 1) return error.InvalidParameters;
        }

        const peers = try allocator.alloc(Peer, sorted.len);
        errdefer allocator.free(peers);
        var x_sum = Secp256k1.identityElement;
        for (sorted, peers) |idx, *p| {
            const pub_keys = share.public_keys.get(idx) orelse return error.InvalidParameters;
            const x_pt = pub_keys.verifying_share.point() catch return error.InvalidParameters;
            const lambda = signing.lagrangeCoefficient(sorted, idx);
            const w_pt = x_pt.mulPublic(lambda.toBytes(.big), .big) catch return error.InvalidParameters;
            x_sum = x_sum.add(w_pt);
            p.* = .{
                .index = idx,
                .pk = pub_keys.paillier_pk,
                .aux = pub_keys.aux,
                .w_point = Element.fromPoint(w_pt) catch return error.InvalidParameters,
            };
        }
        // This party's own share must be the one its public entry announces.
        const own_x = share.public_keys.get(share.index).?.verifying_share;
        if (!std.mem.eql(u8, &own_x.toBytes(), &share.verifying_share.toBytes())) return error.InvalidParameters;
        const x_g = Secp256k1.basePoint.mul(share.secret_share.toBytes(.big), .big) catch return error.InvalidParameters;
        if (!x_g.equivalent(own_x.point() catch return error.InvalidParameters)) return error.InvalidParameters;
        const group_pt = share.group_public_key.point() catch return error.InvalidParameters;
        if (!x_sum.equivalent(group_pt)) return error.InvalidParameters;

        // The session id on the wire binds the caller's `sid` to the group
        // key, the threshold and the signing set: signers configured with a
        // different set fail at the first header instead of later, at a proof
        // (review F7).
        var h = Sha256.init(.{});
        h.update(session_domain);
        h.update(&sid);
        h.update(&share.group_public_key.toBytes());
        var u: [4]u8 = undefined;
        std.mem.writeInt(u32, &u, share.t, .big);
        h.update(&u);
        for (sorted) |idx| {
            std.mem.writeInt(u32, &u, idx, .big);
            h.update(&u);
        }
        const ssid = h.finalResult();
        var t = Sha256.init(.{});
        t.update(transcript_domain);
        t.update(&ssid);
        return .{ .allocator = allocator, .share = share, .sid = ssid, .signers = sorted, .me = me, .peers = peers, .transcript = t.finalResult() };
    }

    pub fn deinit(self: *Party) void {
        self.wipe();
        std.crypto.secureZero(u8, std.mem.asBytes(&self.share.secret_share));
        self.share.paillier_secret.deinit();
        self.allocator.free(self.peers);
        self.allocator.free(self.signers);
        self.* = undefined;
    }

    fn wipe(self: *Party) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.secrets));
    }

    fn fail(self: *Party, culprit: ?u32, fault: Fault) error{ProtocolAbort} {
        self.abort = .{ .culprit = culprit, .fault = fault };
        self.state = .aborted;
        self.wipe();
        return error.ProtocolAbort;
    }

    fn myIndex(self: *const Party) u32 {
        return self.signers[self.me];
    }

    fn myCtx(self: *const Party) [36]u8 {
        return proofContext(self.sid, self.myIndex());
    }

    /// Runs the next round: hand in every message addressed to this party
    /// for the round just finished (empty for the first call). The returned
    /// messages are owned by the caller.
    /// Any error ends the party: an abort as described above, anything
    /// else (`OutOfMemory`, a misuse) with `abort == null` — the round's
    /// accumulators would be half-updated, so it cannot be retried.
    pub fn advance(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        const result = switch (self.state) {
            .round1 => if (inbox.len != 0) error.InvalidParameters else self.round1(random),
            .round2 => self.round2(inbox, random),
            .round3 => self.round3(inbox, random),
            .round4 => self.round4(inbox, random),
            .round5 => self.round5(inbox, random),
            .round6 => self.round6(inbox, random),
            .finish, .done, .aborted => return error.InvalidState,
        };
        return result catch |e| {
            self.state = .aborted;
            self.wipe();
            return e;
        };
    }

    // ── inbox handling ───────────────────────────────────────────────────

    const Slots = struct {
        broadcast: []?[]const u8,
        p2p: []?[]const u8,
    };

    /// Sorts `inbox` into one broadcast and/or one p2p payload per peer and
    /// requires every peer to have sent exactly what `round` calls for.
    fn collect(self: *Party, inbox: []const []const u8, round: u8, want_bc: bool, want_p2p: bool, slots: Slots) Error!void {
        @memset(slots.broadcast, null);
        @memset(slots.p2p, null);
        for (inbox) |msg| {
            const h = peekHeader(msg) catch return self.fail(null, .malformed_message);
            // A bus that hands a party its own broadcast back is not a fault.
            if (h.from == self.myIndex()) continue;
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse return self.fail(h.from, .unexpected_message);
            if (h.round != round or !std.mem.eql(u8, &h.sid, &self.sid)) return self.fail(h.from, .unexpected_message);
            var payload = msg[header_length..];
            if (round >= 2) {
                if (payload.len < echo_length) return self.fail(h.from, .malformed_message);
                if (!std.mem.eql(u8, payload[0..echo_length], &self.transcript)) return self.fail(null, .equivocation);
                payload = payload[echo_length..];
            }
            const slot = if (h.to) |to| blk: {
                if (to != self.myIndex() or !want_p2p) return self.fail(h.from, .unexpected_message);
                break :blk &slots.p2p[pos];
            } else blk: {
                if (!want_bc) return self.fail(h.from, .unexpected_message);
                break :blk &slots.broadcast[pos];
            };
            if (slot.* != null) return self.fail(h.from, .duplicate_message);
            slot.* = payload;
        }
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            if (want_bc and slots.broadcast[pos] == null) return self.fail(p.index, .missing_message);
            if (want_p2p and slots.p2p[pos] == null) return self.fail(p.index, .missing_message);
        }
        if (want_bc) {
            var t = Sha256.init(.{});
            t.update(&self.transcript);
            t.update(&[_]u8{round});
            for (slots.broadcast, 0..) |b, pos| {
                var d: [32]u8 = undefined;
                if (pos == self.me) d = self.own_bc_hash else Sha256.hash(b.?, &d, .{});
                t.update(&d);
            }
            self.transcript = t.finalResult();
        }
    }

    fn withSlots(self: *Party, comptime f: anytype, inbox: []const []const u8, random: std.Random) Error!Outbox {
        const bc = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(p2p);
        return f(self, inbox, .{ .broadcast = bc, .p2p = p2p }, random);
    }

    const OutboxBuilder = struct {
        list: std.ArrayList(Outgoing) = .empty,
        allocator: std.mem.Allocator,

        fn deinit(self: *OutboxBuilder) void {
            for (self.list.items) |m| self.allocator.free(m.bytes);
            self.list.deinit(self.allocator);
        }

        fn add(self: *OutboxBuilder, party: *Party, round: u8, to: ?u32, payload: []const u8) std.mem.Allocator.Error!void {
            const echo: usize = if (round >= 2) echo_length else 0;
            const bytes = try self.allocator.alloc(u8, header_length + echo + payload.len);
            errdefer self.allocator.free(bytes);
            (Header{ .round = round, .sid = party.sid, .from = party.myIndex(), .to = to }).write(bytes[0..header_length]);
            if (echo != 0) bytes[header_length..][0..echo_length].* = party.transcript;
            @memcpy(bytes[header_length + echo ..], payload);
            if (to == null) Sha256.hash(payload, &party.own_bc_hash, .{});
            try self.list.append(self.allocator, .{ .to = to, .bytes = bytes });
        }

        fn finish(self: *OutboxBuilder) std.mem.Allocator.Error!Outbox {
            return .{ .messages = try self.list.toOwnedSlice(self.allocator) };
        }
    };

    /// Maps an error from proving under peer `j`'s keys: a refused key or
    /// tuple is `j`'s fault, anything else propagates.
    fn proveFailed(self: *Party, j: u32, err: anyerror) Error {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => self.fail(j, .invalid_peer_keys),
        };
    }

    // ── Phase 1 ──────────────────────────────────────────────────────────

    fn round1(self: *Party, random: std.Random) Error!Outbox {
        const me = &self.peers[self.me];
        // This party's own Paillier key and aux tuple get the checks every
        // peer will run on them, so a bad local key fails here instead of
        // blaming an honest peer later (review F3).
        me.aux.validate(random) catch return error.InvalidParameters;
        if (!root.paillierNMeetsFloor(me.pk) or !root.paillierGeneratorIsStandard(me.pk)) return error.InvalidParameters;
        const lambda = signing.lagrangeCoefficient(self.signers, me.index);
        self.secrets = .{
            .k = randomScalar(random),
            .gamma = randomScalar(random),
            .w = lambda.mul(self.share.secret_share),
            .ell = Scalar.zero,
            .delta = Scalar.zero,
            .sigma = Scalar.zero,
            .gamma_blind = undefined,
            .r_k = undefined,
        };
        random.bytes(&self.secrets.gamma_blind);
        while (true) {
            const pt = Secp256k1.basePoint.mul(self.secrets.gamma.toBytes(.big), .big) catch {
                self.secrets.gamma = randomScalar(random);
                continue;
            };
            me.big_gamma = Element.fromPoint(pt) catch unreachable;
            break;
        }
        me.commitment = commitGamma(self.sid, me.index, me.big_gamma, self.secrets.gamma_blind);
        const init_k = mta.mtaAliceInitChecked(self.secrets.k, me.pk, random) catch return self.fail(me.index, .invalid_peer_keys);
        me.c_k = init_k.c_a;
        self.secrets.r_k = init_k.r_a;

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();

        var bc: [32 + 4 + paillier.modulus_sq_bytes]u8 = undefined;
        bc[0..32].* = me.commitment;
        std.mem.writeInt(u32, bc[32..36], paillier.modulus_sq_bytes, .big);
        bc[36..].* = ciphertextBytes(me.c_k);
        try out.add(self, 1, null, &bc);

        const my_ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const proof = zkproofs.proveAliceRange(self.allocator, self.secrets.k, self.secrets.r_k, me.pk, p.aux, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer proof.deinit(self.allocator);
            const bytes = proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(bytes);
            try out.add(self, 1, p.index, bytes);
        }
        self.state = .round2;
        return out.finish();
    }

    // ── Phase 2 ──────────────────────────────────────────────────────────

    fn round2(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round2Inner, inbox, random);
    }

    fn round2Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 1, true, true, slots);
        const me = &self.peers[self.me];
        const ctx_me = me.*;

        // Every range proof first: nothing is computed on a ciphertext whose
        // proof has not been checked.
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const bc = slots.broadcast[pos].?;
            if (bc.len < 32) return self.fail(p.index, .malformed_message);
            p.commitment = bc[0..32].*;
            var off: usize = 32;
            const c_bytes = readLenPrefixed(bc, &off) orelse return self.fail(p.index, .malformed_message);
            if (off != bc.len) return self.fail(p.index, .malformed_message);
            p.c_k = paillier.Ciphertext.fromBytes(p.pk, c_bytes) catch return self.fail(p.index, .malformed_message);

            const proof = zkproofs.RangeProof.fromBytesAlloc(self.allocator, ctx_me.aux.n_tilde, p.pk, slots.p2p[pos].?) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer proof.deinit(self.allocator);
            const p_ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyAliceRange(proof, p.c_k, p.pk, ctx_me.aux, &p_ctx)) return self.fail(p.index, .range_proof);
        }

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);

        const my_ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            payload.clearRetainingCapacity();

            // MtA for k_j·γ_i: this party is Bob.
            var g = mta.mtaBobResponseChecked(self.secrets.gamma, p.c_k, p.pk, random) catch |e| return self.proveFailed(p.index, e);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&g));
            const g_proof = zkproofs.proveBobMta(self.allocator, self.secrets.gamma, &g.beta_prime, g.r_b, p.c_k, g.c_b, p.pk, p.aux, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer g_proof.deinit(self.allocator);

            // MtAwc for k_j·w_i, bound to W_i.
            var x = mta.mtaBobResponseChecked(self.secrets.w, p.c_k, p.pk, random) catch |e| return self.proveFailed(p.index, e);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
            const x_proof = zkproofs.proveBobMtaWc(self.allocator, self.secrets.w, &x.beta_prime, x.r_b, p.c_k, x.c_b, p.pk, p.aux, me.w_point, &my_ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer x_proof.deinit(self.allocator);

            self.secrets.delta = self.secrets.delta.add(g.beta);
            self.secrets.sigma = self.secrets.sigma.add(x.beta);

            try appendLenPrefixed(&payload, self.allocator, &ciphertextBytes(g.c_b));
            const gp = g_proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(gp);
            try appendLenPrefixed(&payload, self.allocator, gp);
            try appendLenPrefixed(&payload, self.allocator, &ciphertextBytes(x.c_b));
            const xp = x_proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(xp);
            try appendLenPrefixed(&payload, self.allocator, xp);
            try out.add(self, 2, p.index, payload.items);
        }
        self.state = .round3;
        return out.finish();
    }

    // ── Phase 3 ──────────────────────────────────────────────────────────

    fn round3(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round3Inner, inbox, random);
    }

    fn round3Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 2, false, true, slots);
        const me = &self.peers[self.me];
        const sk = self.share.paillier_secret;

        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const msg = slots.p2p[pos].?;
            var off: usize = 0;
            const cg_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const gp_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const cx_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            const xp_bytes = readLenPrefixed(msg, &off) orelse return self.fail(p.index, .malformed_message);
            if (off != msg.len) return self.fail(p.index, .malformed_message);
            const c_g = paillier.Ciphertext.fromBytes(me.pk, cg_bytes) catch return self.fail(p.index, .malformed_message);
            const c_x = paillier.Ciphertext.fromBytes(me.pk, cx_bytes) catch return self.fail(p.index, .malformed_message);
            const g_proof = zkproofs.MtaProof.fromBytesAlloc(self.allocator, me.aux.n_tilde, me.pk, gp_bytes) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer g_proof.deinit(self.allocator);
            const x_proof = zkproofs.MtaProofWc.fromBytesAlloc(self.allocator, me.aux.n_tilde, me.pk, xp_bytes) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer x_proof.deinit(self.allocator);

            const p_ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyBobMta(g_proof, me.c_k, c_g, me.pk, me.aux, &p_ctx)) return self.fail(p.index, .mta_proof);
            if (!zkproofs.verifyBobMtaWc(x_proof, me.c_k, c_x, me.pk, me.aux, p.w_point, &p_ctx)) return self.fail(p.index, .mtawc_proof);
            var alpha = mta.mtaAliceFinalizeVerified(c_g, sk) catch return self.fail(p.index, .mta_proof);
            var mu = mta.mtaAliceFinalizeVerified(c_x, sk) catch return self.fail(p.index, .mtawc_proof);
            self.secrets.delta = self.secrets.delta.add(alpha);
            self.secrets.sigma = self.secrets.sigma.add(mu);
            std.crypto.secureZero(u8, std.mem.asBytes(&alpha));
            std.crypto.secureZero(u8, std.mem.asBytes(&mu));
        }
        self.secrets.delta = self.secrets.delta.add(self.secrets.k.mul(self.secrets.gamma));
        self.secrets.sigma = self.secrets.sigma.add(self.secrets.k.mul(self.secrets.w));

        while (true) {
            self.secrets.ell = randomScalar(random);
            me.t_point = ecproofs.pedersenCommit(self.secrets.sigma, self.secrets.ell) catch continue;
            break;
        }
        me.delta = self.secrets.delta;
        const ctx = self.myCtx();
        const proof = ecproofs.provePedersen(self.secrets.sigma, self.secrets.ell, me.t_point, &ctx, random);

        var payload: [Ns + Ne + ecproofs.PedersenProof.encoded_length]u8 = undefined;
        payload[0..Ns].* = me.delta.toBytes(.big);
        payload[Ns..][0..Ne].* = me.t_point.toBytes();
        payload[Ns + Ne ..].* = proof.toBytes();

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 3, null, &payload);
        self.state = .round4;
        return out.finish();
    }

    // ── Phase 4 ──────────────────────────────────────────────────────────

    fn round4(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round4Inner, inbox, random);
    }

    fn round4Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 3, true, false, slots);
        const len = Ns + Ne + ecproofs.PedersenProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = slots.broadcast[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.delta = decodeScalar(msg[0..Ns].*) orelse return self.fail(p.index, .malformed_message);
            p.t_point = Element.fromBytes(msg[Ns..][0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = ecproofs.PedersenProof.fromBytes(msg[Ns + Ne ..][0..ecproofs.PedersenProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifyPedersen(proof, p.t_point, &ctx)) return self.fail(p.index, .pedersen_proof);
        }

        const me = &self.peers[self.me];
        const ctx = self.myCtx();
        const proof = ecproofs.proveSchnorr(self.secrets.gamma, me.big_gamma, &ctx, random);
        var payload: [Ne + 32 + ecproofs.SchnorrProof.encoded_length]u8 = undefined;
        payload[0..Ne].* = me.big_gamma.toBytes();
        payload[Ne..][0..32].* = self.secrets.gamma_blind;
        payload[Ne + 32 ..].* = proof.toBytes();

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 4, null, &payload);
        self.state = .round5;
        return out.finish();
    }

    // ── Phase 5 ──────────────────────────────────────────────────────────

    fn round5(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round5Inner, inbox, random);
    }

    fn round5Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 4, true, false, slots);
        const len = Ne + 32 + ecproofs.SchnorrProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = slots.broadcast[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.big_gamma = Element.fromBytes(msg[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const blind = msg[Ne..][0..32].*;
            const proof = ecproofs.SchnorrProof.fromBytes(msg[Ne + 32 ..][0..ecproofs.SchnorrProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            if (!std.mem.eql(u8, &commitGamma(self.sid, p.index, p.big_gamma, blind), &p.commitment))
                return self.fail(p.index, .gamma_decommitment);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifySchnorr(proof, p.big_gamma, &ctx)) return self.fail(p.index, .gamma_proof);
        }

        // δ = Σ δ_j, Γ = Σ Γ_j, R = δ⁻¹·Γ, r = R.x mod q.
        var delta = Scalar.zero;
        var gamma_sum = Secp256k1.identityElement;
        for (self.peers) |p| {
            delta = delta.add(p.delta);
            gamma_sum = gamma_sum.add(p.big_gamma.point() catch unreachable);
        }
        if (delta.isZero()) return self.fail(null, .degenerate);
        const r_full = gamma_sum.mulPublic(delta.invert().toBytes(.big), .big) catch return self.fail(null, .degenerate);
        self.r_point = Element.fromPoint(r_full) catch return self.fail(null, .degenerate);
        self.r = scalarFromHash32(r_full.affineCoordinates().x.toBytes(.big));
        if (self.r.isZero()) return self.fail(null, .degenerate);

        const me = &self.peers[self.me];
        const r_bar_pt = r_full.mul(self.secrets.k.toBytes(.big), .big) catch return self.fail(null, .degenerate);
        me.r_bar = Element.fromPoint(r_bar_pt) catch return self.fail(null, .degenerate);

        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 5, null, &me.r_bar.toBytes());
        const ctx = self.myCtx();
        for (self.peers, 0..) |p, pos| {
            if (pos == self.me) continue;
            const proof = zkproofs.provePdl(self.allocator, self.secrets.k, self.secrets.r_k, me.pk, p.aux, self.r_point, me.r_bar, &ctx, random) catch |e|
                return self.proveFailed(p.index, e);
            defer proof.deinit(self.allocator);
            const bytes = proof.toBytesAlloc(self.allocator) catch |e| return if (e == error.OutOfMemory) error.OutOfMemory else unreachable;
            defer self.allocator.free(bytes);
            try out.add(self, 5, p.index, bytes);
        }
        self.state = .round6;
        return out.finish();
    }

    // ── Phase 6 ──────────────────────────────────────────────────────────

    fn round6(self: *Party, inbox: []const []const u8, random: std.Random) Error!Outbox {
        return self.withSlots(round6Inner, inbox, random);
    }

    fn round6Inner(self: *Party, inbox: []const []const u8, slots: Slots, random: std.Random) Error!Outbox {
        try self.collect(inbox, 5, true, true, slots);
        const me = &self.peers[self.me];
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const bc = slots.broadcast[pos].?;
            if (bc.len != Ne) return self.fail(p.index, .malformed_message);
            p.r_bar = Element.fromBytes(bc[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = zkproofs.PdlProof.fromBytesAlloc(self.allocator, me.aux.n_tilde, p.pk, slots.p2p[pos].?) catch |e|
                return if (e == error.OutOfMemory) error.OutOfMemory else self.fail(p.index, .malformed_message);
            defer proof.deinit(self.allocator);
            const ctx = proofContext(self.sid, p.index);
            if (!zkproofs.verifyPdl(proof, p.c_k, p.pk, me.aux, self.r_point, p.r_bar, &ctx)) return self.fail(p.index, .pdl_proof);
        }
        var r_bar_sum = Secp256k1.identityElement;
        for (self.peers) |p| r_bar_sum = r_bar_sum.add(p.r_bar.point() catch unreachable);
        if (!r_bar_sum.equivalent(Secp256k1.basePoint)) return self.fail(null, .r_bar_sum);

        const r_pt = self.r_point.point() catch unreachable;
        const s_pt = r_pt.mul(self.secrets.sigma.toBytes(.big), .big) catch return self.fail(null, .degenerate);
        me.s_point = Element.fromPoint(s_pt) catch return self.fail(null, .degenerate);
        const ctx = self.myCtx();
        const proof = ecproofs.proveSt(self.secrets.sigma, self.secrets.ell, self.r_point, me.s_point, me.t_point, &ctx, random) catch unreachable;

        var payload: [Ne + ecproofs.StProof.encoded_length]u8 = undefined;
        payload[0..Ne].* = me.s_point.toBytes();
        payload[Ne..].* = proof.toBytes();
        var out: OutboxBuilder = .{ .allocator = self.allocator };
        errdefer out.deinit();
        try out.add(self, 6, null, &payload);
        self.state = .finish;
        return out.finish();
    }

    // ── end of presigning ────────────────────────────────────────────────

    /// Consumes the Phase-6 messages, checks `Σ S_j = X`, and moves this
    /// party's secrets into the returned `Presignature` (the party keeps
    /// none; only `deinit` remains to be called on it).
    pub fn finish(self: *Party, inbox: []const []const u8) Error!Presignature {
        if (self.state != .finish) return error.InvalidState;
        return self.finishInner(inbox) catch |e| {
            self.state = .aborted;
            self.wipe();
            return e;
        };
    }

    fn finishInner(self: *Party, inbox: []const []const u8) Error!Presignature {
        const bc = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(bc);
        const p2p = try self.allocator.alloc(?[]const u8, self.peers.len);
        defer self.allocator.free(p2p);
        try self.collect(inbox, 6, true, false, .{ .broadcast = bc, .p2p = p2p });

        const len = Ne + ecproofs.StProof.encoded_length;
        for (self.peers, 0..) |*p, pos| {
            if (pos == self.me) continue;
            const msg = bc[pos].?;
            if (msg.len != len) return self.fail(p.index, .malformed_message);
            p.s_point = Element.fromBytes(msg[0..Ne].*) catch return self.fail(p.index, .malformed_message);
            const proof = ecproofs.StProof.fromBytes(msg[Ne..][0..ecproofs.StProof.encoded_length].*) catch
                return self.fail(p.index, .malformed_message);
            const ctx = proofContext(self.sid, p.index);
            if (!ecproofs.verifySt(proof, self.r_point, p.s_point, p.t_point, &ctx)) return self.fail(p.index, .st_proof);
        }
        var s_sum = Secp256k1.identityElement;
        for (self.peers) |p| s_sum = s_sum.add(p.s_point.point() catch unreachable);
        if (!s_sum.equivalent(self.share.group_public_key.point() catch unreachable)) return self.fail(null, .s_sum);

        const signers = try self.allocator.dupe(u32, self.signers);
        errdefer self.allocator.free(signers);
        const r_bar = try self.allocator.alloc(Element, self.peers.len);
        errdefer self.allocator.free(r_bar);
        const s_points = try self.allocator.alloc(Element, self.peers.len);
        for (self.peers, r_bar, s_points) |p, *rb, *sp| {
            rb.* = p.r_bar;
            sp.* = p.s_point;
        }
        const presig: Presignature = .{
            .public = .{
                .allocator = self.allocator,
                .sid = self.sid,
                .group_public_key = self.share.group_public_key,
                .signers = signers,
                .r_point = self.r_point,
                .r = self.r,
                .r_bar = r_bar,
                .s_points = s_points,
                .transcript = self.transcript,
            },
            .index = self.myIndex(),
            .k = self.secrets.k,
            .sigma = self.secrets.sigma,
        };
        self.wipe();
        self.state = .done;
        return presig;
    }
};

/// The message to sign: raw bytes (hashed with SHA-256, as
/// `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256` does) or a 32-byte digest
/// the caller computed.
pub const Message = union(enum) {
    bytes: []const u8,
    prehashed: [32]u8,

    fn scalar(self: Message) Scalar {
        return switch (self) {
            .bytes => |b| blk: {
                var digest: [32]u8 = undefined;
                Sha256.hash(b, &digest, .{});
                break :blk scalarFromHash32(digest);
            },
            .prehashed => |d| scalarFromHash32(d),
        };
    }
};

/// Everything about a presignature that is not secret: enough to combine
/// the Phase-7 shares and to name a signer whose share is wrong.
pub const PresignaturePublic = struct {
    allocator: std.mem.Allocator,
    sid: SessionId,
    group_public_key: Element,
    /// Ascending, owned.
    signers: []u32,
    r_point: Element,
    r: Scalar,
    /// `R̄_j = k_j·R`, by position in `signers`, owned.
    r_bar: []Element,
    /// `S_j = σ_j·R`, by position in `signers`, owned.
    s_points: []Element,
    /// The broadcast transcript hash every signer ended presigning with;
    /// carried by every Phase-7 share and compared in `combine`.
    transcript: [32]u8,

    pub fn deinit(self: *PresignaturePublic) void {
        self.allocator.free(self.signers);
        self.allocator.free(self.r_bar);
        self.allocator.free(self.s_points);
        self.* = undefined;
    }

    /// Phase 7: checks every share against `s_j·R == m·R̄_j + r·S_j`
    /// (naming the first signer whose share fails, fault `sig_share`), sums
    /// them, normalises to low-S and verifies the result under the group key
    /// with std ECDSA. `shares` must hold exactly one Phase-7 message from
    /// EVERY signer — the caller's own share too, when the caller signed. The
    /// header's `from` is trusted here as everywhere: the transport
    /// authenticates it.
    pub fn combine(self: *const PresignaturePublic, message: Message, shares: []const []const u8, abort: *?Abort) Error!signing.Signature {
        abort.* = null;
        const found = try self.allocator.alloc(?Scalar, self.signers.len);
        defer self.allocator.free(found);
        @memset(found, null);
        for (shares) |msg| {
            const h = peekHeader(msg) catch return failCombine(abort, null, .malformed_message);
            const pos = std.mem.indexOfScalar(u32, self.signers, h.from) orelse return failCombine(abort, h.from, .unexpected_message);
            if (h.round != sign_round or h.to != null or !std.mem.eql(u8, &h.sid, &self.sid)) return failCombine(abort, h.from, .unexpected_message);
            if (msg.len != header_length + echo_length + Ns) return failCombine(abort, h.from, .malformed_message);
            if (found[pos] != null) return failCombine(abort, h.from, .duplicate_message);
            if (!std.mem.eql(u8, msg[header_length..][0..echo_length], &self.transcript)) return failCombine(abort, null, .equivocation);
            found[pos] = decodeScalar(msg[header_length + echo_length ..][0..Ns].*) orelse return failCombine(abort, h.from, .malformed_message);
        }
        const m = message.scalar();
        const r_pt = self.r_point.point() catch unreachable;
        var s = Scalar.zero;
        for (found, self.signers, 0..) |maybe, idx, pos| {
            const s_j = maybe orelse return failCombine(abort, idx, .missing_message);
            // s_j·R == m·R̄_j + r·S_j (GG20 §4.2, equation 1).
            const lhs = r_pt.mulPublic(s_j.toBytes(.big), .big) catch return failCombine(abort, idx, .sig_share);
            const rb = self.r_bar[pos].point() catch unreachable;
            const sp = self.s_points[pos].point() catch unreachable;
            const m_rb = rb.mulPublic(m.toBytes(.big), .big) catch Secp256k1.identityElement;
            const r_sp = sp.mulPublic(self.r.toBytes(.big), .big) catch unreachable; // r ≠ 0
            if (!lhs.equivalent(m_rb.add(r_sp))) return failCombine(abort, idx, .sig_share);
            s = s.add(s_j);
        }
        if (s.isZero()) return failCombine(abort, null, .degenerate);
        const neg = s.neg();
        const s_low = if (std.mem.order(u8, &s.toBytes(.big), &neg.toBytes(.big)) == .gt) neg else s;
        const sig: signing.Signature = .{ .r = self.r.toBytes(.big), .s = s_low.toBytes(.big) };

        const pk = signing.ecdsa.PublicKey.fromSec1(&self.group_public_key.toBytes()) catch return failCombine(abort, null, .degenerate);
        const ok = switch (message) {
            .bytes => |b| sig.verify(b, pk),
            .prehashed => |d| sig.verifyPrehashed(d, pk),
        };
        ok catch return failCombine(abort, null, .degenerate);
        return sig;
    }
};

fn failCombine(abort: *?Abort, culprit: ?u32, fault: Fault) error{ProtocolAbort} {
    abort.* = .{ .culprit = culprit, .fault = fault };
    return error.ProtocolAbort;
}

/// One signer's presignature: the public half plus its secret `k_i`, `σ_i`.
/// Use exactly once (`signShare`); never copy it.
pub const Presignature = struct {
    public: PresignaturePublic,
    index: u32,
    k: Scalar,
    sigma: Scalar,
    used: bool = false,

    /// Phase 7: `s_i = m·k_i + r·σ_i` as a broadcast message (owned by the
    /// caller). Wipes `k_i`, `σ_i`; a second call is `PresignatureUsed`.
    pub fn signShare(self: *Presignature, message: Message) Error![]u8 {
        if (self.used) return error.PresignatureUsed;
        self.used = true;
        defer self.wipe();
        const s_i = message.scalar().mul(self.k).add(self.public.r.mul(self.sigma));
        const bytes = try self.public.allocator.alloc(u8, header_length + echo_length + Ns);
        (Header{ .round = sign_round, .sid = self.public.sid, .from = self.index, .to = null }).write(bytes[0..header_length]);
        bytes[header_length..][0..echo_length].* = self.public.transcript;
        bytes[header_length + echo_length ..][0..Ns].* = s_i.toBytes(.big);
        return bytes;
    }

    fn wipe(self: *Presignature) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.k));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.sigma));
    }

    pub fn deinit(self: *Presignature) void {
        self.wipe();
        self.public.deinit();
        self.* = undefined;
    }
};

// ── tests ────────────────────────────────────────────────────────────────
//
// The decisive net is adversarial: one signer (the "cheater", position 1)
// deviates in exactly one way, and every honest signer must abort naming the
// fault — and the cheater, wherever GG20 §4.2 can attribute it. Deviations
// are injected into the cheater's outgoing bytes (and, where a consistent
// cheater would also change its own view, into its state), so each case is
// what a real malicious peer could send.

const testing = std.testing;
const builtin = @import("builtin");

const Case = enum {
    honest,
    range_proof,
    mta_swap,
    mtawc_swap,
    delta_shift,
    pedersen_proof,
    gamma_swap,
    gamma_blind,
    gamma_proof,
    pdl_proof,
    r_bar_swap,
    st_proof,
    sigma_shift,
    missing,
    duplicate,
    wrong_sid,
    wrong_round,
    misaddressed,
    truncated,
    equivocate,
};

const Observed = struct { observer: u32, abort: Abort };

const SessionResult = struct {
    presigs: []Presignature,
    aborts: []Observed,

    fn deinit(self: *SessionResult, allocator: std.mem.Allocator) void {
        for (self.presigs) |*p| p.deinit();
        allocator.free(self.presigs);
        allocator.free(self.aborts);
    }
};

fn flipLast(bytes: []u8) void {
    bytes[bytes.len - 1] ^= 0x01;
}

/// Swaps the first and third length-prefixed fields of a Phase-2 payload
/// (`c_γ` and `c_w`), or puts the first in place of the third (`both_first`).
fn rewriteRound2(allocator: std.mem.Allocator, msg: []u8, both_first: bool) !void {
    const payload = msg[header_length + echo_length ..];
    var off: usize = 0;
    var fields: [4][]const u8 = undefined;
    for (&fields) |*f| f.* = readLenPrefixed(payload, &off).?;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);
    const order = if (both_first) [4][]const u8{ fields[0], fields[1], fields[0], fields[3] } else [4][]const u8{ fields[2], fields[1], fields[0], fields[3] };
    for (order) |f| try appendLenPrefixed(&list, allocator, f);
    try testing.expectEqual(payload.len, list.items.len); // ciphertexts are fixed-width
    @memcpy(payload, list.items);
}

/// Drives one presigning session over `shares` with the cheater at position
/// 1 deviating per `case`; returns the presignatures (honest run) or every
/// abort seen in the round where the first one happened.
fn runSession(allocator: std.mem.Allocator, shares: []const root.KeyShare, random: std.Random, case: Case) !SessionResult {
    const t = shares.len;
    var indices: [8]u32 = undefined;
    for (shares, 0..) |s, i| indices[i] = s.index;
    var sid: SessionId = undefined;
    random.bytes(&sid);

    var parties: [8]Party = undefined;
    for (0..t) |i| parties[i] = try Party.init(allocator, shares[i], indices[0..t], sid);
    defer for (parties[0..t]) |*p| p.deinit();
    const cheat = indices[1];
    const cheat_pos = for (parties[0..t], 0..) |p, i| {
        if (p.myIndex() == cheat) break i;
    } else unreachable;

    var inboxes: [8]std.ArrayList([]const u8) = @splat(.empty);
    defer for (&inboxes) |*b| b.deinit(allocator);
    var boxes: [8]?Outbox = @splat(null);
    defer for (boxes) |b| if (b) |o| o.deinit(allocator);
    var aborts: std.ArrayList(Observed) = .empty;
    defer aborts.deinit(allocator);
    var copies: std.ArrayList([]u8) = .empty;
    defer {
        for (copies.items) |c| allocator.free(c);
        copies.deinit(allocator);
    }

    for (1..7) |round| {
        var next: [8]?Outbox = @splat(null);
        errdefer for (next) |b| if (b) |o| o.deinit(allocator);
        for (0..t) |i| {
            if (case == .sigma_shift and round == 3 and i == cheat_pos)
                parties[i].secrets.sigma = parties[i].secrets.sigma.add(Scalar.one);
            next[i] = parties[i].advance(inboxes[i].items, random) catch |e| switch (e) {
                error.ProtocolAbort => blk: {
                    try aborts.append(allocator, .{ .observer = parties[i].myIndex(), .abort = parties[i].abort.? });
                    // An abort wipes the secrets.
                    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&parties[i].secrets), 0));
                    break :blk null;
                },
                else => return e,
            };
        }
        for (boxes) |b| if (b) |o| o.deinit(allocator);
        boxes = next;
        if (aborts.items.len != 0) return .{ .presigs = try allocator.alloc(Presignature, 0), .aborts = try aborts.toOwnedSlice(allocator) };

        // The cheater's deviation, on its outgoing bytes.
        for (boxes[cheat_pos].?.messages) |m| {
            const r: u8 = @intCast(round);
            switch (case) {
                .range_proof => if (r == 1 and m.to != null) flipLast(m.bytes),
                .mta_swap => if (r == 2) try rewriteRound2(allocator, m.bytes, false),
                .mtawc_swap => if (r == 2) try rewriteRound2(allocator, m.bytes, true),
                .delta_shift => if (r == 3) {
                    const me = &parties[cheat_pos].peers[parties[cheat_pos].me];
                    me.delta = me.delta.add(Scalar.one);
                    m.bytes[header_length + echo_length ..][0..Ns].* = me.delta.toBytes(.big);
                    // A consistent liar hashes what it actually sent.
                    Sha256.hash(m.bytes[header_length + echo_length ..], &parties[cheat_pos].own_bc_hash, .{});
                },
                .pedersen_proof => if (r == 3) flipLast(m.bytes),
                .gamma_swap => if (r == 4) {
                    m.bytes[header_length + echo_length ..][0..Ne].* = (Element.fromPoint(Secp256k1.basePoint) catch unreachable).toBytes();
                },
                .gamma_blind => if (r == 4) {
                    m.bytes[header_length + echo_length + Ne] ^= 0x01;
                },
                .gamma_proof => if (r == 4) flipLast(m.bytes),
                .pdl_proof => if (r == 5 and m.to != null) {
                    m.bytes[m.bytes.len - Ne - 1] ^= 0x01; // last byte of the range proof's s2
                },
                .r_bar_swap => if (r == 5 and m.to == null) {
                    m.bytes[header_length + echo_length ..][0..Ne].* = (Element.fromPoint(Secp256k1.basePoint) catch unreachable).toBytes();
                },
                .st_proof => if (r == 6) flipLast(m.bytes),
                .wrong_sid => if (r == 2) {
                    m.bytes[2] ^= 0x01;
                },
                .wrong_round => if (r == 1 and m.to == null) {
                    m.bytes[1] = 2;
                },
                .misaddressed => if (r == 1 and m.to != null) {
                    std.mem.writeInt(u32, m.bytes[38..42], 9999, .big);
                },
                else => {},
            }
        }

        for (&inboxes) |*b| b.clearRetainingCapacity();
        for (0..t) |from| {
            for (boxes[from].?.messages) |m| {
                for (0..t) |to| {
                    // Every party also gets its own broadcasts back, as from a
                    // bus: they must be ignored, not taken as a fault.
                    if (to == from and m.to != null) continue;
                    if (m.to) |dst| if (dst != parties[to].myIndex()) continue;
                    const deliver = from == cheat_pos and to != cheat_pos;
                    // Equivocation: the last signer gets a different δ than
                    // everyone else, on a broadcast whose proof does not cover δ.
                    if (deliver and case == .equivocate and round == 3 and m.to == null and to == t - 1) {
                        const copy = try allocator.dupe(u8, m.bytes);
                        try copies.append(allocator, copy);
                        const at = header_length + echo_length;
                        const d = Scalar.fromBytes(copy[at..][0..Ns].*, .big) catch unreachable;
                        copy[at..][0..Ns].* = d.add(Scalar.one).toBytes(.big);
                        try inboxes[to].append(allocator, copy);
                        continue;
                    }
                    if (deliver and case == .missing and round == 3) continue;
                    if (deliver and case == .truncated and round == 4) {
                        try inboxes[to].append(allocator, m.bytes[0 .. m.bytes.len - 1]);
                        continue;
                    }
                    try inboxes[to].append(allocator, m.bytes);
                    if (deliver and case == .duplicate and round == 4) try inboxes[to].append(allocator, m.bytes);
                }
            }
        }
    }

    const presigs = try allocator.alloc(Presignature, t);
    var ok: [8]bool = @splat(false);
    errdefer {
        for (presigs, ok[0..t]) |*p, made| if (made) p.deinit();
        allocator.free(presigs);
    }
    for (0..t) |i| {
        presigs[i] = parties[i].finish(inboxes[i].items) catch |e| switch (e) {
            error.ProtocolAbort => {
                try aborts.append(allocator, .{ .observer = parties[i].myIndex(), .abort = parties[i].abort.? });
                continue;
            },
            else => return e,
        };
        ok[i] = true;
    }
    if (aborts.items.len != 0) {
        for (presigs, ok[0..t]) |*p, made| if (made) p.deinit();
        allocator.free(presigs);
        return .{ .presigs = try allocator.alloc(Presignature, 0), .aborts = try aborts.toOwnedSlice(allocator) };
    }
    return .{ .presigs = presigs, .aborts = try aborts.toOwnedSlice(allocator) };
}

fn expectLowS(sig: signing.Signature) !void {
    const s = try Scalar.fromBytes(sig.s, .big);
    try testing.expect(std.mem.order(u8, &sig.s, &s.neg().toBytes(.big)) != .gt);
}

/// Signs `message` with every presignature, combines with the first one's
/// public half.
fn signAll(allocator: std.mem.Allocator, presigs: []Presignature, message: Message, abort: *?Abort) !signing.Signature {
    var shares: [8][]u8 = undefined;
    for (presigs, 0..) |*p, i| shares[i] = try p.signShare(message);
    defer for (shares[0..presigs.len]) |s| allocator.free(s);
    return presigs[0].public.combine(message, shares[0..presigs.len], abort);
}

test "presign: per-signer state machines, 2-of-3 and 3-of-3, sign bytes and a prehashed digest; std ECDSA verifies" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7072_6573_6967_6e31);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const pk = try signing.ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());

    // 2-of-3 over shares {3, 1} (out of order on purpose).
    {
        var res = try runSession(allocator, &[_]root.KeyShare{ kg.key_shares[2], kg.key_shares[0] }, random, .honest);
        defer res.deinit(allocator);
        try testing.expectEqual(@as(usize, 0), res.aborts.len);
        var abort: ?Abort = null;
        const sig = try signAll(allocator, res.presigs, .{ .bytes = "presigned, then signed" }, &abort);
        try sig.verify("presigned, then signed", pk);
        try expectLowS(sig);
        try testing.expect(abort == null);
        // A presignature signs once.
        try testing.expectError(error.PresignatureUsed, res.presigs[0].signShare(.{ .bytes = "again" }));
    }
    // 3-of-3, prehashed.
    {
        var res = try runSession(allocator, kg.key_shares, random, .honest);
        defer res.deinit(allocator);
        var digest: [32]u8 = undefined;
        Sha256.hash("prehashed", &digest, .{});
        var abort: ?Abort = null;
        const sig = try signAll(allocator, res.presigs, .{ .prehashed = digest }, &abort);
        try sig.verifyPrehashed(digest, pk);
        try sig.verify("prehashed", pk);
        try expectLowS(sig);
    }
}

test "presign: every deviation aborts every honest signer, naming the cheater where GG20 §4.2 can" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6368_6561_7465_7273);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const shares = [_]root.KeyShare{ kg.key_shares[0], kg.key_shares[1], kg.key_shares[2] };
    const cheat = shares[1].index;

    const Expect = struct { case: Case, fault: Fault, attributed: bool };
    const cases = [_]Expect{
        .{ .case = .range_proof, .fault = .range_proof, .attributed = true },
        .{ .case = .mta_swap, .fault = .mta_proof, .attributed = true },
        .{ .case = .mtawc_swap, .fault = .mtawc_proof, .attributed = true },
        .{ .case = .pedersen_proof, .fault = .pedersen_proof, .attributed = true },
        .{ .case = .gamma_swap, .fault = .gamma_decommitment, .attributed = true },
        .{ .case = .gamma_blind, .fault = .gamma_decommitment, .attributed = true },
        .{ .case = .gamma_proof, .fault = .gamma_proof, .attributed = true },
        .{ .case = .pdl_proof, .fault = .pdl_proof, .attributed = true },
        .{ .case = .r_bar_swap, .fault = .pdl_proof, .attributed = true },
        .{ .case = .st_proof, .fault = .st_proof, .attributed = true },
        .{ .case = .missing, .fault = .missing_message, .attributed = true },
        .{ .case = .duplicate, .fault = .duplicate_message, .attributed = true },
        .{ .case = .wrong_sid, .fault = .unexpected_message, .attributed = true },
        .{ .case = .wrong_round, .fault = .unexpected_message, .attributed = true },
        .{ .case = .misaddressed, .fault = .unexpected_message, .attributed = true },
        .{ .case = .truncated, .fault = .malformed_message, .attributed = true },
        // Different broadcasts to different signers: caught by the echoed
        // transcript before anyone acts on the split view (review F1) —
        // without it each victim would blame the OTHER honest one.
        .{ .case = .equivocate, .fault = .equivocation, .attributed = false },
        // Types 5 and 7: consistent lies every proof accepts; caught by the
        // sums, not attributable without the §4.3 opening protocol.
        .{ .case = .delta_shift, .fault = .r_bar_sum, .attributed = false },
        .{ .case = .sigma_shift, .fault = .s_sum, .attributed = false },
    };
    for (cases) |c| {
        var res = try runSession(allocator, &shares, random, c.case);
        defer res.deinit(allocator);
        errdefer std.debug.print("case {s}: {any}\n", .{ @tagName(c.case), res.aborts });
        try testing.expectEqual(@as(usize, 0), res.presigs.len);
        // Every honest signer aborted (p2p deviations hit both: the cheater
        // sends one to each), and only with the expected verdict.
        var honest_aborts: usize = 0;
        for (res.aborts) |a| {
            if (a.observer == cheat) {
                // The cheater's own party only ever sees honest input.
                try testing.expect(!c.attributed);
                continue;
            }
            honest_aborts += 1;
            try testing.expectEqual(c.fault, a.abort.fault);
            try testing.expectEqual(if (c.attributed) @as(?u32, cheat) else null, a.abort.culprit);
        }
        try testing.expectEqual(shares.len - 1, honest_aborts);
    }
}

test "presign: a wrong signature share is named by combine; a missing or foreign one is refused" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7369_6773_6861_7265);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 2);
    defer kg.deinit(allocator);

    var res = try runSession(allocator, kg.key_shares, random, .honest);
    defer res.deinit(allocator);
    const msg: Message = .{ .bytes = "share check" };
    const s1 = try res.presigs[0].signShare(msg);
    defer allocator.free(s1);
    const s2 = try res.presigs[1].signShare(msg);
    defer allocator.free(s2);
    const public = &res.presigs[0].public;
    var abort: ?Abort = null;

    // Signer 2's share shifted by one: equation (1) of §4.2 fails for 2 only.
    const bad = try allocator.dupe(u8, s2);
    defer allocator.free(bad);
    const s_val = Scalar.fromBytes(bad[header_length + echo_length ..][0..Ns].*, .big) catch unreachable;
    bad[header_length + echo_length ..][0..Ns].* = s_val.add(Scalar.one).toBytes(.big);
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, bad }, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .sig_share }, abort.?);

    // The right shares for another message: every share fails, the first is named.
    try testing.expectError(error.ProtocolAbort, public.combine(.{ .bytes = "other" }, &[_][]const u8{ s1, s2 }, &abort));
    try testing.expectEqual(Fault.sig_share, abort.?.fault);

    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{s1}, &abort));
    try testing.expectEqual(Abort{ .culprit = kg.key_shares[1].index, .fault = .missing_message }, abort.?);
    try testing.expectError(error.ProtocolAbort, public.combine(msg, &[_][]const u8{ s1, s1 }, &abort));
    try testing.expectEqual(Fault.duplicate_message, abort.?.fault);

    const sig = try public.combine(msg, &[_][]const u8{ s2, s1 }, &abort);
    try testing.expect(abort == null);
    const pk = try signing.ecdsa.PublicKey.fromSec1(&kg.key_shares[0].group_public_key.toBytes());
    try sig.verify("share check", pk);
    try expectLowS(sig);
}

test "presign: init refuses a bad signer set" {
    if (builtin.mode == .Debug) return error.SkipZigTest;
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x6261_6473_6574);
    const random = prng.random();
    const kg = try signing.testKeygen(allocator, random, 2, 3);
    defer kg.deinit(allocator);
    const sid = [_]u8{7} ** 32;
    const share = kg.key_shares[0];
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{1}, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 2, 3 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 1 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 4 }, sid));
    try testing.expectError(error.InvalidParameters, Party.init(allocator, share, &[_]u32{ 1, 2, 3, 4 }, sid));
    // Fewer signers than the threshold the share was dealt for.
    var t3 = share;
    t3.t = 3;
    try testing.expectError(error.InvalidParameters, Party.init(allocator, t3, &[_]u32{ 1, 2 }, sid));
    // A public-keys list naming signer 2 twice.
    const dup = try std.mem.concat(allocator, root.PartyPublicKeys, &.{ share.public_keys.entries, share.public_keys.entries[1..2] });
    defer allocator.free(dup);
    var dup_share = share;
    dup_share.public_keys = .{ .entries = dup };
    try testing.expectError(error.InvalidParameters, Party.init(allocator, dup_share, &[_]u32{ 1, 2 }, sid));
    // Signer 2's announced X_2 replaced: signer 1's own share is fine, but
    // Σ λ_j·X_j over {1, 2} is no longer the group key.
    const bad_x = try allocator.dupe(root.PartyPublicKeys, share.public_keys.entries);
    defer allocator.free(bad_x);
    bad_x[1].verifying_share = try Element.fromPoint(Secp256k1.basePoint);
    var bad_x_share = share;
    bad_x_share.public_keys = .{ .entries = bad_x };
    try testing.expectError(error.InvalidParameters, Party.init(allocator, bad_x_share, &[_]u32{ 1, 2 }, sid));
    // Public material intact, but signer 1's secret share is not the x_1
    // behind X_1: only the own-share check can see it.
    var bad_secret = share;
    bad_secret.secret_share = share.secret_share.add(Scalar.one);
    try testing.expectError(error.InvalidParameters, Party.init(allocator, bad_secret, &[_]u32{ 1, 2 }, sid));
    var p = try Party.init(allocator, share, &[_]u32{ 3, 1 }, sid);
    defer p.deinit();
    try testing.expectError(error.InvalidParameters, p.advance(&[_][]const u8{"x"}, random));
    try testing.expectError(error.InvalidState, p.finish(&.{}));
}

test "fuzz: peekHeader and PresignaturePublic.combine never panic on arbitrary shares" {
    try testing.fuzz({}, fuzzCombine, .{});
}
fn fuzzCombine(_: void, smith: *std.testing.Smith) !void {
    var buf: [2][header_length + echo_length + Ns + 8]u8 = undefined;
    var shares: [2][]const u8 = undefined;
    for (&buf, &shares) |*b, *s| s.* = b[0..smith.slice(b)];
    for (shares) |s| _ = peekHeader(s) catch {};
    const g = Element.fromPoint(Secp256k1.basePoint) catch unreachable;
    var signers = [_]u32{ 1, 2 };
    var r_bar = [_]Element{ g, g };
    var s_points = [_]Element{ g, g };
    const public: PresignaturePublic = .{
        .allocator = testing.allocator,
        .sid = [_]u8{0} ** 32,
        .group_public_key = g,
        .signers = &signers,
        .r_point = g,
        .r = Scalar.one,
        .r_bar = &r_bar,
        .s_points = &s_points,
        .transcript = [_]u8{0} ** 32,
    };
    var abort: ?Abort = null;
    _ = public.combine(.{ .bytes = "fuzz" }, &shares, &abort) catch {};
}
