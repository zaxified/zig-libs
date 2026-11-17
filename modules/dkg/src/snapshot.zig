// SPDX-License-Identifier: MIT

//! snapshot — the versioned byte format of an in-flight `Participant` and
//! `ReshareReceiver` (`toBytes` / `encodedLength` / `fromBytes`), so a party
//! that restarts mid-run resumes instead of starting over.
//!
//! **Every byte of a snapshot is secret material** (the party's own secret
//! polynomials, the shares it received, the pending frames that carry shares,
//! the finished key share). The module does NOT wrap it: like frost-core's
//! `round1::SecretPackage` / `round2::SecretPackage` (serde, "MUST NOT be sent
//! to other participants") and bnb-chain/tss-lib's `LocalPartySaveData`, it
//! leaves protection at rest to the caller, who stores the bytes like a key
//! (encrypted, access-controlled) and `secureZero`s the buffer afterwards.
//!
//! **Layout** (integers big-endian, like the wire frames):
//!
//! ```text
//! version(1) = 1 || kind(1) 1 = Participant, 2 = ReshareReceiver
//!   || group(1) = 1 (secp256k1, 32-byte scalars, 33-byte compressed points)
//!   || kind-specific body
//! ```
//!
//! An optional value is a flag octet (0 or 1, nothing else) followed by the
//! value when 1. The decoder is fail-closed: any other version, kind or group
//! tag, any length that does not fit, a non-canonical scalar, a point off the
//! curve, an out-of-range index or a combination of fields no run of the state
//! machine can produce is `error.InvalidState`; bytes after the last field are
//! refused. Counts are proved to fit the input BEFORE anything is allocated,
//! and every secret in a half-built state is wiped on every error path.

const std = @import("std");
const commit = @import("commit.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const burn = @import("burn.zig");
const participant = @import("participant.zig");
const reshare = @import("reshare.zig");

const Allocator = std.mem.Allocator;
const Scalar = types.Scalar;
const Element = types.Element;
const Ne = types.Ne;
const Ns = types.Ns;
const Participant = participant.Participant;
const ReshareReceiver = reshare.ReshareReceiver;
const Outgoing = wire.Outgoing;

pub const format_version: u8 = 1;
const kind_participant: u8 = 1;
const kind_receiver: u8 = 2;
const group_secp256k1: u8 = 1;

const snapshot_stack_burn = 24 * 1024;

pub const EncodeError = error{
    /// `out` is shorter than `encodedLength()`.
    NoSpaceLeft,
};

pub const DecodeError = error{
    /// Not a snapshot this version wrote, or not a state the machine can be in.
    InvalidState,
} || Allocator.Error;

// ── writer: one pass computes the length, a second writes ───────────────

const Writer = struct {
    buf: ?[]u8,
    n: usize = 0,

    fn put(w: *Writer, bytes: []const u8) void {
        if (w.buf) |b| @memcpy(b[w.n..][0..bytes.len], bytes);
        w.n += bytes.len;
    }

    fn byte(w: *Writer, b: u8) void {
        w.put(&.{b});
    }

    fn u32_(w: *Writer, v: u32) void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .big);
        w.put(&b);
    }

    fn flag(w: *Writer, v: bool) void {
        w.byte(@intFromBool(v));
    }

    fn scalar(w: *Writer, s: Scalar) void {
        var b = s.toBytes(.big);
        defer std.crypto.secureZero(u8, &b);
        w.put(&b);
    }

    fn element(w: *Writer, e: Element) void {
        w.put(&e.toBytes());
    }

    fn optScalar(w: *Writer, s: ?Scalar) void {
        w.flag(s != null);
        if (s) |v| w.scalar(v);
    }

    fn optElements(w: *Writer, es: ?[]const Element) void {
        w.flag(es != null);
        if (es) |list| for (list) |e| w.element(e);
    }

    fn optScalars(w: *Writer, ss: ?[]const Scalar) void {
        w.flag(ss != null);
        if (ss) |list| for (list) |s| w.scalar(s);
    }

    fn optOutput(w: *Writer, o: ?types.DkgShareOutput) void {
        w.flag(o != null);
        if (o) |v| {
            var b = v.toBytes();
            defer std.crypto.secureZero(u8, &b);
            w.put(&b);
        }
    }

    fn complaints(w: *Writer, cs: []const types.Complaint, valid: []const bool, seen: []const bool) void {
        w.u32_(@intCast(cs.len));
        for (cs, valid, seen) |c, v, s| {
            w.put(&c.toBytes());
            w.flag(v);
            w.flag(s);
        }
    }

    fn outbox(w: *Writer, items: []const Outgoing) void {
        w.u32_(@intCast(items.len));
        for (items) |m| {
            switch (m.to) {
                .broadcast => w.byte(0),
                .party => |j| {
                    w.byte(1);
                    w.u32_(j);
                },
            }
            w.u32_(@intCast(m.bytes.len));
            w.put(m.bytes);
        }
    }

    fn header(w: *Writer, kind: u8) void {
        w.byte(format_version);
        w.byte(kind);
        w.byte(group_secp256k1);
    }
};

fn writeParticipant(w: *Writer, p: *const Participant) void {
    const n: usize = p.cfg.n;
    w.header(kind_participant);
    w.u32_(p.cfg.t);
    w.u32_(p.cfg.n);
    w.u32_(p.me);
    w.byte(phaseCode(p.phase_));
    for (p.a) |s| w.scalar(s);
    for (p.b) |s| w.scalar(s);
    for (0..n) |d| {
        w.optElements(p.ped[d]);
        w.optElements(p.fel[d]);
        w.optScalar(p.wire_s[d]);
        w.optScalar(p.wire_sp[d]);
        w.optScalar(p.accepted[d]);
        w.optScalar(p.accepted_sp[d]);
        w.flag(p.present[d]);
        w.flag(p.qualified[d]);
        w.flag(p.exposed[d]);
        w.optScalars(p.recovered[d]);
    }
    for (p.revealed) |s| w.optScalar(s);
    w.complaints(p.complaints.items, p.defense_valid.items, p.defense_seen.items);
    w.outbox(p.outbox.items);
    w.optOutput(p.result);
    w.optElements(p.group_commitments);
    w.flag(p.culprit_ != null);
    if (p.culprit_) |c| w.u32_(c);
}

fn writeReceiver(w: *Writer, r: *const ReshareReceiver) void {
    w.header(kind_receiver);
    w.u32_(r.rc.old.t);
    w.u32_(r.rc.old.n);
    w.u32_(r.rc.new.t);
    w.u32_(r.rc.new.n);
    w.u32_(@intCast(r.rc.dealers.len));
    for (r.rc.dealers) |d| w.u32_(d);
    w.element(r.rc.group_public_key);
    for (r.rc.old_verifying_shares) |x| w.element(x);
    w.u32_(r.me);
    w.byte(receiverPhaseCode(r.phase_));
    for (0..r.rc.dealers.len) |pos| {
        w.optElements(r.bcast[pos]);
        w.optScalar(r.wire_s[pos]);
        w.optScalar(r.accepted[pos]);
        w.flag(r.included[pos]);
    }
    w.complaints(r.complaints.items, r.defense_valid.items, r.defense_seen.items);
    w.outbox(r.outbox.items);
    w.optOutput(r.result);
    w.optElements(r.commitments_);
    w.flag(r.used != null);
    if (r.used) |ids| {
        w.u32_(@intCast(ids.len));
        for (ids) |d| w.u32_(d);
    }
}

pub fn participantLength(p: *const Participant) usize {
    var w: Writer = .{ .buf = null };
    writeParticipant(&w, p);
    return w.n;
}

pub fn receiverLength(r: *const ReshareReceiver) usize {
    var w: Writer = .{ .buf = null };
    writeReceiver(&w, r);
    return w.n;
}

pub fn participantToBytes(p: *const Participant, out: []u8) EncodeError![]u8 {
    if (out.len < participantLength(p)) return error.NoSpaceLeft;
    var w: Writer = .{ .buf = out };
    writeParticipant(&w, p);
    burn.stack(snapshot_stack_burn);
    return out[0..w.n];
}

pub fn receiverToBytes(r: *const ReshareReceiver, out: []u8) EncodeError![]u8 {
    if (out.len < receiverLength(r)) return error.NoSpaceLeft;
    var w: Writer = .{ .buf = out };
    writeReceiver(&w, r);
    burn.stack(snapshot_stack_burn);
    return out[0..w.n];
}

fn phaseCode(p: participant.Phase) u8 {
    return @intCast(@backingInt(p));
}

fn receiverPhaseCode(p: reshare.ReceiverPhase) u8 {
    return @intCast(@backingInt(p));
}

fn enumFromByte(comptime E: type, b: u8) ?E {
    inline for (@typeInfo(E).@"enum".field_values) |v| {
        if (b == v) return @fromBackingInt(@intCast(v));
    }
    return null;
}

// ── reader ──────────────────────────────────────────────────────────────

const Reader = struct {
    bytes: []const u8,
    off: usize = 0,

    fn remaining(r: *const Reader) usize {
        return r.bytes.len - r.off;
    }

    fn take(r: *Reader, n: usize) error{InvalidState}![]const u8 {
        if (r.remaining() < n) return error.InvalidState;
        const s = r.bytes[r.off..][0..n];
        r.off += n;
        return s;
    }

    fn byte(r: *Reader) error{InvalidState}!u8 {
        return (try r.take(1))[0];
    }

    fn u32_(r: *Reader) error{InvalidState}!u32 {
        return std.mem.readInt(u32, (try r.take(4))[0..4], .big);
    }

    /// A strict boolean: 0 or 1, nothing else.
    fn flag(r: *Reader) error{InvalidState}!bool {
        return switch (try r.byte()) {
            0 => false,
            1 => true,
            else => error.InvalidState,
        };
    }

    fn scalar(r: *Reader) error{InvalidState}!Scalar {
        var b: [Ns]u8 = (try r.take(Ns))[0..Ns].*;
        defer std.crypto.secureZero(u8, &b);
        return Scalar.fromBytes(b, .big) catch error.InvalidState;
    }

    fn element(r: *Reader) error{InvalidState}!Element {
        return Element.fromBytes((try r.take(Ne))[0..Ne].*) catch error.InvalidState;
    }

    fn optScalar(r: *Reader) error{InvalidState}!?Scalar {
        if (!try r.flag()) return null;
        return try r.scalar();
    }

    fn optElements(r: *Reader, aa: Allocator, count: usize) DecodeError!?[]Element {
        if (!try r.flag()) return null;
        if (r.remaining() / Ne < count) return error.InvalidState;
        const out = try aa.alloc(Element, count);
        for (out) |*e| e.* = try r.element();
        return out;
    }

    /// Secret scalars: the destination wipes them on every error path.
    fn optScalars(r: *Reader, aa: Allocator, count: usize) DecodeError!?[]Scalar {
        if (!try r.flag()) return null;
        if (r.remaining() / Ns < count) return error.InvalidState;
        const out = try aa.alloc(Scalar, count);
        errdefer std.crypto.secureZero(u8, std.mem.sliceAsBytes(out));
        for (out) |*s| s.* = try r.scalar();
        return out;
    }

    fn optOutput(r: *Reader) error{InvalidState}!?types.DkgShareOutput {
        if (!try r.flag()) return null;
        var b: [types.DkgShareOutput.encoded_length]u8 = (try r.take(types.DkgShareOutput.encoded_length))[0..types.DkgShareOutput.encoded_length].*;
        defer std.crypto.secureZero(u8, &b);
        return types.DkgShareOutput.fromBytes(b) catch error.InvalidState;
    }

    fn header(r: *Reader, kind: u8) error{InvalidState}!void {
        if (try r.byte() != format_version) return error.InvalidState;
        if (try r.byte() != kind) return error.InvalidState;
        if (try r.byte() != group_secp256k1) return error.InvalidState;
    }
};

/// Complaint list shared by both machines: the complainant is in `1..max_id`,
/// `accusedOk` checks the accused against the machine's own id space.
fn readComplaints(
    comptime M: type,
    m: *M,
    r: *Reader,
    allocator: Allocator,
    max_id: u32,
    comptime accusedOk: fn (*const M, u32) bool,
) DecodeError!void {
    const count = try r.u32_();
    if (@as(u64, count) * 10 > r.remaining()) return error.InvalidState;
    var seen_pairs: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer seen_pairs.deinit(allocator);
    try seen_pairs.ensureTotalCapacity(allocator, count);
    const aa = m.arena.allocator();
    for (0..count) |_| {
        const complainant = try r.u32_();
        const accused = try r.u32_();
        const valid = try r.flag();
        const seen = try r.flag();
        if (complainant < 1 or complainant > max_id or !accusedOk(m, accused)) return error.InvalidState;
        if (valid and !seen) return error.InvalidState;
        const gop = seen_pairs.getOrPutAssumeCapacity((@as(u64, complainant) << 32) | accused);
        if (gop.found_existing) return error.InvalidState;
        try m.complaints.append(aa, .{ .complainant = complainant, .accused = accused });
        try m.defense_valid.append(aa, valid);
        try m.defense_seen.append(aa, seen);
    }
}

fn participantAccusedOk(p: *const Participant, accused: u32) bool {
    return accused >= 1 and accused <= p.cfg.n;
}

fn receiverAccusedOk(rr: *const ReshareReceiver, accused: u32) bool {
    return std.mem.findScalar(u32, rr.rc.dealers, accused) != null;
}

/// The pending frames. `allowed` gives the exact length and addressing a frame
/// of that kind must have (null: this machine never sends that kind).
fn readOutbox(
    m: anytype,
    r: *Reader,
    max_party: u32,
    me: u32,
    comptime allowed: fn (@TypeOf(m), wire.Kind) ?FrameRule,
) DecodeError!void {
    const count = try r.u32_();
    if (@as(u64, count) * 6 > r.remaining()) return error.InvalidState;
    for (0..count) |_| {
        const tag = try r.byte();
        var to: wire.Target = .broadcast;
        switch (tag) {
            0 => {},
            1 => {
                const j = try r.u32_();
                if (j < 1 or j > max_party or j == me) return error.InvalidState;
                to = .{ .party = j };
            },
            else => return error.InvalidState,
        }
        const len = try r.u32_();
        const body = try r.take(len);
        if (body.len == 0) return error.InvalidState;
        const kind = wire.kindFromByte(body[0]) orelse return error.InvalidState;
        const rule = allowed(m, kind) orelse return error.InvalidState;
        if (body.len != rule.len) return error.InvalidState;
        if (rule.party != (tag == 1)) return error.InvalidState;
        const copy = try m.allocator.dupe(u8, body);
        errdefer {
            std.crypto.secureZero(u8, copy);
            m.allocator.free(copy);
        }
        try m.outbox.append(m.allocator, .{ .to = to, .bytes = copy });
    }
}

const FrameRule = struct { len: usize, party: bool };

fn participantFrameRule(p: *const Participant, kind: wire.Kind) ?FrameRule {
    const share_len = 1 + types.ShareMsg.encoded_length;
    return switch (kind) {
        .pedersen_broadcast, .feldman_broadcast => .{ .len = 1 + 8 + @as(usize, p.cfg.t) * Ne, .party = false },
        .share => .{ .len = share_len, .party = true },
        .complaint => .{ .len = 1 + complaint_len, .party = false },
        .defense, .feldman_complaint, .reveal => .{ .len = share_len, .party = false },
        else => null,
    };
}

const complaint_len = types.Complaint.encoded_length;

fn receiverFrameRule(rr: *const ReshareReceiver, kind: wire.Kind) ?FrameRule {
    _ = rr;
    return switch (kind) {
        .reshare_complaint => .{ .len = 1 + complaint_len, .party = false },
        else => null,
    };
}

// ── Participant ─────────────────────────────────────────────────────────

pub fn participantFromBytes(allocator: Allocator, bytes: []const u8) DecodeError!Participant {
    const result = participantFromBytesBody(allocator, bytes);
    burn.stack(snapshot_stack_burn);
    return result;
}

noinline fn participantFromBytesBody(allocator: Allocator, bytes: []const u8) DecodeError!Participant {
    var r: Reader = .{ .bytes = bytes };
    try r.header(kind_participant);
    const t = try r.u32_();
    const n = try r.u32_();
    const me = try r.u32_();
    const cfg: types.Config = .{ .t = t, .n = n };
    if (!cfg.valid() or !cfg.honestMajority()) return error.InvalidState;
    if (me < 1 or me > n) return error.InvalidState;
    const phase = enumFromByte(participant.Phase, try r.byte()) orelse return error.InvalidState;
    // Nothing is allocated before the input is proved big enough for the
    // fixed part: two polynomials, ten octets per dealer, an n x n reveal
    // table of flags, and the five trailing counts and flags.
    const min_len: u128 = 2 * @as(u128, t) * Ns + 10 * @as(u128, n) + @as(u128, n) * n + 11;
    if (r.remaining() < min_len) return error.InvalidState;

    const tcount: usize = t;
    const nn: usize = n;
    var p = blk: {
        const poly = try allocator.alloc(Scalar, 2 * tcount);
        defer {
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(poly));
            allocator.free(poly);
        }
        for (poly) |*s| s.* = try r.scalar();
        break :blk Participant.initWithPolynomials(allocator, cfg, me, poly[0..tcount], poly[tcount..]) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidState,
        };
    };
    errdefer p.deinit();
    const aa = p.arena.allocator();
    p.phase_ = phase;

    for (0..nn) |d| {
        p.ped[d] = try r.optElements(aa, tcount);
        p.fel[d] = try r.optElements(aa, tcount);
        p.wire_s[d] = try r.optScalar();
        p.wire_sp[d] = try r.optScalar();
        p.accepted[d] = try r.optScalar();
        p.accepted_sp[d] = try r.optScalar();
        p.present[d] = try r.flag();
        p.qualified[d] = try r.flag();
        p.exposed[d] = try r.flag();
        p.recovered[d] = try r.optScalars(aa, tcount);
    }
    for (p.revealed) |*s| s.* = try r.optScalar();
    try readComplaints(Participant, &p, &r, allocator, n, participantAccusedOk);
    try readOutbox(&p, &r, n, me, participantFrameRule);
    p.result = try r.optOutput();
    p.group_commitments = try r.optElements(aa, tcount);
    if (try r.flag()) p.culprit_ = try r.u32_();
    if (r.remaining() != 0) return error.InvalidState;
    try validateParticipant(&p);
    return p;
}

fn rankOf(phase: participant.Phase) u8 {
    return switch (phase) {
        .new => 0,
        .shares => 1,
        .complaints => 2,
        .defenses => 3,
        .feldman => 4,
        .feldman_complaints => 5,
        .reveals => 6,
        .done => 7,
        .aborted => 255,
    };
}

fn bytesEq(a: [Ne]u8, b: [Ne]u8) bool {
    return std.mem.eql(u8, &a, &b);
}

/// The result of a finished run must agree with the public commitments:
/// `Q = F_0`, `X_j = F(j)` and `x_j G = X_j`.
fn checkResult(res: types.DkgShareOutput, fk: []const Element, me: u32) error{InvalidState}!void {
    if (res.index != me or fk.len == 0) return error.InvalidState;
    if (!bytesEq(res.group_public_key.toBytes(), fk[0].toBytes())) return error.InvalidState;
    const x = commit.evalCommitmentAt(fk, me) catch return error.InvalidState;
    if (!bytesEq(res.verifying_share.toBytes(), x.toBytes())) return error.InvalidState;
    const g = commit.feldmanEvalShare(&res.secret_share) catch return error.InvalidState;
    if (!bytesEq(g.toBytes(), x.toBytes())) return error.InvalidState;
}

fn mapErr(e: anyerror) DecodeError {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidState;
}

fn validateParticipant(p: *const Participant) DecodeError!void {
    const n: usize = p.cfg.n;
    const t: usize = p.cfg.t;
    const mi: usize = p.me - 1;
    const rank = rankOf(p.phase_);
    const aborted = p.phase_ == .aborted;

    // Complaints before the defense round carry no defense.
    for (p.defense_seen.items, p.defense_valid.items) |s, v| {
        if (rank < 3 and (s or v)) return error.InvalidState;
    }
    if (rank <= 1 and p.complaints.items.len != 0) return error.InvalidState;

    if (p.phase_ == .new) {
        for (0..n) |d| {
            if (p.ped[d] != null or p.fel[d] != null or p.wire_s[d] != null or p.wire_sp[d] != null) return error.InvalidState;
            if (p.accepted[d] != null or p.accepted_sp[d] != null or p.recovered[d] != null) return error.InvalidState;
            if (p.present[d] or p.qualified[d] or p.exposed[d]) return error.InvalidState;
        }
        for (p.revealed) |s| if (s != null) return error.InvalidState;
        if (p.complaints.items.len != 0 or p.outbox.items.len != 0) return error.InvalidState;
        if (p.result != null or p.group_commitments != null or p.culprit_ != null) return error.InvalidState;
        return;
    }

    // Our own dealing exists from `start` on, and is exactly what the two
    // secret polynomials give.
    const ped_me = p.ped[mi] orelse return error.InvalidState;
    const fel_me = p.fel[mi] orelse return error.InvalidState;
    if (!p.present[mi] or p.accepted[mi] == null or p.accepted_sp[mi] != null) return error.InvalidState;
    {
        var scratch = std.heap.ArenaAllocator.init(p.allocator);
        defer scratch.deinit();
        const sa = scratch.allocator();
        const want_ped = commit.pedersenCommitVector(sa, p.a, p.b, p.h) catch |e| return mapErr(e);
        const want_fel = commit.feldmanCommitVector(sa, p.a) catch |e| return mapErr(e);
        if (want_ped.len != t or want_fel.len != t) return error.InvalidState;
        for (0..t) |k| {
            if (!bytesEq(want_ped[k].toBytes(), ped_me[k].toBytes())) return error.InvalidState;
            if (!bytesEq(want_fel[k].toBytes(), fel_me[k].toBytes())) return error.InvalidState;
        }
        var s_me: Scalar = Scalar.zero;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&s_me));
        commit.evalPoly(p.a, commit.scalarFromIndex(p.me), &s_me);
        if (!p.accepted[mi].?.equivalent(s_me)) return error.InvalidState;
    }

    if (aborted) {
        if (p.result != null or p.group_commitments != null) return error.InvalidState;
        if (p.culprit_) |c| if (c < 1 or c > n) return error.InvalidState;
        return;
    }
    if (p.culprit_ != null) return error.InvalidState;

    var any_exposed = false;
    var any_qualified = false;
    for (0..n) |d| {
        const is_me = d == mi;
        // `present`: only we ourselves before the shares round closes, the
        // dealers that broadcast afterwards.
        if (rank <= 1) {
            if (p.present[d] != is_me) return error.InvalidState;
            if (!is_me and p.accepted[d] != null) return error.InvalidState;
            if (p.accepted_sp[d] != null) return error.InvalidState;
        } else {
            if (p.present[d] != (p.ped[d] != null)) return error.InvalidState;
            if ((p.accepted[d] != null) != (p.accepted_sp[d] != null) and !is_me) return error.InvalidState;
            if (!is_me and p.accepted[d] != null and p.ped[d] == null) return error.InvalidState;
        }
        if (rank < 4) {
            if (p.qualified[d]) return error.InvalidState;
        } else if (p.qualified[d]) {
            if (!p.present[d] or p.accepted[d] == null) return error.InvalidState;
            any_qualified = true;
        }
        if (!is_me and p.fel[d] != null and (rank < 4 or !p.qualified[d])) return error.InvalidState;
        if (rank < 5) {
            if (p.exposed[d]) return error.InvalidState;
        } else if (p.exposed[d]) {
            if (!p.qualified[d]) return error.InvalidState;
            any_exposed = true;
            if (rank >= 6 and (is_me or p.accepted[d] == null or p.accepted_sp[d] == null)) return error.InvalidState;
        }
        // Reconstructed polynomials exist only for exposed dealers, once done.
        if (p.recovered[d] != null and (rank != 7 or !p.exposed[d])) return error.InvalidState;
        if (rank == 7 and p.exposed[d] and p.recovered[d] == null) return error.InvalidState;
        // Reveals: only of exposed dealers, and ours is in from the round's start.
        for (0..n) |h| {
            const slot = p.revealed[d * n + h];
            if (slot != null and (rank < 6 or !p.exposed[d])) return error.InvalidState;
            if (rank >= 6 and p.exposed[d] and h == mi and slot == null) return error.InvalidState;
        }
    }
    // The reveal round exists only when a dealer was exposed; a finished run may or may not have had one.
    if (rank == 6 and !any_exposed) return error.InvalidState;
    if (rank >= 4 and !any_qualified) return error.InvalidState;

    if (rank == 7) {
        const res = p.result orelse return error.InvalidState;
        const fk = p.group_commitments orelse return error.InvalidState;
        if (fk.len != t) return error.InvalidState;
        try checkResult(res, fk, p.me);
    } else if (p.result != null or p.group_commitments != null) {
        return error.InvalidState;
    }
}

// ── ReshareReceiver ─────────────────────────────────────────────────────

pub fn receiverFromBytes(allocator: Allocator, bytes: []const u8) DecodeError!ReshareReceiver {
    const result = receiverFromBytesBody(allocator, bytes);
    burn.stack(snapshot_stack_burn);
    return result;
}

noinline fn receiverFromBytesBody(allocator: Allocator, bytes: []const u8) DecodeError!ReshareReceiver {
    var r: Reader = .{ .bytes = bytes };
    try r.header(kind_receiver);
    const old: types.Config = .{ .t = try r.u32_(), .n = try r.u32_() };
    const new: types.Config = .{ .t = try r.u32_(), .n = try r.u32_() };
    const nd_raw = try r.u32_();
    // The dealer ids, the public key and the old verifying shares must fit
    // before anything is allocated for them.
    if (old.n > r.remaining() or nd_raw > r.remaining()) return error.InvalidState;
    const nd: usize = nd_raw;
    const on: usize = old.n;
    if (@as(u128, nd) * 4 + Ne + @as(u128, on) * Ne + 4 + 1 > r.remaining()) return error.InvalidState;

    const dealers = try allocator.alloc(u32, nd);
    defer allocator.free(dealers);
    for (dealers) |*d| d.* = try r.u32_();
    const gpk = try r.element();
    const xs = try allocator.alloc(Element, on);
    defer allocator.free(xs);
    for (xs) |*x| x.* = try r.element();
    const rc: reshare.ReshareConfig = .{
        .old = old,
        .new = new,
        .dealers = dealers,
        .group_public_key = gpk,
        .old_verifying_shares = xs,
    };
    const me = try r.u32_();
    const phase = enumFromByte(reshare.ReceiverPhase, try r.byte()) orelse return error.InvalidState;
    // Per dealer: three flags and the included octet; then the trailing counts.
    if (@as(u128, nd) * 4 + 4 + 4 + 3 > r.remaining()) return error.InvalidState;

    var rr = ReshareReceiver.init(allocator, rc, me) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidState,
    };
    errdefer rr.deinit();
    const aa = rr.arena.allocator();
    rr.phase_ = phase;
    const nt: usize = new.t;
    for (0..nd) |pos| {
        rr.bcast[pos] = try r.optElements(aa, nt);
        rr.wire_s[pos] = try r.optScalar();
        rr.accepted[pos] = try r.optScalar();
        rr.included[pos] = try r.flag();
    }
    try readComplaints(ReshareReceiver, &rr, &r, allocator, new.n, receiverAccusedOk);
    try readOutbox(&rr, &r, new.n, me, receiverFrameRule);
    rr.result = try r.optOutput();
    rr.commitments_ = try r.optElements(aa, nt);
    if (try r.flag()) {
        const count = try r.u32_();
        if (@as(u64, count) * 4 > r.remaining()) return error.InvalidState;
        const ids = try aa.alloc(u32, count);
        for (ids) |*d| d.* = try r.u32_();
        rr.used = ids;
    }
    if (r.remaining() != 0) return error.InvalidState;
    try validateReceiver(&rr);
    return rr;
}

fn validateReceiver(rr: *const ReshareReceiver) error{InvalidState}!void {
    const nd = rr.rc.dealers.len;
    const phase = rr.phase_;
    const rank: u8 = switch (phase) {
        .shares => 0,
        .complaints => 1,
        .defenses => 2,
        .done => 3,
        .aborted => 255,
    };
    for (0..nd) |pos| {
        if (rr.bcast[pos]) |b| {
            // `onBroadcast` accepts a dealing only if it deals the old share.
            const want = rr.rc.old_verifying_shares[rr.rc.dealers[pos] - 1].toBytes();
            if (!bytesEq(b[0].toBytes(), want)) return error.InvalidState;
        }
        if (rr.accepted[pos] != null and rr.bcast[pos] == null) return error.InvalidState;
        if (rank == 0 and rr.accepted[pos] != null) return error.InvalidState;
        if (rank < 3 and rr.included[pos]) return error.InvalidState;
    }
    for (rr.defense_seen.items, rr.defense_valid.items) |s, v| {
        if (rank < 2 and (s or v)) return error.InvalidState;
    }
    if (rank == 0 and (rr.complaints.items.len != 0 or rr.outbox.items.len != 0)) return error.InvalidState;
    if (rr.outbox.items.len > nd) return error.InvalidState;
    if (rank == 3) {
        const res = rr.result orelse return error.InvalidState;
        const fk = rr.commitments_ orelse return error.InvalidState;
        const used = rr.used orelse return error.InvalidState;
        if (fk.len != rr.rc.new.t or used.len < rr.rc.old.t) return error.InvalidState;
        // `used` is exactly the included dealers, in dealer order.
        var included: usize = 0;
        for (rr.included) |i| included += @intFromBool(i);
        if (included != used.len) return error.InvalidState;
        var w: usize = 0;
        for (0..nd) |pos| {
            if (!rr.included[pos]) continue;
            if (rr.bcast[pos] == null or rr.accepted[pos] == null) return error.InvalidState;
            if (used[w] != rr.rc.dealers[pos]) return error.InvalidState;
            w += 1;
        }
        if (!bytesEq(res.group_public_key.toBytes(), rr.rc.group_public_key.toBytes())) return error.InvalidState;
        try checkResult(res, fk, rr.me);
    } else if (rr.result != null or rr.commitments_ != null or rr.used != null) {
        return error.InvalidState;
    }
}

test "phase codes are pinned (part of the format)" {
    try std.testing.expectEqual(@as(u8, 0), phaseCode(.new));
    try std.testing.expectEqual(@as(u8, 1), phaseCode(.shares));
    try std.testing.expectEqual(@as(u8, 6), phaseCode(.reveals));
    try std.testing.expectEqual(@as(u8, 8), phaseCode(.aborted));
    try std.testing.expectEqual(@as(u8, 0), receiverPhaseCode(.shares));
    try std.testing.expectEqual(@as(u8, 4), receiverPhaseCode(.aborted));
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const tn = @import("testnet.zig");
const checks = @import("checks.zig");

fn snap(p: *const Participant) ![]u8 {
    const buf = try testing.allocator.alloc(u8, p.encodedLength());
    errdefer testing.allocator.free(buf);
    const out = try p.toBytes(buf);
    try testing.expectEqual(buf.len, out.len);
    return buf;
}

fn freeSnap(b: []u8) void {
    std.crypto.secureZero(u8, b);
    testing.allocator.free(b);
}

/// Replace every party by its own restored snapshot (and check that the
/// snapshot of the restored party is the same bytes).
fn resumeAll(net: *tn.TestNet) !void {
    for (net.parties) |*p| {
        const bytes = try snap(p);
        defer freeSnap(bytes);
        var q = try Participant.fromBytes(testing.allocator, bytes);
        errdefer q.deinit();
        const again = try snap(&q);
        defer freeSnap(again);
        try testing.expectEqualSlices(u8, bytes, again);
        p.deinit();
        p.* = q;
    }
}

fn tamperShare2to3(from: u32, to: u32, bytes: []u8) tn.Action {
    if (from == 2 and to == 3 and bytes[0] == @backingInt(wire.Kind.share)) bytes[1 + 8 + Ns - 1] ^= 1;
    if (from == 2 and bytes[0] == @backingInt(wire.Kind.feldman_broadcast)) {
        @memcpy(bytes[1 + 8 + Ne ..][0..Ne], bytes[1 + 8 ..][0..Ne]);
    }
    return .deliver;
}

/// Run to the end; with `do_resume` every party is replaced by its restored
/// snapshot at EVERY round boundary: after `start`, with the frames pending,
/// after delivery, and after each `advance`. Returns whether the reveal round
/// was reached.
fn drive(net: *tn.TestNet, do_resume: bool) !bool {
    var saw_reveals = false;
    try net.startAll();
    if (do_resume) try resumeAll(net);
    for (0..6) |_| {
        var all = true;
        for (net.parties) |*p| switch (p.phase()) {
            .done, .aborted => {},
            .reveals => {
                saw_reveals = true;
                all = false;
            },
            else => all = false,
        };
        if (all) break;
        try net.deliverAll();
        if (do_resume) try resumeAll(net);
        try net.advanceAll();
        if (do_resume) try resumeAll(net);
    }
    return saw_reveals;
}

fn sameRun(cfg: types.Config, seed: u64, bent: bool) !bool {
    var prng_a = std.Random.DefaultPrng.init(seed);
    var base = try tn.TestNet.init(testing.allocator, cfg, prng_a.random());
    defer base.deinit();
    var prng_b = std.Random.DefaultPrng.init(seed);
    var resumed = try tn.TestNet.init(testing.allocator, cfg, prng_b.random());
    defer resumed.deinit();
    if (bent) {
        base.filter = tamperShare2to3;
        resumed.filter = tamperShare2to3;
    }
    const reveals_a = try drive(&base, false);
    const reveals_b = try drive(&resumed, true);
    try testing.expectEqual(reveals_a, reveals_b);
    try testing.expectEqual(base.refused, resumed.refused);
    for (base.parties, resumed.parties) |*a, *b| {
        try testing.expectEqual(a.phase(), b.phase());
        try testing.expectEqual(participant.Phase.done, b.phase());
        const oa = a.output().?;
        const ob = b.output().?;
        try testing.expectEqualSlices(u8, &oa.toBytes(), &ob.toBytes());
        // The public commitments survived as well.
        const fa = a.publicCommitments().?;
        const fb = b.publicCommitments().?;
        for (fa, fb) |x, y| try testing.expectEqualSlices(u8, &x.toBytes(), &y.toBytes());
    }
    const outs = try resumed.outputs();
    defer tn.freeOutputs(testing.allocator, outs);
    try testing.expect(checks.allSameQ(outs));
    return reveals_b;
}

test "Participant: resuming from a snapshot at every round boundary gives the uninterrupted run's key (clean runs)" {
    const cases = [_]types.Config{ .{ .t = 1, .n = 2 }, .{ .t = 2, .n = 3 }, .{ .t = 2, .n = 4 }, .{ .t = 3, .n = 5 } };
    for (cases, 0..) |cfg, i| {
        try testing.expect(!(try sameRun(cfg, 0x5A9_0000 + i, false)));
    }
}

test "Participant: resuming at every boundary through complaint, defense, exposure and reconstruction" {
    // Dealer 2's share to party 3 is bent (complaint + defense) and its
    // Feldman commitments are bent (exposed, rebuilt from revealed shares).
    try testing.expect(try sameRun(.{ .t = 2, .n = 3 }, 0x5A9_1000, true));
}

/// A 2-of-3 world with the bent dealer, brought `steps` rounds on.
fn world(steps: usize) !tn.TestNet {
    return worldIn(testing.allocator, steps);
}

fn worldIn(allocator: Allocator, steps: usize) !tn.TestNet {
    var prng = std.Random.DefaultPrng.init(0xF033);
    var net = try tn.TestNet.init(allocator, .{ .t = 2, .n = 3 }, prng.random());
    errdefer net.deinit();
    net.filter = tamperShare2to3;
    try net.startAll();
    for (0..steps) |_| {
        try net.deliverAll();
        try net.advanceAll();
    }
    return net;
}

fn expectRefused(p: *const Participant) !void {
    const bytes = try snap(p);
    defer freeSnap(bytes);
    try testing.expectError(error.InvalidState, Participant.fromBytes(testing.allocator, bytes));
}

test "Participant: every truncation, a trailing octet, bad tags and a bad phase are refused" {
    for ([_]usize{ 0, 3, 5, 6 }) |steps| {
        var net = try world(steps);
        defer net.deinit();
        const p = &net.parties[0];
        const bytes = try snap(p);
        defer freeSnap(bytes);
        for (0..bytes.len) |len| {
            try testing.expectError(error.InvalidState, Participant.fromBytes(testing.allocator, bytes[0..len]));
        }
        const longer = try testing.allocator.alloc(u8, bytes.len + 1);
        defer freeSnap(longer);
        @memcpy(longer[0..bytes.len], bytes);
        longer[bytes.len] = 0;
        try testing.expectError(error.InvalidState, Participant.fromBytes(testing.allocator, longer));

        const bad = try testing.allocator.dupe(u8, bytes);
        defer freeSnap(bad);
        // version, kind (ReshareReceiver's tag), kind 0, group tag, phase code 9, id 0.
        const edits = [_]struct { at: usize, v: u8 }{
            .{ .at = 0, .v = 0 },  .{ .at = 0, .v = 2 },  .{ .at = 1, .v = 2 },
            .{ .at = 1, .v = 0 },  .{ .at = 2, .v = 0 },  .{ .at = 2, .v = 2 },
            .{ .at = 15, .v = 9 }, .{ .at = 14, .v = 0 },
        };
        for (edits) |e| {
            @memcpy(bad, bytes);
            bad[e.at] = e.v;
            try testing.expectError(error.InvalidState, Participant.fromBytes(testing.allocator, bad));
        }
    }
}

test "Participant: a damaged snapshot is refused or decodes to a state that re-encodes identically (never crashes, never leaks)" {
    for ([_]usize{ 1, 6 }) |steps| {
        var net = try world(steps);
        defer net.deinit();
        const bytes = try snap(&net.parties[0]);
        defer freeSnap(bytes);
        const bad = try testing.allocator.dupe(u8, bytes);
        defer freeSnap(bad);
        for (0..bytes.len) |at| {
            for ([_]u8{ 0xFF, bytes[at] ^ 1 }) |v| {
                @memcpy(bad, bytes);
                bad[at] = v;
                var q = Participant.fromBytes(testing.allocator, bad) catch continue;
                defer q.deinit();
                const again = try snap(&q);
                defer freeSnap(again);
                try testing.expectEqualSlices(u8, bad, again);
            }
        }
    }
}

test "Participant: every allocation failure of fromBytes frees everything" {
    var net = try world(2);
    defer net.deinit();
    const bytes = try snap(&net.parties[0]);
    defer freeSnap(bytes);
    const F = struct {
        fn f(a: Allocator, b: []const u8) !void {
            var q = try Participant.fromBytes(a, b);
            q.deinit();
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, F.f, .{bytes});
}

test "Participant: toBytes needs the whole buffer and writes exactly encodedLength" {
    var net = try world(1);
    defer net.deinit();
    const p = &net.parties[0];
    const len = p.encodedLength();
    const buf = try testing.allocator.alloc(u8, len + 7);
    defer freeSnap(buf);
    try testing.expectError(error.NoSpaceLeft, p.toBytes(buf[0 .. len - 1]));
    try testing.expectError(error.NoSpaceLeft, p.toBytes(buf[0..0]));
    const out = try p.toBytes(buf);
    try testing.expectEqual(len, out.len);
    try testing.expect(out.ptr == buf.ptr);
    // The three tags and the id fields are where the format says.
    try testing.expectEqual(format_version, out[0]);
    try testing.expectEqual(@as(u8, 1), out[1]);
    try testing.expectEqual(@as(u8, 1), out[2]);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, out[3..7], .big));
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, out[7..11], .big));
    try testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, out[11..15], .big));
    try testing.expectEqual(@as(u8, 2), out[15]); // phase .complaints
}

test "Participant: states no run can reach are refused" {
    // After `start` (.shares), with the frames pending.
    var net = try world(0);
    defer net.deinit();
    const p = &net.parties[0];
    {
        // sanity: the unmodified party round-trips
        const bytes = try snap(p);
        defer freeSnap(bytes);
        var q = try Participant.fromBytes(testing.allocator, bytes);
        q.deinit();
    }
    // (each block mutates, expects a refusal, restores)
    {
        const old = p.phase_;
        defer p.phase_ = old;
        p.phase_ = .new;
        try expectRefused(p);
        p.phase_ = .done;
        try expectRefused(p);
        p.phase_ = .feldman;
        try expectRefused(p);
    }
    {
        p.qualified[1] = true;
        defer p.qualified[1] = false;
        try expectRefused(p);
    }
    {
        p.exposed[1] = true;
        defer p.exposed[1] = false;
        try expectRefused(p);
    }
    {
        p.present[2] = true;
        defer p.present[2] = false;
        try expectRefused(p);
    }
    {
        const old = p.a[0];
        defer p.a[0] = old;
        p.a[0] = old.add(Scalar.one);
        try expectRefused(p);
    }
    {
        const old = p.accepted[0];
        defer p.accepted[0] = old;
        p.accepted[0] = null;
        try expectRefused(p);
    }
    {
        p.accepted_sp[0] = Scalar.one;
        defer p.accepted_sp[0] = null;
        try expectRefused(p);
    }
    {
        p.accepted[1] = Scalar.one; // an accepted share before the round closed
        defer p.accepted[1] = null;
        try expectRefused(p);
    }
    {
        p.culprit_ = 2;
        defer p.culprit_ = null;
        try expectRefused(p);
    }
    {
        try p.complaints.append(p.arena.allocator(), .{ .complainant = 1, .accused = 2 });
        try p.defense_valid.append(p.arena.allocator(), false);
        try p.defense_seen.append(p.arena.allocator(), false);
        defer {
            _ = p.complaints.pop();
            _ = p.defense_valid.pop();
            _ = p.defense_seen.pop();
        }
        try expectRefused(p); // complaints before the shares round closed
    }
    {
        // A frame the machine never queues in this shape.
        const m = &p.outbox.items[0];
        const old = m.bytes[0];
        defer m.bytes[0] = old;
        m.bytes[0] = @backingInt(wire.Kind.reveal);
        try expectRefused(p);
        m.bytes[0] = 0;
        try expectRefused(p);
    }
    {
        // A pending frame addressed to ourselves.
        var found: ?*Outgoing = null;
        for (p.outbox.items) |*m| switch (m.to) {
            .party => found = m,
            .broadcast => {},
        };
        const m = found.?;
        const old = m.to;
        defer m.to = old;
        m.to = .{ .party = p.me };
        try expectRefused(p);
        m.to = .{ .party = 9 };
        try expectRefused(p);
        m.to = .broadcast; // a share frame must be point-to-point
        try expectRefused(p);
    }
}

test "Participant: later-round inconsistencies are refused" {
    {
        var net = try world(6);
        defer net.deinit();
        const p = &net.parties[0];
        try testing.expectEqual(participant.Phase.done, p.phase());
        {
            const old = p.result;
            defer p.result = old;
            p.result = null;
            try expectRefused(p);
        }
        {
            const old = p.group_commitments;
            defer p.group_commitments = old;
            p.group_commitments = null;
            try expectRefused(p);
        }
        {
            const old = p.result.?;
            defer p.result = old;
            p.result.?.secret_share = old.secret_share.add(Scalar.one);
            try expectRefused(p);
            p.result.?.secret_share = old.secret_share;
            p.result.?.index = 2;
            try expectRefused(p);
            p.result.?.index = old.index;
            p.result.?.group_public_key = old.verifying_share;
            try expectRefused(p);
            p.result.?.group_public_key = old.group_public_key;
            p.result.?.verifying_share = old.group_public_key;
            try expectRefused(p);
        }
        {
            // an exposed dealer without its reconstructed polynomial
            const old = p.recovered[1];
            defer p.recovered[1] = old;
            try testing.expect(old != null);
            p.recovered[1] = null;
            try expectRefused(p);
        }
        {
            p.recovered[0] = p.recovered[1]; // a polynomial for a dealer that was not exposed
            defer p.recovered[0] = null;
            try expectRefused(p);
        }
    }
    {
        var net = try world(5);
        defer net.deinit();
        const p = &net.parties[0];
        try testing.expectEqual(participant.Phase.reveals, p.phase());
        const old = p.revealed[1 * 3 + 0];
        defer p.revealed[1 * 3 + 0] = old;
        try testing.expect(old != null);
        p.revealed[1 * 3 + 0] = null; // our own reveal is in from the round's start
        try expectRefused(p);
        p.revealed[1 * 3 + 0] = old;
        p.revealed[0] = Scalar.one; // a reveal of a dealer that was not exposed
        defer p.revealed[0] = null;
        try expectRefused(p);
    }
    {
        // An aborted run keeps only what is structurally sound.
        var net = try world(0);
        defer net.deinit();
        const p = &net.parties[0];
        p.phase_ = .aborted;
        p.culprit_ = 2;
        const bytes = try snap(p);
        defer freeSnap(bytes);
        var q = try Participant.fromBytes(testing.allocator, bytes);
        defer q.deinit();
        try testing.expectEqual(@as(?u32, 2), q.culprit());
        p.culprit_ = 4;
        try expectRefused(p);
    }
}

test "Participant: a fresh (never started) party and a snapshot taken before any frame round-trip" {
    var prng = std.Random.DefaultPrng.init(0x5A9_2000);
    var p = try Participant.init(testing.allocator, .{ .t = 2, .n = 3 }, 2, prng.random());
    defer p.deinit();
    const bytes = try snap(&p);
    defer freeSnap(bytes);
    var q = try Participant.fromBytes(testing.allocator, bytes);
    defer q.deinit();
    try testing.expectEqual(participant.Phase.new, q.phase());
    try testing.expectEqual(@as(u32, 2), q.id());
    // The restored party can be started and behaves like the original.
    try p.start();
    try q.start();
    const mp = try p.takeOutgoing();
    defer wire.freeOutgoing(testing.allocator, mp);
    const mq = try q.takeOutgoing();
    defer wire.freeOutgoing(testing.allocator, mq);
    try testing.expectEqual(mp.len, mq.len);
    for (mp, mq) |a, b| try testing.expectEqualSlices(u8, a.bytes, b.bytes);
}

test "Participant: an input claiming a huge n is refused before anything is allocated" {
    var bytes: [40]u8 = @splat(0);
    bytes[0] = format_version;
    bytes[1] = 1;
    bytes[2] = 1;
    std.mem.writeInt(u32, bytes[3..7], 1000, .big);
    std.mem.writeInt(u32, bytes[7..11], 0xFFFF_FFFF, .big);
    std.mem.writeInt(u32, bytes[11..15], 1, .big);
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    try testing.expectError(error.InvalidState, Participant.fromBytes(failing.allocator(), &bytes));
}

/// A decoder that sizes an allocation from a claimed count BEFORE checking it
/// against the input asks for gigabytes: out of a 64 KiB buffer (plenty for
/// any honest snapshot of these tests) that shows as OutOfMemory instead of
/// InvalidState.
pub fn expectRefusedBeforeAllocating(comptime T: type, bytes: []const u8) !void {
    var buf: [64 * 1024]u8 align(16) = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buf);
    try testing.expectError(error.InvalidState, T.fromBytes(fba.allocator(), bytes));
}

test "Participant: a claimed complaint count that does not fit the input is refused before it is allocated" {
    var prng = std.Random.DefaultPrng.init(0x5A9_2001);
    var p = try Participant.init(testing.allocator, .{ .t = 2, .n = 3 }, 1, prng.random());
    defer p.deinit();
    const bytes = try snap(&p);
    defer freeSnap(bytes);
    // The tail of a never-started party: complaint count, outbox count, three flags.
    std.mem.writeInt(u32, bytes[bytes.len - 11 ..][0..4], 0xFFFF_FFFF, .big);
    try expectRefusedBeforeAllocating(Participant, bytes);
}

fn someElements(p: *Participant) ![]Element {
    const e = try p.arena.allocator().alloc(Element, p.cfg.t);
    @memset(e, commit.pedersenH());
    return e;
}

fn someOutput(p: *const Participant) types.DkgShareOutput {
    return .{ .index = p.me, .secret_share = Scalar.one, .group_public_key = commit.pedersenH(), .verifying_share = commit.pedersenH() };
}

fn addComplaint(p: *Participant, complainant: u32, accused: u32, valid: bool, seen: bool) !void {
    const aa = p.arena.allocator();
    try p.complaints.append(aa, .{ .complainant = complainant, .accused = accused });
    try p.defense_valid.append(aa, valid);
    try p.defense_seen.append(aa, seen);
}

fn shareFrame(p: *Participant) *Outgoing {
    for (p.outbox.items) |*m| switch (m.to) {
        .party => return m,
        .broadcast => {},
    };
    unreachable;
}

/// Decode a valid snapshot, break one field, and demand that the broken state
/// is refused (each case violates exactly the rule it is named after).
fn expectBrokenRefused(name: []const u8, bytes: []const u8, breakIt: *const fn (*Participant, usize) anyerror!void, cases: usize) !void {
    for (0..cases) |k| {
        var q = try Participant.fromBytes(testing.allocator, bytes);
        defer q.deinit();
        try breakIt(&q, k);
        const again = try snap(&q);
        defer freeSnap(again);
        testing.expectError(error.InvalidState, Participant.fromBytes(testing.allocator, again)) catch |e| {
            std.debug.print("{s}: case {d} was not refused\n", .{ name, k });
            return e;
        };
    }
}

fn breakNew(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => p.ped[1] = try someElements(p),
        1 => p.fel[1] = try someElements(p),
        2 => p.wire_s[1] = Scalar.one,
        3 => p.wire_sp[1] = Scalar.one,
        4 => p.accepted[1] = Scalar.one,
        5 => p.accepted_sp[1] = Scalar.one,
        6 => p.recovered[1] = p.a,
        7 => p.present[0] = true,
        8 => p.qualified[0] = true,
        9 => p.exposed[0] = true,
        10 => try addComplaint(p, 1, 2, false, false),
        11 => try p.outbox.append(p.allocator, .{ .to = .broadcast, .bytes = try p.allocator.dupe(u8, "x") }),
        12 => p.result = someOutput(p),
        13 => p.group_commitments = try someElements(p),
        14 => p.culprit_ = 1,
        15 => p.revealed[0] = Scalar.one,
        else => unreachable,
    }
}

fn breakShares(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => p.present[0] = false,
        1 => p.accepted_sp[0] = Scalar.one,
        2 => p.accepted_sp[1] = Scalar.one,
        3 => p.ped[0].?[0] = p.ped[0].?[1],
        4 => p.fel[0].?[0] = p.fel[0].?[1],
        5 => p.accepted[0] = Scalar.one,
        6 => shareFrame(p).bytes[0] = 0,
        7 => shareFrame(p).bytes[0] = 255,
        8 => shareFrame(p).to = .{ .party = 0 },
        9 => {
            const m = shareFrame(p);
            p.allocator.free(m.bytes);
            m.bytes = try p.allocator.alloc(u8, 0);
        },
        10 => {
            p.phase_ = .aborted;
            p.result = someOutput(p);
        },
        11 => {
            p.phase_ = .aborted;
            p.group_commitments = try someElements(p);
        },
        else => unreachable,
    }
}

fn breakComplaints(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => p.present[1] = !p.present[1],
        1 => p.accepted_sp[1] = null,
        2 => {
            p.ped[1] = null;
            p.present[1] = false;
        },
        3 => p.accepted_sp[0] = Scalar.one,
        else => unreachable,
    }
}

fn breakComplaintHeld(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => p.defense_seen.items[0] = true,
        1 => p.defense_valid.items[0] = true,
        else => unreachable,
    }
}

fn breakDefenses(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => {
            p.defense_valid.items[0] = true;
            p.defense_seen.items[0] = false;
        },
        1 => try addComplaint(p, 1, 0, false, false),
        2 => try addComplaint(p, 1, 4, false, false),
        3 => p.fel[1] = try someElements(p),
        else => unreachable,
    }
}

fn breakFeldman(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => {
            p.accepted[1] = null;
            p.accepted_sp[1] = null;
        },
        1 => {
            p.qualified[1] = false;
            p.fel[1] = try someElements(p);
        },
        2 => p.exposed[1] = true,
        else => unreachable,
    }
}

fn breakReveals(p: *Participant, k: usize) anyerror!void {
    switch (k) {
        0 => {
            p.qualified[1] = false;
            p.fel[1] = null;
        },
        1 => {
            p.exposed[0] = true;
            p.revealed[0] = Scalar.one;
        },
        2 => {
            p.exposed[1] = false;
            for (p.revealed[3..6]) |*s| s.* = null;
        },
        else => unreachable,
    }
}

test "Participant: each field a run cannot combine is refused, round by round" {
    var prng = std.Random.DefaultPrng.init(0x5A9_2002);
    var fresh = try Participant.init(testing.allocator, .{ .t = 2, .n = 3 }, 1, prng.random());
    defer fresh.deinit();
    {
        const bytes = try snap(&fresh);
        defer freeSnap(bytes);
        try expectBrokenRefused("new", bytes, breakNew, 16);
    }
    const Case = struct { name: []const u8, steps: usize, hold: bool, f: *const fn (*Participant, usize) anyerror!void, cases: usize };
    const table = [_]Case{
        .{ .steps = 0, .hold = false, .name = "breakShares", .f = breakShares, .cases = 12 },
        .{ .steps = 1, .hold = false, .name = "breakComplaints", .f = breakComplaints, .cases = 4 },
        .{ .steps = 1, .hold = true, .name = "breakComplaintHeld", .f = breakComplaintHeld, .cases = 2 },
        .{ .steps = 2, .hold = false, .name = "breakDefenses", .f = breakDefenses, .cases = 4 },
        .{ .steps = 3, .hold = false, .name = "breakFeldman", .f = breakFeldman, .cases = 3 },
        .{ .steps = 5, .hold = false, .name = "breakReveals", .f = breakReveals, .cases = 3 },
    };
    inline for (table) |c| {
        var net = try world(c.steps);
        defer net.deinit();
        if (c.hold) try net.deliverAll(); // party 1 holds party 3's complaint while still in `.complaints`
        const p = &net.parties[0];
        const bytes = try snap(p);
        defer freeSnap(bytes);
        // the unbroken state is accepted
        var ok = try Participant.fromBytes(testing.allocator, bytes);
        ok.deinit();
        try expectBrokenRefused(c.name, bytes, c.f, c.cases);
    }
}

test "ReshareReceiver snapshot: NoSpaceLeft below encodedLength" {
    var buf: [4096]u8 = undefined;
    const old = try reshare_test_receiver(testing.allocator);
    var r = old;
    defer r.deinit();
    const len = r.encodedLength();
    try testing.expect(len < buf.len);
    try testing.expectError(error.NoSpaceLeft, r.toBytes(buf[0 .. len - 1]));
    try testing.expectEqual(len, (try r.toBytes(&buf)).len);
}

fn reshare_test_receiver(allocator: Allocator) !ReshareReceiver {
    return reshare.snapshotTestReceiver(allocator);
}

// ── fuzz: the decoders never panic, leak or accept a non-canonical input ──

const fz = @import("fuzz_test.zig");
const Mark = fz.Marker(enum { refused, accepted_participant, accepted_receiver, canonical_roundtrip });
const snapshot_buf_len = 8192;

var corpus_cache: ?[]const []const u8 = null;

/// Real snapshots (a Participant at every round of a world that passes
/// through complaint, defense, exposure and reconstruction; receivers from
/// `reshare.fuzzSnapshotCorpus`), each behind a little-endian u32 length.
fn corpusEntries() []const []const u8 {
    if (corpus_cache == null) {
        const pa = std.heap.page_allocator; // global-alloc-ok: process-lifetime fuzz/test fixture cached across driver runs, outlives testing.allocator's per-test teardown
        var list: std.ArrayList([]const u8) = .empty;
        for (0..7) |steps| {
            var net = worldIn(pa, steps) catch unreachable;
            defer net.deinit();
            for (net.parties) |*p| {
                const bytes = pa.alloc(u8, p.encodedLength()) catch unreachable;
                _ = p.toBytes(bytes) catch unreachable;
                list.append(pa, withHeader(pa, bytes)) catch unreachable;
            }
        }
        reshare.fuzzSnapshotCorpus(pa, &list) catch unreachable;
        corpus_cache = list.toOwnedSlice(pa) catch unreachable;
    }
    return corpus_cache.?;
}

pub fn withHeader(pa: Allocator, bytes: []const u8) []const u8 {
    const out = pa.alloc(u8, 4 + bytes.len) catch unreachable;
    std.mem.writeInt(u32, out[0..4], @intCast(bytes.len), .little);
    @memcpy(out[4..], bytes);
    return out;
}

fn fuzzSnapshotSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzSnapshotDecode(std.testing.Smith, smith, testing.allocator);
}

fn fuzzSnapshotDecode(comptime S: type, src: *S, gpa: Allocator) anyerror!void {
    var buf: [snapshot_buf_len]u8 = undefined;
    const len: usize = fz.drawInput(S, src, &buf, corpusEntries());
    const input = buf[0..len];
    var accepted = false;
    if (Participant.fromBytes(gpa, input)) |q| {
        var p = q;
        defer p.deinit();
        accepted = true;
        Mark.mark(.accepted_participant);
        const again = try gpa.alloc(u8, p.encodedLength());
        defer freeBytes(gpa, again);
        _ = try p.toBytes(again);
        if (!std.mem.eql(u8, again, input)) return error.NonCanonicalSnapshotAccepted;
        Mark.mark(.canonical_roundtrip);
    } else |_| {}
    if (ReshareReceiver.fromBytes(gpa, input)) |q| {
        var r = q;
        defer r.deinit();
        accepted = true;
        Mark.mark(.accepted_receiver);
        const again = try gpa.alloc(u8, r.encodedLength());
        defer freeBytes(gpa, again);
        _ = try r.toBytes(again);
        if (!std.mem.eql(u8, again, input)) return error.NonCanonicalSnapshotAccepted;
    } else |_| {}
    if (!accepted) Mark.mark(.refused);
}

fn freeBytes(gpa: Allocator, b: []u8) void {
    std.crypto.secureZero(u8, b);
    gpa.free(b);
}

test "fuzz: snapshot decoders never panic" {
    try std.testing.fuzz({}, fuzzSnapshotSmith, .{ .corpus = corpusEntries() });
}

test "fuzz driver: DKG_FUZZ (snapshot decode)" {
    try fz.fuzz_driver.run(fuzzSnapshotDecode, .{ .prefix = "DKG_FUZZ", .name = "dkg-snapshot-decode", .scale = 40 });
}

test "fuzz harness: snapshot decode, 200 seeds, reaches every outcome" {
    try Mark.reach(fuzzSnapshotDecode, "dkg-snapshot-decode", 200);
}
