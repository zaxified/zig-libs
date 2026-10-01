// SPDX-License-Identifier: MIT

//! wire — the framing shared by the per-participant state machines
//! (`participant.zig`, `reshare.zig`): a one-octet message kind in front of the
//! body encodings from `types.zig`, the routing target of an outgoing message,
//! and the typed errors a party returns for a message it refuses.
//!
//! The state machines are sans-I/O: they consume `(sender, bytes)` and produce
//! `Outgoing` frames; carrying those frames (and authenticating who sent them,
//! and encrypting the point-to-point ones) is the caller's transport.

const std = @import("std");

/// The first octet of every frame.
pub const Kind = enum(u8) {
    // GJKR DKG (`participant.zig`)
    pedersen_broadcast = 1,
    share = 2,
    complaint = 3,
    defense = 4,
    feldman_broadcast = 5,
    /// GJKR Fig. 2 step 4(b): a QUAL dealer's Feldman commitments do not
    /// match a share that verifies against its Pedersen commitments. The
    /// body is a `ShareMsg` (dealer = accused, receiver = complainant) that
    /// opens the share, so every party can check the complaint itself.
    feldman_complaint = 6,
    /// GJKR Fig. 2 step 4(c): a party's Pedersen-verified share of an
    /// exposed dealer's polynomial, broadcast so everyone can reconstruct it.
    /// Body: `ShareMsg` (dealer = exposed dealer, receiver = the holder).
    reveal = 7,
    // resharing (`reshare.zig`)
    reshare_broadcast = 16,
    reshare_share = 17,
    reshare_complaint = 18,
    reshare_defense = 19,
};

pub fn kindFromByte(b: u8) ?Kind {
    inline for (@typeInfo(Kind).@"enum".fields) |f| {
        if (b == f.value) return @enumFromInt(f.value);
    }
    return null;
}

/// Where an outgoing frame goes.
pub const Target = union(enum) {
    /// To every OTHER party of the protocol (the sender never receives its own
    /// broadcast; it records the content locally). The transport must give all
    /// receivers the same bytes (reliable broadcast) — GJKR assumes it.
    broadcast,
    /// To exactly one party, by protocol id. Must be confidential.
    party: u32,
};

/// One frame a state machine wants sent. `bytes` is owned by the caller once
/// taken from `takeOutgoing`; release with `deinit` (it wipes first: share
/// frames carry secrets).
pub const Outgoing = struct {
    to: Target,
    bytes: []u8,

    pub fn deinit(self: Outgoing, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
};

/// Free a slice returned by `takeOutgoing` together with every frame in it.
pub fn freeOutgoing(allocator: std.mem.Allocator, msgs: []Outgoing) void {
    for (msgs) |m| m.deinit(allocator);
    allocator.free(msgs);
}

/// Why a party refused a message. None of these is fatal to the protocol run
/// by itself: a refused message changes no state, and the run simply continues
/// (a sender whose message never arrives is handled at the round's deadline).
pub const MessageError = error{
    /// The kind octet is not one this state machine understands.
    UnknownKind,
    /// Wrong length, non-canonical scalar, a point off the curve or at
    /// infinity, an id outside `1..n`, or a wrong commitment count.
    Malformed,
    /// `from` is not a party of this run (out of range, or ourselves).
    UnknownSender,
    /// The id named inside the body is not the authenticated sender.
    SenderMismatch,
    /// A point-to-point message meant for somebody else.
    WrongRecipient,
    /// A valid message, but not for the current round. A network with skew may
    /// hold it back and redeliver it after the round advances.
    WrongRound,
    /// This sender already delivered this message.
    DuplicateMessage,
    /// Well-formed but refers to something that does not exist: a defense
    /// nobody complained about, a Feldman broadcast from a disqualified dealer.
    Unsolicited,
    /// Opens a share that does not verify against the dealer's public
    /// commitments: a Feldman complaint about a dealer whose commitments are
    /// fine, or a revealed share that is not the committed one.
    Unverified,
    /// The run is complete; no message is accepted any more.
    Finished,
    /// The run was aborted (see `culprit`); no message is accepted.
    Aborted,
} || std.mem.Allocator.Error;

/// Map a `types` codec error onto `MessageError`: allocation failure stays,
/// every decoding failure is `Malformed`.
pub fn codecError(err: anytype) MessageError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Malformed,
    };
}

/// `kind || body` in a fresh buffer.
pub fn frame(allocator: std.mem.Allocator, kind: Kind, body: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, 1 + body.len);
    out[0] = @intFromEnum(kind);
    @memcpy(out[1..], body);
    return out;
}

pub fn pushFrame(
    list: *std.ArrayList(Outgoing),
    allocator: std.mem.Allocator,
    to: Target,
    kind: Kind,
    body: []const u8,
) std.mem.Allocator.Error!void {
    const bytes = try frame(allocator, kind, body);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    try list.append(allocator, .{ .to = to, .bytes = bytes });
}

test "kindFromByte covers exactly the declared kinds" {
    var known: usize = 0;
    var b: usize = 0;
    while (b < 256) : (b += 1) {
        if (kindFromByte(@intCast(b))) |k| {
            try std.testing.expectEqual(@as(u8, @intCast(b)), @intFromEnum(k));
            known += 1;
        }
    }
    try std.testing.expectEqual(@typeInfo(Kind).@"enum".fields.len, known);
}
