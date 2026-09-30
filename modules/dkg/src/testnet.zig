// SPDX-License-Identifier: MIT

//! testnet — test-only helpers: an in-memory synchronous network around
//! `Participant`s, and the loader for the recorded transcript
//! (`transcript_vectors.zig`, produced by `tools/gjkr_oracle.py`). Referenced
//! from `test` blocks only; nothing here is part of the module's API.

const std = @import("std");
const commit = @import("commit.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");
const participant = @import("participant.zig");
const vectors = @import("transcript_vectors.zig");

const Participant = participant.Participant;
const Scalar = types.Scalar;
const Element = types.Element;
const Config = types.Config;
const DkgShareOutput = types.DkgShareOutput;
const Ne = types.Ne;
const Ns = types.Ns;
const testing = std.testing;

/// What a test's network does with one delivery.
pub const Action = enum { deliver, drop };
pub const Filter = *const fn (from: u32, to: u32, bytes: []u8) Action;

/// A tiny synchronous router: delivers every queued frame to its recipients
/// (a broadcast to every other party), optionally letting `filter` tamper with
/// or drop each delivery, then advances all live parties.
pub const TestNet = struct {
    allocator: std.mem.Allocator,
    parties: []Participant,
    /// Deliveries the receiving party refused (kept, not fatal).
    refused: usize = 0,
    filter: ?Filter = null,
    /// Parties (1-based) that are crashed: send nothing, receive nothing.
    crashed: []const u32 = &.{},

    pub fn init(allocator: std.mem.Allocator, cfg: Config, random: std.Random) !TestNet {
        const parties = try allocator.alloc(Participant, cfg.n);
        var built: usize = 0;
        errdefer {
            for (parties[0..built]) |*p| p.deinit();
            allocator.free(parties);
        }
        // Draw in id order from the shared generator: this is what makes a run
        // reproduce the lockstep driver for the same seed.
        for (parties, 0..) |*p, i| {
            p.* = try Participant.init(allocator, cfg, @intCast(i + 1), random);
            built += 1;
        }
        return .{ .allocator = allocator, .parties = parties };
    }

    pub fn deinit(self: *TestNet) void {
        for (self.parties) |*p| p.deinit();
        self.allocator.free(self.parties);
    }

    fn isCrashed(self: *const TestNet, id: u32) bool {
        return std.mem.indexOfScalar(u32, self.crashed, id) != null;
    }

    fn deliverTo(self: *TestNet, from: u32, to: u32, bytes: []const u8) !void {
        if (self.isCrashed(to)) return;
        const copy = try self.allocator.dupe(u8, bytes);
        defer self.allocator.free(copy);
        if (self.filter) |f| if (f(from, to, copy) == .drop) return;
        self.parties[to - 1].handle(from, copy) catch |e| switch (e) {
            error.OutOfMemory => return e,
            else => self.refused += 1,
        };
    }

    /// Deliver everything queued by every party.
    pub fn deliverAll(self: *TestNet) !void {
        for (self.parties) |*p| {
            const msgs = try p.takeOutgoing();
            defer wire.freeOutgoing(self.allocator, msgs);
            if (self.isCrashed(p.me)) continue;
            for (msgs) |m| switch (m.to) {
                .broadcast => for (self.parties) |*q| {
                    if (q.me != p.me) try self.deliverTo(p.me, q.me, m.bytes);
                },
                .party => |j| try self.deliverTo(p.me, j, m.bytes),
            };
        }
    }

    pub fn startAll(self: *TestNet) !void {
        for (self.parties) |*p| if (!self.isCrashed(p.me)) try p.start();
    }

    pub fn advanceAll(self: *TestNet) !void {
        for (self.parties) |*p| if (!self.isCrashed(p.me)) try p.advance();
    }

    /// The whole run: start, then four (deliver, advance) rounds.
    pub fn run(self: *TestNet) !void {
        try self.startAll();
        for (0..4) |_| {
            try self.deliverAll();
            try self.advanceAll();
        }
    }

    /// Outputs of the live parties, in id order (caller frees the slice and
    /// wipes each output).
    pub fn outputs(self: *TestNet) ![]DkgShareOutput {
        var list: std.ArrayList(DkgShareOutput) = .empty;
        errdefer list.deinit(self.allocator);
        for (self.parties) |*p| {
            if (self.isCrashed(p.me)) continue;
            try list.append(self.allocator, p.output().?);
        }
        return list.toOwnedSlice(self.allocator);
    }
};

pub fn freeOutputs(allocator: std.mem.Allocator, outs: []DkgShareOutput) void {
    for (outs) |*o| o.deinit();
    allocator.free(outs);
}

pub fn hexScalar(hex: []const u8) !Scalar {
    if (hex.len != 2 * Ns) return error.InvalidEncoding;
    var b: [Ns]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex);
    return Scalar.fromBytes(b, .big) catch error.InvalidEncoding;
}

pub fn hexElement(hex: []const u8) !Element {
    if (hex.len != 2 * Ne) return error.InvalidEncoding;
    var b: [Ne]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, hex);
    return Element.fromBytes(b);
}

pub fn expectHex(hex: []const u8, actual: []const u8) !void {
    var buf: [2 * Ne]u8 = undefined;
    try testing.expectEqual(hex.len, 2 * actual.len);
    _ = try std.fmt.hexToBytes(buf[0..actual.len], hex);
    try testing.expectEqualSlices(u8, buf[0..actual.len], actual);
}

pub const DealerRec = struct {
    id: u32,
    a: []const []const u8,
    b: []const []const u8,
    pedersen: []const []const u8,
    feldman: []const []const u8,
    shares: []const []const []const u8,
};
pub const OutRec = struct { id: u32, x: []const u8, X: []const u8 };
pub const TranscriptRec = struct {
    n: u32,
    t: u32,
    h: []const u8,
    dealers: []const DealerRec,
    group_public_key: []const u8,
    outputs: []const OutRec,
    reshare: ReshareRec,
};
pub const ReshareRec = struct {
    dealers: []const u32,
    new_n: u32,
    new_t: u32,
    dealer_polys: []const struct {
        id: u32,
        c: []const []const u8,
        commitments: []const []const u8,
        shares: []const []const u8,
        lambda: []const u8,
    },
    new_commitments: []const []const u8,
    outputs: []const OutRec,
};

pub fn parseTranscript(allocator: std.mem.Allocator) !std.json.Parsed(TranscriptRec) {
    return std.json.parseFromSlice(TranscriptRec, allocator, vectors.json, .{});
}
