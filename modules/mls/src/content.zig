// SPDX-License-Identifier: MIT
//! mls.content — the two non-application bodies a `FramedContent` can
//! carry: RFC 9420 §12.1's `Proposal` (all seven types) and §12.4's
//! `Commit` (with §12.4's `ProposalOrRef`).
//!
//! **These are §12 structures, not §6 ones — deliberately in Part 5
//! anyway.** RFC 9420 §6's `FramedContent` has a `select
//! (FramedContent.content_type)` whose `proposal`/`commit` arms name these
//! two types, so a framing layer that cannot decode them can decode
//! nothing but application data. Everything in §12 that is NOT wire shape
//! stays out: this file has no proposal-list validity rules (§12.2), no
//! "does this Commit need a path" policy (§12.4's `Path Required` column
//! of the §17.4 registry), no application order (§12.3), and no
//! commit-processing state machine (§12.4.1/§12.4.2). Those are a later
//! part's; a decoder that silently enforced half of them would be worse
//! than one that enforces none, because callers would stop checking.
//!
//! **What "Proposal is complete" costs.** §12.1.1's `Add` carries a
//! `KeyPackage`, which is §10 — see `keypackage.zig`'s own doc comment for
//! why that file exists here. The other six arms are built entirely from
//! types earlier parts already own: `tree.LeafNode` (§12.1.2 `Update`), a
//! bare `uint32` (§12.1.3 `Remove`), `keyschedule.PreSharedKeyId`
//! (§12.1.4 `PreSharedKey`), `tree.Extension` lists (§12.1.5 `ReInit`,
//! §12.1.7 `GroupContextExtensions`), and one `opaque<V>` (§12.1.6
//! `ExternalInit`). §12.4's `Commit` reuses `treekem.UpdatePath` (Part 2).
//!
//! **`ProposalRef` is an opaque vector here, on purpose.** On the wire a
//! by-reference `ProposalOrRef` is just `opaque<V>` (§5.2's
//! `HashReference`). COMPUTING one is `crypto.make_proposal_ref` over an
//! encoded `AuthenticatedContent`, which lives in `framing.zig` (see
//! `framing.proposalRef`) — putting the computation here would make this
//! file depend on the framing layer that depends on it.
//!
//! Model: RFC 9420 §12.1 (Proposals) + §12.1.1-§12.1.7 (the seven bodies)
//! + §12.4 (`ProposalOrRefType`/`ProposalOrRef`/`Commit`) + §17.4's
//! Proposal Types registry for the type values. Anchored by
//! `kat_messages_test.zig` (`messages.json`'s seven `*_proposal` fields
//! and its `commit` field, decode→re-encode byte-exact) and
//! `kat_framing_test.zig` (`message-protection.json`'s `proposal`/`commit`
//! carried through the full protect/unprotect path).

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const treekem = @import("treekem.zig");
const keyschedule = @import("keyschedule.zig");
const wire = @import("wire_lists.zig");

const varintLen = wire.varintLen;

pub const Error = tree.Error;

// ── §12.1 / §17.4: ProposalType ───────────────────────────────────────────

/// RFC 9420 §17.4's "MLS Proposal Types" registry. Non-exhaustive so a
/// GREASE value (`0x0A0A`, `0x1A1A`, … — §13 requires implementations to
/// tolerate them in CAPABILITIES lists) or a future extension proposal type
/// read off the wire compares and prints rather than being reinterpreted as
/// something it is not.
pub const ProposalType = enum(u16) {
    reserved = 0,
    add = 1,
    update = 2,
    remove = 3,
    psk = 4,
    reinit = 5,
    external_init = 6,
    group_context_extensions = 7,
    _,
};

// ── §12.1.1-§12.1.7: the seven proposal bodies ────────────────────────────

/// RFC 9420 §12.1.5's `ReInit`. `version`/`cipher_suite` are the NEW
/// group's parameters — the whole point of a ReInit is that they may differ
/// from the current group's, so they are carried here rather than inferred.
pub const ReInit = struct {
    group_id: []const u8,
    version: keyschedule.ProtocolVersion = .mls10,
    cipher_suite: suite.CipherSuiteId,
    extensions: []const tree.Extension = &.{},

    pub fn encodedLen(self: ReInit) usize {
        return varintLen(self.group_id.len) + self.group_id.len + 2 + 2 +
            wire.varVecLen(tree.Extension, self.extensions);
    }
    pub fn encode(self: ReInit, w: *codec.Writer) codec.Error!void {
        try w.writeVector(self.group_id);
        try w.writeEnum(keyschedule.ProtocolVersion, self.version);
        try w.writeEnum(suite.CipherSuiteId, self.cipher_suite);
        try wire.encodeVarVec(tree.Extension, w, self.extensions);
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !ReInit {
        const group_id = try r.readVector();
        const version = try r.readEnum(keyschedule.ProtocolVersion);
        const cs = try r.readEnum(suite.CipherSuiteId);
        const extensions = try tree.decodeExtensionList(allocator, r);
        return .{ .group_id = group_id, .version = version, .cipher_suite = cs, .extensions = extensions };
    }
    pub fn deinit(self: ReInit, allocator: std.mem.Allocator) void {
        allocator.free(self.extensions);
    }
};

/// RFC 9420 §12.1's `Proposal`, as a Zig tagged union with the RFC's own
/// seven arms. Modeled the way `tree.Credential` is: the union tag carries
/// the variant, and `proposalType()` maps it back to the wire enum, so the
/// discriminant on the wire and the discriminant in memory cannot disagree.
///
/// Every arm's payload uses the SAME aliasing convention as the rest of
/// this module — byte fields alias the reader's buffer; only nested LISTS
/// (a `KeyPackage`'s/`LeafNode`'s extensions, `ReInit`'s extensions,
/// `Commit`'s `proposals`, an `UpdatePath`'s nodes) are allocations, freed
/// by `deinit`.
pub const Proposal = union(enum) {
    add: @import("keypackage.zig").KeyPackage,
    update: tree.LeafNode,
    remove: u32,
    psk: keyschedule.PreSharedKeyId,
    reinit: ReInit,
    external_init: []const u8, // kem_output<V>
    group_context_extensions: []const tree.Extension,

    pub fn proposalType(self: Proposal) ProposalType {
        return switch (self) {
            .add => .add,
            .update => .update,
            .remove => .remove,
            .psk => .psk,
            .reinit => .reinit,
            .external_init => .external_init,
            .group_context_extensions => .group_context_extensions,
        };
    }

    pub fn encodedLen(self: Proposal) usize {
        return 2 + switch (self) {
            .add => |kp| kp.encodedLen(),
            .update => |ln| ln.encodedLen(),
            .remove => 4,
            .psk => |id| id.encodedLen(),
            .reinit => |ri| ri.encodedLen(),
            .external_init => |kem| varintLen(kem.len) + kem.len,
            .group_context_extensions => |ext| wire.varVecLen(tree.Extension, ext),
        };
    }

    pub fn encode(self: Proposal, w: *codec.Writer) Error!void {
        try w.writeEnum(ProposalType, self.proposalType());
        switch (self) {
            .add => |kp| try kp.encode(w),
            .update => |ln| try ln.encode(w),
            .remove => |idx| try w.writeU32(idx),
            .psk => |id| try id.encode(w),
            .reinit => |ri| try ri.encode(w),
            .external_init => |kem| try w.writeVector(kem),
            .group_context_extensions => |ext| try wire.encodeVarVec(tree.Extension, w, ext),
        }
    }

    /// Rejects a `proposal_type` the §12.1 `select` has no arm for
    /// (`reserved`, GREASE, or any extension type) with `error.Malformed`:
    /// unlike an unknown enum in a leaf position, an unknown proposal type
    /// means the REST of the byte stream cannot be parsed at all — there is
    /// no length prefix around a `Proposal` body to skip over. Same
    /// reasoning as `keyschedule.PreSharedKeyId.decode`'s unknown-`psktype`
    /// handling.
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Proposal {
        const t = try r.readEnum(ProposalType);
        return switch (t) {
            .add => .{ .add = try @import("keypackage.zig").KeyPackage.decode(allocator, r) },
            .update => .{ .update = try tree.LeafNode.decode(allocator, r) },
            .remove => .{ .remove = try r.readU32() },
            .psk => .{ .psk = try keyschedule.PreSharedKeyId.decode(r) },
            .reinit => .{ .reinit = try ReInit.decode(allocator, r) },
            .external_init => .{ .external_init = try r.readVector() },
            .group_context_extensions => .{ .group_context_extensions = try tree.decodeExtensionList(allocator, r) },
            else => error.Malformed,
        };
    }

    pub fn deinit(self: Proposal, allocator: std.mem.Allocator) void {
        switch (self) {
            .add => |kp| kp.deinit(allocator),
            .update => |ln| ln.deinit(allocator),
            .remove, .external_init => {},
            .psk => {},
            .reinit => |ri| ri.deinit(allocator),
            .group_context_extensions => |ext| allocator.free(ext),
        }
    }

    /// Serializes into a freshly allocated slice (caller frees) — the input
    /// `crypto.make_proposal_ref` needs is an encoded `AuthenticatedContent`,
    /// not this, but a bare encoded `Proposal` is what
    /// `message-protection.json` compares an unprotected message's body
    /// against.
    pub fn encodeAlloc(self: Proposal, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

// ── §12.4: ProposalOrRef / Commit ─────────────────────────────────────────

pub const ProposalOrRefType = enum(u8) { reserved = 0, proposal = 1, reference = 2, _ };

/// RFC 9420 §12.4. A Commit names each proposal it covers either inline
/// (`proposal`, for proposals the committer is introducing) or by hash
/// (`reference`, §5.2's `ProposalRef` over the `AuthenticatedContent` the
/// proposal was sent in).
pub const ProposalOrRef = union(enum) {
    proposal: Proposal,
    /// An opaque `HashReference` (§5.2) — see this file's doc comment for
    /// why computing one is `framing.proposalRef`, not a method here.
    reference: []const u8,

    pub fn orRefType(self: ProposalOrRef) ProposalOrRefType {
        return switch (self) {
            .proposal => .proposal,
            .reference => .reference,
        };
    }

    pub fn encodedLen(self: ProposalOrRef) usize {
        return 1 + switch (self) {
            .proposal => |p| p.encodedLen(),
            .reference => |ref| varintLen(ref.len) + ref.len,
        };
    }
    pub fn encode(self: ProposalOrRef, w: *codec.Writer) Error!void {
        try w.writeEnum(ProposalOrRefType, self.orRefType());
        switch (self) {
            .proposal => |p| try p.encode(w),
            .reference => |ref| try w.writeVector(ref),
        }
    }
    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !ProposalOrRef {
        return switch (try r.readEnum(ProposalOrRefType)) {
            .proposal => .{ .proposal = try Proposal.decode(allocator, r) },
            .reference => .{ .reference = try r.readVector() },
            else => error.Malformed,
        };
    }
    pub fn deinit(self: ProposalOrRef, allocator: std.mem.Allocator) void {
        switch (self) {
            .proposal => |p| p.deinit(allocator),
            .reference => {},
        }
    }
};

/// RFC 9420 §12.4's `Commit`. `path` is `optional<UpdatePath>` — §2.1.1's
/// presence octet, so absent is one `0x00` byte and not an empty vector.
pub const Commit = struct {
    proposals: []const ProposalOrRef = &.{},
    path: ?treekem.UpdatePath = null,

    pub fn encodedLen(self: Commit) usize {
        return wire.varVecLen(ProposalOrRef, self.proposals) + 1 +
            (if (self.path) |p| p.encodedLen() else 0);
    }

    pub fn encode(self: Commit, w: *codec.Writer) Error!void {
        try wire.encodeVarVecAny(ProposalOrRef, w, self.proposals);
        try w.writePresence(self.path != null);
        if (self.path) |p| try p.encode(w);
    }

    pub fn decode(allocator: std.mem.Allocator, r: *codec.Reader) !Commit {
        const proposals = try wire.decodeVarVec(ProposalOrRef, true, allocator, r, ProposalOrRef.decode);
        errdefer {
            for (proposals) |p| p.deinit(allocator);
            allocator.free(proposals);
        }
        var path: ?treekem.UpdatePath = null;
        if (try r.readPresence()) path = try treekem.UpdatePath.decode(allocator, r);
        return .{ .proposals = proposals, .path = path };
    }

    pub fn deinit(self: Commit, allocator: std.mem.Allocator) void {
        for (self.proposals) |p| p.deinit(allocator);
        allocator.free(self.proposals);
        if (self.path) |p| p.deinit(allocator);
    }

    pub fn encodeAlloc(self: Commit, allocator: std.mem.Allocator) ![]u8 {
        const buf = try allocator.alloc(u8, self.encodedLen());
        errdefer allocator.free(buf);
        var w = codec.Writer.init(buf);
        try self.encode(&w);
        std.debug.assert(w.finish().len == buf.len);
        return buf;
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

fn roundTrip(p: Proposal) !void {
    const bytes = try p.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(p.encodedLen(), bytes.len);
    var r = codec.Reader.init(bytes);
    const back = try Proposal.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(p.proposalType(), back.proposalType());
    const re = try back.encodeAlloc(testing.allocator);
    defer testing.allocator.free(re);
    try testing.expectEqualSlices(u8, bytes, re);
}

test "Proposal: the allocation-free arms round-trip and carry their §17.4 type value" {
    try roundTrip(.{ .remove = 3 });
    try roundTrip(.{ .external_init = &[_]u8{ 1, 2, 3, 4 } });
    try roundTrip(.{ .psk = .{
        .id = .{ .external = &[_]u8{0xab} ** 8 },
        .psk_nonce = &[_]u8{0xcd} ** 32,
    } });
    try roundTrip(.{ .reinit = .{
        .group_id = "g",
        .cipher_suite = suite.default.id,
        .extensions = &.{},
    } });
    try roundTrip(.{ .group_context_extensions = &.{} });

    // §17.4's registry values, checked against the RFC's own table.
    try testing.expectEqual(@as(u16, 1), @intFromEnum(ProposalType.add));
    try testing.expectEqual(@as(u16, 3), @intFromEnum(ProposalType.remove));
    try testing.expectEqual(@as(u16, 7), @intFromEnum(ProposalType.group_context_extensions));
}

test "Proposal.decode: an unknown proposal_type is Malformed, not a mis-parse" {
    // 0x0A0A is §17.4's first GREASE value: a legal thing to SEE, but not a
    // body this select can parse.
    var buf: [2]u8 = .{ 0x0a, 0x0a };
    var r = codec.Reader.init(&buf);
    try testing.expectError(error.Malformed, Proposal.decode(testing.allocator, &r));
}

test "Commit: an empty proposal list with no path is three bytes, and round-trips" {
    const c: Commit = .{};
    const bytes = try c.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    // varint(0) for the empty vector, then the optional<UpdatePath> absence
    // octet. Two bytes, not one — an absent optional is still encoded.
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00 }, bytes);

    var r = codec.Reader.init(bytes);
    const back = try Commit.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(@as(usize, 0), back.proposals.len);
    try testing.expectEqual(@as(?treekem.UpdatePath, null), back.path);
}

test "Commit: by-value and by-reference entries coexist in one proposals vector" {
    const refbytes = [_]u8{0x5a} ** 32;
    const c: Commit = .{ .proposals = &.{
        .{ .proposal = .{ .remove = 1 } },
        .{ .reference = &refbytes },
    } };
    const bytes = try c.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    var r = codec.Reader.init(bytes);
    const back = try Commit.decode(testing.allocator, &r);
    defer back.deinit(testing.allocator);
    try testing.expect(r.atEnd());
    try testing.expectEqual(@as(usize, 2), back.proposals.len);
    try testing.expectEqual(ProposalOrRefType.proposal, back.proposals[0].orRefType());
    try testing.expectEqual(@as(u32, 1), back.proposals[0].proposal.remove);
    try testing.expectEqualSlices(u8, &refbytes, back.proposals[1].reference);
}
