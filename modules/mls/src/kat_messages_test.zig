// SPDX-License-Identifier: MIT
//! mls.kat_messages_test — the official RFC 9420 `messages` interop vector
//! (`mlswg/mls-implementations` `test-vectors/messages.json`), driving every
//! Part 5 wire format through decode→re-encode byte-exact. See `NOTICE` for
//! the exact source commit, fetch date, and the field/entry filter applied
//! before embedding.
//!
//! **What this vector can and cannot prove.** Upstream's own verification
//! procedure for it is exactly two lines — "The contents of each field must
//! decode using the corresponding structure" and "Each decoded object must
//! re-encode to produce the bytes in the test vector" — and it says outright
//! that "the optional MAC values may be invalid but should be populated".
//! So this is a WIRE-FORMAT anchor, not a cryptographic one: it pins field
//! order, varint length prefixes, `select` discriminants and
//! `optional<T>` presence octets against bytes another implementation
//! produced, and it pins nothing about signatures or MACs. The
//! cryptographic anchor is `kat_framing_test.zig`'s `message-protection.json`,
//! which supplies real keys.
//!
//! That is still a strong check, because re-encoding is unforgiving in
//! precisely the places a hand-written TLS-presentation codec goes wrong:
//! a `select` arm read with the wrong discriminant, a `uint32 foo<V>` list
//! whose length was written as an element COUNT instead of a byte length,
//! an `optional<UpdatePath>` encoded as an empty vector instead of a
//! presence octet, or §2.1.2's minimal-varint rule violated on a
//! boundary-length field — each of those decodes happily and re-encodes to
//! different bytes.
//!
//! Every field is driven under its own stage name, so a divergence names
//! the structure that diverged rather than "the vector failed".
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning.

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const tree = @import("tree.zig");
const content = @import("content.zig");
const framing = @import("framing.zig");
const keypackage = @import("keypackage.zig");
const keyschedule = @import("keyschedule.zig");

const messages_json = @embedFile("data/messages.json");

const testing = std.testing;
const S = suite.default;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// Compares a re-encoding against the vector's own bytes, naming the stage
/// and entry on divergence — and, when the lengths differ, saying by how
/// much, since a length delta of exactly one is almost always a varint
/// prefix and a delta of exactly four an `optional<T>`/`uint32` confusion.
fn expectReencode(stage: []const u8, entry: usize, want: []const u8, got: []const u8) !void {
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print(
            "messages.json KAT: '{s}' re-encode diverged at entry {d} (want {d} bytes, got {d})\n",
            .{ stage, entry, want.len, got.len },
        );
        return err;
    };
}

/// Names the stage on a DECODE failure too, not just on a re-encode
/// mismatch — otherwise a corrupted vector byte that stops the parser dead
/// reports a bare `error.Malformed` with no indication of which of the
/// dozen structures per entry it came from, which is exactly the situation
/// a staged harness exists to avoid.
fn noteDecode(stage: []const u8, entry: usize, err: anyerror) anyerror {
    std.debug.print("messages.json KAT: '{s}' failed to decode at entry {d}: {s}\n", .{ stage, entry, @errorName(err) });
    return err;
}

/// decode → re-encode → compare, for a type with the module's usual
/// `decode(allocator, reader)` / `encodedLen()` / `encode(writer)` /
/// `deinit(allocator)` shape.
fn roundTripAlloc(
    comptime T: type,
    stage: []const u8,
    entry: usize,
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !void {
    var r = codec.Reader.init(bytes);
    const value = T.decode(allocator, &r) catch |err| return noteDecode(stage, entry, err);
    defer value.deinit(allocator);
    // A trailing byte the decoder ignored would make the re-encode compare
    // pass while the wire shape is still wrong, so the cursor must land
    // exactly at the end.
    if (!r.atEnd()) {
        std.debug.print("messages.json KAT: '{s}' left {d} trailing bytes at entry {d}\n", .{ stage, r.remaining().len, entry });
        return error.TrailingBytes;
    }
    const buf = try allocator.alloc(u8, value.encodedLen());
    defer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try value.encode(&w);
    try expectReencode(stage, entry, bytes, w.finish());
}

test "messages.json: every Part 5 wire format decodes and re-encodes byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, messages_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();
    const alloc = testing.allocator;

    var entries: usize = 0;
    var wire_formats_seen: [6]bool = @splat(false);
    var content_types_seen: [4]bool = @splat(false);

    for (parsed.value.array.items, 0..) |entry, i| {
        entries += 1;
        const obj = entry.object;

        // ── §12.1.1-§12.1.7: the seven proposal BODIES, each serialized
        // bare (no `proposal_type` prefix — upstream's format calls these
        // "Serialized Add"/"Serialized Remove"/..., i.e. the `select` arm
        // itself). Each is driven through the type this module models that
        // arm with, which is exactly the mapping `content.Proposal` uses.
        try roundTripAlloc(keypackage.KeyPackage, "add_proposal (§12.1.1 KeyPackage)", i, alloc, try hexDecode(arena, obj.get("add_proposal").?.string));
        try roundTripAlloc(tree.LeafNode, "update_proposal (§12.1.2 LeafNode)", i, alloc, try hexDecode(arena, obj.get("update_proposal").?.string));
        try roundTripAlloc(content.ReInit, "re_init_proposal (§12.1.5)", i, alloc, try hexDecode(arena, obj.get("re_init_proposal").?.string));

        {
            // §12.1.3 Remove is a bare `uint32`, so it has no decode/encode
            // pair of its own — driven through `content.Proposal` with the
            // §17.4 type value prepended instead, which also pins that
            // value against the vector's own byte width.
            const bytes = try hexDecode(arena, obj.get("remove_proposal").?.string);
            try testing.expectEqual(@as(usize, 4), bytes.len);
            var r = codec.Reader.init(bytes);
            const p: content.Proposal = .{ .remove = try r.readU32() };
            const re = try p.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectReencode("remove_proposal (§12.1.3)", i, bytes, re[2..]);
            try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x03 }, re[0..2]);
        }
        {
            // §12.1.4 PreSharedKey — `PreSharedKeyID` (Part 4), no allocator.
            const bytes = try hexDecode(arena, obj.get("pre_shared_key_proposal").?.string);
            var r = codec.Reader.init(bytes);
            const id = try keyschedule.PreSharedKeyId.decode(&r);
            try testing.expect(r.atEnd());
            const buf = try alloc.alloc(u8, id.encodedLen());
            defer alloc.free(buf);
            var w = codec.Writer.init(buf);
            try id.encode(&w);
            try expectReencode("pre_shared_key_proposal (§12.1.4)", i, bytes, w.finish());
        }
        {
            // §12.1.6 ExternalInit — one `opaque kem_output<V>`.
            const bytes = try hexDecode(arena, obj.get("external_init_proposal").?.string);
            var r = codec.Reader.init(bytes);
            const p: content.Proposal = .{ .external_init = try r.readVector() };
            try testing.expect(r.atEnd());
            const re = try p.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectReencode("external_init_proposal (§12.1.6)", i, bytes, re[2..]);
        }
        {
            // §12.1.7 GroupContextExtensions — one `Extension extensions<V>`.
            const bytes = try hexDecode(arena, obj.get("group_context_extensions_proposal").?.string);
            var r = codec.Reader.init(bytes);
            const exts = try tree.decodeExtensionList(alloc, &r);
            defer alloc.free(exts);
            try testing.expect(r.atEnd());
            const p: content.Proposal = .{ .group_context_extensions = exts };
            const re = try p.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectReencode("group_context_extensions_proposal (§12.1.7)", i, bytes, re[2..]);
        }

        // ── §12.4: Commit (ProposalOrRef list + optional<UpdatePath>) ──
        try roundTripAlloc(content.Commit, "commit (§12.4)", i, alloc, try hexDecode(arena, obj.get("commit").?.string));

        // ── §6: the four MLSMessage wire formats this part decodes ──
        inline for (.{
            .{ "mls_key_package", "mls_key_package (§6 MLSMessage/§10)" },
            .{ "public_message_application", "public_message_application (§6.2)" },
            .{ "public_message_proposal", "public_message_proposal (§6.2)" },
            .{ "public_message_commit", "public_message_commit (§6.2)" },
            .{ "private_message", "private_message (§6.3)" },
        }) |spec| {
            const bytes = try hexDecode(arena, obj.get(spec[0]).?.string);
            var r = codec.Reader.init(bytes);
            const msg = framing.MLSMessage.decode(alloc, &r) catch |err| return noteDecode(spec[1], i, err);
            defer msg.deinit(alloc);
            if (!r.atEnd()) return noteDecode(spec[1], i, error.TrailingBytes);
            wire_formats_seen[@intFromEnum(msg.wireFormat())] = true;
            switch (msg) {
                .public_message => |pm| content_types_seen[@intFromEnum(pm.content.contentType())] = true,
                .private_message => |pm| content_types_seen[@intFromEnum(pm.content_type)] = true,
                .key_package => {},
            }
            const re = try msg.encodeAlloc(alloc);
            defer alloc.free(re);
            try expectReencode(spec[1], i, bytes, re);
        }
    }

    try testing.expect(entries > 0);
    // The embedded subset must actually reach all three §6 content types
    // and all three §17.2 wire formats this part decodes — otherwise the
    // `select` arms below `application` would go untested and the vector
    // would still "pass". See `NOTICE` for how the subset was chosen.
    try testing.expect(content_types_seen[@intFromEnum(framing.ContentType.application)]);
    try testing.expect(content_types_seen[@intFromEnum(framing.ContentType.proposal)]);
    try testing.expect(content_types_seen[@intFromEnum(framing.ContentType.commit)]);
    try testing.expect(wire_formats_seen[@intFromEnum(framing.WireFormat.mls_public_message)]);
    try testing.expect(wire_formats_seen[@intFromEnum(framing.WireFormat.mls_private_message)]);
    try testing.expect(wire_formats_seen[@intFromEnum(framing.WireFormat.mls_key_package)]);
}

test "messages.json: the Commit vectors really do exercise an UpdatePath and a by-reference proposal" {
    // Guards the check above against a subset that happens to contain only
    // the easy shapes: an `optional<UpdatePath>` that is always absent and a
    // `ProposalOrRef` that is always by-value would leave the two most
    // error-prone arms of §12.4 unexercised while everything still passed.
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, messages_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();

    var with_path: usize = 0;
    var by_reference: usize = 0;
    for (parsed.value.array.items) |entry| {
        const bytes = try hexDecode(arena, entry.object.get("commit").?.string);
        var r = codec.Reader.init(bytes);
        const c = try content.Commit.decode(testing.allocator, &r);
        defer c.deinit(testing.allocator);
        if (c.path != null) with_path += 1;
        for (c.proposals) |p| if (p == .reference) {
            by_reference += 1;
        };
    }
    try testing.expect(with_path > 0);
    try testing.expect(by_reference > 0);
}
