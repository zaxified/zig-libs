// SPDX-License-Identifier: MIT
//! mls.transcript — RFC 9420 §8.2's two transcript hashes.
//!
//! **This file closes the one hole Part 4 left open on purpose.**
//! `keyschedule.zig` implements the whole of §8 except §8.2, and said so:
//! §8.2 hashes an *encoded `AuthenticatedContent`*, which did not exist
//! until Part 5's framing layer. It does now (`framing.AuthenticatedContent`),
//! so the two hashes live here — in their own file rather than back in
//! `keyschedule.zig`, because `keyschedule` is imported BY `framing` and
//! folding §8.2 in would make that a cycle.
//!
//! The running state is two hashes, not one:
//!
//! * `confirmed_transcript_hash` covers every Commit ever sent, up to and
//!   including the most recent Commit's SIGNATURE. It is what the
//!   `confirmation_tag` MACs (§6.1) and what goes into the `GroupContext`
//!   (§8.1).
//! * `interim_transcript_hash` covers that, plus the most recent Commit's
//!   `confirmation_tag`. It is the value the NEXT epoch's confirmed hash
//!   chains from.
//!
//! **Why the split exists at all** — and this is the part that is easy to
//! get wrong by "simplifying": a Commit's own `confirmation_tag` is a MAC
//! over the confirmed hash that that same Commit produces. If there were
//! one running hash covering the tag too, computing the tag would require
//! the hash that requires the tag. Splitting the update in two at exactly
//! the signature boundary breaks the circularity, which is why
//! `ConfirmedTranscriptHashInput` stops at `signature` and
//! `InterimTranscriptHashInput` is nothing but the tag. §8.2's Figure 23
//! is the same statement as a diagram.
//!
//! A new member cannot replay the history, so it takes
//! `interim_transcript_hash` from the `GroupInfo` it was welcomed with
//! (§8.2: "New members compute the interim transcript hash using the
//! confirmation_tag field of the GroupInfo struct") — that is a Part 6
//! flow, but the function it would call is `interimTranscriptHash` here.
//!
//! Model: RFC 9420 §8.2 (Transcript Hashes) — `ConfirmedTranscriptHashInput`,
//! `InterimTranscriptHashInput`, and the two recurrences, with epoch 0
//! seeded by the zero-length string. Anchored byte-exact against the
//! official `mlswg/mls-implementations` `transcript-hashes.json` — see
//! `kat_framing_test.zig` and `NOTICE`.

const std = @import("std");
const codec = @import("codec.zig");
const suite = @import("suite.zig");
const framing = @import("framing.zig");
const keyschedule = @import("keyschedule.zig");
const wire = @import("wire_lists.zig");

pub const Error = error{
    /// §8.2 hashes Commits only ("Commit messages are included directly.
    /// Proposal messages are indirectly included via the Commit that
    /// applied them"), so an `AuthenticatedContent` carrying anything else
    /// is a caller error, not something to hash anyway.
    NotACommit,
} || framing.Error;

/// RFC 9420 §8.2's `ConfirmedTranscriptHashInput` — `wire_format ||
/// content || signature<V>`.
///
/// Note what is NOT in it: no `version` prefix (unlike §6.1's
/// `FramedContentTBS`) and no `confirmation_tag` (unlike the full
/// `FramedContentAuthData` a Commit carries). It is `AuthenticatedContent`
/// truncated at exactly the signature — see this file's doc comment for why
/// that boundary is where it is.
pub fn confirmedInputLen(ac: framing.AuthenticatedContent) usize {
    return 2 + ac.content.encodedLen() +
        wire.varintLen(ac.auth.signature.len) + ac.auth.signature.len;
}

pub fn confirmedInputEncode(w: *codec.Writer, ac: framing.AuthenticatedContent) Error!void {
    if (ac.content.contentType() != .commit) return error.NotACommit;
    try w.writeEnum(framing.WireFormat, ac.wire_format);
    try ac.content.encode(w);
    try w.writeVector(ac.auth.signature);
}

/// RFC 9420 §8.2:
///
/// ```text
/// confirmed_transcript_hash_[epoch] =
///     Hash(interim_transcript_hash_[epoch - 1] ||
///          ConfirmedTranscriptHashInput_[epoch])
/// ```
///
/// `interim_prev` is the PREVIOUS epoch's interim hash; for the first
/// Commit in a group's life it is the zero-length string (§8.2:
/// `interim_transcript_hash_[0] = ""`), which is `&.{}` here, not a
/// zero-filled digest.
pub fn confirmedTranscriptHash(
    comptime S: type,
    allocator: std.mem.Allocator,
    interim_prev: []const u8,
    ac: framing.AuthenticatedContent,
) ![S.Hash.digest_length]u8 {
    const buf = try allocator.alloc(u8, confirmedInputLen(ac));
    defer allocator.free(buf);
    var w = codec.Writer.init(buf);
    try confirmedInputEncode(&w, ac);
    std.debug.assert(w.finish().len == buf.len);

    var h = S.Hash.init(.{});
    h.update(interim_prev);
    h.update(w.finish());
    var out: [S.Hash.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

/// RFC 9420 §8.2:
///
/// ```text
/// interim_transcript_hash_[epoch] =
///     Hash(confirmed_transcript_hash_[epoch] ||
///          InterimTranscriptHashInput_[epoch])
/// ```
///
/// `InterimTranscriptHashInput` is `struct { MAC confirmation_tag; }` —
/// one `opaque<V>` field, so the tag is LENGTH-PREFIXED in the hash input,
/// not appended raw. That varint is the single easiest byte in §8.2 to
/// drop, and dropping it produces a perfectly plausible-looking hash that
/// no other implementation agrees with.
pub fn interimTranscriptHash(
    comptime S: type,
    confirmed: []const u8,
    confirmation_tag: []const u8,
) Error![S.Hash.digest_length]u8 {
    var prefix: [4]u8 = undefined;
    var w = codec.Writer.init(&prefix);
    try w.writeVarint(confirmation_tag.len);

    var h = S.Hash.init(.{});
    h.update(confirmed);
    h.update(w.finish());
    h.update(confirmation_tag);
    var out: [S.Hash.digest_length]u8 = undefined;
    h.final(&out);
    return out;
}

/// Both hashes for one epoch transition, in the order §8.2 defines them —
/// the shape a member actually uses when processing a Commit.
pub fn TranscriptHashes(comptime S: type) type {
    return struct {
        confirmed: [S.Hash.digest_length]u8,
        interim: [S.Hash.digest_length]u8,
    };
}

/// Advances both hashes across one Commit. `ac` must carry a
/// `confirmation_tag` (§6.1 makes it mandatory for Commits), because the
/// interim hash is defined over it.
pub fn advance(
    comptime S: type,
    allocator: std.mem.Allocator,
    interim_prev: []const u8,
    ac: framing.AuthenticatedContent,
) !TranscriptHashes(S) {
    const confirmed = try confirmedTranscriptHash(S, allocator, interim_prev, ac);
    const tag = ac.auth.confirmation_tag orelse return error.MissingConfirmationTag;
    return .{ .confirmed = confirmed, .interim = try interimTranscriptHash(S, &confirmed, tag) };
}

/// RFC 9420 §8.2's epoch-0 seed for both hashes: the zero-length octet
/// string. Named so a caller never has to guess whether "empty" means an
/// empty slice or a zero-filled digest — it is the former, and the
/// difference is a completely different first epoch.
pub const empty_transcript_hash: []const u8 = &.{};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;
const TestSuite = suite.default;

fn commitAc(sig: []const u8, tag: []const u8) framing.AuthenticatedContent {
    return .{
        .wire_format = .mls_public_message,
        .content = .{
            .group_id = "group",
            .epoch = 3,
            .sender = .{ .member = 0 },
            .body = .{ .commit = .{} },
        },
        .auth = .{ .signature = sig, .confirmation_tag = tag },
    };
}

test "ConfirmedTranscriptHashInput: it is AuthenticatedContent minus the confirmation_tag" {
    const sig = [_]u8{0xaa} ** 64;
    const tag = [_]u8{0xbb} ** 32;
    const ac = commitAc(&sig, &tag);

    const full = try ac.encodeAlloc(testing.allocator);
    defer testing.allocator.free(full);

    const buf = try testing.allocator.alloc(u8, confirmedInputLen(ac));
    defer testing.allocator.free(buf);
    var w = codec.Writer.init(buf);
    try confirmedInputEncode(&w, ac);

    // The confirmed input is a strict PREFIX of the full encoding: the only
    // difference is the trailing `MAC confirmation_tag`.
    try testing.expectEqualSlices(u8, buf, full[0..buf.len]);
    try testing.expectEqual(full.len - buf.len, 1 + tag.len); // varint(32) + tag
}

test "confirmedTranscriptHash: a non-Commit is refused rather than hashed" {
    var ac = commitAc(&[_]u8{0xaa} ** 64, &[_]u8{0xbb} ** 32);
    ac.content.body = .{ .proposal = .{ .remove = 1 } };
    ac.auth.confirmation_tag = null;
    try testing.expectError(
        error.NotACommit,
        confirmedTranscriptHash(TestSuite, testing.allocator, empty_transcript_hash, ac),
    );
}

test "interimTranscriptHash: the confirmation_tag is length-prefixed, not appended raw" {
    const confirmed = [_]u8{0x01} ** 32;
    const tag = [_]u8{0x02} ** 32;
    const got = try interimTranscriptHash(TestSuite, &confirmed, &tag);

    // The naive "just concatenate" version must NOT match — that is the
    // whole point of the varint this function writes.
    var naive: [64]u8 = undefined;
    @memcpy(naive[0..32], &confirmed);
    @memcpy(naive[32..], &tag);
    try testing.expect(!std.mem.eql(u8, &got, &TestSuite.hash(&naive)));

    // The explicit expected construction: confirmed || varint(32) || tag.
    var explicit: [65]u8 = undefined;
    @memcpy(explicit[0..32], &confirmed);
    explicit[32] = 32; // one-byte varint for 32
    @memcpy(explicit[33..], &tag);
    try testing.expectEqualSlices(u8, &TestSuite.hash(&explicit), &got);
}

test "advance: chains, and the epoch-0 seed is the empty string not a zero digest" {
    const sig = [_]u8{0xaa} ** 64;
    const tag = [_]u8{0xbb} ** 32;
    const ac = commitAc(&sig, &tag);

    const first = try advance(TestSuite, testing.allocator, empty_transcript_hash, ac);
    const zeroes: [32]u8 = @splat(0);
    const wrong_seed = try advance(TestSuite, testing.allocator, &zeroes, ac);
    try testing.expect(!std.mem.eql(u8, &first.confirmed, &wrong_seed.confirmed));

    // Chaining forward changes the state again.
    const second = try advance(TestSuite, testing.allocator, &first.interim, ac);
    try testing.expect(!std.mem.eql(u8, &first.confirmed, &second.confirmed));
}

test "advance: a Commit whose auth has no confirmation_tag cannot advance the interim hash" {
    var ac = commitAc(&[_]u8{0xaa} ** 64, &[_]u8{0xbb} ** 32);
    ac.auth.confirmation_tag = null;
    try testing.expectError(
        error.MissingConfirmationTag,
        advance(TestSuite, testing.allocator, empty_transcript_hash, ac),
    );
}

test "keyschedule's §8.1 GroupContext consumes exactly what §8.2 produces" {
    // Guards the seam Part 4 documented as blocked: the confirmed hash is a
    // `[TestSuite.Hash.digest_length]u8`, and `GroupContext.confirmed_transcript_hash`
    // is the `opaque<V>` that carries it into the epoch derivation.
    const ac = commitAc(&[_]u8{0xaa} ** 64, &[_]u8{0xbb} ** 32);
    const th = try advance(TestSuite, testing.allocator, empty_transcript_hash, ac);
    const gc: keyschedule.GroupContext = .{
        .cipher_suite = TestSuite.id,
        .group_id = "group",
        .epoch = 4,
        .tree_hash = &[_]u8{0x11} ** 32,
        .confirmed_transcript_hash = &th.confirmed,
    };
    const bytes = try gc.encodeAlloc(testing.allocator);
    defer testing.allocator.free(bytes);
    try testing.expect(std.mem.indexOf(u8, bytes, &th.confirmed) != null);
}
