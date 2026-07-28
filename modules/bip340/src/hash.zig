// SPDX-License-Identifier: MIT
//! Tagged hashing (BIP340 "Design" section): `taggedHash(tag, msg) =
//! SHA256(SHA256(tag) || SHA256(tag) || msg)`. `SHA256(tag)` is exactly 32
//! bytes, so `SHA256(tag) || SHA256(tag)` is exactly one 64-byte SHA-256
//! compression block — this module precomputes, at comptime, the SHA-256
//! *midstate* after absorbing that one fixed block, per tag. Each call then
//! only has to run SHA-256 over `msg` starting from that midstate, instead
//! of re-hashing the 64 fixed prefix bytes on every invocation.
//!
//! `std.crypto.hash.sha2.Sha256`'s streaming struct (`s`/`buf_len`/
//! `total_len`) has no field-level privacy in Zig (only declarations are
//! `pub`/non-`pub`), so a plain value-copy of the struct after feeding it
//! the 64-byte prefix *is* a legitimate, real midstate snapshot — not a
//! simulation of one. `sanity: direct one-shot hash equals the midstate
//! path` below proves the two computations agree.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The three domain tags BIP340 defines.
pub const aux_tag = "BIP0340/aux";
pub const nonce_tag = "BIP0340/nonce";
pub const challenge_tag = "BIP0340/challenge";

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`, RFC-quality "tagged hash"
/// domain separation (BIP340 "Design"). `tag` must be a comptime-known
/// string so the 64-byte-prefix midstate can be precomputed once per tag
/// at comptime rather than recomputed on every call.
pub fn taggedHash(comptime tag: []const u8, msg: []const u8) [32]u8 {
    var d = comptime midstate(tag);
    d.update(msg);
    return d.finalResult();
}

/// Streaming variant of `taggedHash` for messages that are a concatenation
/// of parts (BIP340's nonce/challenge hashes are over `a || b || msg` with
/// a variable-length `msg` — hashing part-by-part avoids assembling the
/// concatenation in a buffer). Returns a ready-to-`update` SHA-256 already
/// seeded with the tag's fixed 64-byte prefix; call `update` for each part,
/// then `finalResult()`.
pub fn taggedHasher(comptime tag: []const u8) Sha256 {
    return comptime midstate(tag);
}

// ── runtime-tag variant ──────────────────────────────────────────────────
//
// `taggedHash`/`taggedHasher` above require `tag` to be comptime-known so
// the fixed 64-byte prefix's midstate can be precomputed once per tag. Some
// BIP340-family tagged hashes need a tag that is only known at RUNTIME —
// e.g. BOLT#12's nonce leaf, whose tag is the literal `"LnNonce"`
// concatenated with the current TLV stream's first record (a value, not a
// fixed string). These callers cannot use the comptime path at all, so they
// re-implemented the tagged-hash construction by hand; the two functions
// below give them a shared, correct implementation instead. There is no
// midstate caching here (the tag varies per call, so there is nothing to
// cache) — the comptime versions above remain the fast path whenever the
// tag actually is fixed.

/// Runtime-tag form of `taggedHash`: `SHA256(SHA256(tag) || SHA256(tag) ||
/// msg)`, where `tag` itself may be assembled from multiple runtime parts
/// (`tag_parts`, concatenated in order before the tag hash) — this covers
/// tags like BOLT#12's `"LnNonce" || first_tlv` without requiring the
/// caller to allocate a concatenated buffer first.
pub fn taggedHashRuntime(tag_parts: []const []const u8, msg: []const u8) [32]u8 {
    var d = taggedHasherRuntime(tag_parts);
    d.update(msg);
    return d.finalResult();
}

/// Streaming variant of `taggedHashRuntime`: returns a hasher already
/// seeded with the runtime tag's fixed 64-byte prefix (`SHA256(tag) ||
/// SHA256(tag)`, `tag` built from `tag_parts`); call `update` for each
/// message part, then `finalResult()`.
pub fn taggedHasherRuntime(tag_parts: []const []const u8) Sha256 {
    var tag_hasher = Sha256.init(.{});
    for (tag_parts) |part| tag_hasher.update(part);
    const tag_digest = tag_hasher.finalResult();

    var d = Sha256.init(.{});
    d.update(&tag_digest);
    d.update(&tag_digest);
    return d;
}

/// The SHA-256 state after absorbing exactly one block, `SHA256(tag) ||
/// SHA256(tag)` (64 bytes = one block), starting from a fresh instance.
/// Computed once at comptime per distinct `tag`.
fn midstate(comptime tag: []const u8) Sha256 {
    @setEvalBranchQuota(100_000);
    const tag_digest = tag_digest: {
        var digest: [32]u8 = undefined;
        Sha256.hash(tag, &digest, .{});
        break :tag_digest digest;
    };
    var d = Sha256.init(.{});
    // Two 32-byte updates land exactly on the 64-byte block boundary, so
    // `update` internally runs its one full-block compression round here
    // and leaves `buf_len == 0` — no partial block is buffered.
    d.update(&tag_digest);
    d.update(&tag_digest);
    return d;
}

test "sanity: direct one-shot hash equals the midstate path" {
    const msg = "hello bip340";
    const got = taggedHash(challenge_tag, msg);

    var tag_digest: [32]u8 = undefined;
    Sha256.hash(challenge_tag, &tag_digest, .{});
    var one_shot_input: [64 + msg.len]u8 = undefined;
    one_shot_input[0..32].* = tag_digest;
    one_shot_input[32..64].* = tag_digest;
    @memcpy(one_shot_input[64..], msg);
    var want: [32]u8 = undefined;
    Sha256.hash(&one_shot_input, &want, .{});

    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "sanity: midstate buf_len is 0 after the fixed prefix (no partial block buffered)" {
    const d = comptime midstate(aux_tag);
    try std.testing.expectEqual(@as(u8, 0), d.buf_len);
    try std.testing.expectEqual(@as(u64, 64), d.total_len);
}

test "taggedHash is deterministic and tag-separated" {
    const msg = "same message";
    const a = taggedHash(aux_tag, msg);
    const b = taggedHash(nonce_tag, msg);
    const c = taggedHash(aux_tag, msg);
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
    try std.testing.expectEqualSlices(u8, &a, &c);
}

test "taggedHasher streaming over parts equals taggedHash over the concatenation" {
    const part_a = "abc";
    const part_b = "defgh";
    var d = taggedHasher(nonce_tag);
    d.update(part_a);
    d.update(part_b);
    const streamed = d.finalResult();
    const one_shot = taggedHash(nonce_tag, part_a ++ part_b);
    try std.testing.expectEqualSlices(u8, &one_shot, &streamed);
}

test "empty message" {
    // Exercised directly by BIP340 test-vector index 15 ("message of size
    // 0"), which needs the challenge tagged hash to work over msg.len == 0.
    _ = taggedHash(challenge_tag, "");
}

test "taggedHashRuntime agrees with taggedHash when the tag is a single, comptime-known part" {
    const msg = "same message";
    const comptime_result = taggedHash(nonce_tag, msg);
    const runtime_result = taggedHashRuntime(&.{nonce_tag}, msg);
    try std.testing.expectEqualSlices(u8, &comptime_result, &runtime_result);
}

test "taggedHashRuntime: a multi-part tag equals taggedHash over the concatenated tag" {
    // BOLT#12's nonce leaf builds its tag from two runtime parts
    // ("LnNonce" || first_tlv); this must equal hashing the same bytes
    // concatenated as a single tag string.
    const tag_a = "LnNonce";
    const tag_b = "\x01\x02\x03";
    const msg = "\x04\x05";
    const multi_part = taggedHashRuntime(&.{ tag_a, tag_b }, msg);
    const concatenated = taggedHashRuntime(&.{tag_a ++ tag_b}, msg);
    try std.testing.expectEqualSlices(u8, &concatenated, &multi_part);
}

test "taggedHasherRuntime streaming over parts equals taggedHashRuntime over the concatenation" {
    const tag_parts = &.{"RuntimeTag"};
    const part_a = "abc";
    const part_b = "defgh";
    var d = taggedHasherRuntime(tag_parts);
    d.update(part_a);
    d.update(part_b);
    const streamed = d.finalResult();
    const one_shot = taggedHashRuntime(tag_parts, part_a ++ part_b);
    try std.testing.expectEqualSlices(u8, &one_shot, &streamed);
}
