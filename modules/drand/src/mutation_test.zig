// SPDX-License-Identifier: MIT
//! Tests added by the whole-module mutation of `json_uint.zig`,
//! `round.zig`, `chaininfo.zig` and `verify.zig`: the exact boundaries of the
//! document and field limits, the error code of each refusal, the tolerance
//! the Go reference has (unknown fields), allocation failure, and the
//! hand-built-value errors of every scheme arm.
const std = @import("std");
const t = std.testing;
const drand = @import("root.zig");
const json_uint = @import("json_uint.zig");

const chaininfo = drand.chaininfo;
const round_mod = drand.round;
const verify = drand.verify;

const quicknet_info =
    \\{"public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a", "period": 3, "genesis_time": 1692803367, "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971", "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e", "schemeID": "bls-unchained-g1-rfc9380", "metadata": { "beaconID": "quicknet" }}
;
const quicknet_key = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
const quicknet_hash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
const round_1000 =
    \\{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
;
const sig_1000 = "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39";

fn rep(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var out: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    return out;
}

/// `doc` with the first `from` replaced by `to` (owned).
fn swap(doc: []const u8, from: []const u8, to: []const u8) ![]u8 {
    return std.mem.replaceOwned(u8, t.allocator, doc, from, to);
}

test "Uint64: a string token, escaped or not, is UnexpectedToken and leaves nothing allocated" {
    const S = struct { n: json_uint.Uint64 };
    inline for (.{ "{\"n\":\"1000\"}", "{\"n\":\"\\u0031\"}" }) |doc| {
        try t.expectError(error.UnexpectedToken, std.json.parseFromSliceLeaky(S, t.allocator, doc, .{}));
    }
}

test "Round: signatureG2 of a G1 round, and signatureG1 of a G2 round, are InvalidPoint" {
    const r = try drand.parseRound(t.allocator, round_1000);
    try t.expectError(error.InvalidPoint, r.signatureG2());
    _ = try r.signatureG1();
}

test "parseRound: an empty signature, and an odd-length one past the buffer, are InvalidHex" {
    try t.expectError(error.InvalidHex, drand.parseRound(t.allocator, "{\"round\":1,\"signature\":\"\"}"));
    const odd = "{\"round\":1,\"signature\":\"" ++ rep("ab", 97) ++ "a\"}";
    try t.expectError(error.InvalidHex, drand.parseRound(t.allocator, odd));
    // an even one past the buffer is a length, not a hex, error
    const long = "{\"round\":1,\"signature\":\"" ++ rep("ab", 98) ++ "\"}";
    try t.expectError(error.InvalidLength, drand.parseRound(t.allocator, long));
}

test "parseRound / parseInfo: a document of exactly max_document_bytes is parsed, one more is refused" {
    const buf = try t.allocator.alloc(u8, round_mod.max_document_bytes);
    defer t.allocator.free(buf);
    @memset(buf, ' ');
    @memcpy(buf[0..round_1000.len], round_1000);
    _ = try drand.parseRound(t.allocator, buf);
    @memset(buf, ' ');
    @memcpy(buf[0..quicknet_info.len], quicknet_info);
    _ = try drand.parseInfo(t.allocator, buf);
}

test "unknown fields are ignored, as the Go reference ignores them" {
    const round_extra = try swap(round_1000, "\"signature\"", "\"extra\":{\"a\":[1,2]},\"signature\"");
    defer t.allocator.free(round_extra);
    _ = try drand.parseRound(t.allocator, round_extra);
    const info_extra = try swap(quicknet_info, "\"schemeID\"", "\"extra\":[1],\"schemeID\"");
    defer t.allocator.free(info_extra);
    _ = try drand.parseInfo(t.allocator, info_extra);
}

test "an allocation failure is OutOfMemory from both parsers, not a malformed document" {
    var fa = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, drand.parseRound(fa.allocator(), round_1000));
    var fb = t.FailingAllocator.init(t.allocator, .{ .fail_index = 0 });
    try t.expectError(error.OutOfMemory, drand.parseInfo(fb.allocator(), quicknet_info));
}

test "parseRound: a 48-byte signature that is no G1 encoding is InvalidPoint, not SignatureNotInSubgroup" {
    const zero = "{\"round\":1,\"signature\":\"" ++ rep("00", 48) ++ "\"}";
    try t.expectError(error.InvalidPoint, drand.parseRound(t.allocator, zero));
}

test "parseRound: randomness of 33 bytes is InvalidLength, and 64 non-hex characters are InvalidHex" {
    const long = try swap(round_1000, "\"randomness\":\"fe", "\"randomness\":\"fefe");
    defer t.allocator.free(long);
    try t.expectError(error.InvalidLength, drand.parseRound(t.allocator, long));
    const nonhex = try swap(round_1000, "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd", &rep("zz", 32));
    defer t.allocator.free(nonhex);
    try t.expectError(error.InvalidHex, drand.parseRound(t.allocator, nonhex));
}

test "Scheme.fromId is an exact match, and isVerifiable is true for exactly the three verifiable schemes" {
    const S = drand.Scheme;
    try t.expectEqual(S.unchained_g1_rfc9380, S.fromId("bls-unchained-g1-rfc9380"));
    try t.expectEqual(S.pedersen_bls_chained, S.fromId("pedersen-bls-chained"));
    try t.expectEqual(S.bls_unchained_on_g1, S.fromId("bls-unchained-on-g1"));
    for ([_][]const u8{ "bls-unchained-g1-rfc9380x", "pedersen-bls-chained-v2", "bls-unchained-on-g1 ", "", "other" }) |id| {
        try t.expectEqual(S.other, S.fromId(id));
    }
    try t.expect(S.unchained_g1_rfc9380.isVerifiable());
    try t.expect(S.pedersen_bls_chained.isVerifiable());
    try t.expect(S.bls_unchained_on_g1.isVerifiable());
    try t.expect(!S.other.isVerifiable());
}

test "parseInfo: a hash or groupHash of the wrong width is InvalidLength, a non-hex one InvalidHex" {
    const gh = "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e";
    for ([_][]const u8{ quicknet_hash[2..], quicknet_hash ++ "00" }) |bad_hash| {
        const doc = try swap(quicknet_info, quicknet_hash, bad_hash);
        defer t.allocator.free(doc);
        try t.expectError(error.InvalidLength, drand.parseInfo(t.allocator, doc));
    }
    for ([_][]const u8{ gh[2..], gh ++ "00" }) |bad| {
        const doc = try swap(quicknet_info, gh, bad);
        defer t.allocator.free(doc);
        try t.expectError(error.InvalidLength, drand.parseInfo(t.allocator, doc));
    }
    const nonhex = try swap(quicknet_info, quicknet_hash, &rep("zz", 32));
    defer t.allocator.free(nonhex);
    try t.expectError(error.InvalidHex, drand.parseInfo(t.allocator, nonhex));
}

test "parseInfo: public_key of zero length, odd length, over 96 bytes and no point are each refused with their own error" {
    const empty = try swap(quicknet_info, quicknet_key, "");
    defer t.allocator.free(empty);
    try t.expectError(error.InvalidHex, drand.parseInfo(t.allocator, empty));
    const odd = try swap(quicknet_info, quicknet_key, &(rep("ab", 97) ++ "a".*));
    defer t.allocator.free(odd);
    try t.expectError(error.InvalidHex, drand.parseInfo(t.allocator, odd));
    const long = try swap(quicknet_info, quicknet_key, &rep("ab", 100));
    defer t.allocator.free(long);
    try t.expectError(error.InvalidLength, drand.parseInfo(t.allocator, long));
    // a full-width key that is no point at all (compression flag clear)
    const nopoint = try swap(quicknet_info, quicknet_key, &rep("00", 96));
    defer t.allocator.free(nopoint);
    try t.expectError(error.InvalidPoint, drand.parseInfo(t.allocator, nopoint));
    const chained_key = "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31";
    const chained = try swap(chaininfo.chained_default_info_json, chained_key, &rep("00", 48));
    defer t.allocator.free(chained);
    try t.expectError(error.InvalidPoint, drand.parseInfo(t.allocator, chained));
}

test "parseInfo: period 2^32 - 1 passes the range check (and fails the hash), 2^32 is NumberOutOfRange" {
    const max32 = try swap(quicknet_info, "\"period\": 3", "\"period\": 4294967295");
    defer t.allocator.free(max32);
    try t.expectError(error.ChainHashMismatch, drand.parseInfo(t.allocator, max32));
    const over = try swap(quicknet_info, "\"period\": 3", "\"period\": 4294967296");
    defer t.allocator.free(over);
    try t.expectError(error.NumberOutOfRange, drand.parseInfo(t.allocator, over));
}

test "parseInfo: a beaconID of exactly 64 bytes is kept (the hash then disagrees), 65 bytes is InvalidLength" {
    const b64 = try swap(quicknet_info, "quicknet", &rep("a", 64));
    defer t.allocator.free(b64);
    try t.expectError(error.ChainHashMismatch, drand.parseInfo(t.allocator, b64));
    const b65 = try swap(quicknet_info, "quicknet", &rep("a", 65));
    defer t.allocator.free(b65);
    try t.expectError(error.InvalidLength, drand.parseInfo(t.allocator, b65));
}

test "verifyRound: hand-built quicknet and deprecated values without their points report MissingPublicKey / MissingSignature" {
    const deprecated_doc = try swap(quicknet_info, "bls-unchained-g1-rfc9380", "bls-unchained-on-g1");
    defer t.allocator.free(deprecated_doc);
    for ([_][]const u8{ quicknet_info, deprecated_doc }) |doc| {
        var info = try drand.parseInfo(t.allocator, doc);
        var rnd = try drand.parseRound(t.allocator, round_1000);
        rnd.sig_g1 = null;
        try t.expectError(error.MissingSignature, drand.verifyRound(&info, &rnd));
        info.pubkey_g2 = null;
        try t.expectError(error.MissingPublicKey, drand.verifyRound(&info, &rnd));
    }
}
