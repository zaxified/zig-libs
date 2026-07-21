// SPDX-License-Identifier: MIT
//! clientdata_test — clientDataJSON parsing, external anchor + adversarial.

const std = @import("std");
const testing = std.testing;
const webauthn = @import("root.zig");
const vectors = @import("vectors.zig");

test "parseClientData: real W3C §16.2 registration clientDataJSON, byte-exact challenge/origin/type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cd = try webauthn.parseClientData(a, &vectors.none_es256.registration_client_data_json);
    try testing.expectEqualStrings("webauthn.create", cd.type);
    try testing.expectEqualStrings(vectors.origin, cd.origin);
    try testing.expectEqualSlices(u8, &vectors.none_es256.registration_challenge, cd.challenge);
    try testing.expectEqual(@as(?bool, false), cd.cross_origin);
}

test "parseClientData: real W3C §16.2 assertion clientDataJSON (type webauthn.get)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cd = try webauthn.parseClientData(a, &vectors.none_es256.assertion_client_data_json);
    try testing.expectEqualStrings("webauthn.get", cd.type);
    try testing.expectEqualStrings(vectors.origin, cd.origin);
    try testing.expectEqualSlices(u8, &vectors.none_es256.assertion_challenge, cd.challenge);
}

test "parseClientData: malformed JSON -> InvalidJson, not a panic" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.InvalidJson, webauthn.parseClientData(a, "{not json"));
    try testing.expectError(error.InvalidJson, webauthn.parseClientData(a, "[]"));
    try testing.expectError(error.InvalidJson, webauthn.parseClientData(a, "{\"type\":\"x\"}")); // missing challenge/origin
}

test "parseClientData: non-base64url challenge -> Base64DecodeError" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const bad = "{\"type\":\"webauthn.get\",\"challenge\":\"not!!valid==base64\",\"origin\":\"https://example.org\"}";
    try testing.expectError(error.Base64DecodeError, webauthn.parseClientData(a, bad));
}
