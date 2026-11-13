// SPDX-License-Identifier: MIT

//! No-panic sweep (2026-11-13). The finding (WHS-1: `Verifier.init`
//! precondition `assert`s on caller values, UB in ReleaseFast) is fixed by
//! making `init` total: every option contract returns `error.InvalidOptions`
//! (one test per contract below). The accepted-side tests pin the boundaries so
//! a "fix" that over-tightens them fails.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");

fn fixedNow(_: ?*anyopaque) i64 {
    return 0;
}
const clock: root.Clock = .{ .nowFn = fixedNow };

test "Verifier.init accepts exactly max_keys secrets and max_keys public keys (sweep clean: init bounds)" {
    const gpa = testing.allocator;
    var secs: [root.max_keys][]const u8 = undefined;
    for (&secs) |*s| s.* = "k";
    var v = try root.Verifier.init(gpa, .{ .secret = secs[0], .extra_secrets = secs[1..] });
    defer v.deinit();
    try testing.expectEqual(@as(usize, root.max_keys), v.secretCount());

    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    const pks: [root.max_keys]std.crypto.sign.Ed25519.PublicKey = @splat(pk);
    var w = try root.Verifier.init(gpa, .{ .scheme = .standard_webhooks, .public_keys = &pks, .clock = clock });
    defer w.deinit();
    try testing.expectEqual(@as(usize, 0), w.secretCount());
}

test "Verifier with only public keys refuses a v1 delivery instead of crashing (sweep clean: no-secret standard)" {
    const gpa = testing.allocator;
    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    var w = try root.Verifier.init(gpa, .{ .scheme = .standard_webhooks, .public_keys = &.{pk}, .clock = clock });
    defer w.deinit();
    try testing.expectError(error.NoMatchingSignature, w.verifyRequest(.{ .signature = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", .timestamp = "0", .id = "m" }, "x", 0));
}

const ta = testing.allocator;
const standard_pk = std.crypto.sign.Ed25519.PublicKey;

test "Verifier.init: an empty secret is error.InvalidOptions (sweep WHS-1)" {
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = "", .max_body_bytes = 8 }));
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = "k", .extra_secrets = &.{""}, .max_body_bytes = 8 }));
}

test "Verifier.init: no secret and no public key is error.InvalidOptions (sweep WHS-1)" {
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .max_body_bytes = 8 }));
    // A secret-less verifier for a scheme that needs a secret.
    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .scheme = .stripe, .public_keys = &.{pk}, .clock = clock, .max_body_bytes = 8 }));
}

test "Verifier.init: more than max_keys secrets or public keys is error.InvalidOptions (sweep WHS-1)" {
    var secs: [root.max_keys + 1][]const u8 = undefined;
    for (&secs) |*s| s.* = "k";
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = secs[0], .extra_secrets = secs[1..], .max_body_bytes = 8 }));
    const pk = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(1))).public_key;
    const pks: [root.max_keys + 1]standard_pk = @splat(pk);
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .scheme = .standard_webhooks, .public_keys = &pks, .clock = clock, .max_body_bytes = 8 }));
}

test "Verifier.init: a timestamped scheme without a clock is error.InvalidOptions (sweep WHS-1)" {
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = "k", .scheme = .stripe, .max_body_bytes = 8 }));
}

test "Verifier.init: an undecoded whsec_ secret for standard_webhooks is error.InvalidOptions (sweep WHS-1)" {
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = "whsec_dGVzdA==", .scheme = .standard_webhooks, .clock = clock, .max_body_bytes = 8 }));
}

test "Verifier.init: an empty header name is error.InvalidOptions (sweep WHS-1)" {
    try testing.expectError(error.InvalidOptions, root.Verifier.init(ta, .{ .secret = "k", .header = "", .max_body_bytes = 8 }));
}
