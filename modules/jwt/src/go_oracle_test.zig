// SPDX-License-Identifier: MIT

//! Replays `go_oracle_vectors.zig` -- the table `zig build interop-jwt`
//! judged against golang-jwt v5 -- without Go: this module's verdict on every
//! row must still be the recorded one, and the rows marked `stricter` (this
//! module refuses, golang-jwt accepts) are the evidence behind the card's
//! correctness lead.

const std = @import("std");
const testing = std.testing;
const hex = @import("testkit").hex;
const jwt = @import("root.zig");
const v = @import("go_oracle_vectors.zig");

const Keys = struct {
    hmac: [64]u8,
    p256: jwt.Key,
    p384: jwt.Key,
    p521: jwt.Key,
    ed: jwt.Key,
    rsa: jwt.Key,

    fn of(k: *const Keys, f: v.Family) jwt.Key {
        return switch (f) {
            .hmac => .{ .hmac = &k.hmac },
            .p256 => k.p256,
            .p384 => k.p384,
            .p521 => k.p521,
            .ed => k.ed,
            .rsa => k.rsa,
        };
    }
};

fn keys() !Keys {
    const rsa_n = hex.bytes(v.rsa_n_hex.len / 2, v.rsa_n_hex);
    return .{
        .hmac = hex.bytes(64, v.hmac_hex),
        .p256 = .{ .ecdsa_p256 = try jwt.EcdsaP256Sha256.PublicKey.fromSec1(&hex.bytes(65, v.p256_sec1_hex)) },
        .p384 = .{ .ecdsa_p384 = try jwt.EcdsaP384Sha384.PublicKey.fromSec1(&hex.bytes(97, v.p384_sec1_hex)) },
        .p521 = .{ .ecdsa_p521 = try jwt.EcdsaP521Sha512.PublicKey.fromSec1(&hex.bytes(133, v.p521_sec1_hex)) },
        .ed = try jwt.Key.ed25519FromBytes(hex.bytes(32, v.ed25519_hex)),
        .rsa = try jwt.Key.rsaFromModExp(&rsa_n, &.{ 1, 0, 1 }),
    };
}

fn verdict(k: *const Keys, c: v.Case) ?anyerror {
    var t = jwt.parseAndVerify(testing.allocator, c.token, k.of(c.family), .{
        .now_s = c.now,
        .leeway_s = 0,
        .issuer = .{ .required = v.issuer },
        .audience = .{ .required = v.audience },
        .require_exp = true,
    }) catch |e| return e;
    t.deinit();
    return null;
}

test "go oracle: every recorded verdict of the golang-jwt interop table still holds" {
    const k = try keys();
    for (v.cases) |c| {
        const got = verdict(&k, c);
        const ok = got == null;
        if (ok != c.ours_ok or (!ok and !std.mem.eql(u8, @errorName(got.?), c.ours_err))) {
            std.debug.print("case {s}: recorded {s}, now {s}\n", .{ c.id, if (c.ours_ok) "ok" else c.ours_err, if (ok) "ok" else @errorName(got.?) });
            return error.VerdictChanged;
        }
        // The table's own claim: `agree` rows agree with golang-jwt.
        if (c.expect == .agree) try testing.expectEqual(c.go_ok, c.ours_ok);
    }
}

test "lead: crit, non-canonical base64url and duplicate claims -- golang-jwt v5.3.1 accepts six tokens this module refuses" {
    const k = try keys();
    var n: usize = 0;
    for (v.cases) |c| {
        if (c.expect != .stricter) continue;
        n += 1;
        try testing.expect(c.go_ok);
        try testing.expect(verdict(&k, c) != null);
    }
    try testing.expectEqual(6, n);
}
