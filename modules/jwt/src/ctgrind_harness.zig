// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh jwt`, which builds the
//! harness and prints the control table.
//!
//! Not wired into `zig build test-jwt`: memcheck's context count is valgrind's
//! own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! Every secret jwt holds: HMAC secrets (HS256/384/512, used to sign AND to
//! verify) and signing keys (ES256, ES384, ES512, EdDSA, RS256, PS256). Each
//! secret is tainted in place after the key is built, the public half stays
//! defined, and the public API is driven: `SigningKey.sign` and `verify`.
//!
//!  * `hmac` — HS256/384/512: `sign` with the tainted secret, then `verify`
//!    of that MAC (accept) and of the same MAC with one bit flipped (reject).
//!    The HMAC is std's; `verify`'s compare is `timing_safe.eql`, whose bool
//!    verdict is the one branch the module takes on a tainted value (the
//!    MAC verdict, public by design: a caller learns accept/reject).
//!  * `ec` — ES256 (p256 module), ES384 (p384 module), ES512 (p521 module), EdDSA
//!    (std Ed25519; the 32-byte seed is tainted, the public half of the
//!    64-byte secret key is not): `sign` with the tainted key.
//!  * `rsa` — RS256 and PS256 `sign` through the `rsa` module. Tainted: the
//!    secret members of `rsa.SecretKey` (d, p, q, dp, dq, qinv and the value
//!    fields of p_mont/q_mont); NOT n, e, n_mont or the slot L (the key size).
//!    PS draws its salt and blinding from a seeded `DefaultCsprng` so output
//!    pins are reproducible.
//!
//! Each signature / MAC is marked defined (`makeMemDefined`) right after it is
//! produced: it is a public value, and the later public processing (the
//! `verify` input, the printing) must not show up as noise. The propagation
//! witness is therefore printed BEFORE that declassification of a copy: a
//! tainted copy of the output is formatted through `std.debug.print`, and the
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count stays what the module itself does.
//!
//! The curve and RSA arithmetic are `p256`'s, `p384`'s, `p521`'s, std's and `rsa`'s and
//! are claimed in their own rows; the contexts they raise on the tainted key
//! are expected here too and are itemised in `ctgrind-expected.tsv`.

const std = @import("std");
const builtin = @import("builtin");
const jwt = @import("root.zig");

const memcheck = std.valgrind.memcheck;

const Target = enum { hmac, ec, rsa };
const Taint = enum { yes, no };

const signing_input = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjdGdyaW5kIn0";

fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

const kat_e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");

fn taint(t: Taint, bytes: []u8) void {
    if (t == .yes) memcheck.makeMemUndefined(bytes);
}

/// The value fields of a `montint.DynModint`, not its slot `L` (the key size,
/// public; every operation dispatches on it).
fn taintMont(t: Taint, mp: anytype) void {
    taint(t, std.mem.asBytes(&mp.m));
    taint(t, std.mem.asBytes(&mp.n0inv));
    taint(t, std.mem.asBytes(&mp.r2));
    taint(t, std.mem.asBytes(&mp.one_mont));
}

/// Format a (possibly tainted) copy of `bytes` through the non-constant-time
/// printer — the propagation witness — then declassify the original: a
/// signature is public from here on.
fn publish(label: []const u8, bytes: []u8) void {
    var copy: [jwt.SigningKey.max_signature_len]u8 = undefined;
    @memcpy(copy[0..bytes.len], bytes);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..bytes.len] });
    memcheck.makeMemDefined(bytes);
}

fn signWith(label: []const u8, key: jwt.SigningKey) !void {
    var out: [jwt.SigningKey.max_signature_len]u8 = undefined;
    const sig = try key.sign(signing_input, &out);
    publish(label, @constCast(sig));
}

fn bare(alg: jwt.Alg, sig: []const u8) jwt.ParsedToken {
    return .{ .header = undefined, .claims = undefined, .arena = undefined, .alg = alg, .signing_input = signing_input, .signature = sig };
}

fn hmacOne(t: Taint, comptime alg: jwt.Alg, comptime len: usize) !void {
    var secret: [len]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    taint(t, &secret);
    const key: jwt.SigningKey = switch (alg) {
        .HS256 => .{ .hs256 = &secret },
        .HS384 => .{ .hs384 = &secret },
        .HS512 => .{ .hs512 = &secret },
        else => unreachable,
    };
    var out: [jwt.SigningKey.max_signature_len]u8 = undefined;
    const mac = try key.sign(signing_input, &out);
    // The MAC is public from here on: witness it, then declassify it; the
    // secret stays tainted.
    publish(@tagName(alg), @constCast(mac));
    var parsed = bare(alg, mac);
    verdict(alg, "accept", &parsed, &secret);
    var bad: [64]u8 = undefined;
    @memcpy(bad[0..mac.len], mac);
    bad[5] ^= 1;
    parsed.signature = bad[0..mac.len];
    verdict(alg, "reject", &parsed, &secret);
}

/// Run `verify` and print its outcome: the harness must consume the verdict,
/// or the optimizer drops a verify whose result nobody reads.
fn verdict(alg: jwt.Alg, label: []const u8, parsed: *const jwt.ParsedToken, secret: []const u8) void {
    const ok = if (jwt.verify(parsed, .{ .hmac = secret })) |_| true else |_| false;
    std.debug.print("ctgrind_result {t} {s} verify={}\n", .{ alg, label, ok });
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const t = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    switch (target) {
        .hmac => {
            try hmacOne(t, .HS256, 32);
            try hmacOne(t, .HS384, 48);
            try hmacOne(t, .HS512, 64);
        },
        .ec => {
            const seed32 = @as([32]u8, @splat(7));
            var es256 = try jwt.EcdsaP256Sha256.KeyPair.generateDeterministic(seed32);
            taint(t, std.mem.asBytes(&es256.secret_key));
            try signWith("ES256", .{ .es256 = &es256 });

            var es384 = try jwt.EcdsaP384Sha384.KeyPair.generateDeterministic(@as([jwt.EcdsaP384Sha384.KeyPair.seed_length]u8, @splat(7)));
            taint(t, std.mem.asBytes(&es384.secret_key));
            try signWith("ES384", .{ .es384 = &es384 });

            var es512: jwt.EcdsaP521Sha512.KeyPair = undefined;
            try jwt.EcdsaP521Sha512.KeyPair.generateDeterministicInto(&es512, &(@as([jwt.EcdsaP521Sha512.KeyPair.seed_length]u8, @splat(7))));
            taint(t, std.mem.asBytes(&es512.secret_key));
            try signWith("ES512", .{ .es512 = &es512 });

            var ed = try jwt.Ed25519.KeyPair.generateDeterministic(seed32);
            // The first 32 bytes of the secret key are the seed; the rest is
            // the public key.
            taint(t, ed.secret_key.bytes[0..32]);
            try signWith("EdDSA", .{ .ed25519 = &ed });
        },
        .rsa => {
            var kp: jwt.rsa.KeyPair = undefined;
            try jwt.rsa.SecretKey.fromPrimes(&kp.secret_key, &kat_p, &kat_q, &kat_e);
            defer kp.secret_key.deinit();
            kp.public_key = try jwt.rsa.PublicKey.fromBytes(&kat_n, &kat_e);
            const sk = &kp.secret_key;
            taint(t, std.mem.asBytes(&sk.d));
            taint(t, std.mem.asBytes(&sk.p));
            taint(t, std.mem.asBytes(&sk.q));
            taint(t, std.mem.asBytes(&sk.dp));
            taint(t, std.mem.asBytes(&sk.dq));
            taint(t, std.mem.asBytes(&sk.qinv));
            taintMont(t, &sk.p_mont);
            taintMont(t, &sk.q_mont);
            try signWith("RS256", .{ .rs256 = &kp });
            var rng = std.Random.DefaultCsprng.init(@as([std.Random.DefaultCsprng.secret_seed_length]u8, @splat(0x42)));
            try signWith("PS256", .{ .ps256 = .{ .key = &kp, .random = rng.random() } });
        },
    }
}
