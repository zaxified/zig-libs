// SPDX-License-Identifier: MIT

//! The deterministic fuzz harness (testkit's driver) over key derivation,
//! ECDSA and ECDH, judged by oracles that do not trust the code under test:
//!
//!   * genuine accepted: a fresh key pair's signature over a random message
//!     verifies (raw and through a DER round trip);
//!   * flipped refused: one flipped bit in the message, in r‖s, or in the
//!     public key's SEC1 encoding makes verification fail (or the key fail to
//!     decode);
//!   * ECDH symmetric: ecdh(a, B) == ecdh(b, A), and the compressed peer gives
//!     the same secret;
//!   * homomorphic: the constant-time a·G equals the vartime a·G, and
//!     (a + b)·G equals a·G + b·G;
//!   * determinism: signing twice with null noise gives the same bytes; with
//!     noise, a different signature that still verifies.
//!
//! Driver: `P521_FUZZ=<runs>[,<first seed>]` (`_ONLY`, `_MS`, `_SEEDFILE`,
//! `_INPUT` per testkit's `fuzz_driver.zig`), harness `p521-ecdsa-ecdh`.
//! Without the variable the driver test skips; the in-suite reach test runs
//! 12 seeds every time.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");

const E = root.EcdsaP521Sha512;
const P521 = root.P521;

const Label = enum { genuine, der, flip_msg, flip_sig, flip_key, ecdh, homomorphic, deterministic, noisy };
var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    counts[@intFromEnum(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var seed_a: [66]u8 = undefined;
    var seed_b: [66]u8 = undefined;
    src.bytes(&seed_a);
    src.bytes(&seed_b);
    var msg_buf: [96]u8 = undefined;
    const msg = msg_buf[0..src.slice(&msg_buf)];

    var a: E.KeyPair = undefined;
    var b: E.KeyPair = undefined;
    try E.KeyPair.generateDeterministicInto(&a, &seed_a);
    try E.KeyPair.generateDeterministicInto(&b, &seed_b);

    // Genuine accepted, raw and DER.
    const sig = try a.sign(msg, null);
    try sig.verify(msg, a.public_key);
    mark(.genuine);
    var der_buf: [E.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);
    const back = try E.Signature.fromDer(der);
    try testing.expectEqualSlices(u8, &sig.toBytes(), &back.toBytes());
    mark(.der);

    // Deterministic, and noisy still valid.
    const sig2 = try a.sign(msg, null);
    try testing.expectEqualSlices(u8, &sig.toBytes(), &sig2.toBytes());
    mark(.deterministic);
    var noise: [E.noise_length]u8 = undefined;
    src.bytes(&noise);
    const sig_n = try a.sign(msg, noise);
    try sig_n.verify(msg, a.public_key);
    try testing.expect(!std.mem.eql(u8, &sig.toBytes(), &sig_n.toBytes()));
    mark(.noisy);

    // Flipped refused: message.
    if (msg.len > 0) {
        var m2 = msg_buf;
        const at = src.index(msg.len);
        m2[at] ^= @as(u8, 1) << @intCast(src.index(8));
        try testing.expect(std.meta.isError(sig.verify(m2[0..msg.len], a.public_key)));
        mark(.flip_msg);
    }
    // Signature.
    {
        var raw = sig.toBytes();
        const at = src.index(raw.len);
        raw[at] ^= @as(u8, 1) << @intCast(src.index(8));
        try testing.expect(std.meta.isError(E.Signature.fromBytes(raw).verify(msg, a.public_key)));
        mark(.flip_sig);
    }
    // Public key (a flipped prefix or coordinate either fails to decode or is
    // a different key).
    {
        var enc = a.public_key.toUncompressedSec1();
        const at = src.index(enc.len);
        enc[at] ^= @as(u8, 1) << @intCast(src.index(8));
        if (E.PublicKey.fromSec1(&enc)) |pk| {
            try testing.expect(std.meta.isError(sig.verify(msg, pk)));
        } else |_| {}
        mark(.flip_key);
    }

    // ECDH symmetric, compressed peer equivalent.
    var z_ab: [66]u8 = undefined;
    var z_ba: [66]u8 = undefined;
    var z_c: [66]u8 = undefined;
    try root.ecdhInto(&z_ab, &a.secret_key.bytes, &b.public_key.toUncompressedSec1());
    try root.ecdhInto(&z_ba, &b.secret_key.bytes, &a.public_key.toUncompressedSec1());
    try root.ecdhInto(&z_c, &a.secret_key.bytes, &b.public_key.toCompressedSec1());
    try testing.expectEqualSlices(u8, &z_ab, &z_ba);
    try testing.expectEqualSlices(u8, &z_ab, &z_c);
    mark(.ecdh);

    // Constant-time vs vartime, and (a + b)·G = a·G + b·G.
    const pa = try P521.basePoint.mulPublic(a.secret_key.bytes, .big);
    try testing.expect(pa.equivalent(a.public_key.p));
    const sum = try root.scalar.add(a.secret_key.bytes, b.secret_key.bytes, .big);
    if (P521.basePoint.mul(sum, .big)) |ps| {
        try testing.expect(ps.equivalent(a.public_key.p.add(b.public_key.p)));
    } else |_| {
        // a + b ≡ 0: then the two public keys are negatives.
        try testing.expect(a.public_key.p.add(b.public_key.p).z.isZero());
    }
    mark(.homomorphic);
}

test "fuzz driver: P521_FUZZ (ecdsa + ecdh)" {
    try fuzz_driver.run(harness, .{ .prefix = "P521_FUZZ", .name = "p521-ecdsa-ecdh" });
}

test "fuzz harness: 12 seeds reach every check" {
    counts = @splat(0);
    for (0..12) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("p521-ecdsa-ecdh seed {d}: {t}\n", .{ seed, err });
            return err;
        };
    }
    for (counts, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: p521-ecdsa-ecdh label {t} never hit\n", .{@as(Label, @enumFromInt(i))});
        return error.HarnessDoesNotReach;
    };
}

test "fuzz: coverage-guided (std.testing.fuzz) over the same harness" {
    try testing.fuzz({}, struct {
        fn f(_: void, s: *testing.Smith) !void {
            return harness(testing.Smith, s, testing.allocator);
        }
    }.f, .{});
}
