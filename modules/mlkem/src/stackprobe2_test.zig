// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the entry points
//! `stackprobe_test.zig` does not call: the `io` forms (`encapsInto`,
//! `tryEncapsInto`, `generateInto`, `tryGenerateInto` with and without the
//! pairwise check), `pairwiseConsistencyCheck`, and the by-value forms
//! (`encapsDeterministic`, `tryEncaps`, `generate`, `tryGenerate`,
//! `SecretKey.fromBytes`). All three parameter sets. ReleaseFast/ReleaseSmall
//! only (`skipUnlessOptimized`). Coverage sweep 2026-11-26.
//!
//! The `io` forms draw m / the seed into their own frame (above the burn of
//! the deterministic body they call), so they run on a test double of
//! `std.Io` whose `randomSecure` is a fixed SHA-512 stream (as hpke's
//! `stackprobe3_test.zig`): the drawn secret is known and is a needle. A
//! by-value result lands in the probe's own call frame by shape, so only the
//! inputs (and the drawn secret) are needles there.

const std = @import("std");
const mlkem = @import("root.zig");
const sp = @import("testkit").stackprobe;

const P = sp.Probe(.{ .window = 256 * 1024 });

fn detFill(buf: []u8) void {
    var off: usize = 0;
    var ctr: u8 = 0;
    while (off < buf.len) : (ctr += 1) {
        var h: [64]u8 = undefined;
        var s = std.crypto.hash.sha2.Sha512.init(.{});
        s.update("mlkem stackprobe2 rng");
        s.update(&[1]u8{ctr});
        s.final(&h);
        const n = @min(h.len, buf.len - off);
        @memcpy(buf[off..][0..n], h[0..n]);
        off += n;
    }
}

fn detRandomSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    detFill(buf);
}

var det_vtable: std.Io.VTable = undefined;
var det_io: std.Io = undefined;

fn setupIo(threaded: *std.Io.Threaded) void {
    const base = threaded.io();
    det_vtable = base.vtable.*;
    det_vtable.randomSecure = detRandomSecure;
    det_io = .{ .userdata = base.userdata, .vtable = &det_vtable };
}

fn Suite(comptime K: type, comptime name: []const u8) type {
    return struct {
        var drawn_m: [32]u8 = undefined;
        var drawn_seed: [K.seed_length]u8 = undefined;
        var kp: K.KeyPair = undefined;
        var kp_io: K.KeyPair = undefined;
        var es: K.EncapsulatedSecret = undefined;
        var sk_bytes: [K.SecretKey.encoded_length]u8 = undefined;

        fn encapsDetW(pk: *const K.PublicKey, m: *const [32]u8) K.EncapsulatedSecret {
            return pk.encapsDeterministic(m);
        }
        fn tryEncapsW(pk: *const K.PublicKey, io: std.Io) !K.EncapsulatedSecret {
            return pk.tryEncaps(io);
        }
        fn tryGenW(io: std.Io) !K.KeyPair {
            return K.KeyPair.tryGenerate(io, .{});
        }
        fn tryGenCheckedIntoW(out: *K.KeyPair, io: std.Io) !void {
            return K.KeyPair.tryGenerateInto(out, io, .{ .pairwise_check = true });
        }
        fn tryGenIntoW(out: *K.KeyPair, io: std.Io) !void {
            return K.KeyPair.tryGenerateInto(out, io, .{});
        }
        fn fromBytesW(b: *const [K.SecretKey.encoded_length]u8) !K.SecretKey {
            return K.SecretKey.fromBytes(b);
        }

        fn probe() !void {
            detFill(&drawn_m);
            detFill(&drawn_seed);
            var seed: [K.seed_length]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash("mlkem stackprobe2 seed " ++ name, &seed, .{});
            K.KeyPair.generateDeterministicInto(&kp, &seed);
            sk_bytes = kp.secret_key.toBytes();
            const s_part = sk_bytes[0 .. K.SecretKey.encoded_length - (K.PublicKey.encoded_length + 64)];
            const pk: *const K.PublicKey = &kp.public_key;

            // io forms: the drawn m / seed and every output secret are needles.
            _ = try P.run(name ++ " encapsInto(io)", K.PublicKey.encapsInto, .{ pk, det_io, &es }, &.{ &drawn_m, &es.shared_secret }, .{});
            _ = try P.run(name ++ " tryEncapsInto(io)", K.PublicKey.tryEncapsInto, .{ pk, det_io, &es }, &.{ &drawn_m, &es.shared_secret }, .{});
            _ = try P.run(name ++ " generateInto(io)", K.KeyPair.generateInto, .{ &kp_io, det_io }, &.{&drawn_seed}, .{});
            _ = try P.run(name ++ " tryGenerateInto(io)", tryGenIntoW, .{ &kp_io, det_io }, &.{&drawn_seed}, .{});
            _ = try P.run(name ++ " tryGenerateInto(io, pairwise_check)", tryGenCheckedIntoW, .{ &kp_io, det_io }, &.{&drawn_seed}, .{});
            _ = try P.run(name ++ " pairwiseConsistencyCheck", K.KeyPair.pairwiseConsistencyCheck, .{&kp}, &.{ &seed, s_part }, .{});

            // By-value forms: inputs and drawn secrets only.
            var m: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash("mlkem stackprobe2 m " ++ name, &m, .{});
            const mm = m;
            _ = try P.run(name ++ " encapsDeterministic", encapsDetW, .{ pk, &mm }, &.{&mm}, .{});
            _ = try P.run(name ++ " tryEncaps(io)", tryEncapsW, .{ pk, det_io }, &.{&drawn_m}, .{});
            // The by-value key pair carries the whole seed d ‖ z (`SecretKey.seed`, the
            // seed-form private key) by shape: the residue rule is the check here.
            _ = try P.run(name ++ " generate(io)", K.KeyPair.generate, .{det_io}, &.{}, .{});
            _ = try P.run(name ++ " tryGenerate(io)", tryGenW, .{det_io}, &.{}, .{});
            _ = try P.run(name ++ " SecretKey.fromBytes", fromBytesW, .{&sk_bytes}, &.{}, .{});
        }
    };
}

test "STACKPROBE: ML-KEM io, pairwise-check and by-value entry points leave no secret on the dead stack" {
    try sp.skipUnlessOptimized();
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    setupIo(&threaded);
    try Suite(mlkem.MLKem512, "512").probe();
    try Suite(mlkem.MLKem768, "768").probe();
    try Suite(mlkem.MLKem1024, "1024").probe();
}
