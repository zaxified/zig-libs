// SPDX-License-Identifier: MIT
//! RFC 9497 Appendix A, every ciphersuite × every mode, byte-exact through
//! the generic `Protocol` instances (`suite_vectors.zig`, generated from the
//! RFC text by `tools/gen_vectors.py`). A.1 is also covered by the older,
//! hand-transcribed `kat_test.zig`; running it here too pins that the
//! generic layer and the top-level API are the same code.

const std = @import("std");
const voprf = @import("root.zig");
const sv = @import("suite_vectors.zig");

const testing = std.testing;

fn hx(comptime n: usize, s: []const u8) ![n]u8 {
    var out: [n]u8 = undefined;
    if (s.len != 2 * n) return error.BadVectorLength;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn hxAlloc(buf: []u8, s: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf[0 .. s.len / 2], s);
}

fn expectHex(expected: []const u8, actual: []const u8) !void {
    var buf: [256]u8 = undefined;
    const got = try hxAlloc(&buf, expected);
    try testing.expectEqualSlices(u8, got, actual);
}

const max_batch = 2;

fn runMode(comptime S: type, comptime mode: voprf.Mode, mv: sv.ModeVectors) !void {
    const seed = try hx(32, mv.seed);
    var key_info_buf: [64]u8 = undefined;
    const key_info = try hxAlloc(&key_info_buf, mv.key_info);
    var kp: S.KeyPair = undefined;
    try S.deriveKeyPair(mode, &seed, key_info, &kp);
    try expectHex(mv.sk, &kp.sk);
    if (mv.pk) |pk| try expectHex(pk, &kp.pk.toBytes());
    try testing.expect(mv.vectors.len >= 2);

    for (mv.vectors) |v| {
        const b = v.input.len;
        try testing.expect(b >= 1 and b <= max_batch);
        var input_bufs: [max_batch][64]u8 = undefined;
        var inputs: [max_batch][]const u8 = undefined;
        var blinds: [max_batch][S.Ns]u8 = undefined;
        var blinded: [max_batch]S.Element = undefined;
        var evaluated: [max_batch]S.Element = undefined;
        var outputs: [max_batch][S.Nh]u8 = undefined;
        var info_buf: [64]u8 = undefined;
        const info: []const u8 = if (v.info) |i| try hxAlloc(&info_buf, i) else "";
        var tweaked: S.Element = undefined;
        for (0..b) |i| {
            inputs[i] = try hxAlloc(&input_bufs[i], v.input[i]);
            blinds[i] = try hx(S.Ns, v.blind[i]);
            if (mode == .poprf) {
                const r = try S.blindPoprf(inputs[i], info, kp.pk, &blinds[i]);
                blinded[i] = r.blinded_element;
                tweaked = r.tweaked_key;
            } else {
                blinded[i] = try S.blind(mode, inputs[i], &blinds[i]);
            }
            try expectHex(v.blinded_element[i], &blinded[i].toBytes());
            // The published element must also round-trip the deserializer.
            _ = try S.Element.fromBytes(try hx(S.Ne, v.blinded_element[i]));
        }

        switch (mode) {
            .oprf => {
                try S.blindEvaluateBatch(&kp.sk, blinded[0..b], evaluated[0..b]);
                for (0..b) |i| {
                    try testing.expectEqualSlices(u8, &S.blindEvaluate(&kp.sk, blinded[i]).toBytes(), &evaluated[i].toBytes());
                    try S.finalize(inputs[i], &blinds[i], evaluated[i], &outputs[i]);
                }
            },
            .voprf => {
                const r = try hx(S.Ns, v.proof_random_scalar.?);
                const proof = try S.blindEvaluateVerifiableBatch(&kp.sk, kp.pk, blinded[0..b], evaluated[0..b], &r);
                try expectHex(v.proof.?, &proof.toBytes());
                try S.verifyProof(.voprf, S.Element.generator, kp.pk, blinded[0..b], evaluated[0..b], proof);
                try S.finalizeVerifiableBatch(inputs[0..b], blinds[0..b], evaluated[0..b], blinded[0..b], kp.pk, proof, outputs[0..b]);
                if (b == 1) {
                    var out: [S.Nh]u8 = undefined;
                    try S.finalizeVerifiable(inputs[0], &blinds[0], evaluated[0], blinded[0], kp.pk, proof, &out);
                    try testing.expectEqualSlices(u8, &outputs[0], &out);
                }
                // A flipped proof bit fails closed.
                var bad = proof.toBytes();
                bad[S.Ns - 1] ^= 1;
                if (S.Proof.fromBytes(bad)) |bp| {
                    try testing.expectError(error.InvalidProof, S.finalizeVerifiableBatch(inputs[0..b], blinds[0..b], evaluated[0..b], blinded[0..b], kp.pk, bp, outputs[0..b]));
                } else |_| {}
            },
            .poprf => {
                const r = try hx(S.Ns, v.proof_random_scalar.?);
                const proof = try S.blindEvaluatePoprfBatch(&kp.sk, blinded[0..b], info, evaluated[0..b], &r);
                try expectHex(v.proof.?, &proof.toBytes());
                try S.finalizePoprfBatch(inputs[0..b], blinds[0..b], evaluated[0..b], blinded[0..b], proof, info, tweaked, outputs[0..b]);
                if (b == 1) {
                    var out: [S.Nh]u8 = undefined;
                    try S.finalizePoprf(inputs[0], &blinds[0], evaluated[0], blinded[0], proof, info, tweaked, &out);
                    try testing.expectEqualSlices(u8, &outputs[0], &out);
                }
                // The proof is against the tweaked key: the untweaked `pkS`
                // (and a flipped proof bit) fail closed. (`info` itself only
                // enters the Finalize hash, so a wrong `info` is not a proof
                // failure — it is a different PRF output.)
                try testing.expectError(error.InvalidProof, S.finalizePoprfBatch(inputs[0..b], blinds[0..b], evaluated[0..b], blinded[0..b], proof, info, kp.pk, outputs[0..b]));
                var bad = proof.toBytes();
                bad[2 * S.Ns - 1] ^= 1;
                if (S.Proof.fromBytes(bad)) |bp| {
                    var junk: [max_batch][S.Nh]u8 = undefined;
                    try testing.expectError(error.InvalidProof, S.finalizePoprfBatch(inputs[0..b], blinds[0..b], evaluated[0..b], blinded[0..b], bp, info, tweaked, junk[0..b]));
                } else |_| {}
            },
        }
        for (0..b) |i| {
            try expectHex(v.evaluation_element[i], &evaluated[i].toBytes());
            try expectHex(v.output[i], &outputs[i]);
            // The direct (non-oblivious) PRF agrees with the blinded round trip.
            var direct: [S.Nh]u8 = undefined;
            if (mode == .poprf) {
                try S.evaluatePoprf(&kp.sk, inputs[i], info, &direct);
            } else {
                try S.evaluate(mode, &kp.sk, inputs[i], &direct);
            }
            try expectHex(v.output[i], &direct);
        }
    }
}

test "RFC 9497 A.1.1 ristretto255-SHA512 OPRF vectors (generic layer)" {
    try runMode(voprf.Ristretto255Sha512, .oprf, sv.ristretto255_sha512.oprf);
}
test "RFC 9497 A.1.2 ristretto255-SHA512 VOPRF vectors (generic layer)" {
    try runMode(voprf.Ristretto255Sha512, .voprf, sv.ristretto255_sha512.voprf);
}
test "RFC 9497 A.1.3 ristretto255-SHA512 POPRF vectors (generic layer)" {
    try runMode(voprf.Ristretto255Sha512, .poprf, sv.ristretto255_sha512.poprf);
}
test "RFC 9497 A.2.1 decaf448-SHAKE256 OPRF vectors" {
    try runMode(voprf.Decaf448Shake256, .oprf, sv.decaf448_shake256.oprf);
}
test "RFC 9497 A.2.2 decaf448-SHAKE256 VOPRF vectors" {
    try runMode(voprf.Decaf448Shake256, .voprf, sv.decaf448_shake256.voprf);
}
test "RFC 9497 A.2.3 decaf448-SHAKE256 POPRF vectors" {
    try runMode(voprf.Decaf448Shake256, .poprf, sv.decaf448_shake256.poprf);
}
test "RFC 9497 A.3.1 P256-SHA256 OPRF vectors" {
    try runMode(voprf.P256Sha256, .oprf, sv.p256_sha256.oprf);
}
test "RFC 9497 A.3.2 P256-SHA256 VOPRF vectors" {
    try runMode(voprf.P256Sha256, .voprf, sv.p256_sha256.voprf);
}
test "RFC 9497 A.3.3 P256-SHA256 POPRF vectors" {
    try runMode(voprf.P256Sha256, .poprf, sv.p256_sha256.poprf);
}
test "RFC 9497 A.4.1 P384-SHA384 OPRF vectors" {
    try runMode(voprf.P384Sha384, .oprf, sv.p384_sha384.oprf);
}
test "RFC 9497 A.4.2 P384-SHA384 VOPRF vectors" {
    try runMode(voprf.P384Sha384, .voprf, sv.p384_sha384.voprf);
}
test "RFC 9497 A.4.3 P384-SHA384 POPRF vectors" {
    try runMode(voprf.P384Sha384, .poprf, sv.p384_sha384.poprf);
}
test "RFC 9497 A.5.1 P521-SHA512 OPRF vectors" {
    try runMode(voprf.P521Sha512, .oprf, sv.p521_sha512.oprf);
}
test "RFC 9497 A.5.2 P521-SHA512 VOPRF vectors" {
    try runMode(voprf.P521Sha512, .voprf, sv.p521_sha512.voprf);
}
test "RFC 9497 A.5.3 P521-SHA512 POPRF vectors" {
    try runMode(voprf.P521Sha512, .poprf, sv.p521_sha512.poprf);
}

test "RFC 9497 Appendix A: 40 vectors transcribed, 8 per suite" {
    try testing.expectEqual(@as(usize, 40), sv.total_vectors);
    inline for (.{ sv.ristretto255_sha512, sv.decaf448_shake256, sv.p256_sha256, sv.p384_sha384, sv.p521_sha512 }) |s| {
        try testing.expectEqual(@as(usize, 8), s.oprf.vectors.len + s.voprf.vectors.len + s.poprf.vectors.len);
    }
}

test "Suite(cs) maps every Ciphersuite to its instance; wire sizes per RFC 9497 §4" {
    const Case = struct { cs: voprf.Ciphersuite, ne: usize, ns: usize, nh: usize };
    inline for (.{
        Case{ .cs = .ristretto255_sha512, .ne = 32, .ns = 32, .nh = 64 },
        Case{ .cs = .decaf448_shake256, .ne = 56, .ns = 56, .nh = 64 },
        Case{ .cs = .p256_sha256, .ne = 33, .ns = 32, .nh = 32 },
        Case{ .cs = .p384_sha384, .ne = 49, .ns = 48, .nh = 48 },
        Case{ .cs = .p521_sha512, .ne = 67, .ns = 66, .nh = 64 },
    }) |c| {
        const S = voprf.Suite(c.cs);
        try testing.expectEqual(c.ne, S.Ne);
        try testing.expectEqual(c.ns, S.Ns);
        try testing.expectEqual(c.nh, S.Nh);
        try testing.expectEqual(2 * c.ns, S.Proof.encoded_length);
    }
}

test "NIST suites: DeserializeElement refuses uncompressed/identity/off-curve encodings" {
    inline for (.{ voprf.P256Sha256, voprf.P384Sha384, voprf.P521Sha512 }) |S| {
        try testing.expectError(error.InvalidElement, S.Element.fromBytes(@as([S.Ne]u8, @splat(0))));
        var b = S.Element.generator.toBytes();
        b[0] = 0x04; // uncompressed tag at the compressed width
        try testing.expectError(error.InvalidElement, S.Element.fromBytes(b));
        var x = @as([S.Ne]u8, @splat(0xff));
        x[0] = 0x02; // x >= p
        try testing.expectError(error.InvalidElement, S.Element.fromBytes(x));
        // A generator round trip.
        const g = try S.Element.fromBytes(S.Element.generator.toBytes());
        try testing.expectEqualSlices(u8, &S.Element.generator.toBytes(), &g.toBytes());
        // The order n is not a canonical scalar.
        try testing.expectError(error.InvalidScalar, S.deserializeScalar(@as([S.Ns]u8, @splat(0xff))));
    }
}

test "every suite: a zero blind is a value at blind, refused at finalize" {
    inline for (.{ voprf.Decaf448Shake256, voprf.P256Sha256, voprf.P384Sha384, voprf.P521Sha512 }) |S| {
        const zero = @as([S.Ns]u8, @splat(0));
        const be = try S.blind(.oprf, "zero blind", &zero);
        var out: [S.Nh]u8 = undefined;
        try testing.expectError(error.InvalidBlind, S.finalize("zero blind", &zero, be, &out));
        // Mismatched batch lengths are errors, not out-of-bounds writes.
        var one: [1]S.Element = undefined;
        try testing.expectError(error.MismatchedLengths, S.blindEvaluateBatch(&zero, &.{ be, be }, &one));
        var outs: [1][S.Nh]u8 = undefined;
        const proof = S.Proof{ .c = zero, .s = zero };
        try testing.expectError(error.EmptyBatch, S.finalizeVerifiableBatch(&.{}, &.{}, &.{}, &.{}, S.Element.generator, proof, outs[0..0]));
        try testing.expectError(error.MismatchedLengths, S.finalizeVerifiableBatch(&.{"a"}, &.{zero}, &.{ be, be }, &.{be}, S.Element.generator, proof, &outs));
    }
}

test "scalarFromWideBytes: canonical output at every suite's width" {
    inline for (.{ voprf.Ristretto255Sha512, voprf.Decaf448Shake256, voprf.P256Sha256, voprf.P384Sha384, voprf.P521Sha512 }) |S| {
        const wide = @as([S.wide_length]u8, @splat(0xff));
        var s: [S.Ns]u8 = undefined;
        S.scalarFromWideBytes(&wide, &s);
        _ = try S.deserializeScalar(s);
    }
}

fn runObjects(comptime S: type, sv_suite: sv.SuiteVectors) !void {
    // Test Vector 1 of each mode, driven through the context objects.
    var ib: [64]u8 = undefined;
    var info_buf: [64]u8 = undefined;
    {
        const mv = sv_suite.oprf;
        const v = mv.vectors[0];
        const seed = try hx(32, mv.seed);
        var server = try S.OprfServer.derive(&seed, try hxAlloc(&ib, mv.key_info));
        defer server.wipe();
        const input = try hxAlloc(&ib, v.input[0]);
        var client = try S.OprfClient.blind(input, &(try hx(S.Ns, v.blind[0])));
        defer client.wipe();
        const ev = server.blindEvaluate(client.blinded_element);
        var out: [S.Nh]u8 = undefined;
        try client.finalize(input, ev, &out);
        try expectHex(v.output[0], &out);
        try server.evaluate(input, &out);
        try expectHex(v.output[0], &out);
    }
    {
        const mv = sv_suite.voprf;
        const v = mv.vectors[0];
        const seed = try hx(32, mv.seed);
        var server = try S.VoprfServer.derive(&seed, try hxAlloc(&ib, mv.key_info));
        defer server.wipe();
        try expectHex(mv.pk.?, &server.publicKey().toBytes());
        const input = try hxAlloc(&ib, v.input[0]);
        var client = try S.VoprfClient.blind(input, &(try hx(S.Ns, v.blind[0])));
        defer client.wipe();
        const ev = try server.blindEvaluate(client.blinded_element, &(try hx(S.Ns, v.proof_random_scalar.?)));
        try expectHex(v.proof.?, &ev.proof.toBytes());
        var out: [S.Nh]u8 = undefined;
        try client.finalize(input, ev.evaluated_element, ev.proof, server.publicKey(), &out);
        try expectHex(v.output[0], &out);
        // Verifying against the wrong key fails closed.
        try testing.expectError(error.InvalidProof, client.finalize(input, ev.evaluated_element, ev.proof, S.Element.generator, &out));
    }
    {
        const mv = sv_suite.poprf;
        const v = mv.vectors[0];
        const seed = try hx(32, mv.seed);
        var server = try S.PoprfServer.derive(&seed, try hxAlloc(&ib, mv.key_info));
        defer server.wipe();
        const input = try hxAlloc(&ib, v.input[0]);
        const info = try hxAlloc(&info_buf, v.info.?);
        var client = try S.PoprfClient.blind(input, info, server.publicKey(), &(try hx(S.Ns, v.blind[0])));
        defer client.wipe();
        const ev = try server.blindEvaluate(client.blinded_element, info, &(try hx(S.Ns, v.proof_random_scalar.?)));
        var out: [S.Nh]u8 = undefined;
        try client.finalize(input, ev.evaluated_element, ev.proof, info, &out);
        try expectHex(v.output[0], &out);
        try server.evaluate(input, info, &out);
        try expectHex(v.output[0], &out);
    }
}

test "context objects (Oprf/Voprf/Poprf Client+Server) reproduce Test Vector 1 of A.1-A.5, every mode" {
    try runObjects(voprf.Ristretto255Sha512, sv.ristretto255_sha512);
    try runObjects(voprf.Decaf448Shake256, sv.decaf448_shake256);
    try runObjects(voprf.P256Sha256, sv.p256_sha256);
    try runObjects(voprf.P384Sha384, sv.p384_sha384);
    try runObjects(voprf.P521Sha512, sv.p521_sha512);
}

test "RFC 9497 2^16-1 input bound: a 65536-byte input/info is error.InputTooLong at every entry point, 65535 is accepted" {
    const long = try testing.allocator.alloc(u8, voprf.max_input_length + 1);
    defer testing.allocator.free(long);
    @memset(long, 'x');
    const max = long[0..voprf.max_input_length];
    inline for (.{ voprf.Ristretto255Sha512, voprf.P256Sha256 }) |S| {
        var seed = @as([32]u8, @splat(7));
        var kp: S.KeyPair = undefined;
        try testing.expectError(error.InputTooLong, S.deriveKeyPair(.voprf, &seed, long, &kp));
        try S.deriveKeyPair(.voprf, &seed, max, &kp);
        var bs: [S.Ns]u8 = undefined;
        S.scalarFromWideBytes(&@as([S.wide_length]u8, @splat(3)), &bs);
        var out: [S.Nh]u8 = undefined;
        var outs: [1][S.Nh]u8 = undefined;
        const g = S.Element.generator;
        const proof = S.Proof{ .c = bs, .s = bs };
        try testing.expectError(error.InputTooLong, S.blind(.oprf, long, &bs));
        _ = try S.blind(.oprf, max, &bs);
        try testing.expectError(error.InputTooLong, S.finalize(long, &bs, g, &out));
        try S.finalize(max, &bs, g, &out);
        try testing.expectError(error.InputTooLong, S.evaluate(.oprf, &kp.sk, long, &out));
        try testing.expectError(error.InputTooLong, S.finalizeVerifiable(long, &bs, g, g, kp.pk, proof, &out));
        try testing.expectError(error.InputTooLong, S.finalizeVerifiableBatch(&.{long}, &.{bs}, &.{g}, &.{g}, kp.pk, proof, &outs));
        try testing.expectError(error.InputTooLong, S.blindPoprf(long, "i", kp.pk, &bs));
        try testing.expectError(error.InputTooLong, S.blindPoprf("x", long, kp.pk, &bs));
        var ev: [1]S.Element = undefined;
        try testing.expectError(error.InputTooLong, S.blindEvaluatePoprfBatch(&kp.sk, &.{g}, long, &ev, &bs));
        try testing.expectError(error.InputTooLong, S.blindEvaluatePoprf(&kp.sk, g, long, &bs));
        try testing.expectError(error.InputTooLong, S.finalizePoprf(long, &bs, g, g, proof, "i", g, &out));
        try testing.expectError(error.InputTooLong, S.finalizePoprf("x", &bs, g, g, proof, long, g, &out));
        try testing.expectError(error.InputTooLong, S.finalizePoprfBatch(&.{"x"}, &.{bs}, &.{g}, &.{g}, proof, long, g, &outs));
        try testing.expectError(error.InputTooLong, S.finalizePoprfUnverified(long, &bs, g, "i", &out));
        try testing.expectError(error.InputTooLong, S.evaluatePoprf(&kp.sk, "x", long, &out));
        try testing.expectError(error.InputTooLong, S.evaluatePoprf(&kp.sk, long, "i", &out));
        try testing.expectError(error.InputTooLong, S.poprfInfoScalar(long));
        _ = try S.poprfInfoScalar(max);
        try testing.expectError(error.InputTooLong, S.OprfServer.derive(&seed, long));
    }
}
