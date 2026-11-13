// SPDX-License-Identifier: MIT

//! No-panic sweep tests (2026-11-13): every suite, every pub entry point,
//! hostile arguments. Test names end with "(sweep <ID>)".

const std = @import("std");
const testing = std.testing;
const voprf = @import("root.zig");

fn Row(comptime cs: voprf.Ciphersuite) type {
    return voprf.Suite(cs);
}

test "batch longer than 2^16 - 1 is an error at every batch entry point, not an index overflow (sweep VOPRF-1)" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = Row(@field(voprf.Ciphersuite, name));
        const n = voprf.max_batch_length + 2; // 65537: the first batch whose index no longer fits a u16
        const g = S.Element.generator;
        const els = try testing.allocator.alloc(S.Element, n);
        defer testing.allocator.free(els);
        @memset(els, g);
        const outs = try testing.allocator.alloc(S.Element, n);
        defer testing.allocator.free(outs);
        const zero: [S.Ns]u8 = @splat(0);
        var sk: [S.Ns]u8 = @splat(0);
        sk[S.Ns - 1] = 7;
        sk[0] = 7;
        const proof: S.Proof = .{ .c = zero, .s = zero };

        // server side
        try testing.expectError(error.ProofGenerationFailed, S.blindEvaluateVerifiableBatch(&sk, g, els, outs, &sk));
        try testing.expectError(error.ProofGenerationFailed, S.blindEvaluatePoprfBatch(&sk, els, "info", outs, &sk));
        try testing.expectError(error.ProofGenerationFailed, S.generateProof(.voprf, &sk, g, g, els, els, &sk));
        // client side
        try testing.expectError(error.InvalidProof, S.verifyProof(.voprf, g, g, els, els, proof));
        try testing.expectError(error.InvalidProof, S.verifyProof(.poprf, g, g, els, els, proof));
        const inputs = try testing.allocator.alloc([]const u8, n);
        defer testing.allocator.free(inputs);
        @memset(inputs, "x");
        const blinds = try testing.allocator.alloc([S.Ns]u8, n);
        defer testing.allocator.free(blinds);
        @memset(blinds, sk);
        const hashes = try testing.allocator.alloc([S.Nh]u8, n);
        defer testing.allocator.free(hashes);
        try testing.expectError(error.InvalidProof, S.finalizeVerifiableBatch(inputs, blinds, els, els, g, proof, hashes));
        try testing.expectError(error.InvalidProof, S.finalizePoprfBatch(inputs, blinds, els, els, proof, "info", g, hashes));
    }
}

test "all-0xff and all-zero secrets (non-canonical, degenerate) never panic on any suite or entry point (sweep VOPRF-2)" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = Row(@field(voprf.Ciphersuite, name));
        const g = S.Element.generator;
        const seed: [32]u8 = @splat(0x42);
        var kp: S.KeyPair = undefined;
        try S.deriveKeyPair(.voprf, &seed, "info", &kp);
        inline for (.{ @as(u8, 0xff), @as(u8, 0x00), @as(u8, 0x01) }) |fill| {
            const bad: [S.Ns]u8 = @splat(fill);
            var out: [S.Nh]u8 = undefined;
            var ev: [1]S.Element = undefined;
            _ = S.blind(.oprf, "x", &bad) catch {};
            _ = S.blindEvaluate(&bad, g);
            S.finalize("x", &bad, g, &out) catch {};
            S.evaluate(.voprf, &bad, "x", &out) catch {};
            _ = S.blindEvaluateVerifiable(&bad, kp.pk, g, &bad) catch {};
            _ = S.blindEvaluateVerifiableBatch(&bad, kp.pk, &.{g}, &ev, &kp.sk) catch {};
            _ = S.blindEvaluateVerifiableBatch(&kp.sk, kp.pk, &.{g}, &ev, &bad) catch {};
            const proof: S.Proof = .{ .c = bad, .s = bad };
            S.finalizeVerifiable("x", &bad, g, g, kp.pk, proof, &out) catch {};
            _ = S.blindPoprf("x", "i", kp.pk, &bad) catch {};
            _ = S.blindEvaluatePoprf(&bad, g, "i", &kp.sk) catch {};
            _ = S.blindEvaluatePoprf(&kp.sk, g, "i", &bad) catch {};
            S.finalizePoprf("x", &bad, g, g, proof, "i", g, &out) catch {};
            S.finalizePoprfUnverified("x", &bad, g, "i", &out) catch {};
            S.evaluatePoprf(&bad, "x", "i", &out) catch {};
            _ = S.generateProof(.voprf, &bad, g, g, &.{g}, &.{g}, &bad) catch {};
            _ = S.verifyProof(.voprf, g, g, &.{g}, &.{g}, proof) catch {};
        }
    }
}

test "hostile element and proof encodings are errors on every suite (sweep VOPRF-3)" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = Row(@field(voprf.Ciphersuite, name));
        inline for (.{ @as(u8, 0x00), @as(u8, 0xff), @as(u8, 0x02), @as(u8, 0x03), @as(u8, 0x04) }) |fill| {
            const enc: [S.Ne]u8 = @splat(fill);
            if (S.Element.fromBytes(enc)) |e| {
                // anything accepted must be canonical
                try testing.expectEqualSlices(u8, &enc, &e.toBytes());
            } else |err| try testing.expect(err == error.InvalidElement);
            // prefix byte valid, x = 0xff.. (>= p)
            var pre = enc;
            pre[0] = 0x02;
            _ = S.Element.fromBytes(pre) catch {};
            pre[0] = 0x03;
            _ = S.Element.fromBytes(pre) catch {};
        }
        const pf: [2 * S.Ns]u8 = @splat(0xff);
        try testing.expectError(error.InvalidScalar, S.Proof.fromBytes(pf));
        try testing.expectError(error.InvalidScalar, S.deserializeScalar(@as([S.Ns]u8, @splat(0xff))));
    }
}

test "wiped per-role objects stay total: no panic, key and blind are gone (sweep VOPRF-4)" {
    inline for (@typeInfo(voprf.Ciphersuite).@"enum".field_names) |name| {
        const S = Row(@field(voprf.Ciphersuite, name));
        const seed: [32]u8 = @splat(0x11);
        const wide: [S.wide_length]u8 = @splat(0x5a);
        var r: [S.Ns]u8 = undefined;
        S.scalarFromWideBytes(&wide, &r); // a canonical, non-zero scalar on every suite
        var out: [S.Nh]u8 = undefined;
        var ev: [1]S.Element = undefined;

        var os = try S.OprfServer.derive(&seed, "i");
        var oc = try S.OprfClient.blind("x", &r);
        const e0 = os.blindEvaluate(oc.blinded_element);
        os.wipe();
        oc.wipe();
        const e1 = os.blindEvaluate(oc.blinded_element);
        try testing.expect(!std.mem.eql(u8, &e0.toBytes(), &e1.toBytes()));
        try testing.expectError(error.InvalidBlind, oc.finalize("x", e0, &out));
        os.evaluate("x", &out) catch {};

        var vs = try S.VoprfServer.derive(&seed, "i");
        var vc = try S.VoprfClient.blind("x", &r);
        const pk = vs.publicKey();
        const e = try vs.blindEvaluate(vc.blinded_element, &r);
        vs.wipe();
        vc.wipe();
        _ = vs.blindEvaluate(vc.blinded_element, &r) catch {};
        _ = vs.blindEvaluateBatch(&.{vc.blinded_element}, &ev, &r) catch {};
        vs.evaluate("x", &out) catch {};
        try testing.expectError(error.InvalidBlind, vc.finalize("x", e.evaluated_element, e.proof, pk, &out));

        var ps = try S.PoprfServer.derive(&seed, "i");
        var pc = try S.PoprfClient.blind("x", "info", ps.publicKey(), &r);
        const pe = try ps.blindEvaluate(pc.blinded_element, "info", &r);
        ps.wipe();
        pc.wipe();
        _ = ps.blindEvaluate(pc.blinded_element, "info", &r) catch {};
        _ = ps.blindEvaluateBatch(&.{pc.blinded_element}, "info", &ev, &r) catch {};
        ps.evaluate("x", "info", &out) catch {};
        try testing.expectError(error.InvalidBlind, pc.finalize("x", pe.evaluated_element, pe.proof, "info", &out));
    }
}

test "expandMessageXmd accepts the whole 1..255 DST range (sweep VOPRF-5)" {
    const d255: [255]u8 = @splat('d');
    _ = voprf.expandMessageXmd(32, &.{"m"}, &d255);
    _ = voprf.expandMessageXmd(64, &.{"m"}, "d");
}
