// SPDX-License-Identifier: MIT
//! `agile.zig`: every Go 1.26 crypto/hpke vector driven through the run-time
//! suite (the same 37 vectors `kat_go_test.zig` drives through the comptime
//! API, here selected by id at run time), all four modes against the comptime
//! entry points byte for byte, and the misuse errors.

const std = @import("std");
const testing = std.testing;
const go = @import("testdata/go_vectors.zig");
const agile = @import("agile.zig");
const dhkem = @import("dhkem.zig");
const pq = @import("pq.zig");
const kdf = @import("kdf.zig");
const schedule = @import("schedule.zig");
const aesgcm = @import("aesgcm");

fn unhex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const b = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(b, h);
    return b;
}

fn expectHex(a: std.mem.Allocator, want_hex: []const u8, got: []const u8) !void {
    try testing.expectEqualSlices(u8, try unhex(a, want_hex), got);
}

fn draw(a: std.mem.Allocator, x: *std.crypto.hash.sha3.Shake128) ![]u8 {
    var l: [1]u8 = undefined;
    x.squeeze(&l);
    const b = try a.alloc(u8, l[0]);
    x.squeeze(b);
    return b;
}

fn checkVector(v: *const go.Vector) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const s = try agile.Suite.init(v.kem_id, v.kdf_id, v.aead_id);
    var skR: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&skR, s.kem, try unhex(a, v.ikmR));
    const pkR = skR.publicKey();
    try expectHex(a, v.pkRm, pkR.slice());
    // The serialized public key round-trips through fromBytes.
    const pk2 = try agile.publicKeyFromBytes(s.kem, try unhex(a, v.pkRm));
    try testing.expectEqualSlices(u8, pkR.slice(), pk2.slice());

    const info = try unhex(a, v.info);
    var st: agile.Setup = undefined;
    try agile.setupSDeterministic(&st, s, .base, &pk2, null, try unhex(a, v.ikmE), info, "", "");
    try expectHex(a, v.enc, st.encSlice());
    try testing.expectEqual(s.encLength(), st.enc_len);
    var r: agile.Context = undefined;
    try agile.setupR(&r, s, .base, st.encSlice(), &skR, null, info, "", "");

    const nt = s.tagLength();
    if (v.aead_id != 0xffff) {
        if (v.encryptions_accumulated.len != 0) {
            var source = std.crypto.hash.sha3.Shake128.init(.{});
            var sink = std.crypto.hash.sha3.Shake128.init(.{});
            for (0..1000) |_| {
                const aad = try draw(a, &source);
                const pt = try draw(a, &source);
                const ct = try a.alloc(u8, pt.len + nt);
                try st.context.seal(aad, pt, ct);
                sink.update(ct);
                const back = try a.alloc(u8, pt.len);
                try r.open(aad, ct, back);
                try testing.expectEqualSlices(u8, pt, back);
            }
            var acc: [16]u8 = undefined;
            sink.squeeze(&acc);
            try expectHex(a, v.encryptions_accumulated, &acc);
        } else {
            for (v.encryptions) |e| {
                const pt = try unhex(a, e.pt);
                const aad = try unhex(a, e.aad);
                const ct = try a.alloc(u8, pt.len + nt);
                try st.context.seal(aad, pt, ct);
                try expectHex(a, e.ct, ct);
                const back = try a.alloc(u8, pt.len);
                try r.open(aad, ct, back);
                try testing.expectEqualSlices(u8, pt, back);
            }
        }
    } else {
        var buf: [16]u8 = undefined;
        try testing.expectError(error.ExportOnly, st.context.seal("", "", &buf));
    }

    if (v.exports_accumulated.len != 0) {
        var source = std.crypto.hash.sha3.Shake128.init(.{});
        var sink = std.crypto.hash.sha3.Shake128.init(.{});
        for (0..1000) |l| {
            const ctx = try draw(a, &source);
            const value = try a.alloc(u8, l);
            try st.context.exportSecret(ctx, value);
            sink.update(value);
            const again = try a.alloc(u8, l);
            try r.exportSecret(ctx, again);
            try testing.expectEqualSlices(u8, value, again);
        }
        var acc: [16]u8 = undefined;
        sink.squeeze(&acc);
        try expectHex(a, v.exports_accumulated, &acc);
    } else {
        for (v.exports) |e| {
            const value = try a.alloc(u8, e.len);
            try st.context.exportSecret(try unhex(a, e.context), value);
            try expectHex(a, e.value, value);
        }
    }
}

test "agile: every Go crypto/hpke vector through a run-time Suite" {
    var ran: usize = 0;
    for (&go.vectors) |*v| {
        checkVector(v) catch |e| {
            std.debug.print("agile vector {s} kem 0x{x:0>4} kdf 0x{x:0>4} aead 0x{x:0>4} failed\n", .{ v.source, v.kem_id, v.kdf_id, v.aead_id });
            return e;
        };
        ran += 1;
    }
    try testing.expectEqual(@as(usize, 37), ran);
}

test "agile: all four modes equal the comptime API byte for byte (P-256, HKDF-SHA384, AES-256-GCM)" {
    const K = dhkem.P256Kem;
    const Kdf = kdf.HkdfSha384;
    const A = aesgcm.Aes256Gcm;
    const s = try agile.Suite.init(K.kem_id, Kdf.kdf_id, 0x0002);
    var kR: K.KeyPair = undefined;
    K.deriveKeyPair(&kR, "recipient ikm");
    var kS: K.KeyPair = undefined;
    K.deriveKeyPair(&kS, "sender ikm");
    var eph: K.KeyPair = undefined;
    K.deriveKeyPair(&eph, "ephemeral ikm");
    var aR: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&aR, s.kem, "recipient ikm");
    var aS: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&aS, s.kem, "sender ikm");
    const pkR = aR.publicKey();
    const pkS = aS.publicKey();
    const psk = "0123456789abcdef0123456789abcdef";

    inline for ([_]agile.Mode{ .base, .psk, .auth, .auth_psk }) |mode| {
        const p: []const u8 = if (mode == .psk or mode == .auth_psk) psk else "";
        const pid: []const u8 = if (p.len != 0) "id" else "";
        const auth = mode == .auth or mode == .auth_psk;
        var want: schedule.Setup(K, A, Kdf) = undefined;
        switch (mode) {
            .base => try schedule.setupBaseSDeterministic(K, A, Kdf, &want, kR.public_key, &eph, "info"),
            .psk => try schedule.setupPskSDeterministic(K, A, Kdf, &want, kR.public_key, &eph, "info", p, pid),
            .auth => try schedule.setupAuthSDeterministic(K, A, Kdf, &want, kR.public_key, &kS, &eph, "info"),
            .auth_psk => try schedule.setupAuthPskSDeterministic(K, A, Kdf, &want, kR.public_key, &kS, &eph, "info", p, pid),
        }
        var got: agile.Setup = undefined;
        try agile.setupSDeterministic(&got, s, mode, &pkR, if (auth) &aS else null, "ephemeral ikm", "info", p, pid);
        try testing.expectEqualSlices(u8, &want.enc, got.encSlice());

        var ct_want: [5 + 16]u8 = undefined;
        var ct_got: [5 + 16]u8 = undefined;
        try want.context.seal("aad", "hello", &ct_want);
        try got.context.seal("aad", "hello", &ct_got);
        try testing.expectEqualSlices(u8, &ct_want, &ct_got);
        try testing.expectEqual(@as(u64, 1), got.context.seq());

        var ex_want: [40]u8 = undefined;
        var ex_got: [40]u8 = undefined;
        const sid = schedule.suiteIdOf(K, A, Kdf);
        try want.context.exportSecret(&sid, "ctx", &ex_want);
        try got.context.exportSecret("ctx", &ex_got);
        try testing.expectEqualSlices(u8, &ex_want, &ex_got);

        var r: agile.Context = undefined;
        try agile.setupR(&r, s, mode, got.encSlice(), &aR, if (auth) &pkS else null, "info", p, pid);
        var back: [5]u8 = undefined;
        try r.open("aad", &ct_got, &back);
        try testing.expectEqualStrings("hello", &back);
        // Tampered ciphertext.
        ct_got[0] ^= 1;
        var r2: agile.Context = undefined;
        try agile.setupR(&r2, s, mode, got.encSlice(), &aR, if (auth) &pkS else null, "info", p, pid);
        try testing.expectError(error.DecryptionFailed, r2.open("aad", &ct_got, &back));
    }
}

test "agile: every KEM x KDF round-trips (generate, single-shot sealBase/openBase), every AEAD" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const kems = [_]u16{ 0x0010, 0x0011, 0x0012, 0x0020, 0x0021, 0x0040, 0x0041, 0x0042, 0x0050, 0x0051, 0x647a };
    const kdfs = [_]u16{ 0x0001, 0x0002, 0x0003, 0x0010, 0x0011, 0x0012, 0x0013 };
    const aeads = [_]u16{ 0x0001, 0x0002, 0x0003 };
    var buf: [2048]u8 = undefined;
    for (kems, 0..) |kem, i| {
        var kp: agile.KeyPair = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
        try agile.generateKeyPair(&kp, @fromBackingInt(@intCast(kem)), io);
        try testing.expectEqual(@as(agile.KemId, @fromBackingInt(@intCast(kem))), kp.kemId());
        const pk = kp.publicKey();
        for (kdfs, 0..) |k, j| {
            const s = try agile.Suite.init(kem, k, aeads[(i + j) % aeads.len]);
            const pt = "agile";
            const n = s.encLength() + pt.len + s.tagLength();
            try agile.sealBase(s, &pk, io, "info", "aad", pt, buf[0..n]);
            var back: [pt.len]u8 = undefined;
            try agile.openBase(s, &kp, "info", "aad", buf[0..n], &back);
            try testing.expectEqualStrings(pt, &back);
            buf[n - 1] ^= 1;
            try testing.expectError(error.DecryptionFailed, agile.openBase(s, &kp, "info", "aad", buf[0..n], &back));
        }
    }
}

test "agile: fromSecret round-trips the serialized private key (DHKEM scalar, pq seed)" {
    const cases = [_]struct { kem: u16, ikm: []const u8 }{
        .{ .kem = 0x0010, .ikm = "a" },
        .{ .kem = 0x0021, .ikm = "b" },
        .{ .kem = 0x0041, .ikm = "c" },
        .{ .kem = 0x647a, .ikm = "d" },
    };
    for (cases) |c| {
        var kp: agile.KeyPair = undefined;
        try agile.deriveKeyPair(&kp, @fromBackingInt(@intCast(c.kem)), c.ikm);
        const sk = kp.secretBytes();
        var kp2: agile.KeyPair = undefined;
        try agile.keyPairFromSecret(&kp2, kp.kemId(), sk);
        try testing.expectEqualSlices(u8, kp.publicKey().slice(), kp2.publicKey().slice());
        try testing.expectError(error.InvalidLength, agile.keyPairFromSecret(&kp2, kp.kemId(), sk[1..]));
    }
}

test "agile: misuse errors" {
    try testing.expectError(error.UnsupportedSuite, agile.Suite.init(0x0099, 1, 1));
    try testing.expectError(error.UnsupportedSuite, agile.Suite.init(0x0020, 0x0099, 1));
    try testing.expectError(error.UnsupportedSuite, agile.Suite.init(0x0020, 1, 0x0004));
    try testing.expectError(error.UnsupportedSuite, agile.publicKeyFromBytes(@fromBackingInt(@intCast(0x0099)), "x"));
    try testing.expectError(error.InvalidLength, agile.publicKeyFromBytes(.dhkem_x25519_hkdf_sha256, "short"));
    var bad_p256: [65]u8 = @splat(0);
    bad_p256[0] = 4;
    try testing.expectError(error.DeserializeError, agile.publicKeyFromBytes(.dhkem_p256_hkdf_sha256, &bad_p256));

    var x: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&x, .dhkem_x25519_hkdf_sha256, "x");
    var m: agile.KeyPair = undefined;
    try agile.deriveKeyPair(&m, .ml_kem_768, "m");
    const pkx = x.publicKey();
    const pkm = m.publicKey();
    var st: agile.Setup = undefined;
    var c: agile.Context = undefined;

    // Key of another KEM than the suite's.
    const sx = try agile.Suite.init(0x0020, 1, 1);
    try testing.expectError(error.KemMismatch, agile.setupSDeterministic(&st, sx, .base, &pkm, null, "e", "", "", ""));
    try testing.expectError(error.KemMismatch, agile.setupR(&c, sx, .base, pkx.slice(), &m, null, "", "", ""));
    // Auth mode without a sender key, base mode with one, auth on ML-KEM.
    try testing.expectError(error.UnsupportedMode, agile.setupSDeterministic(&st, sx, .auth, &pkx, null, "e", "", "", ""));
    try testing.expectError(error.UnsupportedMode, agile.setupSDeterministic(&st, sx, .base, &pkx, &x, "e", "", "", ""));
    const sm = try agile.Suite.init(0x0041, 1, 1);
    try testing.expectError(error.UnsupportedMode, agile.setupSDeterministic(&st, sm, .auth, &pkm, &m, "e", "", "", ""));
    // pq ikmE of the wrong length; enc of the wrong length.
    try testing.expectError(error.InvalidLength, agile.setupSDeterministic(&st, sm, .base, &pkm, null, "short", "", "", ""));
    try testing.expectError(error.InvalidLength, agile.setupR(&c, sx, .base, "short", &x, null, "", "", ""));
    // psk rules are the key schedule's.
    try testing.expectError(error.InconsistentPsk, agile.setupSDeterministic(&st, sx, .psk, &pkx, null, "e", "", "", ""));
    try testing.expectError(error.PskTooShort, agile.setupSDeterministic(&st, sx, .psk, &pkx, null, "e", "", "short", "id"));
    // Export-only: no seal/open, export works.
    const se = try agile.Suite.init(0x0020, 1, 0xffff);
    try agile.setupSDeterministic(&st, se, .base, &pkx, null, "e", "", "", "");
    var out: [16]u8 = undefined;
    try testing.expectError(error.ExportOnly, st.context.seal("", "", &out));
    try testing.expectError(error.ExportOnly, st.context.open("", &out, &out));
    try st.context.exportSecret("ctx", &out);
}

test "agile: a restricted Agile instance dispatches only over its subset" {
    const A = agile.Agile(.{ .kems = &.{.dhkem_x25519_hkdf_sha256}, .kdfs = &.{.hkdf_sha256}, .aeads = &.{.chacha20poly1305} });
    var kp: agile.KeyPair = undefined;
    try A.deriveKeyPair(&kp, .dhkem_x25519_hkdf_sha256, "r");
    const pk = kp.publicKey();
    const s = try agile.Suite.init(0x0020, 0x0001, 0x0003);
    var st: A.Setup = undefined;
    try A.setupSDeterministic(&st, s, .base, &pk, null, "e", "info", "", "");
    // Same bytes as the full set.
    var full: agile.Setup = undefined;
    try agile.setupSDeterministic(&full, s, .base, &pk, null, "e", "info", "", "");
    try testing.expectEqualSlices(u8, full.encSlice(), st.encSlice());
    var c1: [3 + 16]u8 = undefined;
    var c2: [3 + 16]u8 = undefined;
    try st.context.seal("", "abc", &c1);
    try full.context.seal("", "abc", &c2);
    try testing.expectEqualSlices(u8, &c2, &c1);
    // Ids outside the subset (all registered, so Suite.init accepts them).
    var other: agile.KeyPair = undefined;
    try testing.expectError(error.UnsupportedSuite, A.deriveKeyPair(&other, .dhkem_p256_hkdf_sha256, "r"));
    const p256_bytes: [65]u8 = @splat(4);
    try testing.expectError(error.UnsupportedSuite, A.publicKeyFromBytes(.dhkem_p256_hkdf_sha256, &p256_bytes));
    try testing.expectError(error.UnsupportedSuite, A.setupSDeterministic(&st, try agile.Suite.init(0x0020, 0x0001, 0x0001), .base, &pk, null, "e", "", "", ""));
    try testing.expectError(error.UnsupportedSuite, A.setupSDeterministic(&st, try agile.Suite.init(0x0020, 0x0003, 0x0003), .base, &pk, null, "e", "", "", ""));
    var c: A.Context = undefined;
    try testing.expectError(error.UnsupportedSuite, A.setupR(&c, try agile.Suite.init(0x0010, 0x0001, 0x0003), .base, "", &kp, null, "", "", ""));
}
