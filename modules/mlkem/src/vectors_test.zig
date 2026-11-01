// SPDX-License-Identifier: MIT

//! External-authority tests for `mlkem`: reduced slices of C2SP CCTV, NIST
//! ACVP-Server and Wycheproof vectors (`testdata/*.txt`, provenance in each
//! file's header, recipe in `tools/vectors/`), plus the CCTV-style "accumulated"
//! stream (differential against std; see the note there). Line formats are documented in `tools/vectors/extract.py`.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");

const testing = std.testing;
const sha3 = std.crypto.hash.sha3;

const max_dk = 3168;
const max_ek = 1568;
const max_ct = 1568;

fn hex(buf: []u8, s: []const u8) ![]u8 {
    return std.fmt.hexToBytes(buf, s);
}

/// Decode `s` into exactly `n` bytes at `buf`, returning an array pointer.
fn hexArr(comptime n: usize, buf: *[n]u8, s: []const u8) !void {
    if (s.len != 2 * n) return error.BadVectorLength;
    _ = try std.fmt.hexToBytes(buf, s);
}

fn ShapeOf(comptime K: type) type {
    return struct {
        const Ek = [K.PublicKey.encoded_length]u8;
        const Dk = [K.SecretKey.encoded_length]u8;
        const Ct = [K.ciphertext_length]u8;
    };
}

fn doKg(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    var seed: [64]u8 = undefined;
    try hexArr(32, seed[0..32], it.next().?);
    try hexArr(32, seed[32..64], it.next().?);
    var ek: S.Ek = undefined;
    var dk: S.Dk = undefined;
    try hexArr(ek.len, &ek, it.next().?);
    try hexArr(dk.len, &dk, it.next().?);
    const kp = K.KeyPair.generateDeterministic(seed);
    try testing.expectEqualSlices(u8, &ek, &kp.public_key.toBytes());
    try testing.expectEqualSlices(u8, &dk, &kp.secret_key.toBytes());
}

fn doEnc(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    var ek: S.Ek = undefined;
    var m: [32]u8 = undefined;
    var c: S.Ct = undefined;
    var k: [32]u8 = undefined;
    try hexArr(ek.len, &ek, it.next().?);
    try hexArr(32, &m, it.next().?);
    try hexArr(c.len, &c, it.next().?);
    try hexArr(32, &k, it.next().?);
    const pk = try K.PublicKey.fromBytes(&ek);
    const e = pk.encapsDeterministic(&m);
    try testing.expectEqualSlices(u8, &c, &e.ciphertext);
    try testing.expectEqualSlices(u8, &k, &e.shared_secret);
}

fn doDec(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    var dk: S.Dk = undefined;
    var c: S.Ct = undefined;
    var k: [32]u8 = undefined;
    try hexArr(dk.len, &dk, it.next().?);
    try hexArr(c.len, &c, it.next().?);
    try hexArr(32, &k, it.next().?);
    const sk = try K.SecretKey.fromBytes(&dk);
    try testing.expectEqualSlices(u8, &k, &sk.decaps(&c));
}

fn doFull(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    var seed: [64]u8 = undefined;
    var m: [32]u8 = undefined;
    var ek: S.Ek = undefined;
    var dk: S.Dk = undefined;
    var c: S.Ct = undefined;
    var k: [32]u8 = undefined;
    try hexArr(32, seed[0..32], it.next().?);
    try hexArr(32, seed[32..64], it.next().?);
    try hexArr(32, &m, it.next().?);
    try hexArr(ek.len, &ek, it.next().?);
    try hexArr(dk.len, &dk, it.next().?);
    try hexArr(c.len, &c, it.next().?);
    try hexArr(32, &k, it.next().?);
    const kp = K.KeyPair.generateDeterministic(seed);
    try testing.expectEqualSlices(u8, &ek, &kp.public_key.toBytes());
    try testing.expectEqualSlices(u8, &dk, &kp.secret_key.toBytes());
    const e = kp.public_key.encapsDeterministic(&m);
    try testing.expectEqualSlices(u8, &c, &e.ciphertext);
    try testing.expectEqualSlices(u8, &k, &e.shared_secret);
    try testing.expectEqualSlices(u8, &k, &kp.secret_key.decaps(&c));
}

fn doCt(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    var seed: [64]u8 = undefined;
    var ekh: [32]u8 = undefined;
    var c: S.Ct = undefined;
    var k: [32]u8 = undefined;
    try hexArr(64, &seed, it.next().?);
    try hexArr(32, &ekh, it.next().?);
    try hexArr(c.len, &c, it.next().?);
    try hexArr(32, &k, it.next().?);
    const kp = K.KeyPair.generateDeterministic(seed);
    var got: [32]u8 = undefined;
    sha3.Sha3_256.hash(&kp.public_key.toBytes(), &got, .{});
    try testing.expectEqualSlices(u8, &ekh, &got);
    try testing.expectEqualSlices(u8, &k, &kp.secret_key.decaps(&c));
}

fn doEkchk(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    const pass = std.mem.eql(u8, it.next().?, "1");
    var ek: S.Ek = undefined;
    try hexArr(ek.len, &ek, it.next().?);
    if (pass) {
        _ = try K.PublicKey.fromBytes(&ek);
    } else {
        try testing.expectError(error.NonCanonical, K.PublicKey.fromBytes(&ek));
    }
}

fn doDkchk(comptime K: type, it: *std.mem.TokenIterator(u8, .scalar)) !void {
    const S = ShapeOf(K);
    const pass = std.mem.eql(u8, it.next().?, "1");
    var dk: S.Dk = undefined;
    try hexArr(dk.len, &dk, it.next().?);
    if (pass) {
        _ = try K.SecretKey.fromBytes(&dk);
    } else if (K.SecretKey.fromBytes(&dk)) |_| {
        return error.AcceptedBadDecapsulationKey;
    } else |_| {}
}

/// Run every line of `data`. `P`-specific lines dispatch on the parameter set.
fn runFile(data: []const u8) !void {
    var lines = std.mem.splitScalar(u8, data, '\n');
    var lineno: usize = 0;
    var mod_base: [3][max_ek]u8 = undefined; // per set: 512, 768, 1024
    var count: usize = 0;
    while (lines.next()) |line| {
        lineno += 1;
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next().?;
        const pname = it.next().?;
        runLine(kind, pname, &it, &mod_base) catch |err| {
            std.debug.print("vector failure: line {d} ({s} {s}): {s}\n", .{ lineno, kind, pname, @errorName(err) });
            return err;
        };
        count += 1;
    }
    try testing.expect(count > 0);
}

fn runLine(kind: []const u8, pname: []const u8, it: *std.mem.TokenIterator(u8, .scalar), mod_base: *[3][max_ek]u8) !void {
    inline for (.{
        .{ "512", root.MLKem512, 0 },
        .{ "768", root.MLKem768, 1 },
        .{ "1024", root.MLKem1024, 2 },
    }) |e| {
        if (std.mem.eql(u8, pname, e[0])) {
            const K = e[1];
            if (std.mem.eql(u8, kind, "kg")) return doKg(K, it);
            if (std.mem.eql(u8, kind, "enc")) return doEnc(K, it);
            if (std.mem.eql(u8, kind, "dec")) return doDec(K, it);
            if (std.mem.eql(u8, kind, "full")) return doFull(K, it);
            if (std.mem.eql(u8, kind, "ct")) return doCt(K, it);
            if (std.mem.eql(u8, kind, "ekchk")) return doEkchk(K, it);
            if (std.mem.eql(u8, kind, "dkchk")) return doDkchk(K, it);
            const n = K.PublicKey.encoded_length;
            if (std.mem.eql(u8, kind, "modbase")) {
                try hexArr(n, mod_base[e[2]][0..n], it.next().?);
                try testing.expectError(error.NonCanonical, K.PublicKey.fromBytes(mod_base[e[2]][0..n]));
                return;
            }
            if (std.mem.eql(u8, kind, "mod")) {
                var ek: [n]u8 = mod_base[e[2]][0..n].*;
                var patches = std.mem.splitScalar(u8, it.next().?, ',');
                while (patches.next()) |pt| {
                    const colon = std.mem.indexOfScalar(u8, pt, ':').?;
                    const off = try std.fmt.parseInt(usize, pt[0..colon], 10);
                    var tmp: [8]u8 = undefined;
                    const bytes = try hex(&tmp, pt[colon + 1 ..]);
                    @memcpy(ek[off..][0..bytes.len], bytes);
                }
                try testing.expectError(error.NonCanonical, K.PublicKey.fromBytes(&ek));
                return;
            }
            return error.UnknownVectorKind;
        }
    }
    return error.UnknownParameterSet;
}

test "CCTV: modulus check (all 2592 bad encapsulation keys)" {
    try runFile(@embedFile("testdata/cctv.txt"));
}

test "NIST ACVP-Server: keyGen, encaps, decaps, ek/dk checks" {
    try runFile(@embedFile("testdata/acvp.txt"));
}

test "Wycheproof: seeds, rejection-heavy matrices, malleable ciphertexts, key checks" {
    try runFile(@embedFile("testdata/wycheproof.txt"));
}

// ---- accumulated stream (CCTV protocol) ------------------------------------

/// Digest of `n` iterations of the CCTV accumulated protocol over KEM `K`: per
/// iteration d, z, m and a random ciphertext come from a SHAKE128 stream; ek, dk,
/// ct, K (encaps) and K (decaps of the random ciphertext) go into a second SHAKE128.
fn accumulated(comptime K: type, n: usize) ![32]u8 {
    var rng = sha3.Shake128.init(.{});
    var acc = sha3.Shake128.init(.{});
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var seed: [64]u8 = undefined;
        var m: [32]u8 = undefined;
        var bad: [K.ciphertext_length]u8 = undefined;
        rng.squeeze(&seed); // d, then z
        rng.squeeze(&m);
        rng.squeeze(&bad);
        const kp = K.KeyPair.generateDeterministic(seed);
        const e = kp.public_key.encapsDeterministic(&m);
        const k_ok = kp.secret_key.decaps(&e.ciphertext);
        if (!std.mem.eql(u8, &k_ok, &e.shared_secret)) return error.RoundTripFailed;
        const k_bad = kp.secret_key.decaps(&bad);
        acc.update(&kp.public_key.toBytes());
        acc.update(&kp.secret_key.toBytes());
        acc.update(&e.ciphertext);
        acc.update(&e.shared_secret);
        acc.update(&k_bad);
    }
    var out: [32]u8 = undefined;
    acc.squeeze(&out);
    return out;
}

fn expectDigest(comptime K: type, n: usize, expected_hex: []const u8) !void {
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, expected_hex);
    const got = try accumulated(K, n);
    try testing.expectEqualSlices(u8, &want, &got);
}

// The digests published in C2SP/CCTV ML-KEM/README.md (10^4: 845913ea.., f7db260e..,
// 47ac888f..; 10^6: 578eeaa1.., 70090cc5.., 7ccc6d80..) were produced by pq-crystals
// against the FIPS 203 *draft* (KeyGen seeds with G(d), final FIPS 203 uses G(d || k)),
// so a final-spec implementation cannot reproduce them; likewise CCTV unlucky/strcmp.
// The accumulated stream is therefore anchored to std's independent ml_kem instead.

fn iterationsFromEnv(default: usize) usize {
    const env = std.process.Environ.getPosix(testing.environ, "MLKEM_ACCUM") orelse return default;
    return std.fmt.parseInt(usize, env, 10) catch default;
}

test "accumulated stream agrees with std ml_kem (100 iterations; 10 000 when optimized; MLKEM_ACCUM=N overrides)" {
    const n = iterationsFromEnv(if (builtin.mode == .debug) 100 else 10_000);
    const nist = std.crypto.kem.ml_kem;
    inline for (.{
        .{ root.MLKem512, nist.MLKem512 },
        .{ root.MLKem768, nist.MLKem768 },
        .{ root.MLKem1024, nist.MLKem1024 },
    }) |pair| {
        const a = try accumulated(pair[0], n);
        const b = try accumulatedStd(pair[1], n);
        try testing.expectEqualSlices(u8, &b, &a);
    }
}

fn accumulatedStd(comptime K: type, n: usize) ![32]u8 {
    var rng = sha3.Shake128.init(.{});
    var acc = sha3.Shake128.init(.{});
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var seed: [64]u8 = undefined;
        var m: [32]u8 = undefined;
        var bad: [K.ciphertext_length]u8 = undefined;
        rng.squeeze(&seed);
        rng.squeeze(&m);
        rng.squeeze(&bad);
        const kp = try K.KeyPair.generateDeterministic(seed);
        const e = kp.public_key.encapsDeterministic(&m);
        const k_bad = try kp.secret_key.decaps(&bad);
        acc.update(&kp.public_key.toBytes());
        acc.update(&kp.secret_key.toBytes());
        acc.update(&e.ciphertext);
        acc.update(&e.shared_secret);
        acc.update(&k_bad);
    }
    var out: [32]u8 = undefined;
    acc.squeeze(&out);
    return out;
}
