// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh jwe`, which builds the
//! harness and prints the control table.
//!
//! Not wired into `zig build test-jwe`: memcheck's context count is valgrind's
//! own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! Every secret `decryptCompact` holds, one target per key kind. A token is
//! built first with an UNTAINTED copy of the key (so the encoder's base64 of
//! a ciphertext never sees a tainted byte), then the key the decryptor gets is
//! a tainted copy and the public API is driven: an accept (the plaintext comes
//! back; it is secret-derived, so a tainted copy of it is formatted through the
//! non-constant-time printer as the propagation witness, then declassified) and
//! a reject (one token octet flipped: the Encrypted Key for the wrapping algs,
//! the tag for `dir`).
//!
//!  * `content` — `dir` with A128/A192/A256GCM and A128/A192/A256CBC-HS*: the
//!    CEK is the tainted key; the tag check (`timing_safe.eql` / the GCM
//!    verdict) is the one branch the module takes on a tainted value, public
//!    by design (a caller learns accept / reject).
//!  * `kw` — A128KW, A256KW, A128GCMKW, A256GCMKW: the tainted KEK unwraps the
//!    Encrypted Key; the unwrap integrity verdict picks the decoy CEK
//!    (RFC 7516 §11.5), which is the designed, public branch.
//!  * `ecdh` — ECDH-ES and ECDH-ES+A256KW on P-256 and X25519: the tainted
//!    static private key drives `deriveZ`, the Concat KDF and the unwrap.
//!  * `pbes2` — PBES2-HS256+A128KW with a tainted password.
//!  * `rsa` — RSA-OAEP and RSA-OAEP-256: the secret members of
//!    `rsa.SecretKey` (d, p, q, dp, dq, qinv, the value fields of
//!    p_mont/q_mont); NOT n, e, n_mont or the slot L.
//!
//! The encrypt side draws its secrets (CEK, ephemeral scalar, IVs) from the
//! entropy the caller passes; they are not module-held inputs and the
//! ciphertext that comes out is public, so only the decrypt side is measured.
//! The curve, RSA, AES and KDF arithmetic are `p256`'s, `rsa`'s, `aesgcm`'s,
//! `aeskw`'s and std's and are claimed in their own rows; the contexts they
//! raise on the tainted key are expected here too and are itemised in
//! `ctgrind-expected.tsv`.

const std = @import("std");
const builtin = @import("builtin");
const jwe = @import("root.zig");
const rsa = @import("rsa");

const memcheck = std.valgrind.memcheck;
const gpa = std.heap.page_allocator;

const Target = enum { content, kw, ecdh, pbes2, rsa };
const Taint = enum { yes, no };

const plaintext = "ctgrind jwe plaintext 24";

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

var csprng_state: std.Random.DefaultCsprng = undefined;

fn entropy(seed: u8) jwe.Entropy {
    csprng_state = std.Random.DefaultCsprng.init(@as([32]u8, @splat(seed)));
    return .{ .fixed_for_test = csprng_state.random() };
}

/// Format a (possibly tainted) copy of `pt` through the non-constant-time
/// printer — the propagation witness — then declassify the original.
fn publish(label: []const u8, pt: []u8) void {
    var copy: [64]u8 = undefined;
    @memcpy(copy[0..pt.len], pt);
    std.debug.print("ctgrind_result {s}={x}\n", .{ label, copy[0..pt.len] });
    memcheck.makeMemDefined(pt);
}

/// `token` with the first octet of dot-separated segment `seg` replaced by a
/// different base64url character (the segment stays well formed).
fn flipped(token: []const u8, seg: usize) ![]u8 {
    const t = try gpa.dupe(u8, token);
    var at: usize = 0;
    for (0..seg) |_| at = std.mem.indexOfScalarPos(u8, t, at, '.').? + 1;
    t[at] = if (t[at] == 'A') 'B' else 'A';
    return t;
}

/// One token, one decrypt with `dec_key`: accept, then reject by flipping
/// segment `flip_seg` (1 = Encrypted Key, 4 = tag).
fn drive(
    label: []const u8,
    key_alg: jwe.Alg,
    content_enc: jwe.Enc,
    enc_key: jwe.KeyMaterial,
    dec_key: jwe.KeyMaterial,
    flip_seg: usize,
    opts: jwe.EncryptOptions,
    seed: u8,
) !void {
    const token = try jwe.encryptCompact(gpa, key_alg, content_enc, enc_key, plaintext, "", entropy(seed), opts);
    defer gpa.free(token);
    const pt_raw = try jwe.decryptCompact(gpa, dec_key, token, .{});
    // The plaintext LENGTH is public once the tag verified (a CBC unpad length
    // is the sender's choice); memcheck cannot know, so declassify it here and
    // let the harness's own copy / free / print run on a defined length. The
    // module's own length-dependent branches stay in the count.
    var n = pt_raw.len;
    memcheck.makeMemDefined(std.mem.asBytes(&n));
    const pt = pt_raw.ptr[0..n];
    defer gpa.free(pt);
    publish(label, pt);
    const bad = try flipped(token, flip_seg);
    defer gpa.free(bad);
    const ok = if (jwe.decryptCompact(gpa, dec_key, bad, .{})) |p| blk: {
        gpa.free(p);
        break :blk true;
    } else |_| false;
    std.debug.print("ctgrind_result {s} reject accepted={}\n", .{ label, ok });
}

fn symmetric(t: Taint, comptime len: usize, comptime fill: u8, secret: *[len]u8) void {
    for (secret, 0..) |*b, i| b.* = @truncate(i *% 7 +% fill);
    taint(t, secret);
}

fn contentOne(t: Taint, comptime content_enc: jwe.Enc, comptime seed: u8) !void {
    const len = comptime content_enc.cekLen().?;
    var enc_secret: [len]u8 = undefined;
    var dec_secret: [len]u8 = undefined;
    symmetric(.no, len, seed, &enc_secret);
    symmetric(t, len, seed, &dec_secret);
    try drive(@tagName(content_enc), .dir, content_enc, .{ .symmetric = &enc_secret }, .{ .symmetric = &dec_secret }, 4, .{}, seed);
}

fn kwOne(t: Taint, comptime key_alg: jwe.Alg, comptime len: usize, comptime seed: u8) !void {
    var enc_secret: [len]u8 = undefined;
    var dec_secret: [len]u8 = undefined;
    symmetric(.no, len, seed, &enc_secret);
    symmetric(t, len, seed, &dec_secret);
    try drive(@tagName(key_alg), key_alg, .A128GCM, .{ .symmetric = &enc_secret }, .{ .symmetric = &dec_secret }, 1, .{}, seed);
}

fn ecdhOne(t: Taint, comptime curve: jwe.ecdhes.Curve, comptime key_alg: jwe.Alg, comptime content_enc: jwe.Enc, comptime seed: u8) !void {
    var kp: jwe.ecdhes.EphemeralKeyPair = undefined;
    jwe.ecdhes.generateEphemeral(&kp, curve, entropy(seed +% 100));
    var dec_priv = kp.private;
    switch (dec_priv) {
        inline else => |*bytes| taint(t, bytes),
    }
    const label = comptime @tagName(curve) ++ " " ++ @tagName(key_alg);
    // Direct agreement has no Encrypted Key; its reject flips the tag.
    const seg: usize = if (key_alg == .@"ECDH-ES") 4 else 1;
    try drive(label, key_alg, content_enc, .{ .ec_public = kp.public }, .{ .ec_private = &dec_priv }, seg, .{}, seed);
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
        .content => {
            try contentOne(t, .A128GCM, 1);
            try contentOne(t, .A192GCM, 2);
            try contentOne(t, .A256GCM, 3);
            try contentOne(t, .@"A128CBC-HS256", 4);
            try contentOne(t, .@"A192CBC-HS384", 5);
            try contentOne(t, .@"A256CBC-HS512", 6);
        },
        .kw => {
            try kwOne(t, .A128KW, 16, 11);
            try kwOne(t, .A256KW, 32, 12);
            try kwOne(t, .A128GCMKW, 16, 13);
            try kwOne(t, .A256GCMKW, 32, 14);
        },
        .ecdh => {
            try ecdhOne(t, .p256, .@"ECDH-ES", .A128GCM, 21);
            try ecdhOne(t, .p256, .@"ECDH-ES+A256KW", .A256GCM, 22);
            try ecdhOne(t, .x25519, .@"ECDH-ES", .A128GCM, 23);
            try ecdhOne(t, .x25519, .@"ECDH-ES+A256KW", .A256GCM, 24);
        },
        .pbes2 => {
            var enc_pw: [16]u8 = undefined;
            var dec_pw: [16]u8 = undefined;
            symmetric(.no, 16, 31, &enc_pw);
            symmetric(t, 16, 31, &dec_pw);
            try drive("PBES2-HS256+A128KW", .@"PBES2-HS256+A128KW", .A128GCM, .{ .password = &enc_pw }, .{ .password = &dec_pw }, 1, .{ .pbes2_iterations = 1000 }, 31);
        },
        .rsa => {
            var sk: rsa.SecretKey = undefined;
            try rsa.SecretKey.fromPrimes(&sk, &kat_p, &kat_q, &kat_e);
            defer sk.deinit();
            const pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);
            taint(t, std.mem.asBytes(&sk.d));
            taint(t, std.mem.asBytes(&sk.p));
            taint(t, std.mem.asBytes(&sk.q));
            taint(t, std.mem.asBytes(&sk.dp));
            taint(t, std.mem.asBytes(&sk.dq));
            taint(t, std.mem.asBytes(&sk.qinv));
            taintMont(t, &sk.p_mont);
            taintMont(t, &sk.q_mont);
            try drive("RSA-OAEP", .@"RSA-OAEP", .A128GCM, .{ .rsa_public = pk }, .{ .rsa_private = &sk }, 1, .{}, 41);
            try drive("RSA-OAEP-256", .@"RSA-OAEP-256", .A256GCM, .{ .rsa_public = pk }, .{ .rsa_private = &sk }, 1, .{}, 42);
        },
    }
}
