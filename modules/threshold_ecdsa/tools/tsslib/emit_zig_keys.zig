// SPDX-License-Identifier: MIT

//! Prints 2-of-3 key material made by THIS module, in the interchange JSON
//! of `README.md`, for `go run . sign` (tss-lib) to sign with: direction B
//! of the oracle. Trusted-dealer Shamir split (`keygenTrustedDealer`); each
//! party's Paillier primes and ring-Pedersen tuple come from this module's
//! own safe-prime generator (`generateAuxParamsWithTrapdoor`, 2048 bits —
//! one call for the aux tuple, one whose safe primes become the Paillier
//! primes, as tss-lib also uses safe primes there). Seeded from getrandom(2),
//! so every run prints different keys; the committed `zig_keys.json` is one
//! run. See `README.md` for the command line.

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const paillier = @import("paillier");

fn hex(w: *std.Io.Writer, bytes: []const u8) !void {
    var i: usize = 0;
    while (i < bytes.len and bytes[i] == 0) : (i += 1) {}
    if (i == bytes.len) i = bytes.len - 1;
    for (bytes[i..]) |b| try w.print("{x:0>2}", .{b});
}

fn auxFeHex(w: *std.Io.Writer, fe: tecdsa.AuxFe) !void {
    var buf: [tecdsa.aux_modulus_bytes]u8 = undefined;
    try fe.toBytes(&buf, .big);
    try hex(w, &buf);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 = undefined;
    init.io.random(&seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    const random = csprng.random();

    const n = 3;
    var auxes: [n]tecdsa.AuxParamsWithTrapdoor = undefined;
    var pail_gen: [n]tecdsa.AuxParamsWithTrapdoor = undefined;
    var keys: [n]paillier.KeyPair = undefined;
    var aux_params: [n]tecdsa.AuxParams = undefined;
    for (0..n) |i| {
        auxes[i] = try tecdsa.generateAuxParamsWithTrapdoor(gpa, random, tecdsa.aux_modulus_bits);
        aux_params[i] = auxes[i].params;
        pail_gen[i] = try tecdsa.generateAuxParamsWithTrapdoor(gpa, random, paillier.modulus_bits);
        keys[i] = try paillier.fromPrimes(pail_gen[i].trapdoor.p, pail_gen[i].trapdoor.q);
        std.debug.print("party {d}: primes done\n", .{i + 1});
    }
    defer for (0..n) |i| {
        auxes[i].trapdoor.deinit(gpa);
        pail_gen[i].trapdoor.deinit(gpa);
    };

    const secret = tecdsa.Scalar.random(init.io);
    const coefficient = tecdsa.Scalar.random(init.io);
    var message_seeds: [n][32]u8 = undefined;
    for (&message_seeds) |*sd| sd.* = tecdsa.Scalar.random(init.io).toBytes(.big);
    const shares = try tecdsa.keygenTrustedDealer(gpa, 2, n, secret, &.{coefficient}, &keys, &aux_params, &message_seeds);
    defer gpa.free(shares);
    defer gpa.free(shares[0].public_keys.entries);

    var out_buf: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &out_buf);
    const w = &out.interface;
    try w.print("{{\n  \"t\": 2,\n  \"n\": {d},\n  \"public_key\": \"", .{n});
    try hex(w, &shares[0].group_public_key.toBytes());
    try w.writeAll("\",\n  \"parties\": [\n");
    for (shares, 0..) |s, i| {
        try w.print("    {{\n      \"index\": {d},\n      \"x\": \"", .{s.index});
        for (s.secret_share.toBytes(.big)) |b| try w.print("{x:0>2}", .{b});
        try w.writeAll("\",\n      \"big_x\": \"");
        try hex(w, &s.verifying_share.toBytes());
        try w.writeAll("\",\n      \"paillier_p\": \"");
        try hex(w, pail_gen[i].trapdoor.p);
        try w.writeAll("\",\n      \"paillier_q\": \"");
        try hex(w, pail_gen[i].trapdoor.q);
        try w.writeAll("\",\n      \"n_tilde\": \"");
        var nt: [tecdsa.aux_modulus_bytes]u8 = undefined;
        try aux_params[i].n_tilde.toBytes(&nt, .big);
        try hex(w, &nt);
        try w.writeAll("\",\n      \"h1\": \"");
        try auxFeHex(w, aux_params[i].h1);
        try w.writeAll("\",\n      \"h2\": \"");
        try auxFeHex(w, aux_params[i].h2);
        try w.writeAll("\",\n      \"aux_p_safe\": \"");
        try hex(w, auxes[i].trapdoor.p);
        try w.writeAll("\",\n      \"aux_q_safe\": \"");
        try hex(w, auxes[i].trapdoor.q);
        try w.writeAll("\",\n      \"aux_lambda\": \"");
        // tss-lib's Alpha (h2 = h1^Alpha) is the inverse of this module's
        // trapdoor (h1 = h2^lambda, since 2026-10-03).
        const td = auxes[i].trapdoor;
        try auxFeHex(w, try tecdsa.auxLogInverse(aux_params[i].n_tilde, td.p, td.q, td.lambda));
        try w.print("\"\n    }}{s}\n", .{if (i + 1 < n) "," else ""});
    }
    try w.writeAll("  ]\n}\n");
    try w.flush();
}
