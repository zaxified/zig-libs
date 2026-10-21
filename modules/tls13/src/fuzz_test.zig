// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for tls13 (added 2026-10-20): `TLS13_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver). Harness name:
//! `tls13-certverify`: `certverify.verify` is the module's one entry point fed
//! peer bytes (the CertificateVerify signature). For each KAT key (ECDSA
//! P-256/P-384, Ed25519, RSA-PSS SHA-256) the genuine signature is accepted;
//! a damaged signature (random octets, and the DER length/INTEGER headers aimed
//! at), a flipped transcript-hash bit and the other side's context string are
//! refused with `InvalidSignature`; a key of the wrong family is `KeyMismatch`;
//! an arbitrary scheme code point with an arbitrary transcript-hash length and
//! signature bytes never panics and is accepted only when it is the genuine
//! triple. A share of runs signs a fresh transcript hash (ECDSA, Ed25519;
//! deterministic and with noise) and verifies it back.
//! `tls13-kex`: `kex.serverExchange` / `kex.sharedSecret` on peer shares. For
//! every group a genuine exchange agrees on both sides; a peer share of any
//! length, damaged genuine shares (random octets, the SEC1 prefix, the
//! hybrid's X25519 half zeroed) and arbitrary group code points end in a typed
//! error or an exchange, never a panic; a failure leaves no secret in `out`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ScriptSource = testkit.fuzz.ScriptSource;

const cv = @import("certverify.zig");
const kex = @import("kex.zig");
const kat = @import("certverify_kat_vectors.zig");
const Ecdsa = std.crypto.sign.ecdsa;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP521 = @import("p521").EcdsaP521Sha512;

/// Reach counters for one harness's labels (copied from `aeskw`'s fuzz_test).
/// `mark` also feeds the driver's `REACH` report; `reach` runs `seeds` seeds
/// in the ordinary test binary and fails with `error.HarnessDoesNotReach` if
/// a label never fired.
fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

const Mark = Marker(enum {
    genuine_p256,
    genuine_p384,
    genuine_ed25519,
    genuine_rsa,
    genuine_p521,
    genuine_mldsa,
    damaged_refused,
    damaged_header,
    damaged_resized,
    hash_flip_refused,
    side_refused,
    family_refused,
    wild_refused,
    wild_known_scheme,
    fresh_ecdsa,
    fresh_ed25519,
    fresh_mldsa,
});

/// ML-DSA-44's KAT key (`kat.mldsa44_server`) and its deterministic
/// signature, made once per process: the key is ~80 KiB and signing is the
/// slow part.
const MlDsa44 = std.crypto.sign.mldsa.MLDSA44;
var mldsa_kp: MlDsa44.KeyPair = undefined;
var mldsa_pk: [MlDsa44.PublicKey.encoded_length]u8 = undefined;
var mldsa_sig: [MlDsa44.Signature.encoded_length]u8 = undefined;
var mldsa_ready = false;

fn mldsaFixture() !void {
    if (mldsa_ready) return;
    mldsa_kp = try MlDsa44.KeyPair.generateDeterministic(kat.mldsa44_server.seed);
    mldsa_pk = mldsa_kp.public_key.toBytes();
    _ = try cv.sign(.mldsa44, .{ .mldsa44 = &mldsa_kp.secret_key }, .server, &kat.mldsa44_server.transcript_hash, null, &mldsa_sig);
    mldsa_ready = true;
}

/// One KAT key with its genuine (scheme, side, transcript hash, signature).
const Case = struct {
    scheme: cv.SignatureScheme,
    pk: cv.PublicKey,
    /// A public key of another family, for the `KeyMismatch` check.
    other: cv.PublicKey,
    side: cv.Side,
    th: []const u8,
    sig: []const u8,
    der: bool,
};

fn pickCase(which: u8) !Case {
    const ed_pk = try Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes);
    const p256_pk = try kat.ecdsa_p256_server.publicKey();
    return switch (which) {
        0 => .{ .scheme = .ecdsa_secp256r1_sha256, .pk = .{ .ecdsa_p256 = p256_pk }, .other = .{ .ed25519 = ed_pk }, .side = .server, .th = &kat.ecdsa_p256_server.transcript_hash, .sig = &kat.ecdsa_p256_server.signature_der, .der = true },
        1 => .{ .scheme = .ecdsa_secp384r1_sha384, .pk = .{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() }, .other = .{ .ecdsa_p256 = p256_pk }, .side = .server, .th = &kat.ecdsa_p384_server.transcript_hash, .sig = &kat.ecdsa_p384_server.signature_der, .der = true },
        2 => .{ .scheme = .ed25519, .pk = .{ .ed25519 = ed_pk }, .other = .{ .ecdsa_p256 = p256_pk }, .side = .client, .th = &kat.ed25519_client.transcript_hash, .sig = &kat.ed25519_client.signature, .der = false },
        3 => .{ .scheme = .rsa_pss_rsae_sha256, .pk = .{ .rsa = try kat.rsa_pss_sha256_server.publicKey() }, .other = .{ .ed25519 = ed_pk }, .side = .server, .th = &kat.rsa_pss_sha256_server.transcript_hash, .sig = &kat.rsa_pss_sha256_server.signature, .der = false },
        // P-521's DER has a long-form SEQUENCE length, so the header spots
        // aimed at below are off by one or two: still damage to refuse.
        4 => .{ .scheme = .ecdsa_secp521r1_sha512, .pk = .{ .ecdsa_p521 = try EcdsaP521.PublicKey.fromSec1(&kat.ecdsa_p521_server.public_key_uncompressed_sec1) }, .other = .{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() }, .side = .server, .th = &kat.ecdsa_p521_server.transcript_hash, .sig = &kat.ecdsa_p521_server.signature_der, .der = true },
        else => blk: {
            try mldsaFixture();
            break :blk .{ .scheme = .mldsa44, .pk = .{ .mldsa44 = &mldsa_pk }, .other = .{ .ed25519 = ed_pk }, .side = .server, .th = &kat.mldsa44_server.transcript_hash, .sig = &mldsa_sig, .der = false };
        },
    };
}

fn otherSide(side: cv.Side) cv.Side {
    return if (side == .server) .client else .server;
}

fn expectInvalid(r: cv.VerifyError!void) !void {
    if (r) |_| return error.ForgedSignatureAccepted else |e| {
        if (e != error.InvalidSignature) return error.WrongRefusalKind;
    }
}

const max_sig = cv.max_signature_len + 16; // room for growth by damage

fn fuzzVerify(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const which = src.valueRangeAtMost(u8, 0, 5);
    const c = try pickCase(which);

    try cv.verify(c.scheme, c.pk, c.side, c.th, c.sig);
    switch (which) {
        0 => Mark.mark(.genuine_p256),
        1 => Mark.mark(.genuine_p384),
        2 => Mark.mark(.genuine_ed25519),
        3 => Mark.mark(.genuine_rsa),
        4 => Mark.mark(.genuine_p521),
        else => Mark.mark(.genuine_mldsa),
    }

    // A damaged signature: accepted only if the damage left it identical.
    {
        var buf: [max_sig]u8 = undefined;
        var n = c.sig.len;
        @memcpy(buf[0..n], c.sig);
        for (0..src.valueRangeAtMost(u8, 1, 3)) |_| buf[src.index(n)] = src.value(u8);
        if (c.der and src.value(bool)) {
            // Aim at the structure: SEQUENCE length, r's INTEGER header and
            // length, s's INTEGER header and length.
            const r_len: usize = c.sig[3];
            const spots = [_]usize{ 1, 2, 3, 4 + r_len, 5 + r_len };
            const at = spots[src.index(spots.len)];
            buf[at] = switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => buf[at] +% 1,
                1 => buf[at] -% 1,
                else => src.value(u8),
            };
            Mark.mark(.damaged_header);
        }
        if (src.valueRangeAtMost(u8, 0, 3) == 0) {
            // Truncate or extend with arbitrary bytes.
            const new_n = src.valueRangeAtMost(u16, 0, @intCast(@min(max_sig, c.sig.len + 8)));
            if (new_n > n) src.bytes(buf[n..new_n]);
            n = new_n;
            Mark.mark(.damaged_resized);
        }
        if (cv.verify(c.scheme, c.pk, c.side, c.th, buf[0..n])) |_| {
            if (!std.mem.eql(u8, buf[0..n], c.sig)) return error.DamagedSignatureAccepted;
        } else |e| {
            if (e != error.InvalidSignature) return error.WrongRefusalKind;
            Mark.mark(.damaged_refused);
        }
    }

    // The genuine signature over another transcript hash or the other side.
    {
        var th: [64]u8 = undefined;
        @memcpy(th[0..c.th.len], c.th);
        th[src.index(c.th.len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
        try expectInvalid(cv.verify(c.scheme, c.pk, c.side, th[0..c.th.len], c.sig));
        Mark.mark(.hash_flip_refused);
        try expectInvalid(cv.verify(c.scheme, c.pk, otherSide(c.side), c.th, c.sig));
        Mark.mark(.side_refused);
    }

    // A key of another family.
    if (cv.verify(c.scheme, c.other, c.side, c.th, c.sig)) |_| return error.WrongFamilyAccepted else |e| {
        if (e != error.KeyMismatch) return error.WrongRefusalKind;
        Mark.mark(.family_refused);
    }

    // Arbitrary scheme code point, transcript-hash length and signature
    // bytes: an error or the genuine triple, never a panic.
    {
        const scheme: cv.SignatureScheme = if (src.value(bool))
            @fromBackingInt(src.value(u16))
        else blk: {
            const known = [_]cv.SignatureScheme{ .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384, .ecdsa_secp521r1_sha512, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ed25519, .mldsa44, .mldsa65, .mldsa87 };
            Mark.mark(.wild_known_scheme);
            break :blk known[src.index(known.len)];
        };
        var th: [80]u8 = undefined;
        const th_len = src.valueRangeAtMost(u16, 0, th.len);
        src.bytes(th[0..th_len]);
        var sig: [max_sig]u8 = undefined;
        const sig_len = src.valueRangeAtMost(u16, 0, 300);
        src.bytes(sig[0..sig_len]);
        if (cv.verify(scheme, c.pk, c.side, th[0..th_len], sig[0..sig_len])) |_| {
            return error.ArbitrarySignatureAccepted;
        } else |_| Mark.mark(.wild_refused);
    }

    // Fresh signatures over an arbitrary transcript hash (one run in four:
    // signing is the slow part). RSA is left out: its signer is ~1 ms and the
    // PSS round trip is pinned by the unit tests.
    if (src.valueRangeAtMost(u8, 0, 3) == 0) {
        var sig_buf: [cv.max_signature_len]u8 = undefined;
        var noise_prng = std.Random.DefaultPrng.init(src.value(u64));
        const random: ?std.Random = if (src.value(bool)) noise_prng.random() else null;
        switch (src.valueRangeAtMost(u8, 0, 4)) {
            3 => {
                var th: [64]u8 = undefined;
                src.bytes(&th);
                const sk = try EcdsaP521.SecretKey.fromBytes(kat.ecdsa_p521_server.secret_key_bytes);
                const sig = try cv.sign(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = &sk }, .server, &th, random, &sig_buf);
                try cv.verify(.ecdsa_secp521r1_sha512, .{ .ecdsa_p521 = try EcdsaP521.PublicKey.fromSec1(&kat.ecdsa_p521_server.public_key_uncompressed_sec1) }, .server, &th, sig);
                Mark.mark(.fresh_ecdsa);
            },
            4 => {
                // Pure ML-DSA signs the content itself: any hash length.
                try mldsaFixture();
                var th: [64]u8 = undefined;
                const th_len = src.valueRangeAtMost(u16, 0, th.len);
                src.bytes(th[0..th_len]);
                const sig = try cv.sign(.mldsa44, .{ .mldsa44 = &mldsa_kp.secret_key }, .client, th[0..th_len], random, &sig_buf);
                try cv.verify(.mldsa44, .{ .mldsa44 = &mldsa_pk }, .client, th[0..th_len], sig);
                try expectInvalid(cv.verify(.mldsa44, .{ .mldsa44 = &mldsa_pk }, .server, th[0..th_len], sig));
                Mark.mark(.fresh_mldsa);
            },
            0 => {
                var th: [32]u8 = undefined;
                src.bytes(&th);
                const sk = try kat.ecdsa_p256_server.secretKey();
                const sig = try cv.sign(.ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = &sk }, .server, &th, random, &sig_buf);
                try cv.verify(.ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = try kat.ecdsa_p256_server.publicKey() }, .server, &th, sig);
                Mark.mark(.fresh_ecdsa);
            },
            1 => {
                var th: [48]u8 = undefined;
                src.bytes(&th);
                const sk = try kat.ecdsa_p384_server.secretKey();
                const sig = try cv.sign(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = &sk }, .server, &th, random, &sig_buf);
                try cv.verify(.ecdsa_secp384r1_sha384, .{ .ecdsa_p384 = try kat.ecdsa_p384_server.publicKey() }, .server, &th, sig);
                Mark.mark(.fresh_ecdsa);
            },
            else => {
                // Ed25519 signs the content itself, so any hash length the
                // limit allows is fine.
                var th: [64]u8 = undefined;
                const th_len = src.valueRangeAtMost(u16, 0, th.len);
                src.bytes(th[0..th_len]);
                const sk = try Ed25519.SecretKey.fromBytes(kat.ed25519_client.secret_key_bytes);
                const sig = try cv.sign(.ed25519, .{ .ed25519 = &sk }, .client, th[0..th_len], random, &sig_buf);
                const pk = try Ed25519.PublicKey.fromBytes(kat.ed25519_client.public_key_bytes);
                try cv.verify(.ed25519, .{ .ed25519 = pk }, .client, th[0..th_len], sig);
                try expectInvalid(cv.verify(.ed25519, .{ .ed25519 = pk }, .server, th[0..th_len], sig));
                Mark.mark(.fresh_ed25519);
            },
        }
    }
}

const KexMark = Marker(enum {
    agree_x25519,
    agree_p256,
    agree_p384,
    agree_hybrid,
    agree_mlkem1024,
    server_refused,
    server_accepted_damaged,
    client_refused,
    client_accepted_damaged,
    zeroed_on_failure,
    unusable_refused,
    unknown_group,
});

fn allZero(b: []const u8) bool {
    for (b) |x| if (x != 0) return false;
    return true;
}

const Damaged = struct {
    n: usize,
    /// The damage makes the share unusable by construction (an all-zero
    /// X25519 point, a zeroed hybrid X25519 half, a SEC1 form octet other
    /// than 0x04): the exchange MUST refuse it.
    must_refuse: bool,
};

/// `share` with 1-3 random octets replaced, or one structural spot aimed at,
/// and sometimes truncated / extended.
/// `to_server`: `share` is a client-form share the server consumes (an
/// ML-KEM-1024 encapsulation key is checked; its ciphertext never is).
fn damageShare(comptime S: type, src: *S, group: u16, share: []const u8, to_server: bool, buf: []u8) Damaged {
    var d: Damaged = .{ .n = share.len, .must_refuse = false };
    @memcpy(buf[0..d.n], share);
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => if (group == kex.secp256r1_group or group == kex.secp384r1_group) {
            buf[0] = src.value(u8); // the SEC1 form octet
            d.must_refuse = buf[0] != 0x04;
        } else if (group == kex.x25519_mlkem768_group) {
            @memset(buf[d.n - 32 .. d.n], 0); // identity X25519 half
            d.must_refuse = true;
        } else if (group == kex.mlkem1024_group) {
            // First coefficient 0xFFF ≥ q: a non-canonical encapsulation
            // key (FIPS 203 §7.2); in a ciphertext, implicit rejection.
            buf[0] = 0xFF;
            buf[1] |= 0x0F;
            d.must_refuse = to_server;
        } else {
            @memset(buf[0..d.n], 0);
            d.must_refuse = true;
        },
        1 => buf[d.n - 1] ^= 0x80, // the curve point's last coordinate octet
        else => for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
            buf[src.index(d.n)] = src.value(u8);
        },
    }
    if (src.valueRangeAtMost(u8, 0, 5) == 0) {
        const new_n = src.valueRangeAtMost(u16, 0, @intCast(@min(buf.len, d.n + 4)));
        if (new_n > d.n) src.bytes(buf[d.n..new_n]);
        if (new_n != d.n) d.must_refuse = true; // every group's length is exact
        d.n = new_n;
    }
    return d;
}

fn fuzzKex(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var seed: [32]u8 = undefined;
    src.bytes(&seed);
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = csprng.random();
    const groups = [_]u16{ kex.x25519_group, kex.secp256r1_group, kex.secp384r1_group, kex.x25519_mlkem768_group, kex.mlkem1024_group };
    const group = groups[src.index(groups.len)];

    var kp: kex.KeyPair = undefined;
    try kex.generate(group, rnd, &kp);
    var ex: kex.ServerExchange = undefined;
    try kex.serverExchange(group, kp.public[0..kp.public_len], rnd, &ex);
    var ss: kex.SharedSecret = undefined;
    try kex.sharedSecret(group, &kp.secret, ex.public[0..ex.public_len], &ss);
    if (!std.mem.eql(u8, ss.slice(), ex.shared.slice())) return error.SidesDisagree;
    switch (group) {
        kex.x25519_group => KexMark.mark(.agree_x25519),
        kex.secp256r1_group => KexMark.mark(.agree_p256),
        kex.secp384r1_group => KexMark.mark(.agree_p384),
        kex.mlkem1024_group => KexMark.mark(.agree_mlkem1024),
        else => KexMark.mark(.agree_hybrid),
    }

    // The server on a damaged client share.
    var buf: [kex.max_share_len + 8]u8 = undefined;
    {
        const d = damageShare(S, src, group, kp.public[0..kp.public_len], true, &buf);
        var out: kex.ServerExchange = undefined;
        @memset(&out.shared.bytes, 0xAB);
        if (kex.serverExchange(group, buf[0..d.n], rnd, &out)) |_| {
            if (d.must_refuse) return error.UnusableShareAccepted;
            KexMark.mark(.server_accepted_damaged);
        } else |_| {
            if (!allZero(&out.shared.bytes)) return error.SecretLeftOnFailure;
            KexMark.mark(.server_refused);
            KexMark.mark(.zeroed_on_failure);
            if (d.must_refuse) KexMark.mark(.unusable_refused);
        }
    }
    // The client on a damaged server share.
    {
        const d = damageShare(S, src, group, ex.public[0..ex.public_len], false, &buf);
        var out: kex.SharedSecret = .{ .bytes = @splat(0xAB), .len = 0 };
        if (kex.sharedSecret(group, &kp.secret, buf[0..d.n], &out)) |_| {
            if (d.must_refuse) return error.UnusableShareAccepted;
            // A damaged hybrid ciphertext decapsulates (FIPS 203 implicit
            // rejection) — to a different secret unless untouched.
            if (std.mem.eql(u8, buf[0..d.n], ex.public[0..ex.public_len])) {
                if (!std.mem.eql(u8, out.slice(), ss.slice())) return error.SidesDisagree;
            }
            KexMark.mark(.client_accepted_damaged);
        } else |_| {
            if (!allZero(&out.bytes)) return error.SecretLeftOnFailure;
            KexMark.mark(.client_refused);
        }
    }
    // An arbitrary group code point with arbitrary share bytes.
    {
        const g = src.value(u16);
        const n = src.valueRangeAtMost(u16, 0, 100);
        src.bytes(buf[0..n]);
        var out: kex.ServerExchange = undefined;
        @memset(&out.shared.bytes, 0xAB);
        if (kex.serverExchange(g, buf[0..n], rnd, &out)) |_| {
            if (kex.expectedShareLen(g) == 0) return error.UnknownGroupAccepted;
        } else |_| {
            if (!allZero(&out.shared.bytes)) return error.SecretLeftOnFailure;
        }
        if (kex.expectedShareLen(g) == 0) KexMark.mark(.unknown_group);
    }
}

fn fuzzKexSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzKex(ScriptSource, &src, testing.allocator);
}

fn fuzzVerifySmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzVerify(ScriptSource, &src, testing.allocator);
}

test "fuzz: tls13 certverify, genuine accepted / damaged refused" {
    try testing.fuzz({}, fuzzVerifySmith, .{});
}
test "fuzz driver: TLS13_FUZZ (certverify)" {
    try fuzz_driver.run(fuzzVerify, .{ .prefix = "TLS13_FUZZ", .name = "tls13-certverify" });
}
test "fuzz harness: certverify, 200 seeds, reaches every outcome" {
    try Mark.reach(fuzzVerify, "tls13-certverify", 200);
}

test "fuzz: tls13 kex, genuine exchanges agree / damaged shares never panic" {
    try testing.fuzz({}, fuzzKexSmith, .{});
}
test "fuzz driver: TLS13_FUZZ (kex)" {
    try fuzz_driver.run(fuzzKex, .{ .prefix = "TLS13_FUZZ", .name = "tls13-kex" });
}
test "fuzz harness: kex, 200 seeds, reaches every outcome" {
    try KexMark.reach(fuzzKex, "tls13-kex", 200);
}
