// SPDX-License-Identifier: MIT

//! Shared plumbing for hpke's deterministic fuzz driver (added 2026-10-09),
//! and the whole-suite harness (`hpke-seal-open`).
//!
//! The DHKEM harness BODIES stay in `dhkem.zig` beside their corpora; each is
//! generic over its source of choices, `fn(comptime S, *S, gpa)`, and
//! `testing.fuzz` hands it a `std.testing.Smith` directly (corpus seeds replay
//! exactly as before: the `Smith` path of every draw is unchanged). This file
//! holds what they share with the driver -- the reach counters with the N-seed
//! in-suite check -- and the seal/open round-trip oracle.
//!
//! Driver: `HPKE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there). Harness names: `hpke-p256-decap`, `hpke-p256-auth-decap`,
//! `hpke-p384-decap`, `hpke-p384-auth-decap`, `hpke-seal-open`, and for the
//! post-quantum surface `hpke-pq-kem`, `hpke-pq-kdf` (bottom of this file).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const aesgcm = @import("aesgcm");
pub const fuzz_driver = testkit.fuzz.driver;

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone almost never get
/// past the first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
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

const root = @import("root.zig");

const SealMark = Marker(enum { x25519, p256, p384, genuine_opened, tamper_refused });

test "fuzz driver: HPKE_FUZZ (seal + open)" {
    try fuzz_driver.run(sealOpenHarness, .{ .prefix = "HPKE_FUZZ", .name = "hpke-seal-open", .scale = 16 });
}

test "fuzz harness: seal + open, 60 seeds, reaches every outcome" {
    try SealMark.reach(sealOpenHarness, "hpke-seal-open", 60);
}

/// Single-shot HPKE end to end, KEM and AEAD knob-chosen: what the sender
/// sealed the receiver opens (base mode, then auth mode), and every damaged
/// copy is REFUSED -- a flipped ciphertext or tag octet, a flipped `enc`, a
/// different `aad`, a different `info`, a wrong receiver key.
fn sealOpenHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var ikm: [96]u8 = undefined;
    src.bytes(&ikm);
    var pt_buf: [48]u8 = undefined;
    const pt_len = src.valueRangeAtMost(u8, 0, pt_buf.len);
    src.bytes(&pt_buf);
    const pt = pt_buf[0..pt_len];
    var aad_buf: [8]u8 = undefined;
    src.bytes(&aad_buf);
    const aad = aad_buf[0..src.valueRangeAtMost(u8, 0, aad_buf.len)];
    const info = ikm[64..][0..src.valueRangeAtMost(u8, 0, 16)];
    switch (src.valueRangeAtMost(u8, 0, 2)) {
        0 => {
            SealMark.mark(.x25519);
            try sealOpenOne(root.X25519Kem, aesgcm.Aes128Gcm, 32, &ikm, info, aad, pt, src.value(bool));
        },
        1 => {
            SealMark.mark(.p256);
            try sealOpenOne(root.P256Kem, root.ChaCha20Poly1305, 32, &ikm, info, aad, pt, src.value(bool));
        },
        else => {
            SealMark.mark(.p384);
            try sealOpenOne(root.P384Kem, aesgcm.Aes256Gcm, 48, &ikm, info, aad, pt, src.value(bool));
        },
    }
}

fn sealOpenOne(
    comptime Kem: type,
    comptime Aead: type,
    comptime Nh: usize,
    ikm: *const [96]u8,
    info: []const u8,
    aad: []const u8,
    pt: []const u8,
    auth: bool,
) !void {
    var skR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skR, ikm[0..32]);
    var skS: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skS, ikm[32..64]);
    var eph: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&eph, ikm[16..48]);

    var ct_buf: [48 + 16]u8 = undefined;
    const ct = ct_buf[0 .. pt.len + Aead.tag_length];
    const schedule = root.schedule;
    var enc: Kem.EncappedKey = undefined;
    if (auth) {
        const sealed = try schedule.sealAuthDeterministic(Kem, Aead, Nh, skR.public_key, &skS, &eph, info, aad, pt, ct);
        enc = sealed.enc;
    } else {
        const sealed = try schedule.sealBaseDeterministic(Kem, Aead, Nh, skR.public_key, &eph, info, aad, pt, ct);
        enc = sealed.enc;
    }

    var out_buf: [48]u8 = undefined;
    const out = out_buf[0..pt.len];
    const Opener = struct {
        fn open(e: Kem.EncappedKey, sk: *const Kem.KeyPair, pkS: Kem.PublicKey, is_auth: bool, i: []const u8, a: []const u8, c: []const u8, o: []u8) !void {
            if (is_auth) {
                try schedule.openAuth(Kem, Aead, Nh, e, sk, pkS, i, a, c, o);
            } else {
                try schedule.openBase(Kem, Aead, Nh, e, sk, i, a, c, o);
            }
        }
    };
    Opener.open(enc, &skR, skS.public_key, auth, info, aad, ct, out) catch return error.GenuineMessageRefused;
    if (!std.mem.eql(u8, out, pt)) return error.OpenedWrongPlaintext;
    SealMark.mark(.genuine_opened);

    // Every damaged copy must be refused. The ciphertext octet is the last
    // one drawn from the key material (a stable, seed-derived position).
    var bad = ct_buf;
    bad[ikm[90] % ct.len] ^= @as(u8, 1) << @as(u3, @intCast(ikm[91] % 8));
    if (Opener.open(enc, &skR, skS.public_key, auth, info, aad, bad[0..ct.len], out)) |_| return error.FlippedCiphertextAccepted else |_| {}

    var bad_enc = enc;
    bad_enc[ikm[92] % bad_enc.len] ^= @as(u8, 1) << @as(u3, @intCast(ikm[93] % 8));
    if (Opener.open(bad_enc, &skR, skS.public_key, auth, info, aad, ct, out)) |_| return error.FlippedEncAccepted else |_| {}

    var bad_aad: [9]u8 = undefined;
    @memcpy(bad_aad[0..aad.len], aad);
    bad_aad[aad.len] = 0x5a; // one octet longer
    if (Opener.open(enc, &skR, skS.public_key, auth, info, bad_aad[0 .. aad.len + 1], ct, out)) |_| return error.WrongAadAccepted else |_| {}

    var bad_info: [17]u8 = undefined;
    @memcpy(bad_info[0..info.len], info);
    bad_info[info.len] = 0xa5;
    if (Opener.open(enc, &skR, skS.public_key, auth, bad_info[0 .. info.len + 1], aad, ct, out)) |_| return error.WrongInfoAccepted else |_| {}

    if (Opener.open(enc, &eph, skS.public_key, auth, info, aad, ct, out)) |_| return error.WrongReceiverKeyAccepted else |_| {}
    if (auth) {
        if (Opener.open(enc, &skR, eph.public_key, auth, info, aad, ct, out)) |_| return error.WrongSenderKeyAccepted else |_| {}
    }
    if (Opener.open(enc, &skR, skS.public_key, auth, info, aad, ct[0 .. ct.len - 1], out)) |_| return error.TruncatedCiphertextAccepted else |_| {}
    SealMark.mark(.tamper_refused);
}

// ── draft-ietf-hpke-pq: the post-quantum / hybrid KEMs (`pq.zig`) ───────────
//
// Per run one of the six pq KEMs (ML-KEM-512/768/1024, MLKEM768-P256,
// MLKEM1024-P384, X-Wing) with a key pair derived from drawn octets:
//   * a genuine setupBaseS/setupBaseR pair agrees and the receiver opens what
//     the sender sealed;
//   * every damage of `enc` -- random octets (all of it, or the curve half
//     only), a flipped bit in the ML-KEM part, in the curve part, an all-zero
//     curve half, a SEC1 form byte (NIST curves), the masked top bit of the
//     X25519 u-coordinate (X-Wing) -- is either a refused `enc`
//     (DeserializeError / DhFailed) or a context that FAILS to open the genuine
//     ciphertext (FIPS 203 implicit rejection; the combiner binds ct_T);
//   * every damaged public key -- a non-canonical ML-KEM coefficient (>= q), an
//     off-curve / all-zero / random NIST point, a zero or low-order X25519 point
//     -- is refused by `encapDeterministic`, never accepted and never a panic.

const PqMark = Marker(enum {
    pq_genuine_agrees,
    pq_enc_refused,
    pq_enc_rejected_implicitly,
    pq_dmg_random,
    pq_dmg_pq_bit,
    pq_dmg_curve_bit,
    pq_dmg_zero_curve,
    pq_dmg_form_byte,
    pq_dmg_x25519_msb,
    pq_pk_coeff_refused,
    pq_pk_point_refused,
    pq_pk_lowshape_refused,
});

const KemShape = enum { pure, nist, xwing };

test "fuzz driver: HPKE_FUZZ (pq KEMs)" {
    try fuzz_driver.run(pqKemHarness, .{ .prefix = "HPKE_FUZZ", .name = "hpke-pq-kem", .scale = 16 });
}

test "fuzz harness: pq KEMs, 24 seeds, reaches every outcome" {
    try PqMark.reach(pqKemHarness, "hpke-pq-kem", 24);
}

fn pqKemHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    switch (src.valueRangeAtMost(u8, 0, 5)) {
        0 => try pqKemOne(S, src, root.MlKem512Kem, .pure, root.MlKem512Kem.Nenc),
        1 => try pqKemOne(S, src, root.MlKem768Kem, .pure, root.MlKem768Kem.Nenc),
        2 => try pqKemOne(S, src, root.MlKem1024Kem, .pure, root.MlKem1024Kem.Nenc),
        3 => try pqKemOne(S, src, root.MlKem768P256Kem, .nist, 1088),
        4 => try pqKemOne(S, src, root.MlKem1024P384Kem, .nist, 1568),
        else => try pqKemOne(S, src, root.MlKem768X25519Kem, .xwing, 1088),
    }
}

fn pqKemOne(comptime S: type, src: *S, comptime Kem: type, comptime shape: KemShape, comptime ct_len: usize) !void {
    const Aead = root.ChaCha20Poly1305;
    const Kdf = root.kdf.HkdfSha256;
    const schedule = root.schedule;
    const info = "hpke pq fuzz info";
    const aad = "pq fuzz aad";
    const message = "pq fuzz plaintext";
    const has_curve = shape != .pure;
    // The curve half of `enc` and of the public key (a point / a u-coordinate).
    const curve_len = comptime switch (shape) {
        .pure => 0,
        .nist => Kem.Nenc - ct_len,
        .xwing => 32,
    };

    var ikm: [32]u8 = undefined;
    src.bytes(&ikm);
    var skR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skR, &ikm);
    var eph: Kem.Ephemeral = undefined;
    src.bytes(&eph);

    // The genuine pair.
    var s: schedule.Setup(Kem, Aead, Kdf) = undefined;
    schedule.setupBaseSDeterministic(Kem, Aead, Kdf, &s, skR.public_key, &eph, info) catch return error.GenuineEncapRefused;
    var r: schedule.Context(Aead, Kdf) = undefined;
    schedule.setupBaseR(Kem, Aead, Kdf, &r, s.enc, &skR, info) catch return error.GenuineDecapRefused;
    if (!std.mem.eql(u8, &s.context.key, &r.key) or
        !std.mem.eql(u8, &s.context.base_nonce, &r.base_nonce) or
        !std.mem.eql(u8, &s.context.exporter_secret, &r.exporter_secret)) return error.GenuinePairDisagrees;
    var ct: [message.len + Aead.tag_length]u8 = undefined;
    try s.context.seal(aad, message, &ct);
    var back: [message.len]u8 = undefined;
    r.open(aad, &ct, &back) catch return error.GenuineMessageRefused;
    if (!std.mem.eql(u8, &back, message)) return error.OpenedWrongPlaintext;
    PqMark.mark(.pq_genuine_agrees);

    // Damaged `enc`.
    inline for (0..5) |kind| {
        if (comptime (kind >= 2 and !has_curve)) continue;
        var bad = s.enc;
        const bit: u8 = @as(u8, 1) << @as(u3, @intCast(src.index(8)));
        switch (kind) {
            0 => {
                if (has_curve and src.value(bool)) src.bytes(bad[ct_len..]) else src.bytes(&bad);
                PqMark.mark(.pq_dmg_random);
            },
            1 => {
                bad[src.index(ct_len)] ^= bit;
                PqMark.mark(.pq_dmg_pq_bit);
            },
            2 => {
                bad[ct_len + src.index(curve_len)] ^= bit;
                PqMark.mark(.pq_dmg_curve_bit);
            },
            3 => {
                @memset(bad[ct_len..], 0);
                PqMark.mark(.pq_dmg_zero_curve);
            },
            else => switch (shape) {
                .nist => {
                    // The SEC1 form byte: anything but 0x04 (uncompressed).
                    bad[ct_len] = src.value(u8);
                    if (bad[ct_len] == 0x04) bad[ct_len] = 0x05;
                    PqMark.mark(.pq_dmg_form_byte);
                },
                .xwing => {
                    // RFC 7748 masks this bit of u, so the DH output is the
                    // same; only a combiner that binds ct_T notices.
                    bad[bad.len - 1] ^= 0x80;
                    PqMark.mark(.pq_dmg_x25519_msb);
                },
                .pure => unreachable,
            },
        }
        if (!std.mem.eql(u8, &bad, &s.enc)) {
            var r2: schedule.Context(Aead, Kdf) = undefined;
            if (schedule.setupBaseR(Kem, Aead, Kdf, &r2, bad, &skR, info)) |_| {
                var out: [message.len]u8 = undefined;
                if (r2.open(aad, &ct, &out)) |_| return error.DamagedEncOpensGenuineCiphertext else |_| {}
                if (std.mem.eql(u8, &r2.key, &r.key)) return error.DamagedEncSameKey;
                PqMark.mark(.pq_enc_rejected_implicitly);
            } else |e| switch (e) {
                error.DeserializeError, error.DhFailed => PqMark.mark(.pq_enc_refused),
                else => return error.UnexpectedDecapError,
            }
        }
    }

    // Damaged public key.
    inline for (0..2) |kind| {
        if (comptime (kind == 1 and !has_curve)) continue;
        var bad_pk = skR.public_key;
        switch (kind) {
            0 => {
                // A coefficient of the ML-KEM t-vector set to a value >= q
                // (3329): ByteEncode12 packs two per three octets, the first in
                // b0 and the low nibble of b1.
                const pairs = (Kem.Npk - curve_len - 32) / 3;
                const i = src.index(pairs);
                const v: u16 = 3329 + src.valueRangeAtMost(u16, 0, 4095 - 3329);
                bad_pk[3 * i] = @truncate(v);
                bad_pk[3 * i + 1] = (bad_pk[3 * i + 1] & 0xf0) | @as(u8, @intCast(v >> 8));
            },
            else => {
                const half = bad_pk[Kem.Npk - curve_len ..];
                switch (shape) {
                    .nist => switch (src.valueRangeAtMost(u8, 0, 2)) {
                        // A flipped bit in y: off the curve.
                        0 => half[1 + (curve_len - 1) / 2 + src.index((curve_len - 1) / 2)] ^= @as(u8, 1) << @as(u3, @intCast(src.index(8))),
                        1 => @memset(half, 0),
                        else => src.bytes(half),
                    },
                    .xwing => if (src.value(bool)) @memset(half, 0) else {
                        // u = 1: a point of small order.
                        @memset(half, 0);
                        half[0] = 1;
                    },
                    .pure => unreachable,
                }
            },
        }
        var out: Kem.Encapped = undefined;
        if (Kem.encapDeterministic(&out, bad_pk, &eph)) |_| {
            return error.DamagedPublicKeyAccepted;
        } else |e| switch (e) {
            error.DeserializeError, error.DhFailed => switch (kind) {
                0 => PqMark.mark(.pq_pk_coeff_refused),
                else => if (shape == .nist) PqMark.mark(.pq_pk_point_refused) else PqMark.mark(.pq_pk_lowshape_refused),
            },
        }
    }
}

// ── draft-ietf-hpke-pq: the one-stage KDFs (SHAKE / TurboSHAKE) ─────────────
//
// Per run one of the four one-stage KDFs, over ChaCha20-Poly1305 or the
// export-only AEAD, X25519 as the KEM (the KEM half is the harness above). psk,
// psk_id and info are drawn with lengths around the one-stage limit (65,535:
// they are length-prefixed in two octets), exports with L around it:
//   * any field above 65,535 (setup) / L above 65,535 (export) is LabelTooLong
//     on both sides, never a panic or a silent truncation;
//   * otherwise sender and receiver agree and the context equals an
//     independent restatement of `CombineSecrets_OneStage` / `Export`
//     (draft-ietf-hpke-hpke §5.1/§5.3) driven straight through the XOF.

const KdfMark = Marker(enum {
    kdf_shake128,
    kdf_shake256,
    kdf_turboshake128,
    kdf_turboshake256,
    kdf_aead_export_only,
    kdf_ok_matches_model,
    kdf_label_too_long,
    kdf_export_ok_matches_model,
    kdf_export_too_long,
});

test "fuzz driver: HPKE_FUZZ (one-stage KDFs)" {
    try fuzz_driver.run(kdfHarness, .{ .prefix = "HPKE_FUZZ", .name = "hpke-pq-kdf", .scale = 16 });
}

test "fuzz harness: one-stage KDFs, 60 seeds, reaches every outcome" {
    try KdfMark.reach(kdfHarness, "hpke-pq-kdf", 60);
}

fn kdfHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => {
            KdfMark.mark(.kdf_shake128);
            try kdfOne(S, src, gpa, root.kdf.Shake128);
        },
        1 => {
            KdfMark.mark(.kdf_shake256);
            try kdfOne(S, src, gpa, root.kdf.Shake256);
        },
        2 => {
            KdfMark.mark(.kdf_turboshake128);
            try kdfOne(S, src, gpa, root.kdf.TurboShake128);
        },
        else => {
            KdfMark.mark(.kdf_turboshake256);
            try kdfOne(S, src, gpa, root.kdf.TurboShake256);
        },
    }
}

fn kdfOne(comptime S: type, src: *S, gpa: std.mem.Allocator, comptime Kdf: type) !void {
    if (src.value(bool)) {
        KdfMark.mark(.kdf_aead_export_only);
        try kdfAead(S, src, gpa, Kdf, root.ExportOnly);
    } else try kdfAead(S, src, gpa, Kdf, root.ChaCha20Poly1305);
}

/// A length of a length-prefixed field: mostly small, often exactly at or one
/// past the 65,535 limit, sometimes well past it.
fn drawFieldLen(src: anytype, min: usize) usize {
    return switch (src.valueRangeAtMost(u8, 0, 5)) {
        0, 1, 2 => min + src.valueRangeAtMost(u8, 0, 64),
        3 => 65535,
        4 => 65536,
        else => 65537 + @as(usize, src.valueRangeAtMost(u16, 0, 70000 - 65537)),
    };
}

fn be16(n: usize) [2]u8 {
    return .{ @intCast(n >> 8), @truncate(n) };
}

fn kdfAead(comptime S: type, src: *S, gpa: std.mem.Allocator, comptime Kdf: type, comptime Aead: type) !void {
    const Kem = root.X25519Kem;
    const schedule = root.schedule;
    const limit = 65535;
    const Nk = Aead.key_length;
    const Nn = Aead.nonce_length;
    const aead_id: u16 = if (Aead == root.ExportOnly) 0xffff else 0x0003;

    var ikm: [64]u8 = undefined;
    src.bytes(&ikm);
    var skR: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skR, ikm[0..32]);
    var skE: Kem.KeyPair = undefined;
    Kem.deriveKeyPair(&skE, ikm[32..]);
    var kenc: Kem.Encapped = undefined;
    try Kem.encapDeterministic(&kenc, skR.public_key, &skE);

    // psk, psk_id and info overlap in one pattern buffer at different offsets.
    const pad = 1024;
    const buf = try gpa.alloc(u8, pad + 70000 + 3 * 70001);
    defer gpa.free(buf);
    var pat: [251]u8 = undefined;
    src.bytes(&pat);
    for (buf[0 .. pad + 70000], 0..) |*b, i| b.* = pat[i % pat.len] +% @as(u8, @truncate(i / pat.len));
    const psk = buf[0..drawFieldLen(src, 32)];
    const psk_id = buf[512..][0..drawFieldLen(src, 1)];
    const info = buf[pad..][0..drawFieldLen(src, 0)];
    const too_long = psk.len > limit or psk_id.len > limit or info.len > limit;

    var s: schedule.Setup(Kem, Aead, Kdf) = undefined;
    const sres = schedule.setupPskSDeterministic(Kem, Aead, Kdf, &s, skR.public_key, &skE, info, psk, psk_id);
    var r: schedule.Context(Aead, Kdf) = undefined;
    const rres = schedule.setupPskR(Kem, Aead, Kdf, &r, kenc.enc, &skR, info, psk, psk_id);
    if (too_long) {
        if (sres) |_| return error.OversizeFieldAccepted else |e| if (e != error.LabelTooLong) return error.WrongErrorForOversizeField;
        if (rres) |_| return error.OversizeFieldAcceptedByReceiver else |e| if (e != error.LabelTooLong) return error.WrongErrorForOversizeFieldReceiver;
        KdfMark.mark(.kdf_label_too_long);
        return;
    }
    sres catch return error.GenuineSetupRefused;
    rres catch return error.GenuineSetupRRefused;
    if (!std.mem.eql(u8, &s.enc, &kenc.enc)) return error.EncChanged;
    if (!std.mem.eql(u8, &s.context.key, &r.key) or
        !std.mem.eql(u8, &s.context.base_nonce, &r.base_nonce) or
        !std.mem.eql(u8, &s.context.exporter_secret, &r.exporter_secret)) return error.GenuinePairDisagrees;

    // The model: secret = LabeledDerive(lp(psk) || lp(ss), "secret",
    // mode || lp(psk_id) || lp(info), Nk + Nn + Nh), restated octet by octet.
    var sid: [10]u8 = undefined;
    sid[0..4].* = "HPKE".*;
    sid[4..6].* = be16(Kem.kem_id);
    sid[6..8].* = be16(Kdf.kdf_id);
    sid[8..10].* = be16(aead_id);
    var want: [Nk + Nn + Kdf.Nh]u8 = undefined;
    {
        var x = Kdf.Xof.init(.{});
        x.update(&be16(psk.len));
        x.update(psk);
        x.update(&be16(kenc.shared_secret.len));
        x.update(&kenc.shared_secret);
        x.update("HPKE-v1");
        x.update(&sid);
        x.update(&be16("secret".len));
        x.update("secret");
        x.update(&be16(want.len));
        x.update(&[1]u8{1}); // mode_psk
        x.update(&be16(psk_id.len));
        x.update(psk_id);
        x.update(&be16(info.len));
        x.update(info);
        x.squeeze(&want);
    }
    if (!std.mem.eql(u8, want[0..Nk], &s.context.key) or
        !std.mem.eql(u8, want[Nk..][0..Nn], &s.context.base_nonce) or
        !std.mem.eql(u8, want[Nk + Nn ..], &s.context.exporter_secret)) return error.ScheduleDiffersFromModel;
    KdfMark.mark(.kdf_ok_matches_model);

    // Exports: L around the limit.
    const out_a = buf[pad + 70000 ..][0..70001];
    const out_b = buf[pad + 70000 + 70001 ..][0..70001];
    const out_m = buf[pad + 70000 + 2 * 70001 ..][0..70001];
    for (0..2) |_| {
        const l: usize = switch (src.valueRangeAtMost(u8, 0, 5)) {
            0, 1, 2 => src.valueRangeAtMost(u8, 0, 64),
            3 => 65535,
            4 => 65536,
            else => 65537 + @as(usize, src.valueRangeAtMost(u16, 0, 70000 - 65537)),
        };
        const ctx = info[0..@min(info.len, src.valueRangeAtMost(u8, 0, 32))];
        const ea = s.context.exportSecret(&sid, ctx, out_a[0..l]);
        const eb = r.exportSecret(&sid, ctx, out_b[0..l]);
        if (l > limit) {
            if (ea) |_| return error.OversizeExportAccepted else |e| if (e != error.LabelTooLong) return error.WrongErrorForOversizeExport;
            if (eb) |_| return error.OversizeExportAcceptedByReceiver else |e| if (e != error.LabelTooLong) return error.WrongErrorForOversizeExportReceiver;
            KdfMark.mark(.kdf_export_too_long);
            continue;
        }
        ea catch return error.GenuineExportRefused;
        eb catch return error.GenuineExportRRefused;
        if (!std.mem.eql(u8, out_a[0..l], out_b[0..l])) return error.ExportsDisagree;
        var x = Kdf.Xof.init(.{});
        x.update(&s.context.exporter_secret);
        x.update("HPKE-v1");
        x.update(&sid);
        x.update(&be16("sec".len));
        x.update("sec");
        x.update(&be16(l));
        x.update(ctx);
        x.squeeze(out_m[0..l]);
        if (!std.mem.eql(u8, out_a[0..l], out_m[0..l])) return error.ExportDiffersFromModel;
        KdfMark.mark(.kdf_export_ok_matches_model);
    }
}
