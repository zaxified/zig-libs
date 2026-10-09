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
//! `hpke-p384-decap`, `hpke-p384-auth-decap`, `hpke-seal-open`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
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
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
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
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
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
            try sealOpenOne(root.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm, 32, &ikm, info, aad, pt, src.value(bool));
        },
        1 => {
            SealMark.mark(.p256);
            try sealOpenOne(root.P256Kem, root.ChaCha20Poly1305, 32, &ikm, info, aad, pt, src.value(bool));
        },
        else => {
            SealMark.mark(.p384);
            try sealOpenOne(root.P384Kem, std.crypto.aead.aes_gcm.Aes256Gcm, 48, &ikm, info, aad, pt, src.value(bool));
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
