// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over `mlkem`'s public API (added 2026-11-01), one
//! harness per parameter set, each generic over its source of choices
//! (`fn(comptime S, *S, gpa)`), each checked against std's
//! `std.crypto.kem.ml_kem.nist.MLKem*` as the oracle. One draw picks a mode:
//!
//!   - `roundtrip`:   keygen -> encaps -> decaps returns the shared secret
//!                    (std agrees on every byte), and ONE flipped ciphertext bit
//!                    changes it to std's implicit-rejection value;
//!   - `arbitrary`:   decaps of an arbitrary ciphertext never panics and equals
//!                    std's result (the implicit-rejection path);
//!   - `ek`:          `PublicKey.fromBytes` of arbitrary / damaged / forced
//!                    non-canonical bytes agrees with std's acceptance (both do
//!                    the §7.2 modulus check); an accepted key encapsulates like
//!                    std's and re-serialises to its input;
//!   - `dk`:          `SecretKey.fromBytes` of a damaged decapsulation key (one of
//!                    its four regions): the modulus verdict agrees with std; our
//!                    additional §7.3 hash check is only allowed to refuse a key
//!                    whose hash really is wrong; an accepted key decapsulates
//!                    like std's.
//!
//! Driver: `MLKEM_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there). The 60-seed in-suite
//! run at the bottom checks that every label is reached.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const root = @import("root.zig");

const sha3 = std.crypto.hash.sha3;
const StdKem = std.crypto.kem.ml_kem;

pub const Label = enum {
    roundtrip,
    tamper_differs,
    arbitrary_ct,
    ek_accepted,
    ek_rejected,
    dk_accepted,
    dk_rejected_modulus,
    dk_rejected_hash,
};
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

/// Damage 1..4 bytes of `buf[lo..hi]`: a single bit flip or a whole new byte.
fn damage(comptime S: type, src: *S, buf: []u8, lo: usize, hi: usize) void {
    const n = 1 + src.index(4);
    for (0..n) |_| {
        const at = lo + src.index(hi - lo);
        if (src.index(2) == 0) {
            buf[at] ^= @as(u8, 1) << @intCast(src.index(8));
        } else {
            buf[at] = src.value(u8);
        }
    }
}

fn Harness(comptime Ours: type, comptime Std: type) type {
    return struct {
        const ct_len = Ours.ciphertext_length;
        const ek_len = Ours.PublicKey.encoded_length;
        const dk_len = Ours.SecretKey.encoded_length;
        // dk = dk_pke (384k) ‖ ek ‖ H(ek) ‖ z
        const pke_len = ek_len - 32;
        const hpk_at = pke_len + ek_len;
        const z_at = hpk_at + 32;

        comptime {
            std.debug.assert(ct_len == Std.ciphertext_length);
            std.debug.assert(ek_len == Std.PublicKey.encoded_length);
            std.debug.assert(dk_len == Std.SecretKey.encoded_length);
            std.debug.assert(z_at + 32 == dk_len);
        }

        fn run(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
            _ = gpa;
            var seed: [Ours.seed_length]u8 = undefined;
            src.bytes(&seed);
            const ours = Ours.KeyPair.generateDeterministic(seed);
            const theirs = try Std.KeyPair.generateDeterministic(seed);
            const ek_bytes = ours.public_key.toBytes();
            const dk_bytes = ours.secret_key.toBytes();
            if (!std.mem.eql(u8, &ek_bytes, &theirs.public_key.toBytes())) return error.EkDiffersFromStd;
            if (!std.mem.eql(u8, &dk_bytes, &theirs.secret_key.toBytes())) return error.DkDiffersFromStd;

            switch (src.index(4)) {
                0 => try roundtrip(S, src, ours, theirs),
                1 => try arbitrary(S, src, ours, theirs),
                2 => try ek(S, src, ours, theirs, ek_bytes),
                else => try dk(S, src, ours, theirs, dk_bytes),
            }
        }

        fn roundtrip(comptime S: type, src: *S, ours: Ours.KeyPair, theirs: Std.KeyPair) !void {
            var m: [32]u8 = undefined;
            src.bytes(&m);
            const enc = ours.public_key.encapsDeterministic(&m);
            const senc = theirs.public_key.encapsDeterministic(&m);
            if (!std.mem.eql(u8, &enc.ciphertext, &senc.ciphertext)) return error.CiphertextDiffersFromStd;
            if (!std.mem.eql(u8, &enc.shared_secret, &senc.shared_secret)) return error.SecretDiffersFromStd;
            const ss = ours.secret_key.decaps(&enc.ciphertext);
            if (!std.mem.eql(u8, &ss, &enc.shared_secret)) return error.RoundTripFailed;
            mark(.roundtrip);

            var bad = enc.ciphertext;
            const bit = src.index(ct_len * 8);
            bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
            const ss_bad = ours.secret_key.decaps(&bad);
            if (std.mem.eql(u8, &ss_bad, &enc.shared_secret)) return error.TamperedCiphertextAccepted;
            const ss_std = try theirs.secret_key.decaps(&bad);
            if (!std.mem.eql(u8, &ss_bad, &ss_std)) return error.ImplicitRejectionDiffersFromStd;
            mark(.tamper_differs);
        }

        fn arbitrary(comptime S: type, src: *S, ours: Ours.KeyPair, theirs: Std.KeyPair) !void {
            var ct: [ct_len]u8 = undefined;
            src.bytes(&ct);
            const a = ours.secret_key.decaps(&ct);
            const b = try theirs.secret_key.decaps(&ct);
            if (!std.mem.eql(u8, &a, &b)) return error.DecapsDiffersFromStd;
            mark(.arbitrary_ct);
        }

        fn ek(comptime S: type, src: *S, ours: Ours.KeyPair, theirs: Std.KeyPair, ek_valid: [ek_len]u8) !void {
            var buf = ek_valid;
            switch (src.index(3)) {
                0 => src.bytes(&buf),
                1 => damage(S, src, &buf, 0, ek_len),
                else => {
                    // A 12-bit coefficient of 4095 >= q: two coefficients are
                    // three bytes, and the polynomial vector is `pke_len` long.
                    const at = 3 * src.index(pke_len / 3);
                    buf[at] = 0xff;
                    buf[at + 1] |= 0x0f;
                },
            }
            const o = Ours.PublicKey.fromBytes(&buf);
            const s = Std.PublicKey.fromBytes(&buf);
            if (o) |opk| {
                const spk = s catch return error.OursAcceptsEkStdRejects;
                if (!std.mem.eql(u8, &opk.toBytes(), &buf)) return error.EkNotReserialised;
                var m: [32]u8 = undefined;
                src.bytes(&m);
                const a = opk.encapsDeterministic(&m);
                const b = spk.encapsDeterministic(&m);
                if (!std.mem.eql(u8, &a.ciphertext, &b.ciphertext) or
                    !std.mem.eql(u8, &a.shared_secret, &b.shared_secret)) return error.AcceptedEkEncapsDiffers;
                mark(.ek_accepted);
            } else |_| {
                if (s) |_| return error.OursRejectsEkStdAccepts else |_| {}
                mark(.ek_rejected);
            }
            _ = ours;
            _ = theirs;
        }

        fn dk(comptime S: type, src: *S, ours: Ours.KeyPair, theirs: Std.KeyPair, dk_valid: [dk_len]u8) !void {
            _ = ours;
            _ = theirs;
            var buf = dk_valid;
            switch (src.index(5)) {
                0 => damage(S, src, &buf, 0, dk_len),
                1 => damage(S, src, &buf, 0, pke_len),
                2 => damage(S, src, &buf, pke_len, hpk_at),
                3 => damage(S, src, &buf, hpk_at, z_at),
                else => damage(S, src, &buf, z_at, dk_len),
            }
            var ct: [ct_len]u8 = undefined;
            src.bytes(&ct);

            const o = Ours.SecretKey.fromBytes(&buf);
            const s = Std.SecretKey.fromBytes(&buf);
            if (o) |osk| {
                const ssk = s catch return error.OursAcceptsDkStdRejects;
                // dk_pke coefficients are not range-checked on import (FIPS 203
                // only checks ek and the hash), so compare with std, not the input.
                if (!std.mem.eql(u8, &osk.toBytes(), &ssk.toBytes())) return error.DkReserialisedDiffersFromStd;
                var h: [32]u8 = undefined;
                sha3.Sha3_256.hash(buf[pke_len..hpk_at], &h, .{});
                if (!std.mem.eql(u8, &h, buf[hpk_at..z_at])) return error.AcceptedDkWithBadHash;
                const a = osk.decaps(&ct);
                const b = try ssk.decaps(&ct);
                if (!std.mem.eql(u8, &a, &b)) return error.AcceptedDkDecapsDiffers;
                mark(.dk_accepted);
            } else |err| switch (err) {
                error.NonCanonical => {
                    if (s) |_| return error.OursRejectsDkModulusStdAccepts else |_| {}
                    mark(.dk_rejected_modulus);
                },
                error.InconsistentKey => {
                    // The modulus check passed (it runs first), so std accepts;
                    // the only thing we may refuse on top is a wrong hash.
                    _ = s catch return error.OursInconsistentButModulusFailsInStd;
                    var h: [32]u8 = undefined;
                    sha3.Sha3_256.hash(buf[pke_len..hpk_at], &h, .{});
                    if (std.mem.eql(u8, &h, buf[hpk_at..z_at])) return error.RejectedDkWithGoodHash;
                    mark(.dk_rejected_hash);
                },
            }
        }
    };
}

const H512 = Harness(root.MLKem512, StdKem.MLKem512);
const H768 = Harness(root.MLKem768, StdKem.MLKem768);
const H1024 = Harness(root.MLKem1024, StdKem.MLKem1024);

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [1024]u8 = undefined;
            const n = smith.slice(&script);
            var src = testkit.fuzz.ScriptSource.init(script[0..n]);
            return harness(testkit.fuzz.ScriptSource, &src, testing.allocator);
        }
    }.f;
}

test "fuzz: mlkem512 matches std on every public entry point" {
    try testing.fuzz({}, fuzzScript(H512.run), .{});
}
test "fuzz: mlkem768 matches std on every public entry point" {
    try testing.fuzz({}, fuzzScript(H768.run), .{});
}
test "fuzz: mlkem1024 matches std on every public entry point" {
    try testing.fuzz({}, fuzzScript(H1024.run), .{});
}

test "fuzz driver: MLKEM_FUZZ (mlkem)" {
    try fuzz_driver.runAll(.{
        .{ H512.run, .{ .prefix = "MLKEM_FUZZ", .name = "mlkem512" } },
        .{ H768.run, .{ .prefix = "MLKEM_FUZZ", .name = "mlkem768" } },
        .{ H1024.run, .{ .prefix = "MLKEM_FUZZ", .name = "mlkem1024" } },
    });
}

test "fuzz harness: 60 seeds per set in every test run, and they get everywhere" {
    reach = @splat(0);
    inline for (.{ H512.run, H768.run, H1024.run }, 0..) |h, which| {
        for (0..60) |seed| {
            var prng = std.Random.DefaultPrng.init(seed);
            var rng: fuzz_driver.Rng = .{ .r = prng.random() };
            h(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                std.debug.print("mlkem set {d} seed {d}: {t}\n", .{ which, seed, err });
                return err;
            };
        }
    }
    // Reach before verdict: every outcome the harness judges was seen.
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 3 x 60 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}
