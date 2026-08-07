// SPDX-License-Identifier: MIT

//! security_test — the acceptance harness for the two-lock AND contract.
//!
//! Round-trip, the three AND-composition negatives (each lock is
//! necessary), per-region tamper detection, malformed-input robustness
//! (a `std.testing.fuzz` harness over `parse`/`open`), and a permanent
//! positive control proving the suite actually detects a broken AND.
//!
//! The time gate is exercised deterministically WITHOUT a live drand by
//! reusing `tlock`'s own interop-verified quicknet vector: the genuine
//! League-of-Entropy quicknet master public key and its published
//! round-1000 threshold signature (the round's BF-IBE private key). Both
//! are the exact bytes `tlock`'s `kat_test.zig` pins with an ungated
//! pairing-sanity check `e(sig, G2gen) == e(h1(beaconId(1000)), P_pub)`,
//! so sealing to round 1000 and opening with the round-1000 signature is
//! a real, deterministic timelock round-trip — no beacon fetch, no DKG.

const std = @import("std");
const tlock = @import("tlock");
const hqc = @import("hqc");
const chachapoly = @import("chachapoly");
const envelope = @import("envelope.zig");

const bls12_381 = tlock.bls12_381;
const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const testing = std.testing;

const Env = envelope.Envelope128;
const Kem = hqc.Hqc128;
const Aead = chachapoly.ChaCha20Poly1305;

fn hexBytes(comptime n: usize, comptime hex: *const [2 * n:0]u8) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// ── genuine drand quicknet production vector (via tlock/kat_test.zig) ──
//
// Source: `https://api.drand.sh/v2/beacons/quicknet/info` (P_pub) and
// `.../52db9ba7.../public/1000` (round-1000 signature), fetched
// 2026-07-16 for tlock's KAT harness. Copied verbatim here so this
// module's timelock round-trip uses real, pairing-verified beacon
// material rather than a live fetch.

const quicknet_pubkey_hex =
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183" ++
    "c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4b" ++
    "cb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece" ++
    "45a";

const round_1000_sig_hex =
    "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb112" ++
    "5e342b73a8dd2bacbe47e4b6b63ed5e39";

// A valid G1 point that is NOT the private key for any quicknet round:
// quicknet-t (testnet) round 5423142's signature — a different beacon
// entirely (tlock's own interop vector). Used to model "the time gate
// is still closed" (no correct signature available).
const wrong_sig_hex =
    "96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4" ++
    "f84681a45b1af2ce0511e5a32dd72508f";

const seal_round: u64 = 1000;

fn quicknetPubkey() g2.Affine {
    return g2.fromBytesCompressed(hexBytes(96, quicknet_pubkey_hex)) catch unreachable;
}
fn round1000Signature() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, round_1000_sig_hex)) catch unreachable;
}
fn wrongSignature() g1.Affine {
    return g1.fromBytesCompressed(hexBytes(48, wrong_sig_hex)) catch unreachable;
}

// Deterministic randomness for reproducible tests (the repo convention:
// randomness is an explicit input; see envelope.SealRandomness).
fn fixedRandomness() Env.SealRandomness {
    return .{
        .s_time = [_]u8{0x11} ** envelope.time_secret_bytes,
        .tlock_sigma = [_]u8{0x22} ** envelope.time_secret_bytes,
        .kem_coins = [_]u8{0x33} ** Kem.coins_bytes,
    };
}

fn recipientKeypair(seed_byte: u8) Kem.KeyPair {
    return Kem.keypair(&[_]u8{seed_byte} ** 32);
}

const plaintext = "the launch codes expire at dawn";

// ── round-trip ────────────────────────────────────────────────────────

test "round-trip: seal then open recovers the exact plaintext with both locks satisfied" {
    const kp = recipientKeypair(0x01);

    const env = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(env);

    try testing.expectEqual(Env.overhead + plaintext.len, env.len);

    const opened = try Env.open(testing.allocator, env, kp.dk, round1000Signature());
    defer testing.allocator.free(opened);

    try testing.expectEqualSlices(u8, plaintext, opened);
}

test "round-trip works across all three HQC parameter sets" {
    inline for (.{
        .{ envelope.Envelope128, hqc.Hqc128 },
        .{ envelope.Envelope192, hqc.Hqc192 },
        .{ envelope.Envelope256, hqc.Hqc256 },
    }) |pair| {
        const E = pair[0];
        const K = pair[1];
        const kp = K.keypair(&[_]u8{0x07} ** 32);
        const rnd: E.SealRandomness = .{
            .s_time = [_]u8{0x44} ** envelope.time_secret_bytes,
            .tlock_sigma = [_]u8{0x55} ** envelope.time_secret_bytes,
            .kem_coins = [_]u8{0x66} ** K.coins_bytes,
        };
        const env = try E.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, rnd);
        defer testing.allocator.free(env);
        const opened = try E.open(testing.allocator, env, kp.dk, round1000Signature());
        defer testing.allocator.free(opened);
        try testing.expectEqualSlices(u8, plaintext, opened);
    }
}

test "empty plaintext round-trips" {
    const kp = recipientKeypair(0x02);
    const env = try Env.seal(testing.allocator, "", kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(env);
    const opened = try Env.open(testing.allocator, env, kp.dk, round1000Signature());
    defer testing.allocator.free(opened);
    try testing.expectEqual(@as(usize, 0), opened.len);
}

// ── AND-composition negatives (each lock is individually necessary) ────

test "AND #1: correct PQ key but the time gate is still closed (wrong signature) → TimeGateClosed" {
    const kp = recipientKeypair(0x03);
    const env = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(env);

    // Right recipient key, but no valid round signature (models "before
    // round R"): the time lock must not open.
    try testing.expectError(error.TimeGateClosed, Env.open(testing.allocator, env, kp.dk, wrongSignature()));
}

test "AND #2: time gate open but wrong HQC secret key → AuthFailed" {
    const kp = recipientKeypair(0x04);
    const other = recipientKeypair(0x05); // different keypair entirely
    const env = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(env);

    // Correct round signature, but the wrong PQ secret key: HQC's
    // implicit rejection yields a pseudo-random s_pq → wrong K → the
    // AEAD tag rejects. Never a garbage plaintext.
    try testing.expectError(error.AuthFailed, Env.open(testing.allocator, env, other.dk, round1000Signature()));
}

test "AND #3: signature is for a DIFFERENT round than the envelope → TimeGateClosed" {
    const kp = recipientKeypair(0x06);
    // Seal to round 1001, but the only signature we hold is round 1000's.
    const env = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), 1001, fixedRandomness());
    defer testing.allocator.free(env);

    try testing.expectError(error.TimeGateClosed, Env.open(testing.allocator, env, kp.dk, round1000Signature()));
}

// ── tamper detection (per region) ─────────────────────────────────────

fn expectOpenIsError(env: []const u8, dk: Kem.DecapsKey, sig: g1.Affine) !void {
    if (Env.open(testing.allocator, env, dk, sig)) |pt| {
        testing.allocator.free(pt);
        return error.TestUnexpectedlyOpened;
    } else |_| {}
}

test "tamper: flipping a byte in any region makes open fail with a typed error, never a wrong plaintext" {
    const kp = recipientKeypair(0x08);
    const base = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(base);

    // Representative offsets: round field, tlock ct, hqc ct, tag, aead ct.
    const offsets = [_]usize{
        7, // round field (header, in the AAD + feeds the KDF)
        envelope.header_bytes + 4, // inside the tlock ciphertext
        envelope.header_bytes + Env.time_lock_bytes + 10, // inside the hqc ciphertext
        Env.aad_bytes + 1, // inside the AEAD tag
        Env.aad_bytes + envelope.tag_bytes, // first content byte
    };
    for (offsets) |off| {
        const dup = try testing.allocator.dupe(u8, base);
        defer testing.allocator.free(dup);
        dup[off] ^= 0xFF;
        try expectOpenIsError(dup, kp.dk, round1000Signature());
    }
}

test "F1: tampering the flags byte (offset 6) is rejected — the only AAD-EXCLUSIVE byte" {
    // Every other tamper-test offset is shadowed by a second binding: the
    // round field also feeds the KDF info, the tlock/HQC ciphertexts are
    // checked by their own consistency checks, and tag/content are covered
    // by the AEAD itself. `flags` at offset 6 is deliberately left
    // unconstrained by `parse` (reserved for future use) and is authenticated
    // ONLY because it is inside the AAD region — so this is the one test
    // that actually exercises "the AAD binding matters", as opposed to being
    // shadowed by some other check that would catch the same offset anyway.
    const kp = recipientKeypair(0x0D);
    const base = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(base);

    const dup = try testing.allocator.dupe(u8, base);
    defer testing.allocator.free(dup);
    dup[6] ^= 0xFF; // the flags byte
    try expectOpenIsError(dup, kp.dk, round1000Signature());
}

test "tamper: corrupting the magic / version / suite bytes is rejected at parse" {
    const kp = recipientKeypair(0x09);
    const base = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(base);

    {
        const dup = try testing.allocator.dupe(u8, base);
        defer testing.allocator.free(dup);
        dup[0] ^= 0xFF;
        try testing.expectError(error.BadMagic, Env.open(testing.allocator, dup, kp.dk, round1000Signature()));
    }
    {
        const dup = try testing.allocator.dupe(u8, base);
        defer testing.allocator.free(dup);
        dup[4] ^= 0xFF;
        try testing.expectError(error.UnsupportedVersion, Env.open(testing.allocator, dup, kp.dk, round1000Signature()));
    }
    {
        const dup = try testing.allocator.dupe(u8, base);
        defer testing.allocator.free(dup);
        dup[5] = 32; // hqc-256's suite id
        try testing.expectError(error.SuiteMismatch, Env.open(testing.allocator, dup, kp.dk, round1000Signature()));
    }
}

test "tamper: truncating the envelope is rejected, never a panic" {
    const kp = recipientKeypair(0x0A);
    const base = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(base);

    try testing.expectError(error.LengthMismatch, Env.open(testing.allocator, base[0 .. base.len - 1], kp.dk, round1000Signature()));
    try testing.expectError(error.Truncated, Env.open(testing.allocator, base[0..3], kp.dk, round1000Signature()));
}

// ── positive control (proves the negatives actually detect a broken AND) ──

test "positive control: a KDF that dropped s_pq would let the PQ-lock negative pass" {
    // Model the exact AND bug we guard against: derive the content key
    // from s_time ALONE (s_pq zeroed). Then an attacker who only passes
    // the TIME gate — recovering s_time via the round signature, holding
    // NO HQC secret key — can reconstruct the same key and open. That is
    // precisely what makes AND #2 (wrong-PQ-key → AuthFailed) a real
    // detector: on the real construction it rejects; under this broken
    // KDF it would not.
    const rnd = fixedRandomness();
    const zero_pq = [_]u8{0} ** hqc.params.shared_secret_bytes;

    // Broken seal: key ignores s_pq.
    const broken_keys = envelope.deriveKeys(rnd.s_time, zero_pq, Env.suite_id, seal_round);
    var ct: [plaintext.len]u8 = undefined;
    var tag: [envelope.tag_bytes]u8 = undefined;
    Aead.encrypt(&ct, &tag, plaintext, "", broken_keys.nonce, broken_keys.key);

    // Attacker path: recover s_time from the time lock (post-R), derive
    // the broken key WITHOUT any PQ secret, and open.
    const tl = tlock.encrypt(quicknetPubkey(), seal_round, rnd.s_time, rnd.tlock_sigma);
    const s_time_recovered = try tlock.decrypt(round1000Signature(), tl);
    const attacker_keys = envelope.deriveKeys(s_time_recovered, zero_pq, Env.suite_id, seal_round);

    var dec: [plaintext.len]u8 = undefined;
    try Aead.decrypt(&dec, &ct, tag, "", attacker_keys.nonce, attacker_keys.key);
    try testing.expectEqualSlices(u8, plaintext, &dec); // opened with NO PQ lock → AND void
}

test "positive control: the REAL construction binds s_pq (attacker without it cannot derive the key)" {
    // Same attacker as above, but against the REAL key which binds the
    // genuine s_pq: the s_pq-less derivation yields a different key, so
    // the AEAD would reject — the property AND #2 relies on.
    const kp = recipientKeypair(0x0B);
    const rnd = fixedRandomness();

    const enc = Kem.encaps(kp.ek, &rnd.kem_coins);
    const real_keys = envelope.deriveKeys(rnd.s_time, enc.ss, Env.suite_id, seal_round);

    const zero_pq = [_]u8{0} ** hqc.params.shared_secret_bytes;
    const attacker_keys = envelope.deriveKeys(rnd.s_time, zero_pq, Env.suite_id, seal_round);

    try testing.expect(!std.mem.eql(u8, &real_keys.key, &attacker_keys.key));
}

// ── malformed-input robustness (fuzz over parse + open) ────────────────

const FuzzCtx = struct {
    dk: Kem.DecapsKey,
    sig: g1.Affine,
    base: []const u8, // a valid envelope, to mutate
};

fn fuzzOpen(ctx: *const FuzzCtx, smith: *std.testing.Smith) anyerror!void {
    // Two sources of input: purely random bytes, and mutations of a real
    // envelope. Both must never panic / OOB / hang; open must return a
    // typed error or (only for an unmutated copy) the exact plaintext.
    var buf: [Env.overhead + 64]u8 = undefined;

    const mode = smith.value(u8) & 1;
    const input: []u8 = blk: {
        if (mode == 0) {
            // Random-length random bytes.
            const len: usize = smith.valueRangeAtMost(u32, 0, @intCast(buf.len));
            smith.bytes(buf[0..len]);
            break :blk buf[0..len];
        } else {
            // Copy the valid envelope, then flip a bounded number of bytes.
            const n = @min(ctx.base.len, buf.len);
            @memcpy(buf[0..n], ctx.base[0..n]);
            const flips = smith.valueRangeAtMost(u8, 0, 8);
            var i: usize = 0;
            while (i < flips) : (i += 1) {
                const at: usize = smith.valueRangeAtMost(u32, 0, @intCast(n - 1));
                buf[at] ^= smith.value(u8);
            }
            break :blk buf[0..n];
        }
    };

    if (Env.open(testing.allocator, input, ctx.dk, ctx.sig)) |pt| {
        defer testing.allocator.free(pt);
        // A successful open is only possible for a byte-identical copy of
        // the base envelope; assert it really is the original plaintext.
        try testing.expectEqualSlices(u8, plaintext, pt);
    } else |_| {
        // Any typed OpenError is acceptable — the requirement is only
        // that it never panics or returns a wrong plaintext.
    }
}

test "fuzz: open never panics / OOBs / hangs on arbitrary or mutated input" {
    const kp = recipientKeypair(0x0C);
    const base = try Env.seal(testing.allocator, plaintext, kp.ek, quicknetPubkey(), seal_round, fixedRandomness());
    defer testing.allocator.free(base);

    const ctx = FuzzCtx{ .dk = kp.dk, .sig = round1000Signature(), .base = base };
    try std.testing.fuzz(&ctx, fuzzOpen, .{});
}
