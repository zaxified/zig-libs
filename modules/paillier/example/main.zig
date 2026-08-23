// SPDX-License-Identifier: MIT

//! What a payroll-aggregation service does with `paillier`: keygen (both
//! the real search path AND the deterministic `fromPrimes` path a KAT/
//! reproducible scenario needs), encrypt several salaries, homomorphically
//! SUM them without ever decrypting an individual one, then — a SECOND
//! round that builds on the first's still-encrypted output, never
//! touching the plaintext in between — add an encrypted bonus and apply
//! an encrypted-domain scalar multiplier, and only decrypt the final
//! total. Then show — an honest finding, not a defect — that vanilla
//! Paillier has NO ciphertext integrity (a bit-flipped ciphertext
//! decrypts CLEANLY to a different value, never an error), before
//! rejecting the two cases `decrypt`/`Ciphertext.fromBytes` genuinely do
//! reject by name: a "ciphertext" that shares a factor with `n`, and one
//! parsed under the wrong key's modulus.
//!
//! `paillier`'s PUBLIC API takes an `std.mem.Allocator` NOWHERE —
//! `generate`/`fromPrimes`/`encrypt`/`decrypt`/the homomorphic ops all
//! work over fixed-size `std.crypto.ff` values and a private, stack-
//! resident `FixedBufferAllocator` scratch arena internal to `decrypt`
//! (never the caller's heap). No `DebugAllocator` appears below; there is
//! no caller-visible allocation for one to catch.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only,
//! no `test_deps`, no access to anything the module does not export).
//!
//! External judge — ACTUALLY RUN at authoring time: `phe` (python-
//! paillier) 1.5.0 — the SAME third-party implementation this module's
//! own `kat_test`s were checked against (see NOTICE), but run here as a
//! pure BLACK-BOX oracle (its API called, its output compared; no `phe`
//! source read or copied — GPLv3, so nothing from it is eligible to be
//! copied anyway) against a FRESH scenario its own KATs never touch: two
//! well-known public Mersenne primes (2^61-1, 2^31-1 — not the module's
//! toy p=11/q=17 KAT), a `PaillierPrivateKey` phe derives independently
//! from those same primes, `raw_encrypt`/`raw_decrypt` with the SAME
//! explicit `r`, and the same chained addCiphertexts/addPlaintext/
//! mulPlaintext sequence recomputed with plain Python modexp over phe's
//! `n`/`n_sq`/`g`. Every intermediate ciphertext and the final decrypted
//! total matched byte/value-exact. Tool output only.

const std = @import("std");
const paillier = @import("paillier");
const Fe = paillier.Fe;

fn printHex(label: []const u8, out: []const u8) void {
    std.debug.print("{s}: {x}\n", .{ label, out });
}

pub fn main() !void {
    // ── Real keygen, exercised once to prove the production search path
    // works (deterministic PRNG here only because this is an example —
    // `generate`'s own doc comment requires a CSPRNG for real keys). Not
    // part of the oracle-checked scenario below (its primes are never
    // extracted, matching real usage — nobody keeps p/q around after
    // `fromPrimes` derives the key material). ──────────────────────────
    {
        var prng = std.Random.DefaultPrng.init(0xC0FFEE_1234_5678);
        const random = prng.random();
        var kp_gen = try paillier.generate(random, paillier.min_generate_bits);
        defer kp_gen.secret.deinit();

        const probe = try Fe.fromPrimitive(u64, kp_gen.public.n_sq, 42);
        const ct = try paillier.encryptRandom(kp_gen.public, probe, random);
        const pt = try paillier.decrypt(kp_gen.secret, ct);
        std.debug.assert(pt.eql(try Fe.fromPrimitive(u64, kp_gen.secret.n, 42)));
        std.debug.print("real generate({d} bits): keygen + encrypt/decrypt round-trip OK\n", .{paillier.min_generate_bits});
    }

    // ── The oracle-checked scenario: a key derived from two well-known,
    // public Mersenne primes (not the module's own toy KAT primes),
    // deterministic throughout so the external oracle below is exactly
    // reproducible. ─────────────────────────────────────────────────────
    var p_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &p_be, 2305843009213693951, .big); // 2^61 - 1
    var q_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &q_be, 2147483647, .big); // 2^31 - 1

    const kp = try paillier.fromPrimes(&p_be, &q_be);
    const pk = kp.public;
    const sk = kp.secret;

    var n_buf: [paillier.modulus_bytes]u8 = undefined;
    try pk.nToBytes(n_buf[0..pk.nByteLen()]);
    printHex("n = p*q", n_buf[0..pk.nByteLen()]);

    // ── Round 1: two encrypted salaries, summed without ever decrypting
    // either one individually. ─────────────────────────────────────────
    const salary1: u64 = 50_000;
    const salary2: u64 = 75_000;
    const r1: u64 = 12_345;
    const r2: u64 = 67_890;

    const ct1 = try paillier.encrypt(pk, try Fe.fromPrimitive(u64, pk.n_sq, salary1), try Fe.fromPrimitive(u64, pk.n_sq, r1));
    const ct2 = try paillier.encrypt(pk, try Fe.fromPrimitive(u64, pk.n_sq, salary2), try Fe.fromPrimitive(u64, pk.n_sq, r2));

    var ct1_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try ct1.toBytes(&ct1_buf);
    printHex("ct1 = E(salary1, r1)", &ct1_buf);
    var ct2_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try ct2.toBytes(&ct2_buf);
    printHex("ct2 = E(salary2, r2)", &ct2_buf);

    const sum_ct = paillier.addCiphertexts(pk, ct1, ct2); // cannot fail
    const round1_total = try paillier.decrypt(sk, sum_ct);
    const expected_round1 = try Fe.fromPrimitive(u64, sk.n, salary1 + salary2);
    std.debug.assert(round1_total.eql(expected_round1));
    std.debug.print("round1: decrypt(E(s1)*E(s2)) == s1+s2 ({d})\n", .{salary1 + salary2});

    // ── Round 2: builds on round 1's STILL-ENCRYPTED output — a bonus
    // added in the plaintext-add sense, then an employer-match multiplier
    // applied in the encrypted domain — the whole point of an additively
    // homomorphic scheme being that this chain never needs an
    // intermediate decrypt. Only the FINAL total is opened. ────────────
    const bonus: u64 = 5_000;
    const match_multiplier: u64 = 2;

    const ct_with_bonus = try paillier.addPlaintext(pk, sum_ct, try Fe.fromPrimitive(u64, pk.n_sq, bonus));
    const ct_matched = try paillier.mulPlaintext(pk, ct_with_bonus, try Fe.fromPrimitive(u64, pk.n_sq, match_multiplier));

    var ct_matched_buf: [paillier.modulus_sq_bytes]u8 = undefined;
    try ct_matched.toBytes(&ct_matched_buf);
    printHex("ct_matched = ((E(s1)*E(s2))*g^bonus)^match_multiplier", &ct_matched_buf);

    const final_total = try paillier.decrypt(sk, ct_matched);
    const expected_final = (salary1 + salary2 + bonus) * match_multiplier;
    const expected_final_fe = try Fe.fromPrimitive(u64, sk.n, expected_final);
    std.debug.assert(final_total.eql(expected_final_fe));
    std.debug.print("round2: decrypt(((E(s1)*E(s2))+bonus)*match_multiplier) == {d}\n", .{expected_final});

    // ── An honest finding, not a negative test: vanilla Paillier (this
    // module implements exactly the base cryptosystem — the ZK proofs
    // that would bind a ciphertext to a specific, non-malleable ciphertext
    // shape are explicitly out of scope, see root.zig's "TODO(phase2)")
    // carries NO ciphertext integrity at all. A single bit flipped in
    // ct1's LEAST-significant byte does NOT raise `InvalidCiphertext` —
    // it decrypts CLEANLY to a DIFFERENT plaintext, because `decrypt`'s
    // formula is total over every unit of `Z_n²*`, not just values of the
    // `g^m·r^n` shape a genuine `encrypt` call produces (`Z_n²* ≅ Z_n ×
    // Z_n*`, and `g = n+1` generates the `Z_n` factor, so EVERY unit
    // factors as `g^m·r^n` for SOME `m`). This is Paillier's textbook
    // malleability — the same mathematical fact that makes
    // `addCiphertexts`/`mulPlaintext` work at all — not a bug: an
    // application needing tamper-evidence must add its own MAC/AEAD layer
    // OR the Phase-2 ZK proof of correct encryption, never rely on
    // `decrypt` to reject a modified ciphertext.
    {
        var tampered = ct1_buf;
        tampered[tampered.len - 1] ^= 0x01;
        const bad_ct = try paillier.Ciphertext.fromBytes(pk, &tampered);
        const decrypted_garbage = try paillier.decrypt(sk, bad_ct);
        std.debug.assert(!decrypted_garbage.eql(try Fe.fromPrimitive(u64, sk.n, salary1)));
        std.debug.print("tampered ct1 (one flipped byte): decrypted CLEANLY to a different value (Paillier has no ciphertext integrity — expected, not a defect)\n", .{});
    }

    // ── Negative path 1: `decrypt` DOES reject a `c` that shares a factor
    // with `n` (not a unit mod n² at all, so no `m` exists for it) — here,
    // literally `c = p`, a degenerate "ciphertext" a caller could only
    // produce by mistake (e.g. feeding a raw key-derivation intermediate
    // in place of a real ciphertext). ──────────────────────────────────
    {
        const degenerate_c: paillier.Ciphertext = .{ .c = try Fe.fromPrimitive(u64, pk.n_sq, 2305843009213693951) };
        if (paillier.decrypt(sk, degenerate_c)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidCiphertext => std.debug.print("c = p (shares a factor with n): InvalidCiphertext (expected)\n", .{}),
            else => return err,
        }
    }

    // ── Negative path 2: ct1's bytes parsed under an UNRELATED key's
    // (much smaller) modulus — a "wrong key" scenario rejected at PARSE
    // time rather than decrypt time, a different failure point than
    // negative path 1. ──────────────────────────────────────────────────
    {
        const other_kp = try paillier.fromPrimes(&[_]u8{23}, &[_]u8{29});
        if (paillier.Ciphertext.fromBytes(other_kp.public, &ct1_buf)) |_| {
            return error.UnexpectedAccept;
        } else |err| switch (err) {
            error.InvalidCiphertext => std.debug.print("ct1 parsed under an unrelated (tiny) key: InvalidCiphertext (expected)\n", .{}),
        }
    }

    std.debug.print("paillier example: OK\n", .{});
}
