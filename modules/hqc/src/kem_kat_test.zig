// SPDX-License-Identifier: MIT
//! kem_kat_test — Part 3's definitive deliverable: byte-exact NIST KAT
//! reproduction for HQC-128/192/256, driven exactly the way the
//! reference's own `main_kat.c` harness drives it (see
//! kat_vectors_kem.zig's module doc): seed a single continuing
//! `prng.Prng` from the `.rsp` vector's 48-byte `seed`, draw `seed_kem`
//! (32 B) for `keypair`, then continue drawing `coins` (m || salt) off
//! the SAME Prng for `encaps` — the exact `prng_get_bytes` call sequence
//! `crypto_kem_keypair` then `crypto_kem_enc` make on one shared DRBG
//! stream in the reference.
//!
//! Also: a random-coins round-trip property test (keypair/encaps/decaps
//! agree on the shared secret across several random seeds, all three
//! parameter sets) and a decaps-failure/implicit-reject test (a
//! corrupted ciphertext makes `decaps` return the `J(...)`-derived
//! rejection value — deterministically, not a crash, and not equal to
//! the real shared secret).

const std = @import("std");
const testing = std.testing;

const params = @import("params.zig");
const prng = @import("prng.zig");
const reedsolomon = @import("reedsolomon.zig");
const kem = @import("kem.zig");
const v = @import("kat_vectors_kem.zig");

const Kem128 = kem.Kem(params.hqc128, reedsolomon.generator_hqc128);
const Kem192 = kem.Kem(params.hqc192, reedsolomon.generator_hqc192);
const Kem256 = kem.Kem(params.hqc256, reedsolomon.generator_hqc256);

fn hexBytes(comptime len: usize, hex: []const u8) [len]u8 {
    var out: [len]u8 = undefined;
    const decoded = std.fmt.hexToBytes(&out, hex) catch unreachable;
    std.debug.assert(decoded.len == len);
    return out;
}

// ── byte-exact NIST KAT (the definitive check) ──────────────────────────

fn checkKat(comptime Kem: type, vec: v.Vector) !void {
    const seed = hexBytes(48, vec.seed);

    // One continuing Prng stream across keypair + encaps, exactly as
    // main_kat.c's single `prng_init(seed, ...)` feeds both
    // `crypto_kem_keypair` and `crypto_kem_enc` in sequence.
    var rsp_prng = prng.Prng.init(&seed, &[_]u8{});

    var seed_kem: [params.seed_bytes]u8 = undefined;
    rsp_prng.getBytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    const want_pk = hexBytes(Kem.ek_bytes, vec.pk);
    try testing.expectEqualSlices(u8, &want_pk, &kp.ek);
    const want_sk = hexBytes(Kem.dk_bytes, vec.sk);
    try testing.expectEqualSlices(u8, &want_sk, &kp.dk);

    var coins: [Kem.coins_bytes]u8 = undefined;
    rsp_prng.getBytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const want_ct = hexBytes(Kem.ct_bytes, vec.ct);
    try testing.expectEqualSlices(u8, &want_ct, &enc.ct);
    const want_ss = hexBytes(Kem.ss_bytes, vec.ss);
    try testing.expectEqualSlices(u8, &want_ss, &enc.ss);

    // decaps on the genuine ciphertext must recover the same ss (the
    // .rsp itself doesn't publish this as a separate field -- it's what
    // main_kat.c's own internal `memcmp(ss, ss1, ...)` self-check
    // verifies -- so this is us reproducing that self-check).
    const dec_ss = Kem.decaps(kp.dk, enc.ct);
    try testing.expectEqualSlices(u8, &want_ss, &dec_ss);
}

test "NIST KAT: HQC-128 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc128) |vec| try checkKat(Kem128, vec);
}

test "NIST KAT: HQC-192 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc192) |vec| try checkKat(Kem192, vec);
}

test "NIST KAT: HQC-256 count 0..2 byte-exact pk/sk/ct/ss, decaps agrees" {
    for (v.hqc256) |vec| try checkKat(Kem256, vec);
}

// ── round-trip property test: random coins, three parameter sets ───────

fn testRoundTrip(comptime Kem: type, seed_val: u64) !void {
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const dec_ss = Kem.decaps(kp.dk, enc.ct);
    try testing.expectEqualSlices(u8, &enc.ss, &dec_ss);
}

test "round-trip: HQC-128 keypair/encaps/decaps agree across random coins" {
    for (0..4) |i| try testRoundTrip(Kem128, i);
}

test "round-trip: HQC-192 keypair/encaps/decaps agree across random coins" {
    for (10..13) |i| try testRoundTrip(Kem192, i);
}

test "round-trip: HQC-256 keypair/encaps/decaps agree across random coins" {
    for (20..23) |i| try testRoundTrip(Kem256, i);
}

// ── decaps-failure / implicit-rejection ─────────────────────────────────

fn testImplicitReject(comptime Kem: type, seed_val: u64) !void {
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    // Flip one bit inside u (the ciphertext's leading component) --
    // decaps must not crash, and must NOT recover the real ss.
    var corrupted = enc.ct;
    corrupted[0] ^= 0x01;

    const rejected_ss = Kem.decaps(kp.dk, corrupted);
    try testing.expect(!std.mem.eql(u8, &rejected_ss, &enc.ss));

    // The implicit-reject value is J(H(ek), sigma, ct) -- a deterministic
    // hash, not randomness -- so decapsing the same corrupted ct twice
    // must yield the identical rejection value both times.
    const rejected_ss2 = Kem.decaps(kp.dk, corrupted);
    try testing.expectEqualSlices(u8, &rejected_ss, &rejected_ss2);

    // Also corrupt the salt (the ciphertext's tail) -- same contract.
    var corrupted_salt = enc.ct;
    corrupted_salt[corrupted_salt.len - 1] ^= 0x80;
    const rejected_salt_ss = Kem.decaps(kp.dk, corrupted_salt);
    try testing.expect(!std.mem.eql(u8, &rejected_salt_ss, &enc.ss));
}

test "implicit reject: corrupted ciphertext decaps returns a differing, deterministic ss" {
    try testImplicitReject(Kem128, 100);
    try testImplicitReject(Kem192, 101);
    try testImplicitReject(Kem256, 102);
}

// ── H2: the FO comparison must depend on every byte of `v`, not just u/salt ─
//
// Audit A1 finding `hqc` H2: `vectCompare(&ct_prime, &ct)` can be shrunk to
// compare only `u` (2209 of 4433 B) or even a single byte of `ct`, and the
// suite above stayed 75/75 green, because the only corruption it ever tried
// was a bit inside `u` (`corrupted[0]`) or inside `salt` (the last byte) --
// never inside `v`. Demonstrated as a real IND-CCA2 break in the audit
// record (`A1/hqc.md` H2, `repro/hqc/attack.zig`): a ciphertext with one bit
// flipped inside `v` was accepted as genuine, recovering the real shared
// secret, once the comparison no longer covered `v`. This test corrupts
// several positions spread across EACH of the three ciphertext components
// (u, v, salt) and requires every one of them to be rejected.

fn testImplicitRejectEveryComponent(comptime Kem: type, seed_val: u64) !void {
    const t = testing;
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const u_bytes = Kem.Ring.n_bytes;
    const v_bytes = Kem.Pke.Code.codeword_len;
    const ct_len = enc.ct.len;
    std.debug.assert(u_bytes + v_bytes + params.salt_bytes == ct_len);

    const Range = struct { start: usize, end: usize, name: []const u8 };
    const ranges = [_]Range{
        .{ .start = 0, .end = u_bytes, .name = "u" },
        .{ .start = u_bytes, .end = u_bytes + v_bytes, .name = "v" },
        .{ .start = u_bytes + v_bytes, .end = ct_len, .name = "salt" },
    };

    for (ranges) |r| {
        const span = r.end - r.start;
        const step = @max(span / 8, 1); // ~8 sampled positions across the component
        var pos = r.start;
        while (pos < r.end) : (pos += step) {
            var corrupted = enc.ct;
            corrupted[pos] ^= 0x01;
            const rejected = Kem.decaps(kp.dk, corrupted);
            t.expect(!std.mem.eql(u8, &rejected, &enc.ss)) catch |err| {
                std.debug.print("component {s} byte {d}: decaps accepted the corrupted ciphertext as genuine\n", .{ r.name, pos });
                return err;
            };
        }
    }
}

test "implicit reject: every ciphertext component (u, v, salt) is covered, not just u/salt" {
    try testImplicitRejectEveryComponent(Kem128, 200);
    try testImplicitRejectEveryComponent(Kem192, 201);
    try testImplicitRejectEveryComponent(Kem256, 202);
}

// ── H3: the implicit-rejection value has no anchor -- add what black-box
// coverage is cheaply available ──────────────────────────────────────────
//
// Audit A1 finding `hqc` H3: `K_bar = J(H(ek), sigma, ct)` (the implicit-
// rejection value) has no external KAT vector (the reference's own fixture
// never exercises the reject path), and the only test touching it before
// this one checked "differs from the real ss" and "is deterministic" --
// both of which are ALSO true of `sigma` itself, so a mutant returning
// `sigma` verbatim (i.e. leaking the long-term rejection secret on every
// rejected decapsulation) passed 75/75. `A1/hqc.md` recommends, as the
// cheap partial fix short of a full external anchor for `hashJ`: a test that
// `K_bar` is not equal to any part of `dk`, and a test that it depends on
// `ct`. Both below.

fn testImplicitRejectNotSigma(comptime Kem: type, seed_val: u64) !void {
    const t = testing;
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    var corrupted = enc.ct;
    corrupted[0] ^= 0x01;
    const rejected = Kem.decaps(kp.dk, corrupted);

    // dk_kem = ek || dk_pke(seed_bytes) || sigma(security_bytes) || seed_kem
    // (kem.zig's `keypair` doc). `sigma` is the implicit-rejection secret;
    // the rejection value must not simply BE it.
    const sigma_offset = Kem.ek_bytes + params.seed_bytes;
    const sigma: [Kem.security_bytes]u8 = kp.dk[sigma_offset..][0..Kem.security_bytes].*;
    try t.expect(!std.mem.eql(u8, rejected[0..Kem.security_bytes], &sigma));
}

test "implicit reject: rejection value is not the raw sigma secret" {
    try testImplicitRejectNotSigma(Kem128, 300);
    try testImplicitRejectNotSigma(Kem192, 301);
    try testImplicitRejectNotSigma(Kem256, 302);
}

fn testImplicitRejectDependsOnCt(comptime Kem: type, seed_val: u64) !void {
    const t = testing;
    var rng = std.Random.DefaultPrng.init(seed_val);
    const random = rng.random();

    var seed_kem: [params.seed_bytes]u8 = undefined;
    random.bytes(&seed_kem);
    const kp = Kem.keypair(&seed_kem);

    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const enc = Kem.encaps(kp.ek, &coins);

    const u_bytes = Kem.Ring.n_bytes;
    const v_bytes = Kem.Pke.Code.codeword_len;

    var corrupt_u = enc.ct;
    corrupt_u[0] ^= 0x01; // inside u
    var corrupt_v = enc.ct;
    corrupt_v[u_bytes] ^= 0x01; // inside v
    var corrupt_salt = enc.ct;
    corrupt_salt[u_bytes + v_bytes] ^= 0x01; // inside salt

    const reject_u = Kem.decaps(kp.dk, corrupt_u);
    const reject_v = Kem.decaps(kp.dk, corrupt_v);
    const reject_salt = Kem.decaps(kp.dk, corrupt_salt);

    // Three DIFFERENT corrupted ciphertexts must produce three DIFFERENT
    // rejection values. An honest implementation hashes over the literal
    // `ct` bytes it was given, so this holds trivially; a mutant that
    // derives `K_bar` from something that does not vary with `ct` (e.g. a
    // fixed domain constant, or the re-encrypted `ct'` in a case where
    // `ct'` happens not to depend on the corrupted byte) would collide here.
    try t.expect(!std.mem.eql(u8, &reject_u, &reject_v));
    try t.expect(!std.mem.eql(u8, &reject_v, &reject_salt));
    try t.expect(!std.mem.eql(u8, &reject_u, &reject_salt));
}

test "implicit reject: rejection value depends on which ciphertext byte was corrupted" {
    try testImplicitRejectDependsOnCt(Kem128, 400);
    try testImplicitRejectDependsOnCt(Kem192, 401);
    try testImplicitRejectDependsOnCt(Kem256, 402);
}

// ── fuzz: decaps on arbitrary ciphertext bytes ──────────────────────────
//
// `decaps` is the module's untrusted-input entry point: a `Ciphertext`
// arrives from a peer and MUST NEVER panic or read out of bounds,
// however its bits are set — that is HQC-KEM's whole implicit-rejection
// contract (see `kem.zig`'s module doc and the property test above,
// which only ever flips one bit). This drives fully arbitrary bytes
// through the concatenated Reed-Muller/Reed-Solomon DECODE path (this
// arc's Fable-hard core — `code.zig`'s `decode`, syndromes, Berlekamp-
// Massey, Gao-Mateer root-finding) against a fixed keypair, rather than
// the property test's single-bit-flip corruption. HQC-128 only (the
// smallest parameter set): the decoder cost is the same shape at every
// security level, and the gate only requires one harness to exist
// per module.
fn fuzzDecaps(_: void, smith: *std.testing.Smith) !void {
    const seed_kem = [_]u8{0x37} ** params.seed_bytes;
    const kp = Kem128.keypair(&seed_kem);

    var ct: Kem128.Ciphertext = undefined;
    smith.bytes(&ct);
    _ = Kem128.decaps(kp.dk, ct);
}

test "fuzz: decaps never panics on arbitrary ciphertext bytes" {
    try std.testing.fuzz({}, fuzzDecaps, .{});
}
