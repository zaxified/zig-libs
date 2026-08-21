// SPDX-License-Identifier: MIT

//! What a PQ-KEM consumer does with `hqc`: generate a keypair, encapsulate a
//! shared secret to it, decapsulate on the other side, and confirm both
//! ends agree. Then flip one ciphertext byte and decapsulate again — HQC's
//! Fujisaki-Okamoto transform uses IMPLICIT rejection (spec §4.2): a
//! tampered ciphertext never surfaces as an error, it silently produces a
//! different (pseudorandom) shared secret instead, so a caller's only
//! signal that something went wrong is exactly this kind of mismatch.
//!
//! Uses `Hqc128` (NIST category 1, the fastest parameter set) — the same
//! API shape (`keypair`/`encaps`/`decaps`, all named byte-array sizes)
//! applies to `Hqc192`/`Hqc256`.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a
//! type/size needed to drive the KEM is not re-exported, this file stops
//! compiling.

const std = @import("std");
const hqc = @import("hqc");
const Kem = hqc.Hqc128;

pub fn main() !void {
    // The module takes randomness as explicit caller-supplied bytes rather
    // than owning a PRNG (its own doc comment) -- a real caller seeds a
    // std.Random.DefaultCsprng from getrandom(2); this example uses a fixed
    // seed so the run is reproducible, the same posture the sibling
    // bolt8/falcon/dtls examples take for their own entropy inputs.
    var rng: std.Random.DefaultPrng = .init(0x48_51_43_5f_73_65_65_64);
    const random = rng.random();

    var seed: [32]u8 = undefined; // params.seed_bytes
    random.bytes(&seed);
    const kp = Kem.keypair(&seed);

    std.debug.print("Hqc128: ek={d}B dk={d}B ct={d}B ss={d}B coins={d}B\n", .{
        Kem.ek_bytes, Kem.dk_bytes, Kem.ct_bytes, Kem.ss_bytes, Kem.coins_bytes,
    });

    // Bob encapsulates to Alice's encapsulation key.
    var coins: [Kem.coins_bytes]u8 = undefined;
    random.bytes(&coins);
    const encapsed = Kem.encaps(kp.ek, &coins);

    // Alice decapsulates with her decapsulation key.
    const ss_alice = Kem.decaps(kp.dk, encapsed.ct);
    if (!std.mem.eql(u8, &ss_alice, &encapsed.ss)) @panic("shared secrets must agree on a genuine exchange");
    std.debug.print("shared secret agreed, {d} bytes\n", .{ss_alice.len});

    // Tamper with one ciphertext byte and decapsulate again. No error is
    // raised -- decaps has no fallible return at all, by design (implicit
    // rejection) -- but the recovered secret must silently diverge from
    // the genuine one, which is the only signal a caller gets.
    var tampered_ct = encapsed.ct;
    tampered_ct[0] ^= 0x01;
    const ss_tampered = Kem.decaps(kp.dk, tampered_ct);
    if (std.mem.eql(u8, &ss_tampered, &encapsed.ss)) @panic("a tampered ciphertext must not decapsulate to the genuine secret");
    std.debug.print("tampered ciphertext correctly diverged (implicit rejection, no error raised)\n", .{});
}
