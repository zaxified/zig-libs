// SPDX-License-Identifier: MIT

//! Test-only helpers shared by the ECDSA keygen, refresh and resharing tests
//! (imported from test code only; not part of the module's API).

const std = @import("std");
const tecdsa = @import("threshold_ecdsa");
const aux_info = tecdsa.aux_info;

/// Test-only `LocalAux` from Blum primes: a second Paillier-Blum modulus
/// stands in for `Ñ` (production uses safe primes — `LocalAux.generate` —
/// which take minutes; Πprm/Πmod hold over any Blum modulus with a known
/// `λ`, so the proofs and every check run for real).
pub fn quickLocal(allocator: std.mem.Allocator, random: std.Random) !aux_info.LocalAux {
    var key: tecdsa.PaillierBlumKey = undefined;
    try tecdsa.generatePaillierBlum(random, 2048, &key);
    errdefer key.wipe();
    var ring: tecdsa.PaillierBlumKey = undefined;
    try tecdsa.generatePaillierBlum(random, 2048, &ring);
    defer ring.wipe();
    const nt = ring.modulus();
    var buf: [tecdsa.aux_modulus_bytes]u8 = undefined;
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const h2 = nt.sq(try tecdsa.AuxFe.fromBytes(nt, &buf, .big));
    random.bytes(&buf);
    buf[0] &= 0x3f;
    const lambda = try tecdsa.AuxFe.fromBytes(nt, &buf, .big);
    const h1 = try nt.pow(h2, lambda); // h1 ∈ ⟨h2⟩, the relation Πprm proves
    const p = try allocator.dupe(u8, ring.p());
    errdefer allocator.free(p);
    const q = try allocator.dupe(u8, ring.q());
    var seed: [32]u8 = undefined;
    random.bytes(&seed);
    const aux: tecdsa.AuxParams = .{ .n_tilde = nt, .h1 = h1, .h2 = h2 };
    var trapdoor: tecdsa.AuxTrapdoor = .{ .p = p, .q = q, .lambda = lambda };
    var local: aux_info.LocalAux = undefined;
    aux_info.LocalAux.fromParts(&key, aux, &trapdoor, &seed, &local);
    return local;
}
