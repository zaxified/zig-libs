// SPDX-License-Identifier: MIT

//! What a 2-server private-analytics setup does with `fss`: the client
//! secret-shares a point function `f_{α,β}` — "give record α a vote worth
//! β" — into two DPF keys, ships one to each non-colluding server, and each
//! server evaluates its own key over (a slice of) the shared domain without
//! ever learning α or β. Summing the two servers' shares reconstructs the
//! function; each key alone is uniformly random. This example plays both
//! servers locally to check reconstruction, then shows the wire codec's
//! format guard rejecting a key meant for a different PRG.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const fss = @import("fss");

// A 256-record domain (n=8), votes counted in a 32-bit group (L=4 bytes).
const D = fss.Dpf(8, 4);

pub fn main() !void {
    const alpha: D.Index = 42; // the record this vote targets
    const beta: D.Elem = 7; // the vote's weight

    // `fss` deliberately has no entropy dependency of its own (SPEC.md: the
    // two root seeds are the DPF's only source of randomness, and keeping
    // them caller-supplied is what makes this module pure `.any`
    // computation). `std.crypto.random` was removed in Zig 0.16, so a real
    // deployment seeds a CSPRNG-backed `std.Random` itself; this example
    // seeds one from a fixed array instead of reading OS entropy, to stay
    // self-contained.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rand = csprng.random();

    var s0: fss.prg.Seed = undefined;
    var s1: fss.prg.Seed = undefined;
    rand.bytes(&s0);
    rand.bytes(&s1);

    const keys = D.genWithSeeds(alpha, beta, s0, s1);
    const k0 = keys[0];
    const k1 = keys[1];

    // Each server sums its own share over the whole domain via the
    // tree-reuse evaluator — the realistic path (a real domain is far
    // bigger than one `eval` call per record would tolerate).
    var share0: [D.domain_size]D.Elem = undefined;
    var share1: [D.domain_size]D.Elem = undefined;
    D.evalFull(0, k0, &share0);
    D.evalFull(1, k1, &share1);

    // Reconstruct: at every point except alpha the two shares cancel to
    // zero; at alpha they sum to beta. A third party sees only one share,
    // which is why this delivers privacy — but the example, playing both
    // servers, can check correctness directly.
    var nonzero_count: usize = 0;
    var reconstructed_at_alpha: D.Elem = 0;
    var x: usize = 0;
    while (x < D.domain_size) : (x += 1) {
        const sum = D.G.add(share0[x], share1[x]);
        if (sum != 0) {
            nonzero_count += 1;
            if (x == alpha) reconstructed_at_alpha = sum;
        }
    }
    std.debug.print("nonzero points: {d} (expect 1), reconstructed value at alpha: {d} (expect {d})\n", .{ nonzero_count, reconstructed_at_alpha, beta });

    // Wire round trip: a key travels to its server as tagged bytes.
    var buf0: [D.Key.tagged_len]u8 = undefined;
    k0.toBytesTagged(&buf0);
    const decoded0 = try D.Key.fromBytesTagged(&buf0);
    std.debug.print("decoded key reproduces eval(0, k0, alpha): {}\n", .{D.eval(0, decoded0, alpha) == D.eval(0, k0, alpha)});

    // A key produced by the OTHER PRG instantiation must be rejected by
    // name, not silently decoded into a garbage (but same-length) key —
    // this is exactly what the format tag exists to catch.
    const DSha = fss.DpfWith(fss.prg.Sha256Prg, 8, 4);
    const sha_keys = DSha.genWithSeeds(alpha, beta, s0, s1);
    var sha_buf: [DSha.Key.tagged_len]u8 = undefined;
    sha_keys[0].toBytesTagged(&sha_buf);
    // Same tagged length as the AES instantiation, so only the tag byte
    // stands between this and silently wrong bytes.
    std.debug.assert(sha_buf.len == buf0.len);
    _ = D.Key.fromBytesTagged(&sha_buf) catch |err| switch (err) {
        error.UnsupportedKeyFormat => std.debug.print("cross-PRG key correctly rejected by its format tag\n", .{}),
    };
}
