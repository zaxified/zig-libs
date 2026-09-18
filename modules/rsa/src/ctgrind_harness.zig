// SPDX-License-Identifier: MIT
//! ctgrind harness for `rsa` — the instrument for `SPEC.md`'s "Threat model /
//! out of scope" sentence:
//!
//!   "Constant-time requirements on every secret-dependent operation
//!    (`rsadp`/`rsadpCrt`/`rsasp1`/CRT parameter handling — routes through
//!    `montint`/`Modulus.pow`, never a public-exponent path, and never
//!    branches on secret data)"
//!
//! Until this harness that sentence had no measurement behind it. Run it
//! through `../../../scripts/checks/ctgrind.sh rsa`; that script's header has the
//! exact commands.
//!
//! ## What is tainted, and what is deliberately NOT
//!
//! The private key: the CRT primes `p`/`q`, the CRT exponents `dp`/`dq`, the
//! CRT coefficient `qinv`, their precomputed Montgomery params `p_mont`/
//! `q_mont` (target `crt`, driving `rsadpCrt` — the fast default path every
//! real caller uses), or the non-CRT exponent `d` (target `noncrt`, driving
//! `rsadp`). The modulus `n`, its Montgomery params `n_mont`, and the public
//! exponent `e` stay untainted in both targets: they are public, derived from
//! `n` alone, and a harness that flags branches on them would be measuring
//! the wrong thing (the module's own SPEC calls out "never a public-exponent
//! path" as the thing that must stay clean).
//!
//! Only the private-key operations are driven — `rsaep`/`rsavp1` (the
//! public-key path: verification, encryption with `e`) are out of scope by
//! the same reasoning and are not reachable from this file's `Target` enum.
//! The ciphertext fed to both targets IS built with `rsaep` first, but that
//! call runs BEFORE any taint is applied — it is the attacker-chosen public
//! input, not part of the claim.
//!
//! ## The fixed key
//!
//! `p`/`q`/`e` below are the module's own 2048-bit OpenSSL KAT (`kat2048` in
//! `root.zig`'s test suite; not `pub`, so the literal bytes are duplicated
//! here rather than imported) — a committed, reproducible key rather than a
//! freshly generated one, so repeated runs of the table are comparable and no
//! run pays RSA keygen's cost. Sized so the CRT halves land on montint's
//! `L=16` slot (1024-bit primes -> 16 64-bit limbs), the portable CIOS path
//! `root.zig`'s own comment calls out as the common RSA-2048 case (`L=16 <
//! montint's asm_min_limbs=32`) — the textbook 61/53/17 key used elsewhere in
//! this module's tests would instead force the smallest slot (`L=4`) and
//! exercise a width no real RSA-2048 key ever uses.
//!
//! ## Why the pattern also names `montint`'s files
//!
//! `rsadpCrt`/`rsadp` bridge bytes into limbs and do the Garner CRT
//! recombination in THIS module's `root.zig`, but the actual Montgomery
//! ladder (`powMont`) that consumes the secret exponent runs inside the
//! sibling `montint` module (`montint.zig`/`limbs.zig`/`asm_core.zig`) — the
//! same "our own arithmetic, not std's" reasoning `bolt8`'s harness applies
//! to `k256`. `std.crypto.ff` plays no role in the hot path this harness
//! drives (SPEC.md: "routes through montint/Modulus.pow" — `Modulus.pow` is
//! the key-derivation-time path, exercised by `SecretKey.fromPrimes` below
//! BEFORE any taint, never by `rsadpCrt`/`rsadp`).
//!
//! ## The two traps (see `ct25519`'s harness or `scripts/checks/ctgrind.sh`'s header)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without `-fvalgrind`
//!    (off by default outside Debug) — the driver script builds both ways so
//!    this shows up as its own trap row, not a silent false clean.
//! 2. The optimizer could in principle keep a defined copy of a tainted field
//!    from before `makeMemUndefined` ran (this harness builds the whole
//!    `SecretKey` untainted first, then taints specific fields in place).
//!    `reloadVolatile` forces one real byte-by-byte load of the WHOLE struct
//!    through a volatile pointer immediately before the call under test, so
//!    the private op cannot be fed a pre-taint copy.
//!
//! ## The propagation proof
//!
//! After the call, the result is formatted through `std.debug.print`, which
//! is NOT constant-time by design (digit/hex formatting branches on the
//! value). Its contexts are reported separately (the WITNESS bucket) from
//! the target's own contexts, so a zero count inside `root.zig`/`montint`
//! means "no branch found", not "taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const rsa = @import("root.zig");

/// Duplicated from `root.zig`'s private `hexLit` — same shape, not `pub`
/// there so not importable.
fn hexLit(comptime hex: []const u8) [hex.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [hex.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
        return out;
    }
}

// The module's own committed 2048-bit OpenSSL KAT (`kat2048` in
// `root.zig`'s tests) — see the module doc comment above for why this key
// and not the textbook 61/53/17 one used elsewhere in the test suite.
const kat_e = [_]u8{ 0x01, 0x00, 0x01 }; // 65537
const kat_p = hexLit("cd91a6496cfb79576c073ddea09edc423deebdaa3b103017d00572ebb61b1a05b9e7340239fd8019790b76ec74233842f786d620f80362ca455e6c0b26859db9e5c50d71c551759ffd2ef2facc98c10d6c2e8e0662a5d25a0d847c4fc54a062fc4bb75c552ae1cdef197916cd81c4dd102f314a8a4eb8c73c5c6b3e85c40a11d");
const kat_q = hexLit("c9c4dbb594569066caaaadbf5be98990357e0ea3d3619601b2155bac8ed96b28d6eec9578163dd3b08e0132a0f91a99c98a139b3e7b016f7e83dfe6e18d97b4448dccab617a3ac3aa6aa1359c3f5396473f4b0b20038252ae1d77e8cdf1fce2a9f4ea3208269f79d516e7b9a22e2fe4b4dad87621173348f896e2303cae5b59f");
const kat_n = hexLit("a2056f805f21fbf8815681fc5f7bb07bb8c7cba3be6e10ef3c3905981d666aa60adde3a7ebd258efae4e0d120e109c42cde35c6c322287135644e25eb79640aa91bc69a63b96fc3a72d85641cf567f4d4775c70c11d3c319989e764bc94c68002eb159d8fb05b73cafe489fb33b99e8f58ada35d59577e657f5097bb0e7a3f53e74b3592dbb31772092b96ab5aac70cef3b2afb54d1a35da41e895222c898f0306f9cd9ecb5b4e3bee111dcd5bfc44b976e7620b0e01b3072d0d3f5e995dcf20aa78d6633ef658bc1468f311ac4e6e005b2cf37d18f82cdc661f7d8cbd93709a4c122dd732bd243632b4a9d51da2f1d3c677a54d0f36c8f8458165d2fefe9203");

const modulus_len = 256; // 2048 bits / 8

/// Force one real byte-by-byte load of `s` through a volatile pointer, so the
/// private op cannot be fed a copy of `T` that predates `makeMemUndefined` —
/// see trap 2 in the module doc comment above.
fn reloadVolatile(comptime T: type, s: *const T) T {
    var out: T = undefined;
    const src = std.mem.asBytes(s);
    const dst = std.mem.asBytes(&out);
    for (dst, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { crt, noncrt };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "crt")) return .crt;
    if (std.mem.eql(u8, s, "noncrt")) return .noncrt;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    // Key construction (variable-time by SPEC's own admission: fromPrimes'
    // n/lambda/d/dP/dQ derivation uses std.math.big.int) runs entirely on the
    // UNTAINTED fixed KAT bytes -- this is the one-time key-import cost the
    // module's doc comment excludes from the constant-time claim, not the
    // per-operation path this harness measures.
    var sk = try rsa.SecretKey.fromPrimes(&kat_p, &kat_q, &kat_e);
    const pk = try rsa.PublicKey.fromBytes(&kat_n, &kat_e);

    // A fixed, public "attacker-chosen" ciphertext: encrypt a fixed message
    // representative (< n: top byte held at 0) with the PUBLIC key, before
    // any taint exists. This is RSAEP -- the public-key path -- and is
    // deliberately built outside the measured region.
    var m: [modulus_len]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = @truncate(i *% 37 +% 11);
    m[0] = 0;
    const c = try rsa.rsaep(modulus_len, m, pk);

    // Taint exactly the fields the target's private op reads, and nothing
    // else -- see the module doc comment for why n/n_mont/e stay public in
    // both targets.
    switch (target) {
        .crt => {
            taintBytes(taint, std.mem.asBytes(&sk.p));
            taintBytes(taint, std.mem.asBytes(&sk.q));
            taintBytes(taint, std.mem.asBytes(&sk.dp));
            taintBytes(taint, std.mem.asBytes(&sk.dq));
            taintBytes(taint, std.mem.asBytes(&sk.qinv));
            // p_mont/q_mont are separate memory from p/q (precomputed at key
            // construction), carrying the same secret value in Montgomery
            // form -- montPowSecret reads THIS struct's `.m` as the modulus,
            // so leaving it untainted would let the ladder consume the
            // secret modulus through a channel the taint never reached.
            taintBytes(taint, std.mem.asBytes(&sk.p_mont));
            taintBytes(taint, std.mem.asBytes(&sk.q_mont));
        },
        .noncrt => {
            taintBytes(taint, std.mem.asBytes(&sk.d));
        },
    }

    const sk_reloaded = reloadVolatile(rsa.SecretKey, &sk);

    var out: [modulus_len]u8 = undefined;
    switch (target) {
        .crt => out = try rsa.rsadpCrt(modulus_len, c, sk_reloaded),
        .noncrt => out = try rsa.rsadp(modulus_len, c, sk_reloaded),
    }

    // Propagation proof: format the (tainted, if taint=yes) result through a
    // non-constant-time path. See the module doc comment above.
    std.debug.print("m={x}\n", .{out});
}
