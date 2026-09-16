// SPDX-License-Identifier: MIT
//! ctgrind harness for `blindrsa` — the instrument for `SPEC.md`'s
//! "Constant-time posture (as implemented)" paragraph under "Threat model /
//! limits":
//!
//!   "every modular multiplication and exponentiation on secret material
//!    goes through `std.crypto.ff`'s constant-time paths — the private-key
//!    operation inside `blindSign` is `rsa.rsasp1`'s CRT modexp
//!    (constant-time `pow`), and every secret-operand `mul` (blinding,
//!    unblinding, unmasking) is `ff`'s constant-time multiplication. The
//!    ONE inherently non-constant-time piece is the extended-Euclid modular
//!    inverse … The secret paths therefore never feed a raw secret into
//!    it: `blind` and `blindSign` invert through `maskedInvert`, which runs
//!    Euclid on `v = x·u mod n` for a fresh uniform secret mask `u` … and
//!    unmasks with one more constant-time `mul`."
//!
//! Until this harness that paragraph had no measurement behind it. Run it
//! by hand (this module has NO per-module block in `scripts/ctgrind.sh` yet
//! — see that script's header for why, and the suggested config lines at
//! the bottom of this comment for what to paste in):
//!
//!   zig build ctgrind -Dctgrind-module=blindrsa -Dctgrind-valgrind=true  -Doptimize=ReleaseFast
//!   zig build ctgrind -Dctgrind-module=blindrsa -Dctgrind-valgrind=false -Doptimize=ReleaseFast
//!   valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!       zig-out/ctgrind/ctgrind-blindrsa <target> <yes|no>
//!
//! ## The two targets — two secrets, two different parties
//!
//! `blindrsa` has exactly two operations that consume secret material, held
//! by two different parties, and they are measured separately rather than
//! folded into one row:
//!
//! - `.blind` — the CLIENT's blinding factor `r` (`blind`'s own arithmetic:
//!   `sampleFe`/`maskedInvert`/`feInvert`/`blindCore`, all in THIS module's
//!   `root.zig`, bottoming out in `rsa.bigModInverse` — a routine `rsa`
//!   exports and `blindrsa` calls, so it is "inherited" in the sense of
//!   living in the sibling module's file, but the DECISION to run it on a
//!   masked value instead of `r` itself is entirely this module's). This is
//!   `blindrsa`'s own arithmetic and the one SPEC.md stakes a real claim on
//!   ("the secret paths … invert through `maskedInvert`").
//! - `.sign` — the SERVER's `rsa.SecretKey` (the CRT fields) entering
//!   `blindSign`. Mostly inherited: the private-key operation itself is
//!   `rsa.rsasp1`'s CRT modexp, i.e. exactly the arithmetic `rsa`'s own
//!   `ctgrind_harness.zig` (`crt` target) already measures. What is
//!   `blindrsa`'s OWN code on this path is the §7.2 blinding wrapper
//!   around it (`blindSign`'s `sk.n.mul(s_b, b_inv)`, the self-check
//!   comparison, the final `Fe.fromBytes`/`memcpy`) — all downstream of
//!   `rsasp1`'s tainted output, in `blindrsa`'s `root.zig`.
//!
//! Deliberately NOT tainted in either target: the public modulus `n`/`n_mont`,
//! the public exponent `e`, the message/salt, the blinded value the server
//! sees, and (in `.sign`) the server's own per-call blinding factor `b` — `b`
//! is drawn fresh from the harness's own untainted deterministic RNG, so any
//! context this target reports is attributable to `sk`, not to `b`.
//!
//! ## Why `.blind` taints at the SOURCE, not after construction
//!
//! `rsa`'s and `ct25519`'s harnesses build a plaintext secret first and then
//! call `std.valgrind.memcheck.makeMemUndefined` on specific struct fields
//! in place (needing `reloadVolatile` as insurance against the optimizer
//! keeping a pre-taint copy). `blind`'s blinding factor `r` is sampled
//! INSIDE `blind` itself (`sampleFe(pk.n, random)`, private, not reachable
//! from outside the module) — there is no struct field to taint after the
//! fact. Instead, `BlindRandom` below is a `std.Random` whose `fill` call
//! (the ONE `random.bytes()` draw `sampleFe` makes to produce `r`, for this
//! fixed KAT modulus and the RFC's own `r` — see below) writes the fixed
//! bytes and then, in the tainted mode, immediately marks them undefined —
//! so the memory `r` is read from is *born* tainted rather than tainted
//! after a window where an untainted copy could exist. Every OTHER `fill`
//! call (`blind`'s own salt draw, now made before `r` is sampled — audit
//! finding B16 — the masking secret `u` inside `maskedInvert`, redraws, and
//! `.sign`'s server-side blinding factor `b`) is served from a separate
//! deterministic CSPRNG stream that is never tainted; `BlindRandom`
//! distinguishes the `r` draw from the others by LENGTH
//! (`r_bytes.len` == the modulus length, never the salt's `Hash
//! .digest_length`/`0`), not by call order. This also means `.blind` needs
//! no `reloadVolatile`: there is no pre-taint copy to guard against,
//! because the call dispatches through the `std.Random` vtable (a real
//! indirect call) before the bytes exist at all.
//!
//! `.sign` DOES taint an existing struct (`rsa.SecretKey`, built from the
//! module's own KAT) after construction, exactly like `rsa`'s `crt` target
//! — `reloadVolatile` is used there for the same reason it is in `rsa`'s
//! harness.
//!
//! ## The fixed key and blinding factor
//!
//! `kat_vectors.zig`'s `secretKey`/`publicKey`/`r` are the module's own
//! RFC 9474 Appendix A.1/A.4 KAT (a real, committed, reproducible 4096-bit
//! key) — reused here rather than generating a fresh key, for the same
//! comparability-across-runs reason `rsa`'s harness gives, and reused
//! rather than duplicated because `kat_vectors.zig` already makes these
//! `pub` (unlike `rsa`'s `kat2048`, which is not `pub` and had to be
//! duplicated by that harness). `kat.r` is a valid blinding factor for
//! `kat.n` (RFC-published-derived, cross-checked in `kat_vectors.zig`'s own
//! doc comment), so feeding it on the modulus-length-sized draw is accepted
//! by `sampleFe`'s rejection loop on the very first attempt — no retry, so
//! exactly one `fill` call carries the taint.
//!
//! ## The two traps (see `ct25519`'s or `rsa`'s harness)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind` (off by default outside Debug) — build both ways; the
//!    driver script's own row for this is the "trap" row below.
//! 2. `.sign`'s `reloadVolatile` forces one real byte-by-byte load of the
//!    whole `SecretKey` through a volatile pointer immediately before the
//!    call under test, so the private op cannot be fed a pre-taint copy.
//!    `.blind` has no analogous risk — see above.
//!
//! ## The propagation proof
//!
//! Both targets format their tainted-derived result through
//! `std.debug.print` (not constant-time by design) before returning — the
//! WITNESS bucket — so a zero count inside `root.zig`/`rsa`'s files means
//! "no branch found", not "taint never arrived".
//!
//! ## Suggested `scripts/ctgrind.sh` config (for the coordinator to paste in)
//!
//! ⚠ `root.zig` is NOT a unique basename here: `blindrsa`'s own
//! `modules/blindrsa/src/root.zig` and the sibling `modules/rsa/src/root.zig`
//! BOTH appear in `.blind`'s and `.sign`'s call stacks, and
//! `classify_contexts` buckets by matching the pattern against entire
//! stack-frame TEXT lines, not by module directory. Check what valgrind
//! actually prints for a frame (a bare `(root.zig:NNN)` or something
//! path-qualified) before trusting a plain `root[.]zig` to mean "blindrsa's
//! own file" here the way it unambiguously does in `rsa`'s own recipe —
//! this harness's report separates the two by line number, not by pattern.
//!
//!   [blindrsa]="blind sign"                                   # TARGETS
//!   [blindrsa]="ReleaseFast"                                  # MODES
//!   [blindrsa/blind]='root[.]zig|ff[.]zig'   # PATTERN — both root.zigs + std.crypto.ff (bigModInverse's operand construction, Modulus.mul/Fe ops)
//!   [blindrsa/sign]='root[.]zig|ff[.]zig'    # PATTERN — both root.zigs (rsasp1's CRT path + the §7.2 wrapper) + std.crypto.ff
//!   [blindrsa/blind]='blindrsa blind (client r, masked inverse)'   # LABEL
//!   [blindrsa/sign]='blindrsa blindSign (server sk, +std ff)'      # LABEL

const std = @import("std");
const builtin = @import("builtin");
const blindrsa = @import("root.zig");
const rsa = @import("rsa");
const kat = @import("kat_vectors.zig");

const Target = enum { blind, sign };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "blind")) return .blind;
    if (std.mem.eql(u8, s, "sign")) return .sign;
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

/// Force one real byte-by-byte load of `s` through a volatile pointer, so
/// `.sign`'s private op cannot be fed a copy of `T` that predates
/// `makeMemUndefined` — see trap 2 in the module doc comment above. Same
/// shape as `rsa`'s and `ct25519`'s harnesses.
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

/// `std.Random` that hands out the CLIENT's blinding factor `r` on the
/// FIRST `fill` call WHOSE LENGTH MATCHES `r_bytes.len` (from the fixed KAT
/// bytes, tainted iff `r_taint == .yes` — see "Why `.blind` taints at the
/// SOURCE" above), and real deterministic-but-never-tainted bytes from a
/// `ChaCha` CSPRNG on every other call (audit finding B16: `blind` now
/// draws its own PSS salt from `random` BEFORE sampling `r` — `Hash
/// .digest_length` or `0` bytes, never `r_bytes.len`, so length alone still
/// discriminates the salt draw, `sampleFe`'s `r` draw, the masking secret
/// `u` inside `maskedInvert`, any redraw, and — for `.sign` — the server's
/// own blinding factor `b`). This is the ONE controlled variable in
/// `.blind`'s measurement: everything the masked-inversion pipeline touches
/// besides `r` comes from a real, untainted random stream — including the
/// salt, which is public in the final signature and was never the secret
/// this harness measures.
const BlindRandom = struct {
    r_bytes: []const u8,
    r_taint: Taint,
    used_r: bool = false,
    csprng: std.Random.ChaCha,

    fn init(r_bytes: []const u8, r_taint: Taint, seed: [32]u8) BlindRandom {
        return .{ .r_bytes = r_bytes, .r_taint = r_taint, .csprng = std.Random.ChaCha.init(seed) };
    }

    fn fill(self: *BlindRandom, buf: []u8) void {
        if (!self.used_r and buf.len == self.r_bytes.len) {
            self.used_r = true;
            @memcpy(buf, self.r_bytes);
            taintBytes(self.r_taint, buf);
            return;
        }
        self.csprng.random().bytes(buf);
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    const pk = try kat.publicKey();

    switch (target) {
        .blind => {
            // r is the ONLY tainted value; the masking secret `u` (drawn
            // inside maskedInvert via the SAME `random`) and every redraw
            // come from the untainted ChaCha stream below — see BlindRandom.
            var br = BlindRandom.init(&kat.r, taint, [_]u8{0x51} ** 32);
            const random = std.Random.init(&br, BlindRandom.fill);

            var ctx: blindrsa.Context = undefined;
            var blinded_msg: [blindrsa.max_modulus_len]u8 = undefined;
            const blinded = try blindrsa.blind(
                pk,
                std.crypto.hash.sha2.Sha384,
                &kat.a1.prepared_msg,
                kat.a1.salt.len,
                random,
                &ctx,
                &blinded_msg,
            );

            // Propagation proof: blinded_msg = m * RSAVP1(pk, r) mod n, so a
            // tainted r makes blinded_msg tainted too.
            std.debug.print("blinded={x}\n", .{blinded});
        },
        .sign => {
            // b (the server's own §7.2 blinding factor) is drawn fresh from
            // an untainted deterministic CSPRNG — only sk is tainted.
            var csprng = std.Random.ChaCha.init([_]u8{0x9c} ** 32);
            const random = csprng.random();

            var sk = try kat.secretKey();
            // Same field set as rsa's `crt` target: the CRT primes/exponents/
            // coefficient and their Montgomery params. n/n_mont/e stay public
            // (see the module doc comment for why).
            taintBytes(taint, std.mem.asBytes(&sk.p));
            taintBytes(taint, std.mem.asBytes(&sk.q));
            taintBytes(taint, std.mem.asBytes(&sk.dp));
            taintBytes(taint, std.mem.asBytes(&sk.dq));
            taintBytes(taint, std.mem.asBytes(&sk.qinv));
            taintBytes(taint, std.mem.asBytes(&sk.p_mont));
            taintBytes(taint, std.mem.asBytes(&sk.q_mont));
            const sk_reloaded = reloadVolatile(rsa.SecretKey, &sk);

            // The RFC's own published blinded_msg — a fixed, public,
            // "attacker/client-chosen" input, built outside the measured
            // region (it is just KAT bytes here, not derived from anything
            // tainted).
            var out: [blindrsa.max_modulus_len]u8 = undefined;
            const sig = try blindrsa.blindSign(&sk_reloaded, pk, random, &kat.a1.blinded_msg, &out);

            // Propagation proof: the blind signature is derived from the
            // tainted sk via rsasp1 + the §7.2 unblind multiply.
            std.debug.print("blind_sig={x}\n", .{sig});
        },
    }
}
