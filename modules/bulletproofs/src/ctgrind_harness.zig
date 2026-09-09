// SPDX-License-Identifier: MIT

//! ctgrind_harness — constant-time evidence for the Bulletproofs PROVER
//! (`rangeproof.prove` / `ipa.proveIpa`), as an actual committed program.
//! Suggested driver commands (this module has no `TARGETS`/`MODES`/
//! `PATTERN`/`LABEL` entry in `../../../scripts/ctgrind.sh` yet — that
//! script's header explains why a per-module block belongs there, not
//! here; the lines below are what such a block would contain):
//!
//! ```text
//! zig build ctgrind -Dctgrind-module=bulletproofs -Dctgrind-valgrind=true
//! zig build ctgrind -Dctgrind-module=bulletproofs -Dctgrind-valgrind=false
//! valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!     zig-out/ctgrind/ctgrind-bulletproofs rangeproof yes
//!     # ...and {rangeproof,ipa} x {yes,no}, plus the -valgrind=false build
//!     # run the same way (that build is the row 3 "silent no-op" trap).
//!
//! TARGETS[bulletproofs]="rangeproof ipa"
//! MODES[bulletproofs]="ReleaseFast"
//! PATTERN[bulletproofs/rangeproof]='rangeproof[.]zig|ipa[.]zig|scalarvec[.]zig|generators[.]zig|transcript[.]zig|root[.]zig'
//! PATTERN[bulletproofs/ipa]='ipa[.]zig|scalarvec[.]zig|transcript[.]zig|root[.]zig'
//! LABEL[bulletproofs/rangeproof]='bulletproofs prove (v,gamma)+ct25519'
//! LABEL[bulletproofs/ipa]='bulletproofs ipa witness (l_x,r_x)+ct25519'
//! ```
//!
//! `root[.]zig` in both patterns is deliberate, not decorative — see
//! "Delegate: ct25519" below; it is also this module's OWN root.zig
//! basename, which is the exact `blindrsa`/`rsa` collision
//! `scripts/ctgrind.sh`'s header documents (same basename, two files,
//! matched by the same regex). Unlike that case, this module's own
//! `root.zig` is pure re-exports with no executable logic of its own (no
//! branches, nothing to attribute), so in practice a `root[.]zig` hit
//! here should always resolve to ct25519's `mulRistretto` when the
//! qualified symbol name is checked — but it must be CHECKED, not
//! assumed, exactly as `blindrsa/SPEC.md` did for its own collision.
//!
//! ## What this measures, and what it deliberately does not
//!
//! Two targets, both on the PROVER side only:
//!
//! * `rangeproof` — the full `rangeproof.prove(allocator, gens, transcript,
//!   v, gamma)` call, with the committed value `v` (`u64`) and its Pedersen
//!   blinding factor `gamma` (`[32]u8` scalar) tainted. This exercises the
//!   bit-decomposition (`a_L`/`a_R`), the `A`/`S`/`T1`/`T2` commitments
//!   (`scalarvec.multiScalarMul` -> `mulCt` -> ct25519's ladder), the
//!   `l(x)`/`r(x)` polynomial evaluation, and the IPA sub-call this
//!   function makes internally — end to end, exactly as a real caller
//!   drives it.
//! * `ipa` — a DIRECT call to `ipa.proveIpa(allocator, transcript, g_vec,
//!   h_vec, q, a_in, b_in)` with synthetic tainted `a_in`/`b_in` vectors
//!   standing in for `l(x)`/`r(x)` (the range proof's per-proof IPA
//!   witness — the values `a_L`/`a_R`/`s_L`/`s_R` and the challenge `x`
//!   fold into before entering the IPA). This isolates the recursive fold
//!   itself (`ipa.zig`'s round loop: cross inner products, `L`/`R`
//!   commitments, the `u`/`u^{-1}` fold of `a`/`b`/`g`/`h`) from the outer
//!   range-proof polynomial machinery, using the SAME public generators
//!   `Generators` derives (`g_vec`/`h_vec`) and an arbitrary public point
//!   (`gens.g`) standing in for the real `q = w*gens.g` the range proof
//!   binds per-instance — `w` is a Fiat-Shamir challenge (public), so
//!   which public point plays `q` has no bearing on the fold's timing.
//!
//! **NOT tainted, on purpose:**
//! - Every point (`gens.g`/`gens.h`/`g_vec`/`h_vec`, and every `A`/`S`/
//!   `T1`/`T2`/`L`/`R` the prove call produces) — points are public in
//!   this protocol; tainting one would report `Generators.init`'s own
//!   NUMS hash-to-curve derivation, or the codec/`toBytes` calls the
//!   propagation witness below uses, as findings nobody claims (mirrors
//!   `bn254`'s harness rule 1).
//! - Every Fiat-Shamir challenge (`y`, `z`, `x`, `w`, and each round's
//!   `u`/`u^{-1}`) — each is `transcript.challengeScalar(...)`, a
//!   deterministic hash of values already bound to the transcript
//!   (commitments + prior challenges), i.e. a PUBLIC function of public
//!   data. Tainting a challenge would misrepresent a public quantity as a
//!   secret one.
//! - **`rangeproof.prove`'s own internal blinding draws** — `alpha`,
//!   `rho`, `s_L`, `s_R`, `tau1`, `tau2` (`randomScalar()`, real
//!   `getrandom(2)` output, drawn INSIDE `prove` on every call). These are
//!   genuinely secret in the real protocol (their name is literally what
//!   the task brief means by "the per-proof nonces of the inner-product
//!   argument": `s_L`/`s_R` are exactly the blinding vectors that get
//!   folded into the IPA's `a_in`/`b_in` alongside the witness). This
//!   harness cannot taint them from the outside: `prove`'s public
//!   signature takes only `v`/`gamma`, drawing everything else from the
//!   OS itself, and hooking that draw would mean editing
//!   `rangeproof.zig`, out of scope for a harness (`modules/bulletproofs/
//!   src/*.zig` is not touched here). What the `rangeproof` target DOES
//!   show is that the SAME code paths those internal draws travel through
//!   (`multiScalarMul`/`mulCt`, the `l(x)`/`r(x)` construction, the IPA
//!   fold) carry no branch on `v`/`gamma`, which occupy structurally
//!   identical roles (secret scalars/vectors flowing into the same
//!   multiplications) — but this is an argument from code-path identity,
//!   not a direct measurement of `alpha`/`rho`/`s_L`/`s_R`/`tau1`/`tau2`
//!   themselves. The `ipa` target's synthetic `a_in`/`b_in` come closer:
//!   they occupy exactly the slot `l_x`/`r_x` (which `s_L`/`s_R` are
//!   summed into) fill in the real call.
//! - **The verify path is not exercised at all.** `rangeproof.verify`/
//!   `ipa.verifyIpa` operate only on published proof fields plus the
//!   public statement — there is no witness for them to leak, so there is
//!   nothing for a taint-propagation harness to check on that side (the
//!   task brief's own instruction: don't taint verify, and say so rather
//!   than silently skipping it — this comment is that statement).
//!
//! ## Delegate: ct25519
//!
//! `scalarvec.mulCt` (used by both targets, directly and via
//! `multiScalarMul`) is `ct25519.mulRistretto` — see `scalarvec.zig`'s own
//! header. Every scalar multiplication either target performs, secret or
//! public, bottoms out in ct25519's ladder, not this module's own code.
//! Naming ct25519 in the pattern (as `root[.]zig`, its only source file)
//! is the same posture `bolt8`/`bip340` take for their own k256 delegate:
//! attributing that arithmetic to "someone else's module" would be the
//! evasion `scripts/ctgrind.sh`'s header exists to refuse.
//!
//! ## The two traps (see `ct25519`/`bn254`'s harnesses for the same shape)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind` (off by default outside Debug) — a ReleaseFast binary
//!    built without it is a SILENT NO-OP under valgrind. The trap-row
//!    build (`-Dctgrind-valgrind=false`) exists to make that its own
//!    measured row rather than a false clean.
//! 2. The optimizer could in principle keep a defined copy of a tainted
//!    value around from before `makeMemUndefined` ran. `reloadVolatile`
//!    forces one real byte-by-byte load from freshly-tainted memory
//!    immediately before the call under test, exactly as the sibling
//!    harnesses do.
//!
//! ## The propagation proof
//!
//! After the call under test, this harness prints proof fields that are
//! DOWNSTREAM of the tainted input (`t_hat`/`tau_x` for `rangeproof`,
//! `a`/`b` for `ipa`) through `std.debug.print`, which is not
//! constant-time. Those contexts are classified separately (the WITNESS
//! bucket) — seeing them nonzero is what proves the taint actually
//! travelled through the call, so a zero count inside this module's own
//! files means "no branch found", not "taint never arrived".
//!
//! ## Sizing
//!
//! `n = 64` for both targets — the width `README.md` calls the typical
//! case ("`n` typically 64"), and the same size the IPA runs at inside a
//! real range proof. `ipa`'s direct call therefore exercises 6 fold
//! rounds (`log2(64)`), the same recursion depth the `rangeproof` target
//! reaches internally.

const std = @import("std");
const builtin = @import("builtin");
const bulletproofs = @import("root.zig");
const Ristretto255 = bulletproofs.Ristretto255;

const n = 64;

/// Deterministic (not comptime-folded) "random" `u64` witness value —
/// tainting requires real runtime memory, not a comptime constant.
fn secretValueBytes() [8]u8 {
    const msg = "ctgrind-bulletproofs-harness-secret-v-v1";
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(msg, &wide, .{});
    return wide[0..8].*;
}

/// Deterministic "random" scalar reduced mod L (the Ristretto255 scalar
/// field), domain-separated by `domain` alone.
fn secretScalarBytes(domain: []const u8) [32]u8 {
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(domain, &wide, .{});
    return Ristretto255.scalar.reduce64(wide);
}

/// Same, domain-separated additionally by an index — used to fill the
/// `ipa` target's length-`n` `a_in`/`b_in` vectors with distinct scalars.
fn secretScalarIndexed(domain: []const u8, i: usize) [32]u8 {
    var h = std.crypto.hash.sha2.Sha512.init(.{});
    h.update(domain);
    var idx: [8]u8 = undefined;
    std.mem.writeInt(u64, &idx, @intCast(i), .little);
    h.update(&idx);
    var wide: [64]u8 = undefined;
    h.final(&wide);
    return Ristretto255.scalar.reduce64(wide);
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` (see trap 2 above).
fn reloadVolatile(comptime len: usize, s: *const [len]u8) [len]u8 {
    var out: [len]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { rangeproof, ipa };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "rangeproof")) return .rangeproof;
    if (std.mem.eql(u8, s, "ipa")) return .ipa;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const tainted = (try parseTaint(taint_arg)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    const allocator = std.heap.page_allocator;

    // Public generators — never tainted (see module doc comment).
    const gens = try bulletproofs.Generators.init(allocator, n);
    defer gens.deinit(allocator);

    switch (target) {
        .rangeproof => {
            var v_raw = secretValueBytes();
            var gamma_raw = secretScalarBytes("ctgrind-bulletproofs-harness-gamma-v1");
            if (tainted) {
                std.valgrind.memcheck.makeMemUndefined(&v_raw);
                std.valgrind.memcheck.makeMemUndefined(&gamma_raw);
            }
            const v_bytes = reloadVolatile(8, &v_raw);
            const gamma = reloadVolatile(32, &gamma_raw);
            const v = std.mem.readInt(u64, &v_bytes, .little);

            var t = bulletproofs.Transcript.init(bulletproofs.rangeproof_domain);
            const proof = try bulletproofs.prove(allocator, gens, &t, v, gamma);
            defer proof.deinit(allocator);

            // Propagation witness: downstream of both v and gamma.
            std.debug.print("t_hat={x}\n", .{proof.t_hat});
            std.debug.print("tau_x={x}\n", .{proof.tau_x});
            std.debug.print("ipa_a={x}\n", .{proof.ipa.a});
            std.debug.print("ipa_b={x}\n", .{proof.ipa.b});
        },
        .ipa => {
            var a_in: [n][32]u8 = undefined;
            var b_in: [n][32]u8 = undefined;
            for (&a_in, &b_in, 0..) |*a, *b, i| {
                a.* = secretScalarIndexed("ctgrind-bulletproofs-harness-ipa-a-v1", i);
                b.* = secretScalarIndexed("ctgrind-bulletproofs-harness-ipa-b-v1", i);
            }
            if (tainted) {
                for (&a_in) |*a| std.valgrind.memcheck.makeMemUndefined(a);
                for (&b_in) |*b| std.valgrind.memcheck.makeMemUndefined(b);
            }
            var a_re: [n][32]u8 = undefined;
            var b_re: [n][32]u8 = undefined;
            for (&a_re, &a_in) |*o, *s| o.* = reloadVolatile(32, s);
            for (&b_re, &b_in) |*o, *s| o.* = reloadVolatile(32, s);

            var t = bulletproofs.Transcript.init(bulletproofs.ipa_domain);
            // `q = gens.g`: an arbitrary public point standing in for the
            // real `w*gens.g` — see module doc comment.
            const proof = try bulletproofs.proveIpa(allocator, &t, gens.g_vec, gens.h_vec, gens.g, &a_re, &b_re);
            defer proof.deinit(allocator);

            std.debug.print("ipa_a={x}\n", .{proof.a});
            std.debug.print("ipa_b={x}\n", .{proof.b});
        },
    }
}
