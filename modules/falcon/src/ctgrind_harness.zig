// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time instrument for `falcon`'s signing
//! key. Run it through `../../../scripts/checks/ctgrind.sh falcon`; that script's
//! header explains the two traps (silent no-op without `-fvalgrind`, and a
//! counting rule that must classify every context or fail).
//!
//! ## SPEC.md already says this module "should not get one" — read that first
//!
//! `SPEC.md`'s "Threat model / limits" section (§ Keygen + sign) states
//! plainly: "Why this module has no in-repo ctgrind harness, and should not
//! get one. ... `sampler`'s reject loop iterates a *value-dependent* number
//! of times and `berExp` keeps one data-dependent early break, both copied
//! deliberately from the reference ... the constant-time argument there is
//! Bernoulli decorrelation, not a fixed trip count. ctgrind measures exactly
//! what those two constructs do — branch on tainted data — so an in-repo row
//! for `falcon` would be a permanent red that measures the reference design
//! rather than a defect, and pinning it green would require excluding the
//! one primitive the whole gate exists to watch. A red that measures nothing
//! is worse than no row."
//!
//! That argument is about what `--check`'s green/red verdict is worth here,
//! not about whether the measurement itself has value. This file exists
//! anyway, on explicit instruction, for a narrower reason: `gaussian.zig`'s
//! own module doc already admits "no machine-checked constant-time
//! verification (dudect / ctgrind / binsec) has been run on the compiled
//! artifact" — that sentence had no measurement behind it at all, same gap
//! `oscore`'s harness closed for F8. Running it once, reading the actual
//! context count and source lines, and recording them is strictly more
//! honest than leaving the claim unmeasured. The coordinator, not this
//! file, decides whether `scripts/checks/ctgrind-expected.tsv` gets a permanent
//! (DEFECT-style, like `hqc`'s sampler row) entry for it or whether
//! `SPEC.md`'s "should not get one" stands as written.
//!
//! ## What is tainted
//!
//! `falcon.signRandomized`'s one secret input is `sk: *const SigningKey` —
//! the NTRU trapdoor basis (f, g, F, G). `sign.Signer.signWithRng` reads it
//! only through `sk.tree` (a `ffsampling.Tree(Ring)` copy of the same four
//! arrays — see `keygen.zig`'s `SigningKey`), and `ffsampling.sampleSignature`
//! turns it into the Gram matrix / LDL* decomposition and the per-leaf
//! (mu, sigma) that `gaussian.samplerZ` draws around. So this harness taints
//! exactly `sk.tree.{f,g,big_f,big_g}` — the bytes the call under test
//! actually dereferences — and nothing else:
//!
//!   * the key is generated fresh through `falcon.generateKeyPair` off an
//!     UNTAINTED, fixed-seed RNG first, so keygen's own NTRU acceptance loop
//!     and `signWithRng`'s norm-bound retry both see a normal, valid basis
//!     and behave exactly as they would in production;
//!   * only afterwards is `sk.tree` marked undefined, and reloaded through a
//!     volatile pointer (see `reloadVolatile` below) so the values
//!     `sampleSignature` reads are provably post-taint memory reads, not a
//!     register copy the optimizer kept from before the taint call;
//!   * the per-signature entropy (`rng`, threaded into `signRandomized` for
//!     the nonce and the internal ChaCha-seed draw) is left UNTAINTED
//!     throughout. That stream is public per-message randomness, not the key
//!     this claim is about — tainting it too would blur "the key leaks
//!     through the sampler" with "the nonce/salt draw is not itself
//!     constant-time", which is a different and unasked question.
//!
//! ## The propagation proof
//!
//! Same shape as every other harness in this collection: after the call,
//! the (real, byte-exact — taint never changes a value, only valgrind's
//! shadow bookkeeping) nonce and signature bytes are formatted through
//! `std.debug.print`, which is not constant-time by design. Its contexts are
//! reported separately (the WITNESS bucket in `scripts/checks/ctgrind.sh`); seeing
//! them nonzero is what proves the taint travelled key -> sampler -> stdout,
//! so a zero count inside falcon's own files means "no branch found", not
//! "taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const falcon = @import("root.zig");
const Ring = falcon.poly.Ring512;

/// Force a volatile, one-byte-at-a-time reload of `n` bytes from `s`, so the
/// optimizer cannot feed the call under test a copy of the trapdoor that
/// predates `makeMemUndefined` — see the module doc's second bullet.
fn reloadVolatile(comptime n: usize, s: *const [n]i8) [n]i8 {
    var out: [n]i8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile i8 = b;
        o.* = vb.*;
    }
    return out;
}

fn taintAndReload(t: Taint, arr: *[Ring.n]i8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(std.mem.sliceAsBytes(arr[0..]));
    arr.* = reloadVolatile(Ring.n, arr);
}

const Taint = enum { yes, no };

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn parseTarget(s: []const u8) !void {
    // Exactly one target: the trapdoor entering `signRandomized`. Kept as an
    // explicit argv slot (rather than dropping it) to match this
    // collection's `<target> <yes|no>` calling convention, so
    // `scripts/checks/ctgrind.sh`'s per-module TARGETS/MODES/PATTERN table can name
    // "sign" the same way it names every other module's targets.
    if (std.mem.eql(u8, s, "sign")) return;
    return error.UnknownTarget;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    try parseTarget(target_arg);
    const t = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={} target={s}\n", .{ builtin.valgrind_support, target_arg });

    // Fixed-seed, non-cryptographic RNG — deliberately, same reasoning as
    // ct25519's `secretScalar`: this is a diagnostic tool, not a keygen
    // path, and a fixed seed keeps repeated runs of the table comparable.
    // Left UNTAINTED for the whole run (see module doc above).
    var prng = std.Random.DefaultPrng.init(0xfa1c04_5ec4e7_5eed);
    const rng = prng.random();

    var pair = falcon.generateKeyPair(rng) catch |err| {
        // Reachable only if the fixed seed draws a non-invertible `f`,
        // which it does not today. Handled anyway so a future seed or
        // NTRUGen change fails loudly instead of silently skipping the
        // call under test.
        std.debug.print("keygen rejected: {t}\n", .{err});
        return err;
    };

    // Taint (or not) exactly the four arrays `sampleSignature` dereferences
    // through `sk.tree` — see the module doc's "What is tainted" section.
    taintAndReload(t, &pair.signing_key.tree.f);
    taintAndReload(t, &pair.signing_key.tree.g);
    taintAndReload(t, &pair.signing_key.tree.big_f);
    taintAndReload(t, &pair.signing_key.tree.big_g);

    const msg = "ctgrind-falcon-harness-message-v1";
    var nonce: [falcon.nonce_length]u8 = undefined;
    var sig_buf: [falcon.max_sig_field_length]u8 = undefined;

    // The call under test: `signRandomized` -> `Signer.signWithRng` ->
    // `ffsampling.sampleSignature` -> `gaussian.samplerZ`/`gaussian0`/
    // `berExp`. Taint never changes the actual bytes (only valgrind's
    // shadow "defined" bits), so this succeeds identically whether `t` is
    // `.yes` or `.no` — the norm-bound retry loop and NTRU basis are both
    // real and valid either way.
    const sig_len = falcon.signRandomized(&pair.signing_key, msg, rng, &nonce, &sig_buf) catch |err| {
        std.debug.print("signRandomized failed: {t}\n", .{err});
        return err;
    };

    // Propagation proof: format the (tainted, if taint=yes) result through
    // a non-constant-time path. See the module doc comment above.
    std.debug.print("nonce={x} sig={x}\n", .{ nonce, sig_buf[0..sig_len] });
}
