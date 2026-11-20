// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time instrument for `falcon`'s signing
//! key. Run it through `../../../scripts/checks/ctgrind.sh falcon`; that script's
//! header explains the two traps (silent no-op without `-fvalgrind`, and a
//! counting rule that must classify every context or fail).
//!
//! ## What the row means
//!
//! The row is pinned as a bound (`scripts/checks/ctgrind-expected.tsv`), not
//! as an exact count, because `sampler`'s reject loop iterates a
//! *value-dependent* number of times and `berExp` keeps one data-dependent
//! early break, both copied deliberately from the reference: the
//! constant-time argument there is Bernoulli decorrelation, not a fixed trip
//! count, and ctgrind measures exactly what those two constructs do — branch
//! on tainted data. Only the direction (the count must not grow) is
//! load-bearing; `SPEC.md`'s "Threat model / limits" section states what
//! that does and does not establish. See also `gaussian.zig`'s
//! "CONSTANT-TIME STATUS".
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

    var signing_key: falcon.SigningKey = undefined;
    var public_key: falcon.PublicKey = undefined;
    falcon.generateKeyPair(rng, &signing_key, &public_key) catch |err| {
        // Reachable only if the fixed seed draws a non-invertible `f`,
        // which it does not today. Handled anyway so a future seed or
        // NTRUGen change fails loudly instead of silently skipping the
        // call under test.
        std.debug.print("keygen rejected: {t}\n", .{err});
        return err;
    };

    // Taint (or not) exactly the four arrays `sampleSignature` dereferences
    // through `sk.tree` — see the module doc's "What is tainted" section.
    taintAndReload(t, &signing_key.tree.f);
    taintAndReload(t, &signing_key.tree.g);
    taintAndReload(t, &signing_key.tree.big_f);
    taintAndReload(t, &signing_key.tree.big_g);

    const msg = "ctgrind-falcon-harness-message-v1";
    var nonce: [falcon.nonce_length]u8 = undefined;
    var sig_buf: [falcon.max_sig_field_length]u8 = undefined;

    // The call under test: `signRandomized` -> `Signer.signWithRng` ->
    // `ffsampling.sampleSignature` -> `gaussian.samplerZ`/`gaussian0`/
    // `berExp`. Taint never changes the actual bytes (only valgrind's
    // shadow "defined" bits), so this succeeds identically whether `t` is
    // `.yes` or `.no` — the norm-bound retry loop and NTRU basis are both
    // real and valid either way.
    const sig_len = falcon.signRandomized(&signing_key, msg, rng, &nonce, &sig_buf) catch |err| {
        std.debug.print("signRandomized failed: {t}\n", .{err});
        return err;
    };

    // Propagation proof: format the (tainted, if taint=yes) result through
    // a non-constant-time path. See the module doc comment above.
    std.debug.print("nonce={x} sig={x}\n", .{ nonce, sig_buf[0..sig_len] });
}
