// SPDX-License-Identifier: MIT
//! ctgrind_harness — the constant-time instrument for SPEC.md's § "Threat
//! model / out of scope" admission:
//!
//!   "Signing is not constant-time hardened. Verification is public-input;
//!    for signing, hash-based schemes have no secret-dependent branching in
//!    the structure itself (chain lengths derive from the public digest),
//!    but no systematic side-channel review was done."
//!
//! Until this harness, that sentence had no measurement behind it. Run
//! through `../../../scripts/checks/ctgrind.sh slhdsa`, which builds every
//! mode/target/taint combination and prints the control table; that
//! script's header explains the table format and the two traps this file
//! guards against (repeated below because this harness is not wired into
//! ctgrind.sh's per-module tables yet — see the note at the bottom of this
//! comment).
//!
//! ⚠ UNLIKE ct25519/oscore/ct25519's harnesses, THIS ONE IS NOT DEFENDING A
//! HARDENING CLAIM. SPEC.md already admits the gap; this instrument exists
//! to put an exact number and exact source lines on it, not to reach zero.
//! Do not "fix" a nonzero in-file count by editing `engine.zig` or
//! `address.zig` — that would falsify what this file is for.
//!
//! ## What is tainted, per target
//!
//! FIPS 205 §9.1 secret key is SK = (SK.seed, SK.prf, PK.seed, PK.root);
//! only the first two are secret (`engine.zig`'s `SecretKey.{seed,prf}`).
//! Both targets drive the same public entry point, `sign()`:
//!
//!   - `seed`: taints SK.seed only. This is the field `forsSkGen`,
//!     `wotsPkGen`/`wotsSign` and every `xmssNode`/`forsNode` recursion feed
//!     into `Thash.f` as PRF input — i.e. every FORS/WOTS+/hypertree secret
//!     value derivation. SK.prf stays public, so the message-randomizer `r`
//!     and the tree/leaf index it is hashed into stay public too — this
//!     target isolates the tree/FORS machinery from the index computation.
//!   - `prf`: taints SK.prf only. `prfMsg`'s HMAC key, and *only* that —
//!     SK.prf feeds `r = prfMsg(sk.prf, opt_rand, msg)`, and `r` in turn
//!     feeds `hMsg` to derive `idx_tree`/`idx_leaf` (Algorithm 19 lines
//!     4-9), so tainting SK.prf also taints those indices as an honest
//!     consequence — they are computed FROM this secret, not independent of
//!     it. SK.seed stays public for this target.
//!
//! `SlhDsaSha2_128f` is the instantiation under test — chosen for signing
//! speed under valgrind ("f" sets trade signature size for fast signing;
//! this instrument's job is to measure the gap, not to find the worst
//! case). `addrnd = null` (FIPS 205 deterministic signing, Algorithm 22)
//! so opt_rand = PK.seed and no extra entropy source needs modeling.
//!
//! ## The two traps (see `ct25519`'s harness for the full writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default
//!    outside Debug. A build without `-fvalgrind` is a silent no-op: every
//!    row would read zero regardless of what `sign()` does. The driver
//!    builds both ways so this is its own measured row, not an assumption.
//! 2. An optimizer could in principle keep a defined copy of `seed`/`prf`
//!    across `makeMemUndefined` (register retention or CSE against a
//!    spilled pre-taint copy). `reloadVolatile` forces one real load from
//!    freshly-tainted memory immediately before `sign()` is called.
//!
//! ## The propagation proof
//!
//! After signing, this harness prints one signature byte through
//! `std.debug.print`, which is NOT constant-time (digit/hex formatting
//! branches on the value). That print's own contexts are reported
//! separately from `engine.zig`/`address.zig`'s: seeing them nonzero is
//! what proves the taint actually reached `sign()` and came back out, so a
//! zero inside the module's own files means "no branch found", not "taint
//! never arrived" — see `scripts/checks/ctgrind.sh`'s header, "the propagation
//! proof" is the same shape this repo already uses for ct25519/oscore.
//!
//! ## Wiring note for the coordinator
//!
//! This file only needs to exist for `zig build ctgrind
//! -Dctgrind-module=slhdsa` and `zig build check-ctgrind` to pick it up
//! (`ctgrindHarnesses` in build.zig derives its list from file existence).
//! Driving it through `scripts/checks/ctgrind.sh slhdsa` additionally needs a
//! `TARGETS[slhdsa]`, `MODES[slhdsa]`, `PATTERN[slhdsa/seed]`,
//! `PATTERN[slhdsa/prf]` and `LABEL[...]` entry in that script (see its
//! per-module configuration block) and a row pin in
//! `scripts/checks/ctgrind-expected.tsv` — both out of scope for this change per
//! the task that produced this file (shared coordinator-owned files).
//! Suggested values, for whoever wires it in:
//!   TARGETS[slhdsa]="seed prf"
//!   MODES[slhdsa]="ReleaseFast"
//!   PATTERN[slhdsa/seed]='engine[.]zig|address[.]zig'
//!   PATTERN[slhdsa/prf]='engine[.]zig|address[.]zig'
//!   LABEL[slhdsa/seed]='slhdsa SK.seed'
//!   LABEL[slhdsa/prf]='slhdsa SK.prf'

const std = @import("std");
const builtin = @import("builtin");
const slhdsa = @import("root.zig");

/// The instantiation under test — see the module doc above for why "f".
const S = slhdsa.SlhDsaSha2_128f;

const Target = enum { seed, prf };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "seed")) return .seed;
    if (std.mem.eql(u8, s, "prf")) return .prf;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// Deterministic "random" keypair — not a KAT, a diagnostic fixture.
/// Computed at runtime (not folded at comptime) so tainting SK.seed/SK.prf
/// afterwards actually marks memory `sign()` reads. A fixed seed just keeps
/// repeated runs of the table comparable.
fn fixedKeyPair() S.KeyPair {
    const msg = "ctgrind-slhdsa-harness-keygen-seed-v1";
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(msg, &wide, .{});
    var seed: [3 * S.n]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = wide[i % wide.len];
    return S.keyGen(seed);
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the sign path cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var kp = fixedKeyPair();

    switch (target) {
        .seed => if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&kp.sk.seed),
        .prf => if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&kp.sk.prf),
    }
    // Reload BOTH fields through the volatile barrier regardless of which
    // one was tainted: the untainted field is already fully defined, so
    // reloading it is a no-op for memcheck and keeps this call site
    // target-independent.
    kp.sk.seed = reloadVolatile(S.n, &kp.sk.seed);
    kp.sk.prf = reloadVolatile(S.n, &kp.sk.prf);

    // The call under test: FIPS 205 Algorithm 22, deterministic
    // (addrnd = null => opt_rand = PK.seed).
    var sig: [S.signature_length]u8 = undefined;
    try S.sign(&sig, "ctgrind slhdsa harness message", kp.sk, "", null);

    // Propagation proof: format one (tainted, if taint=yes) signature byte
    // through a non-constant-time path. See the module doc comment above.
    // Also the output pin ctgrind.sh's `out_digest` looks for (>=32 hex
    // digits): the R value plus the FORS/HT sig prefix, well past that
    // floor.
    std.debug.print("sig={x}\n", .{sig[0..32]});
}
