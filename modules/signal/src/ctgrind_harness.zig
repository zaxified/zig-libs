// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s two
//! "Constant-time" paragraphs (the XEdDSA one under X3DH, and the
//! "Const-time / zeroization" one under the Double Ratchet), as an actual
//! committed program instead of a code block a reader has to retype. Build
//! and run it the way `ct25519`'s harness documents (`modules/ct25519/src/
//! ctgrind_harness.zig`'s header) — `scripts/ctgrind.sh` needs a per-module
//! config block this module does not yet have, so drive this file directly:
//!
//!     zig build ctgrind -Dctgrind-module=signal -Dctgrind-valgrind=true -Doptimize=ReleaseFast
//!     valgrind --tool=memcheck --error-exitcode=99 --num-callers=20 \
//!         ./zig-out/ctgrind/ctgrind-signal <target> <yes|no>
//!
//! and again with `-Dctgrind-valgrind=false` for the no-`-fvalgrind` trap
//! row. `<target>` is `sign` or `ratchet` (see below). NOT wired into `zig
//! build test-signal` for the same reason ct25519's isn't: memcheck's
//! context count is valgrind's own verdict, not something a Zig test can
//! observe.
//!
//! ## What this measures, and what it deliberately does NOT
//!
//! A triage pass flagged `xeddsa.calculateKeyPair`'s negate-if-sign-1 step
//! as signal's OWN branch on a secret scalar (point multiplication itself
//! is delegated to `ct25519`). Reading `xeddsa.zig` confirms it: `sign 178:
//! const e = ct25519.mulBase(k);` — the point multiplication IS someone
//! else's code — followed at `191-193` by
//!
//!     const mask: u8 = 0 -% sign_bit; // 0x00 or 0xFF — branchless select
//!     var a: scalar.CompressedScalar = undefined;
//!     for (&a, k, k_neg) |*out, plain, negated| out.* = (plain & ~mask) | (negated & mask);
//!
//! which is signal's own arithmetic select over the secret scalar `k`/
//! `k_neg` — a real place for this module's own code to leak, independent
//! of whatever ct25519 does. `target = .sign` exercises exactly this path.
//!
//! - **`target = .sign`** — `xeddsa.sign(montgomery_priv, msg, z)`, tainting
//!   `montgomery_priv`: the identity-key or signed-prekey PRIVATE scalar
//!   `x3dh.generateSignedPreKey` passes as `bob_ik.secret_key` (`x3dh.zig`
//!   line ~503, `xeddsa.sign(bob_ik.secret_key, &kp.public_key, z)` — this
//!   harness's call is that call site, not a synthetic stand-in). Exercises
//!   `calculateKeyPair`'s clamp/reduce/negate-select, both `hash1`/plain
//!   SHA-512 derivations, `ct25519.mulBase` (twice: key point and nonce
//!   point `R`), and `scalar.mulAdd`. `msg` and `z` are NOT tainted: `msg`
//!   is the signed prekey's PUBLIC half (an adversary already sees it on
//!   the wire), and `z` is XEdDSA's caller-supplied auxiliary randomness,
//!   which the scheme tolerates being weak/observed (SPEC.md, "Constant-
//!   time" paragraph) — hashed alongside the secret scalar, never used
//!   alone. The task brief names "identity/prekey private keys and the
//!   XEdDSA signing scalar" as one thing to taint, and in this call they
//!   ARE one thing: `montgomery_priv` IS both the identity/prekey private
//!   key and (after `calculateKeyPair`'s clamp+reduce+negate) the scalar
//!   XEdDSA signs with.
//!
//! - **`target = .ratchet`** — the Double Ratchet's root-key/chain-key KDF
//!   step, driven through the REAL public API rather than calling the
//!   module's private `kdfRk`/`rootRatchet`/`kdfCk` directly (those aren't
//!   `pub`, so a harness in a different file cannot reach them any other
//!   way): `buildSession` runs an actual X3DH handshake
//!   (`x3dh.initiateUnverified` + `x3dh.respond`, the same shape as
//!   `ratchet.zig`'s own `seedSession` test helper) to get a real Alice/Bob
//!   `ratchet.State` pair, Alice `encrypt`s one message, and this harness
//!   taints Bob's `rk` (root key) and `dhs.secret_key` (his current ratchet
//!   private key — his signed-prekey secret) immediately before calling
//!   `bob.decrypt`. Bob has no `dhr` yet, so `decrypt` unconditionally
//!   drives the DH ratchet (`dhRatchet` -> `rootRatchet` -> two chained
//!   `kdfRkWithInfo` calls, root key first) before its `kdfCk` derives the
//!   message key and the AEAD opens. `makeMemUndefined` changes valgrind's
//!   SHADOW state only — the real bytes are untouched — so the DH ratchet
//!   computes the SAME keys Bob's side always would, and `decrypt` succeeds
//!   for real: the printed plaintext at the end is proof the taint
//!   propagated all the way through `rk` -> `dh_recv`/`dh_send` ->
//!   `rootRatchet`'s two `KDF_RK` calls -> `ckr` -> `kdfCk` -> `mk` -> the
//!   AEAD open, not just into some dead intermediate. Nothing here taints
//!   `header`/`ciphertext` (the wire message an adversary observes) or
//!   Alice's own state.
//!
//! ## Suggested `scripts/ctgrind.sh` config (NOT added here — the shared
//! script's per-module blocks are the coordinator's to wire; see the task
//! that produced this file)
//!
//!     [signal]="sign ratchet"                              # TARGETS
//!     [signal]="ReleaseFast"                                # MODES
//!     [signal/sign]='xeddsa[.]zig|root[.]zig|scalar[.]zig'  # PATTERN — root.zig is ct25519's (this module's own root.zig is never on this call's stack: the harness imports xeddsa.zig directly, not signal's aggregator)
//!     [signal/ratchet]='ratchet[.]zig|x3dh[.]zig|x25519[.]zig|curve25519[.]zig|scalar[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig|root[.]zig|chacha20[.]zig|poly1305[.]zig'
//!         # ratchet.zig/x3dh.zig: this module's own. x25519/curve25519/
//!         # scalar: std's X25519 DH ladder the DH ratchet calls
//!         # (`X25519.scalarmult`, `x3dh.generateKeyPair`'s
//!         # `X25519.KeyPair.generateDeterministic`). hkdf/hmac/sha2: std's
//!         # KDF_RK (HKDF-SHA256) and KDF_CK (HMAC-SHA256) primitives.
//!         # root/chacha20/poly1305: the `chachapoly` sibling's AEAD, which
//!         # this call also reaches (`aeadOpen`, keyed by the tainted-derived
//!         # `mk`) — named for the same reason bolt8/oscore/p256 name their
//!         # delegates: SPEC.md's own "Const-time / zeroization" paragraph
//!         # bundles `X25519.scalarmult`, "HMAC/HKDF over SHA-256" AND
//!         # "ChaCha20-Poly1305" into one claim, so all three belong in the
//!         # pattern this row is evidence for. ⚠ `root[.]zig` here can also
//!         # match `chachapoly`'s own `root.zig` AND (if it ever appeared on
//!         # this stack, which it does not for this call path) signal's own
//!         # `root.zig` — see the k256/blindrsa lesson in ctgrind.sh: verify
//!         # any `root.zig` hit by its QUALIFIED symbol, not the bare
//!         # filename, before trusting which module it is.
//!
//! ## The two traps (see ct25519's harness for the fuller writeup)
//!
//! 1. Built WITHOUT `-fvalgrind`, `doClientRequest` compiles to nothing —
//!    the no-`-fvalgrind` trap row below exists so a silent no-op reads as
//!    its own row, not as a false-clean claim row.
//! 2. `reloadInPlace` forces a genuine volatile load+store on every tainted
//!    byte right before the call under test, so the ladder cannot be fed a
//!    copy the optimizer kept from before `makeMemUndefined` ran — the same
//!    defensive (not demonstrated-necessary) insurance as ct25519's
//!    `reloadVolatile`.

const std = @import("std");
const builtin = @import("builtin");
const xeddsa = @import("xeddsa.zig");
const x3dh = @import("x3dh.zig");
const ratchet = @import("ratchet.zig");

const X25519 = std.crypto.dh.X25519;

/// Deterministic 32-byte "secret" — computed at runtime (not folded at
/// comptime) so tainting it actually marks memory the code under test
/// reads. Not a KAT, just a stable non-zero seed so repeated runs of the
/// table are comparable.
fn deterministic32(comptime label: []const u8) [32]u8 {
    var wide: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash("ctgrind-signal-harness-" ++ label, &wide, .{});
    return wide[0..32].*;
}

/// Forces a genuine volatile load+store on every byte of `field`, so a
/// value freshly marked undefined by `makeMemUndefined` cannot be served to
/// the code under test from a stale defined copy the optimizer kept in a
/// register. See ct25519's `ctgrind_harness.zig` ("trap 2") for the same
/// insurance and the same honesty about it being defensive, not measured as
/// necessary on today's compiler.
fn reloadInPlace(field: []u8) void {
    for (field) |*b| {
        const vb: *volatile u8 = b;
        vb.* = vb.*;
    }
}

const Target = enum { sign, ratchet };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "sign")) return .sign;
    if (std.mem.eql(u8, s, "ratchet")) return .ratchet;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

/// Builds a real Alice/Bob Double Ratchet pair from a real X3DH handshake —
/// body-identical to `ratchet.zig`'s own (private, test-only) `seedSession`
/// helper, reproduced here because a harness in a different file cannot
/// reach a private test helper any more than it can reach `kdfRk` itself.
/// Every call below is the module's real public API; nothing here computes
/// ratchet/X3DH cryptography of its own.
fn buildSession(allocator: std.mem.Allocator, io: std.Io) !struct { alice: ratchet.State, bob: ratchet.State } {
    const alice_ik = X25519.KeyPair.generate(io);
    const bob_ik = X25519.KeyPair.generate(io);
    const bob_spk_kp = X25519.KeyPair.generate(io);
    const bob_opk_kp = X25519.KeyPair.generate(io);

    const bob_spk: x3dh.SignedPreKey = .{ .key_pair = bob_spk_kp, .signature = undefined, .id = 1 };
    const bob_opk: x3dh.OneTimePreKey = .{ .key_pair = bob_opk_kp, .id = 2 };
    const bundle: x3dh.PreKeyBundle = .{
        .identity_key = bob_ik.public_key,
        .signed_prekey = bob_spk_kp.public_key,
        .signed_prekey_id = bob_spk.id,
        .signed_prekey_signature = undefined,
        .one_time_prekey = bob_opk_kp.public_key,
        .one_time_prekey_id = bob_opk.id,
    };

    const alice_out = try x3dh.initiateUnverified(allocator, alice_ik, bundle, "", io);
    defer alice_out.message.deinit(allocator);
    const bob_agr = try x3dh.respond(bob_ik, bob_spk, bob_opk, alice_out.message);

    const alice = try ratchet.State.initAlice(
        alice_out.agreement.shared_secret,
        alice_out.agreement.associated_data,
        bob_spk_kp.public_key,
        io,
    );
    const bob = ratchet.State.initBob(bob_agr.shared_secret, bob_agr.associated_data, bob_spk_kp);
    return .{ .alice = alice, .bob = bob };
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target_arg = it.next() orelse return error.MissingTarget;
    const taint_arg = it.next() orelse return error.MissingTaint;
    const target = try parseTarget(target_arg);
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .sign => {
            // The identity/signed-prekey PRIVATE scalar — see the module
            // doc comment: this IS `x3dh.generateSignedPreKey`'s
            // `bob_ik.secret_key` argument to `xeddsa.sign`.
            var priv = deterministic32("xeddsa-identity-priv-v1");
            if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&priv);
            reloadInPlace(&priv);

            // PUBLIC: the signed prekey's public half, exactly what
            // `generateSignedPreKey` signs (`&kp.public_key`). Not tainted.
            const msg = "ctgrind-signal-harness-signed-prekey-public-placeholder";
            // PUBLIC-tolerant auxiliary randomness (SPEC.md's own claim).
            // Not tainted -- see the module doc comment.
            const z: xeddsa.RandomData = [_]u8{0x5A} ** 64;

            const sig = xeddsa.sign(priv, msg, z);
            // Propagation proof: std.debug.print is NOT constant-time.
            std.debug.print("sig={x}\n", .{sig});
        },
        .ratchet => {
            var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{});
            defer threaded.deinit();
            const io = threaded.io();

            const session = try buildSession(std.heap.page_allocator, io);
            var alice = session.alice;
            var bob = session.bob;

            var msg = try alice.encrypt(std.heap.page_allocator, "ctgrind-signal-harness-plaintext");
            defer msg.deinit(std.heap.page_allocator);

            // Bob's root key and his current ratchet private key -- both
            // secret, both inputs to the DH-ratchet's `rootRatchet` ->
            // `KDF_RK` step that `bob.decrypt` is about to run (see the
            // module doc comment for why `bob.dhr == null` forces that
            // path unconditionally on this first receive).
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(&bob.rk);
                std.valgrind.memcheck.makeMemUndefined(&bob.dhs.secret_key);
            }
            reloadInPlace(&bob.rk);
            reloadInPlace(&bob.dhs.secret_key);

            // Real bytes are untouched by makeMemUndefined (it only marks
            // valgrind's shadow state), so this succeeds for real and the
            // printed plaintext is the propagation witness -- proof the
            // taint travelled root key -> DH ratchet -> chain key ->
            // message key -> AEAD open, not just into a dead intermediate.
            const pt = try bob.decrypt(std.heap.page_allocator, msg.header, msg.ciphertext, io);
            defer std.heap.page_allocator.free(pt);
            std.debug.print("plaintext={x}\n", .{pt});
        },
    }
}
