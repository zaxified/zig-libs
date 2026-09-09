// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for HPKE's DHKEM decap path
//! and the AEAD encryption context, which `SPEC.md`/`README.md` do NOT yet
//! state as fact anywhere (see "SPEC.md/README.md currently make NO
//! constant-time claim" below). Run it through `../../../scripts/ctgrind.sh`
//! once the coordinator adds hpke's TARGETS/MODES/PATTERN block — this
//! module has none yet, so `ctgrind.sh hpke` refuses to run; see the
//! suggested config lines at the bottom of this comment. This file follows
//! the shape of `ct25519`'s and `chachapoly`'s harnesses (both read before
//! writing this one): a standalone program driven by argv, deliberately NOT
//! wired into `zig build test-hpke` — memcheck's context count is
//! valgrind's own verdict, not something a Zig test can assert on.
//!
//! ## What is tainted, and why these two boundaries
//!
//! Two independent secret-entry points, matching RFC 9180's own two
//! sensitive values on the RECEIVING side:
//!
//! 1. **The recipient's KEM private key entering `decap`/`authDecap`**
//!    (`dhkem.zig`) — the DHKEM Diffie-Hellman. `enc` (the sender's
//!    ephemeral public key) and, for auth mode, `pkS` (the sender's static
//!    public key) are WIRE data an attacker controls; only `skR.secret_key`
//!    is secret, and it is what this harness marks `MAKE_MEM_UNDEFINED`.
//! 2. **The derived AEAD key + base_nonce entering `Context.open`**
//!    (`schedule.zig`) — the OUTPUT of `KeySchedule`, not the DHKEM shared
//!    secret it was itself derived from (that would be the same value
//!    target 1 already covers, one layer up). `ct`/`aad` are wire data;
//!    only `ctx.key`/`ctx.base_nonce` are tainted.
//!
//! Every tainted value here is produced by a REAL module call —
//! `dhkem.*Kem.deriveKeyPair`/`encapDeterministic`/`authEncapDeterministic`
//! for the KEM targets, `schedule.keySchedule` for `open` — never invented
//! in a private helper. `deriveKeyPair`'s own internal branches (X25519:
//! none; P-256/P-384: the §7.1.3 rejection-sampling loop) run BEFORE the
//! taint is applied and so contribute nothing to any tainted row; see "the
//! setup phase is clean" below.
//!
//! ## The three DHKEMs, and which are covered
//!
//! All three DHKEMs this module implements get BOTH a `decap` and an
//! `authDecap` target — nothing is skipped:
//!
//! * `x25519_decap` / `x25519_authdecap` — DHKEM(X25519, HKDF-SHA256).
//! * `p256_decap` / `p256_authdecap` — DHKEM(P-256, HKDF-SHA256), whose group
//!   arithmetic is this repo's own asm-accelerated `p256` module, not std.
//! * `p384_decap` / `p384_authdecap` — DHKEM(P-384, HKDF-SHA384), whose
//!   group arithmetic is `std.crypto.ecc.P384` directly (no local
//!   perf-specialized sibling exists for P-384 — see `dhkem.zig`'s module
//!   doc comment).
//!
//! RFC 9180 also registers P-521 and X448 DHKEMs; this module implements
//! neither (`suite.zig`'s `KemId` doc comment), so there is nothing to
//! target for them.
//!
//! ## Own code vs. delegate, per target — read before trusting a pattern
//!
//! Every KEM target's `dh = point.mul(skR.secret_key, ...)` result feeds
//! `dhkem.extractAndExpand`, i.e. `suite.labeledExtract`/`.labeledExpand`
//! (HKDF), before the secret ever leaves this module's own two files
//! (`dhkem.zig`, `suite.zig`). Naming ONLY those two and leaving the actual
//! group arithmetic — and the HKDF/HMAC/SHA-2 the shared secret is then
//! extracted through — off the pattern would be exactly the evasion
//! `scripts/ctgrind.sh`'s header warns about: the group multiply is where a
//! scalar-dependent branch would actually live, not in `dhkem.zig`'s own
//! glue code, and a bug inside HKDF's HMAC is a DIFFERENT failure than a
//! leaky ladder. So every KEM pattern below names BOTH:
//!
//! | Target | hpke's own | Delegate (the taint's real destination) |
//! |---|---|---|
//! | `x25519_*` | `dhkem.zig`, `suite.zig` | std `x25519.zig`, `curve25519.zig`, 25519's `field.zig`; std `hkdf.zig`, `hmac.zig`, `sha2.zig` (HKDF-SHA256) |
//! | `p256_*` | `dhkem.zig`, `suite.zig` | **this repo's own** `p256` module: `group.zig`, `field.zig`, `fast_core.zig`; std `hkdf.zig`, `hmac.zig`, `sha2.zig` (HKDF-SHA256) |
//! | `p384_*` | `dhkem.zig`, `suite.zig` | std `pcurves/p384.zig`, pcurves p384's `field.zig`, pcurves' `common.zig`; std `hkdf.zig`, `hmac.zig`, `sha2.zig` (HKDF-SHA384) |
//! | `open` | `schedule.zig` | `chachapoly`'s own `root.zig`/`chacha20.zig`/`poly1305.zig` (this module's RECOMMENDED AEAD binding, re-exported as `hpke.ChaCha20Poly1305`) |
//!
//! `p256`'s own arithmetic is a DELEGATE here in the same sense std's is for
//! the other two KEMs — it is a sibling module in this repo, not code this
//! file owns — and its round-1 ctgrind result (`p256/comb`, `p256/sign`: 9
//! in-file contexts, all `rejectIdentity`/scalar-canonicality/`isZero`
//! degenerate checks, none of them the ladder itself) is a PRIOR
//! measurement of the same arithmetic `p256_decap`/`p256_authdecap` now
//! drive with a different caller. A nonzero count in that arithmetic here
//! should be checked against that prior result before being called new.
//!
//! ## The setup phase is clean
//!
//! `deriveKeyPair(ikm)` (X25519: `LabeledExpand` only; P-256/P-384: the same
//! plus a rejection-sampling loop over `rejectNonCanonical`/`isZero`) runs
//! on a fixed PUBLIC `ikm` string BEFORE this harness taints anything —
//! `MAKE_MEM_UNDEFINED` is applied to `skR.secret_key` only after
//! `deriveKeyPair` has already returned. So `scalar.zig`/`common.zig`'s
//! canonicality-rejection branches (the same ones round 1 found in
//! `p256/sign`) are NOT reachable as tainted contexts from this harness's
//! `decap`/`authDecap` targets — they would only appear if `deriveKeyPair`
//! itself were the code under test, which it is not here. This is why the
//! per-KEM patterns above do not need to name a scalar-canonicality file for
//! the DH step itself: `mul`'s own ladder (`p384.zig`'s
//! `pcMul16`/`precompute`, `p256`'s `group.zig` comb, `curve25519.zig`'s
//! `clampedMul`) runs over the point/field type, not the
//! scalar-canonicality machinery `deriveKeyPair` alone uses.
//!
//! ## `enc`/`pkS` are real, not zero/degenerate
//!
//! Every `enc` this harness feeds to `decap`/`authDecap` comes from a REAL
//! `encapDeterministic`/`authEncapDeterministic` call against the tainted
//! key's own (untainted, pre-taint) public key — a genuine on-curve point
//! the DH will actually accept, not the low-order/all-zero input
//! `dhkem.zig`'s own tests use to exercise `error.DhFailed`. A degenerate
//! `enc` would make `decap` bail out through `rejectIdentity`/`fromSec1`
//! BEFORE the scalar multiply proper runs, measuring the reject path
//! instead of the ladder RFC 9180's DH actually targets.
//!
//! ## `open`: the derived key/nonce, not the DH shared secret
//!
//! `open`'s `ctx` comes from a real `schedule.keySchedule(ChaCha20Poly1305,
//! 32, .base, suite_id, shared_secret, info, "", "")` call over a FIXED
//! public `shared_secret` (this target is not re-measuring the KEM — that is
//! the six KEM targets' job) — only `ctx.key`/`ctx.base_nonce`, the key
//! schedule's OUTPUT, are tainted, matching the task's framing exactly ("the
//! derived AEAD key/base-nonce entering `Context.open`"). To reach a real
//! `Context.open` success (rather than an immediate `error.DecryptionFailed`
//! that never touches the AEAD's decrypt body), the ciphertext under test is
//! produced by a SEPARATE, untainted `Context.seal` call sharing the exact
//! same deterministic derivation — same `key`/`base_nonce` bit pattern,
//! different memcheck shadow.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` compiles to nothing without
//!    `-fvalgrind` (off by default outside Debug) — a silent no-op, not an
//!    error. The driver builds both ways and prints the no-op row on
//!    purpose.
//! 2. An optimizer could in principle keep a defined register/stack copy of
//!    a value from before `makeMemUndefined` ran. `reloadVolatile` forces one
//!    real load from freshly-tainted memory immediately before the call
//!    under test, as insurance (see `ct25519`'s harness for the measurement
//!    showing this is precaution, not an observed requirement on this
//!    compiler).
//!
//! `ReleaseFast` only, for the reason every other module's row is
//! ReleaseFast-only: `Debug`/`ReleaseSafe` add overflow-check branches on
//! tainted limbs inside std's bigint reduction (measured elsewhere in this
//! campaign at tens of thousands of contexts, `scripts/ctgrind.sh` § MODES)
//! that would bury this module's own signal, and Debug's self-hosted
//! backend is unreadable by valgrind's DWARF parser regardless.
//!
//! ## The propagation witness
//!
//! Every KEM target prints its `shared_secret` via `std.debug.print`'s hex
//! formatting (not constant-time); `open` prints the decrypted plaintext the
//! same way. A non-zero total next to a small/zero in-file count is what
//! makes the in-file count mean "no branch found", not "the harness never
//! ran" — see `ct25519`'s harness for the fuller argument.
//!
//! ## SPEC.md/README.md currently make NO constant-time claim
//!
//! Neither file contains the words "constant-time"/"constant time"/
//! "side-channel" as of this harness's authoring (checked by grep) — this
//! table is therefore evidence FOR a claim nobody has written down yet, not
//! verification of an existing one. Left unstated here on purpose: this
//! file's job is to measure, not to add prose to SPEC.md/README.md the
//! module's maintainer has not signed off on.
//!
//! ## Suggested `scripts/ctgrind.sh` config (NOT added by this change —
//! touching that file is the coordinator's job, not this one)
//!
//! ```text
//! TARGETS[hpke]="x25519_decap x25519_authdecap p256_decap p256_authdecap p384_decap p384_authdecap open"
//! MODES[hpke]="ReleaseFast"
//! PATTERN[hpke/x25519_decap]="dhkem[.]zig|suite[.]zig|x25519[.]zig|curve25519[.]zig|field[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/x25519_authdecap]="dhkem[.]zig|suite[.]zig|x25519[.]zig|curve25519[.]zig|field[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/p256_decap]="dhkem[.]zig|suite[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/p256_authdecap]="dhkem[.]zig|suite[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/p384_decap]="dhkem[.]zig|suite[.]zig|p384[.]zig|field[.]zig|common[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/p384_authdecap]="dhkem[.]zig|suite[.]zig|p384[.]zig|field[.]zig|common[.]zig|hkdf[.]zig|hmac[.]zig|sha2[.]zig"
//! PATTERN[hpke/open]="schedule[.]zig|root[.]zig|chacha20[.]zig|poly1305[.]zig"
//! LABEL[hpke/x25519_decap]="hpke X25519 decap (skR)+std x25519+hkdf"
//! LABEL[hpke/x25519_authdecap]="hpke X25519 authDecap (skR dh+dh2)+std x25519+hkdf"
//! LABEL[hpke/p256_decap]="hpke P-256 decap (skR)+p256 group/field+hkdf"
//! LABEL[hpke/p256_authdecap]="hpke P-256 authDecap (skR dh+dh2)+p256+hkdf"
//! LABEL[hpke/p384_decap]="hpke P-384 decap (skR)+std p384+hkdf"
//! LABEL[hpke/p384_authdecap]="hpke P-384 authDecap (skR dh+dh2)+std p384+hkdf"
//! LABEL[hpke/open]="hpke Context.open (key,base_nonce)+chachapoly"
//! ```
//! `field[.]zig` is reused across THREE different files here (std's
//! `25519/field.zig`, this repo's `p256/field.zig`, std's
//! `pcurves/p384/field.zig`) — never a collision in practice because each
//! target's log only contains frames the binary actually executed for that
//! argv, but worth stating given `blindrsa`/`rsa`'s documented `root[.]zig`
//! basename collision in this same script.

const std = @import("std");
const builtin = @import("builtin");
const hpke = @import("root.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");
const suite = @import("suite.zig");

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 in the module doc comment.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

/// The post-KEM half of every `decap` target: derive a REAL recipient
/// keypair and a REAL ephemeral keypair (both via the module's own
/// `deriveKeyPair`, on fixed public `ikm` strings), encapsulate a genuine
/// on-curve `enc` against the recipient's own public key, THEN taint the
/// recipient's `secret_key` in place and call the module's real `decap`.
/// `Kem` is one of `dhkem.X25519Kem` / `.P256Kem` / `.P384Kem` — all three
/// share the `Nsk`/`KeyPair{secret_key,public_key}`/`deriveKeyPair`/
/// `encapDeterministic`/`decap` shape, so one generic function drives all
/// three `*_decap` targets.
fn kemDecap(comptime Kem: type, taint: bool, recipient_ikm: []const u8, eph_ikm: []const u8) !void {
    const skR_clean = Kem.deriveKeyPair(recipient_ikm);
    const eph = Kem.deriveKeyPair(eph_ikm);
    const encapped = try Kem.encapDeterministic(skR_clean.public_key, eph);

    var skR = skR_clean;
    if (taint) std.valgrind.memcheck.makeMemUndefined(&skR.secret_key);
    skR.secret_key = reloadVolatile(Kem.Nsk, &skR.secret_key);

    // The call under test: `enc` is wire data (a genuine on-curve point,
    // not tainted); `skR.secret_key` is the tainted recipient private key.
    const shared_secret = try Kem.decap(encapped.enc, skR);
    // Propagation witness: hex formatting is not constant-time.
    std.debug.print("shared_secret={x}\n", .{shared_secret});
}

/// The `authDecap` mirror of `kemDecap`: an extra REAL sender keypair
/// (`skS`, only its PUBLIC half used by `authDecap` — RFC 9180's `pkS`),
/// folded into `authEncapDeterministic` alongside the ephemeral, then the
/// same taint-recipient-secret-key + call-real-`authDecap` shape.
fn kemAuthDecap(comptime Kem: type, taint: bool, recipient_ikm: []const u8, sender_ikm: []const u8, eph_ikm: []const u8) !void {
    const skR_clean = Kem.deriveKeyPair(recipient_ikm);
    const skS = Kem.deriveKeyPair(sender_ikm);
    const eph = Kem.deriveKeyPair(eph_ikm);
    const encapped = try Kem.authEncapDeterministic(skR_clean.public_key, skS, eph);

    var skR = skR_clean;
    if (taint) std.valgrind.memcheck.makeMemUndefined(&skR.secret_key);
    skR.secret_key = reloadVolatile(Kem.Nsk, &skR.secret_key);

    // `enc` and `skS.public_key` are both wire data (public); only
    // `skR.secret_key` is tainted. `authDecap` computes DH(skR,enc) AND
    // DH(skR,pkS) — both against the SAME tainted scalar — so this target
    // covers both halves of the `dh || dh2` fold in one run.
    const shared_secret = try Kem.authDecap(encapped.enc, skR, skS.public_key);
    std.debug.print("shared_secret={x}\n", .{shared_secret});
}

/// `Context.open`'s own claim: the derived AEAD key + base_nonce, not the
/// DHKEM shared secret they came from (see the module doc comment's "open:
/// the derived key/nonce" section). `ChaCha20Poly1305` is this module's
/// RECOMMENDED AEAD binding (`hpke.ChaCha20Poly1305`, byte-exact to std's) —
/// the AES-GCM path has no sibling implementation and is std-only, so it is
/// not separately targeted here.
fn openTarget(taint: bool) !void {
    const Aead = hpke.ChaCha20Poly1305;
    const Nh: usize = 32; // HKDF-SHA256 outer key schedule

    // An arbitrary REGISTERED (kem_id, kdf_id, aead_id) triple — suite_id
    // construction is public plumbing (suite.zig), not part of this
    // target's claim, which is entirely about Context.open below.
    const suite_id = comptime suite.suiteId(
        @intFromEnum(hpke.KemId.dhkem_x25519_hkdf_sha256),
        @intFromEnum(hpke.KdfId.hkdf_sha256),
        @intFromEnum(hpke.AeadId.chacha20poly1305),
    );
    // PUBLIC placeholder: this target's claim is about `ctx.key`/
    // `ctx.base_nonce` (KeySchedule's OUTPUT), not this input -- the DHKEM
    // shared secret itself is targets 1-6's claim, one layer down.
    const shared_secret = "ctgrind-hpke-open-harness-shared-secret-not-under-test";
    const info = "ctgrind-hpke-open-harness-info";
    const aad = [_]u8{ 0x10, 0x11, 0x12, 0x13 };
    const pt = "hpke ctgrind open-target plaintext";

    // Untainted twin: same deterministic derivation, used only to produce a
    // REAL ciphertext `open` below can authenticate -- without this, a
    // tainted key/nonce would make every `open` fail at the tag compare
    // before the AEAD body under test ever runs.
    var sealer = try schedule.keySchedule(Aead, Nh, .base, &suite_id, shared_secret, info, "", "");
    var ct: [pt.len + Aead.tag_length]u8 = undefined;
    try sealer.seal(&aad, pt, &ct);

    // The call under test: a fresh Context from the SAME derivation (so its
    // key/base_nonce bit pattern matches `sealer`'s exactly), with
    // `ctx.key`/`ctx.base_nonce` tainted in place before `open`.
    var ctx = try schedule.keySchedule(Aead, Nh, .base, &suite_id, shared_secret, info, "", "");
    if (taint) {
        std.valgrind.memcheck.makeMemUndefined(&ctx.key);
        std.valgrind.memcheck.makeMemUndefined(&ctx.base_nonce);
    }
    ctx.key = reloadVolatile(Aead.key_length, &ctx.key);
    ctx.base_nonce = reloadVolatile(Aead.nonce_length, &ctx.base_nonce);

    var out: [pt.len]u8 = undefined;
    try ctx.open(&aad, &ct, &out);
    // Propagation witness: hex formatting is not constant-time.
    std.debug.print("open={x}\n", .{out});
}

const Target = enum {
    x25519_decap,
    x25519_authdecap,
    p256_decap,
    p256_authdecap,
    p384_decap,
    p384_authdecap,
    open,
};
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "x25519_decap")) return .x25519_decap;
    if (std.mem.eql(u8, s, "x25519_authdecap")) return .x25519_authdecap;
    if (std.mem.eql(u8, s, "p256_decap")) return .p256_decap;
    if (std.mem.eql(u8, s, "p256_authdecap")) return .p256_authdecap;
    if (std.mem.eql(u8, s, "p384_decap")) return .p384_decap;
    if (std.mem.eql(u8, s, "p384_authdecap")) return .p384_authdecap;
    if (std.mem.eql(u8, s, "open")) return .open;
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
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const taint = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .x25519_decap => try kemDecap(
            dhkem.X25519Kem,
            taint,
            "ctgrind-hpke-x25519-decap-recipient-ikm",
            "ctgrind-hpke-x25519-decap-ephemeral-ikm",
        ),
        .x25519_authdecap => try kemAuthDecap(
            dhkem.X25519Kem,
            taint,
            "ctgrind-hpke-x25519-authdecap-recipient-ikm",
            "ctgrind-hpke-x25519-authdecap-sender-ikm",
            "ctgrind-hpke-x25519-authdecap-ephemeral-ikm",
        ),
        .p256_decap => try kemDecap(
            dhkem.P256Kem,
            taint,
            "ctgrind-hpke-p256-decap-recipient-ikm",
            "ctgrind-hpke-p256-decap-ephemeral-ikm",
        ),
        .p256_authdecap => try kemAuthDecap(
            dhkem.P256Kem,
            taint,
            "ctgrind-hpke-p256-authdecap-recipient-ikm",
            "ctgrind-hpke-p256-authdecap-sender-ikm",
            "ctgrind-hpke-p256-authdecap-ephemeral-ikm",
        ),
        .p384_decap => try kemDecap(
            dhkem.P384Kem,
            taint,
            "ctgrind-hpke-p384-decap-recipient-ikm",
            "ctgrind-hpke-p384-decap-ephemeral-ikm",
        ),
        .p384_authdecap => try kemAuthDecap(
            dhkem.P384Kem,
            taint,
            "ctgrind-hpke-p384-authdecap-recipient-ikm",
            "ctgrind-hpke-p384-authdecap-sender-ikm",
            "ctgrind-hpke-p384-authdecap-ephemeral-ikm",
        ),
        .open => try openTarget(taint),
    }
}
