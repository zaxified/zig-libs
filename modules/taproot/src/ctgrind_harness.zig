// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Constant-time"
//! bullet: "`tweakSecretKey` handles secret data (`d`, `q`) and uses only
//! `Secp256k1.scalar`'s constant-time field arithmetic for the `(d + t) mod n`
//! step; the even-y normalization is delegated verbatim to
//! `bip340.KeyPair.fromSecretKey`, so this module introduces no
//! secret-dependent branching beyond what the bip340 signing path itself
//! already has (the parity branch inside `fromSecretKey` — the identical code
//! `bip340.sign` runs). `tweakPublicKey` operates on public data only and
//! makes no constant-time claim (mirroring `bip340.verify`'s documented
//! exemption)." — as an actual committed program instead of a sentence nobody
//! re-checks. Run through `zig build ctgrind -Dctgrind-module=taproot
//! -Dctgrind-valgrind=…` plus `valgrind --tool=memcheck` by hand —
//! `scripts/ctgrind.sh` has no per-module TARGETS/MODES/PATTERN/LABEL entry
//! for `taproot` yet; the suggested lines are at the bottom of this comment
//! for the coordinator to paste in.
//!
//! NOT wired into `zig build test-taproot` — memcheck's context count is
//! valgrind's own output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## FIRST: does this module actually touch a secret?
//!
//! Yes, but only through ONE function. `tweakPublicKey` (BIP341's
//! `taproot_output_key`) takes an x-only public key and an optional Merkle
//! root — both public — and its own doc comment says so explicitly:
//! "Constant-time: NOT required and not attempted — every input here is
//! public". There is nothing to measure there; tainting it would light up
//! memcheck by design (a variable-time `Fe.invert`-free lift + point add
//! over PUBLIC data), the same wrong-target failure mode this campaign's
//! briefs keep calling out. `tweakSecretKey` is the module's only secret path
//! and the ONLY target below.
//!
//! ## The one target: `secret` (`tweakSecretKey`)
//!
//! Tainted: the 32-byte BIP340 `SecretKey` (`internal_sk`) that
//! `tweakSecretKey` receives — the "internal private key" the task brief asks
//! for. That taint reaches, end to end: the raw scalar `d0` (validated inside
//! `bip340.SecretKey.fromBytes`/`KeyPair.fromSecretKey`), the even-y-normalized
//! effective scalar `d` (`kp.secret`), and the final tweaked scalar `q = (d +
//! t) mod n` — the "tweaked private key" the brief asks for. `q` is what this
//! harness formats through the propagation witness below.
//!
//! NOT tainted (both PUBLIC by BIP341, matching `tweakPublicKey`'s own
//! exemption and the task brief's instruction not to taint the script tree /
//! Merkle path / public output key): `merkle_root` is passed as `null` (the
//! key-path-only case — `tapTweakHash` then hashes over `P_x` alone). `t`
//! itself is derived from `kp.public.x` (a PUBLIC value, the even-y internal
//! x-only key) and `merkle_root`, so `tapTweakHash`'s own SHA-256 work runs
//! over public bytes — except that `kp.public.x` is *data-flow* tainted by
//! memcheck (it was computed from the tainted secret via `combMulBase`) even
//! though it is not secret in the protocol sense. Memcheck cannot tell
//! "derived from a secret but now disclosed" from "still secret" (same
//! caveat `k256`'s own harness states for `Pa.y.isOdd()`); any context this
//! produces inside `hash.zig`/`bip340`'s tagged-hash code is therefore
//! attributed and discussed below, not assumed away.
//!
//! ## taproot-own vs bip340/k256/std-delegated
//!
//! `tweakSecretKey`'s OWN code (`root.zig`) does exactly three things with the
//! secret: (1) calls `bip340.KeyPair.fromSecretKey(internal_sk)` — entirely
//! delegated; (2) re-extracts `d = Scalar.fromBytes(kp.secret, .big)` — a std
//! canonicality check on an already-canonical value ("canonical by
//! construction" per the source comment); (3) `d.add(t)` — std's fiat-crypto
//! field add, branch-free limb arithmetic. There is no taproot-authored
//! branch, mask, or select anywhere in this path — every conditional touching
//! the secret lives in `bip340`'s or std's code:
//!
//!   * `modules/bip340/src/root.zig:161` — `Scalar.fromBytes(sk.bytes, .big)`
//!     inside `KeyPair.fromSecretKey`: std's canonicality check
//!     (`crypto/pcurves/common.zig`'s `rejectNonCanonical`, a
//!     `timing_safe.compare` result branched on with `if (... != .lt) return
//!     error`). bip340-delegated.
//!   * `modules/bip340/src/root.zig:162` — `if (d.isZero()) return
//!     error.InvalidSecretKey;`: a real branch on the raw secret scalar being
//!     exactly zero. bip340-delegated, negligible-probability class (1/2^256
//!     for a real random key — same shape as `k256`'s `rejectIdentity`, see
//!     below).
//!   * `modules/bip340/src/root.zig:163` — `Secp256k1.combMulBase(sk.bytes,
//!     .big)`: k256's fixed-base comb, ending in `group.zig:347`'s `try
//!     acc.rejectIdentity()`. **This is the accepted `rejectIdentity` class
//!     named in the campaign brief** (k256's `mul`/`combMulBase` both end
//!     this way, `group.zig:278` and `:347`) — a branch on "did the whole
//!     scalar multiplication land on the neutral element", probability
//!     ~2^-256, not a new defect. One `combMulBase` call here (vs. bip340's
//!     own `sign`, which has two: pubkey derivation + nonce commitment).
//!   * `modules/bip340/src/root.zig:165` — `if (xy.y.isOdd()) scalar.neg(...)
//!     else sk.bytes;`: **the parity handling the task brief specifically
//!     asks about.** THIS branch is a plain Zig `if`/`else`, not a masked
//!     select — unlike `sign`'s own step-7 nonce-parity select (`root.zig`
//!     lines ~298-305, built from `0 -% @intFromBool(...)` and `&`/`|`, no
//!     conditional instruction at all), `KeyPair.fromSecretKey`'s effective-
//!     scalar normalization is a genuine data-dependent branch. `xy.y` is the
//!     y-parity of `p = d0*G`, the RAW (pre-normalization) point — a value
//!     the protocol never discloses on its own (only the final even-y `Q` is
//!     published), so branching on it is a real one-bit function of the
//!     secret with no public counterpart to excuse it, unlike `Pa.y.isOdd()`
//!     in a context where `Pa` itself is later published. Whether this
//!     actually reaches machine code as a `Jcc`/`CMOVcc` memcheck flags is an
//!     empirical question the measurement below answers, not asserted here.
//!     bip340-delegated — this module did not write the branch, but
//!     `tweakSecretKey` exercises it on every call and re-uses it "so
//!     divergence is structurally impossible" per `root.zig`'s own doc
//!     comment, i.e. the delegation is deliberate, not incidental.
//!   * `modules/taproot/src/root.zig:274` — `Scalar.fromBytes(kp.secret,
//!     .big) catch unreachable`: taproot's OWN call site, but the branch it
//!     triggers (`rejectNonCanonical`, same as bip340's :161) is std's, on an
//!     already-canonical value. taproot-own call, std-delegated branch.
//!   * `modules/taproot/src/root.zig:287` — `d.add(t).toBytes(.big)`: std's
//!     `fiat.add` (branch-free limb arithmetic) then `fiat.toBytes` (also
//!     branch-free). Expected to contribute NOTHING — this is the line the
//!     SPEC's constant-time claim is actually about, and its zero (if
//!     measured as zero) is the strong claim, readable only next to the
//!     non-zero rows above proving the taint is live.
//!
//! Net: **zero taproot-authored branches on the secret.** Every non-zero
//! context this harness finds belongs to bip340 or std, reached because
//! `tweakSecretKey` calls into them — which is exactly what SPEC.md's
//! sentence "this module introduces no secret-dependent branching beyond what
//! the bip340 signing path itself already has" claims, and what this harness
//! exists to make falsifiable instead of asserted.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. `std.valgrind.doClientRequest` opens with
//!    `if (!builtin.valgrind_support) return default;`, off by default outside
//!    Debug. Built WITHOUT `-fvalgrind`, every client request compiles to
//!    nothing and `--taint=yes` silently behaves like `--taint=no` — measured
//!    as its own row below, not assumed.
//! 2. An optimizer is in principle free to keep a defined copy of `internal_sk`
//!    in a register rather than reading back the memory `makeMemUndefined`
//!    marked. `reloadVolatile` forces one real load from freshly-tainted
//!    memory immediately before the call under test. Defensive, not
//!    demonstrated on this host/compiler.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow checks in the
//!    field/scalar arithmetic underneath (k256's `field.zig`, std's
//!    `common.zig`) that branch on tainted values and bury the signal, and
//!    Debug's self-hosted backend is not readable by valgrind's DWARF parser
//!    at all (`scripts/ctgrind.sh` § MODES).
//!
//! ## The propagation witness
//!
//! The tweaked scalar `q` is formatted with `std.debug.print`, which is not
//! constant-time, so a tainted byte reaching it always produces contexts of
//! its own. A non-zero total next to a small, itemised in-file count is what
//! makes the itemisation mean "no branch found" rather than "the harness
//! never ran".
//!
//! ## Suggested config lines for scripts/ctgrind.sh (coordinator to paste in)
//!
//! ```
//! TARGETS[taproot]="secret"
//! MODES[taproot]="ReleaseFast"
//! PATTERN[taproot/secret]='root[.]zig|hash[.]zig|group[.]zig|field[.]zig|fast_core[.]zig|common[.]zig'
//! LABEL[taproot/secret]='taproot tweakSecretKey+bip340 fromSecretKey+k256 comb+std scalar'
//! ```
//! `root[.]zig` matches BOTH `modules/taproot/src/root.zig` and
//! `modules/bip340/src/root.zig` — deliberately, same trap `blindrsa`'s
//! pattern comment documents for its own same-basename dependency: every hit
//! was traced by qualified symbol name (`root.tweakSecretKey` vs.
//! `root.KeyPair.fromSecretKey`) rather than assumed. `common[.]zig` is std's
//! `crypto/pcurves/common.zig`, reached through both `bip340`'s and
//! `k256`'s scalar re-exports.

const std = @import("std");
const builtin = @import("builtin");
const taproot = @import("root.zig");
const bip340 = @import("bip340");

/// Deterministic "random" secret key material. Computed at runtime (not
/// folded at comptime) so tainting it marks memory `tweakSecretKey` actually
/// reads.
fn secretBytes(comptime n: usize, comptime domain: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    var st = std.crypto.hash.sha3.Shake256.init(.{});
    st.update(domain);
    st.squeeze(&out);
    return out;
}

/// A secret key comfortably inside `[1, n)`: clearing the top byte keeps the
/// value below the curve order, so `tweakSecretKey` gets a realistic input
/// rather than one that happens to exercise the reduction/zero edge.
fn secretScalar(comptime domain: []const u8) [32]u8 {
    var s = secretBytes(32, domain);
    s[0] = 0;
    if (s[31] == 0) s[31] = 1;
    return s;
}

/// Forces one real load from `s` through a volatile pointer, one byte at a
/// time, so `tweakSecretKey` cannot be fed a copy that predates
/// `makeMemUndefined` — see trap 2 above.
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { secret };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "secret")) return .secret;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;
    _ = target; // only one target exists today; kept for parity with every other harness's CLI shape

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    // The "internal private key" the task brief asks to taint.
    var sk_bytes = secretScalar("ctgrind-taproot-harness-internal-secret-key-v1");
    taintIf(tainted, &sk_bytes);
    const sk_raw = reloadVolatile(32, &sk_bytes);
    const internal_sk = try bip340.SecretKey.fromBytes(sk_raw);

    // PUBLIC by BIP341 (see the module doc comment above) — no script tree at
    // all, so tapTweakHash hashes over the internal x-only key alone. Never
    // tainted (it does not exist as a byte buffer here); do not taint the
    // Merkle path/script tree per the task brief.
    const merkle_root: ?[32]u8 = null;

    // The call under test — taproot's ONLY secret-data path. Produces the
    // "tweaked private key" q the task brief asks to taint/observe.
    const q = try taproot.tweakSecretKey(internal_sk, merkle_root);

    // Propagation witness: format the (tainted, if taint=yes) tweaked scalar
    // through a non-constant-time path. See the module doc comment above.
    std.debug.print("q={x}\n", .{q});
}
