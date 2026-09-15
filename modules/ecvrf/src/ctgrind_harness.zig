// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s "Verified, not
//! asserted" bullet, as an actual committed program. Run it through
//! `../../../scripts/ctgrind.sh ecvrf`.
//!
//! That bullet quoted "11 errors / 10 contexts before, 4 / 3 after" with no
//! harness in the repo. The "before" half describes code that no longer exists
//! (`ecvrf` carried its own copy of std's ladder, `rejectIdentity` and all,
//! until it moved to `ct25519`), so it is not reproducible by construction and
//! is now labelled as history rather than as a number a reader can re-take.
//!
//! NOT wired into `zig build test-ecvrf` — memcheck's context count is
//! valgrind's output, not something a Zig test can assert on. `zig build
//! check-ctgrind` compiles it so it cannot rot into an unbuildable recipe.
//!
//! ## `prove` — the secret key, and ONLY the secret key
//!
//! The 32-byte VRF secret key is marked `MAKE_MEM_UNDEFINED` and driven through
//! `KeyPair.fromSecretKey` (`publicKey`: `x`, `Y = x*B`) and `KeyPair.prove`
//! (`Gamma = x*H`, the nonce `k`, `k*B`, `k*H`, `s = k + c*x`).
//!
//! ⭐ `Y` is DECLASSIFIED between the two calls (`MAKE_MEM_DEFINED`), because
//! it is the published public key. Until 2026-09-16 this harness called the
//! one-shot `prove(sk, alpha)`, which recomputes `Y` from `sk` internally, so
//! there was no seam at which `Y` could be declassified and every branch on a
//! function of `Y` was reported as if it were a branch on `sk`: `encodeToCurve`'s
//! try-and-increment (`H = encode_to_curve(PK_string, alpha)`, which every
//! verifier recomputes from public inputs) and `proveExpanded`'s decode of `H`.
//! That was 3 contexts, and 5 once A1 E14 made `stringToPoint` strict — all
//! five over-taint of a public value, none on `x` or `k` (measured with
//! `--stacks`; see A1 `ecvrf.md` § Dispozice 2026-09-16 (ctgrind harness)).
//! `KeyPair` (A1 E10) is that seam. The only code of the one-shot `prove` this
//! target does not execute is its own single line composing `expandSecretKey`,
//! `mulBase` and `proveExpanded`, all three of which it does execute.
//!
//! A zero in-file count here therefore means "no branch on `x`, `prefix` or
//! `k`", not "no branch on a function of `Y`".
//!
//! ## `verify` — DOCUMENTARY, not a constant-time claim (A1 E15)
//!
//! `verify` has no secret: the key, `alpha` and the proof are all public, and
//! SPEC.md says `verify` is variable-time by design. This target taints
//! `alpha` only to LIST where `verify`'s control flow depends on its input
//! (7 contexts: the try-and-increment candidate decode and identity check, the
//! decode of `H`, `mulDoubleBasePublic`, and the `c == c'` verdict). None of
//! them is a leak.
//!
//! ⛔ It does NOT prove what E15 asked for. E15 named the mutation
//! "`timing_safe.eql` → `std.mem.eql`" as green in every gate; measured
//! 2026-09-16, that mutation is green HERE too — 7 / 7, same lines — because
//! both forms end in one branch on a tainted equality at the same call site,
//! and memcheck counts contexts by address. The proof and key are computed
//! untainted first; the verdict is declassified before the harness branches
//! on it (accept/reject is public).
//!
//! ⭐ The gate that DOES catch it is `scripts/check-ct-compare.py`, which pins
//! `modules/ecvrf/src/ecvrf.zig` at one `timing_safe` comparison and zero
//! plain `std.mem` ones. Measured on that mutation 2026-09-16: the module's
//! own suite is 31/31 green in both release modes, this harness's counts do
//! not move, and that gate fails naming the file and the direction (1 → 0 on
//! the left, 0 → 1 on the right). ctgrind's own red there is the SOURCE
//! DIGEST, which trips on any edit to the file — a comment included — so it
//! says "re-read this", not "the comparison changed".
//!
//! ⚠ What neither gate does: the pin is a count per FILE, so it cannot see
//! WHICH values are compared. Swapping the compare while adding a
//! `timing_safe` call elsewhere in the same file keeps the count at one.
//!
//! ## The traps
//!
//! 1. Without `-fvalgrind` every row reads 0 regardless
//!    (`std.valgrind.doClientRequest` returns early unless
//!    `builtin.valgrind_support`, which the release modes disable). The driver
//!    prints that as its own row.
//! 2. `reloadVolatile` forces a real load from freshly-(un)tainted memory, so a
//!    register copy that predates the client request cannot be used instead.
//! 3. ReleaseFast only — `Debug`/`ReleaseSafe` add overflow branches inside
//!    `std.crypto.25519.field` that flood the report.
//!
//! ## The propagation witness
//!
//! `prove`: the proof is formatted through `std.debug.print`, which is not
//! constant-time. `verify`: `beta` is a function of the public `Gamma` only, so
//! it carries no taint; the row's non-zero total comes from the in-file
//! contexts themselves (the try-and-increment branches on `alpha`).

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const memcheck = std.valgrind.memcheck;

fn secretKey() root.SecretKey {
    var sk: root.SecretKey = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-ecvrf-harness-secret-key-v1", &sk, .{});
    return sk;
}

fn reloadVolatile(comptime T: type, s: *const T) T {
    const v: *const volatile T = s;
    return v.*;
}

/// `alpha_string` for both targets. PUBLIC in `prove`; the tainted subject in
/// `verify`.
const alpha_text = "ctgrind harness alpha";

const Target = enum { prove, verify };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "prove")) return .prove;
    if (std.mem.eql(u8, s, "verify")) return .verify;
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
    const taint = try parseTaint(taint_arg);

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .prove => {
            var sk = secretKey();
            if (taint == .yes) memcheck.makeMemUndefined(&sk);
            const secret = reloadVolatile(root.SecretKey, &sk);

            // Measured: `x` from `sk`, `Y = x*B`.
            var kp = root.KeyPair.fromSecretKey(secret);
            // `Y` is published — declassify it, then force the next read of it
            // to come from the now-defined memory.
            if (taint == .yes) memcheck.makeMemDefined(&kp.public_key);
            kp.public_key = reloadVolatile(root.PublicKey, &kp.public_key);

            // Measured: everything `prove` does with `x`, `prefix` and `k`.
            const pi = kp.prove(alpha_text);

            std.debug.print("pk={x}\n", .{kp.public_key}); // public: no witness
            std.debug.print("pi={x}\n", .{pi}); // propagation witness
        },
        .verify => {
            // Untainted setup: an honest proof over the same alpha.
            const kp = root.KeyPair.fromSecretKey(secretKey());
            const pi = kp.prove(alpha_text);

            var alpha: [alpha_text.len]u8 = alpha_text.*;
            if (taint == .yes) memcheck.makeMemUndefined(&alpha);
            const alpha_in = reloadVolatile([alpha_text.len]u8, &alpha);

            // Measured.
            var res = root.verify(kp.public_key, &alpha_in, pi);
            // The verdict is public. Declassify before the harness branches.
            if (taint == .yes) memcheck.makeMemDefined(std.mem.asBytes(&res));
            const beta = try reloadVolatile(@TypeOf(res), &res);

            std.debug.print("beta={x}\n", .{beta});
        },
    }
}
