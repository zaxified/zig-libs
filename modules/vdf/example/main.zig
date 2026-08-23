// SPDX-License-Identifier: MIT

//! What a randomness-beacon / delay-based leader-election caller does with
//! `vdf`: `eval` the sequential delay `y = x^(2^T) mod N` over the module's
//! own RSA-2048 Factoring Challenge reference group, `prove` a succinct
//! proof, and `verify` it in time independent of `T` — plus see a forged
//! proof rejected and a malformed element rejected by NAME.
//!
//! ## External oracle: attempted, and does not apply — see why
//!
//! The task instructions here name Chia's `chiavdf` (pip-installable) as
//! the reference VDF implementation to try first. It WAS installed and run
//! offline (`python3 -m venv`, `pip install chiavdf`, both succeeded,
//! `chiavdf-1.1.14`), and its public entry points were inspected:
//! `create_discriminant`, `prove`, `verify_wesolowski`, ...  — `prove`'s
//! signature takes a `discriminant`, not an RSA modulus `N`. `chiavdf`
//! implements Wesolowski's proof over an imaginary-quadratic CLASS GROUP
//! (elements are binary quadratic forms under a negative discriminant), not
//! this module's RSA `Z_N*` hidden-order group — a structurally different
//! group with a different element encoding, so there is no `(N, x, y, T)`
//! this module could hand it and no `(discriminant, x, y, T)` chiavdf
//! produces that this module could check. This exact gap is independently
//! documented in `SPEC.md`'s "Verification" section (chiavdf/iotaledger/
//! poanetwork all searched, all class-group, "none publishes byte-level
//! fixtures suitable for cross-language embedding regardless of group") —
//! this example's install-and-inspect attempt confirms that finding rather
//! than superseding it.
//!
//! Falling back, per the task instructions, to the module's own published
//! parameters: the RSA-2048 Factoring Challenge modulus `vdf.group.
//! rsa2048ChallengeModulus()` (a real, historically-public, never-factored
//! 2048-bit RSA number — see `NOTICE`), `x = 5`, run through the full
//! `eval` -> `prove` -> `verify` round trip, PLUS an independent
//! cross-language check of `eval`'s own output: `expected_y_hex` below is
//! `pow(5, 2**2000, N)` computed directly in Python's arbitrary-precision
//! `pow()` — a different language and a different modexp implementation
//! than this module's sequential-squaring loop, the same style of
//! cross-check `SPEC.md` records for its own `eval` KATs (just a different
//! `T`, chosen small enough that the SEQUENTIAL loop this module actually
//! runs — unlike Python's `pow()`, which is not obligated to visit `T`
//! sequential squarings — finishes in about a second on this machine).
//!
//! `T = 2000` is far below any real delay parameter (a real deployment
//! would pick `T` in the billions), chosen only so this example — which,
//! unlike a production VDF, is a correctness GATE that must run fast, not a
//! demonstration of an actual time delay — finishes quickly. `vdf`
//! allocates nothing and keeps no state (`Modulus`/`Fe`/`Proof` are plain
//! value types), so there is no DebugAllocator to wrap — same shape as
//! `modules/ct25519/example/main.zig`.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const vdf = @import("vdf");

const modulus_bytes = vdf.group.modulus_bytes;

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(1 << 16);
    var out: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable;
    return out;
}

// pow(5, 2**2000, N) computed independently in Python (see header comment)
// against the SAME RSA-2048 Factoring Challenge modulus this module embeds.
const expected_y = hexToBytes("015580a72fcd7fc38b9dfe019ad32504a60aaa3103034e4c2f84d073d198c729be848304104ba75b1ce6104966ff562b319179a765e968affa0884665cddc85aa9926fbe9f7fb98b90362e2079d40fb61776f46a2d0d0dfa79fb0e4dd9b175a966c2989580a1b2b96ee0d5d0ecb08fcbc5fd9e6854c4c5f88baf00181a00d22eda727c453f7b948defe1db8ac081345d591d90947454042a088b02a1eb51b81f432c94ab3d668b226de61cd625d4e4d48861e90c83fa770135d5257fd27dec67173c8866af614bafd9fc35e8219a58c546e7178ac94d8ee2b1dd43e44d82e697c345dab9163426ad54101c980da750123ca84294881f5bb9885620e9d5bc1a16");

const T: u64 = 2000;

pub fn main() !void {
    const m = vdf.group.rsa2048ChallengeModulus();

    var x_canon: [modulus_bytes]u8 = [_]u8{0} ** modulus_bytes;
    x_canon[modulus_bytes - 1] = 5;
    const x = try vdf.group.elementFromBytes(m, &x_canon);

    // ── eval: the sequential delay, cross-checked against an independent
    //    Python computation of the SAME (N, x, T) ──────────────────────
    const y = vdf.eval(m, x, T);
    var y_canon: [modulus_bytes]u8 = undefined;
    try vdf.group.toBytes(y, &y_canon);
    if (!std.mem.eql(u8, &y_canon, &expected_y)) return error.EvalMismatch;
    std.debug.print("eval: y = x^(2^{d}) mod N matches independent Python pow() computation\n", .{T});

    // ── prove + verify: the succinct Wesolowski round trip ──────────────
    const proof = try vdf.prove(m, &x_canon, &y_canon, T);
    const ok = try vdf.verify(m, &x_canon, &y_canon, proof, T);
    if (!ok) return error.HonestProofRejected;
    std.debug.print("prove/verify: an honest proof is accepted\n", .{});

    // ── soundness: a single-bit-tampered (forged) proof is rejected ─────
    // `verify`'s doc comment documents this as a `false` return (its
    // element-validation step is allowed to answer "false (or a documented
    // error)" — here it is well-formed-but-wrong, so verify runs the full
    // check and the algebraic identity fails), not a distinct error name —
    // this is the boolean soundness check `SPEC.md` calls the module's
    // actual crux.
    {
        var forged = proof;
        forged.pi[forged.pi.len - 1] ^= 0xff;
        const forged_ok = try vdf.verify(m, &x_canon, &y_canon, forged, T);
        if (forged_ok) return error.ForgedProofAccepted;
        std.debug.print("verify: a tampered proof is rejected (boolean soundness check)\n", .{});
    }

    // ── malformed element, rejected by NAMED error ───────────────────────
    // `prove` (unlike `verify`) DOES propagate a named error for an
    // out-of-range/zero element -- see `ProveError`. A zero `x` is never a
    // member of Z_N* and `group.elementFromBytes` rejects it outright.
    {
        const zero_x: [modulus_bytes]u8 = [_]u8{0} ** modulus_bytes;
        if (vdf.prove(m, &zero_x, &y_canon, T)) |_| {
            return error.UnexpectedProveSuccess;
        } else |err| switch (err) {
            error.InvalidElement => std.debug.print("prove with x=0: InvalidElement (expected)\n", .{}),
        }
    }
}
